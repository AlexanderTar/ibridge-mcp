// SPDX-License-Identifier: Apache-2.0

//! SMTP send. Login uses the full Apple ID. `MAIL FROM` may be a custom domain.

use std::time::{SystemTime, UNIX_EPOCH};

use ibridge_auth::Credentials;
use ibridge_core::CoreError;
use lettre::address::{Address, Envelope};
use lettre::transport::smtp::authentication::Credentials as SmtpCredentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use tracing::Instrument;

/// A message handed to SMTP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutgoingMail {
    /// Address in `From` and `MAIL FROM`. A custom domain is allowed here.
    pub from: String,
    /// Envelope recipients.
    pub to: Vec<String>,
    /// Subject.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// `In-Reply-To` message id, when this message is a reply.
    pub in_reply_to: Option<String>,
    /// `References` message ids. Empty means "same as `in_reply_to`" when that is set.
    pub references: Vec<String>,
}

/// SMTP client for one account.
///
/// [`Self::icloud`] is the production constructor: port 587 and required STARTTLS.
/// Tests build a cleartext client for a loopback server only.
#[derive(Debug)]
pub struct SmtpClient {
    credentials: Login,
    host: String,
    port: u16,
    starttls: bool,
}

/// Where a send gets its password.
#[derive(Debug)]
enum Login {
    /// The client owns the credentials.
    Owned(Credentials),
    /// The client owns none. Each send reads the call's, for this account only.
    PerCall(ibridge_core::AppleId),
}

impl Login {
    fn apple_id(&self) -> &ibridge_core::AppleId {
        match self {
            Self::Owned(credentials) => &credentials.apple_id,
            Self::PerCall(apple_id) => apple_id,
        }
    }

    /// The login for one `AUTH`: this client's own, or the one the call carries.
    fn for_auth(&self) -> Result<SmtpCredentials, CoreError> {
        // Known limit: lettre keeps the password in a plain `String` until it sends
        // `AUTH`, and its `Credentials` is not zeroized on drop. Wipe it here if lettre
        // ever exposes a way to.
        let read = |credentials: &Credentials| {
            credentials.with_secret(|secret| {
                SmtpCredentials::new(credentials.apple_id.as_str().to_owned(), secret.to_owned())
            })
        };
        match self {
            Self::Owned(credentials) => Ok(read(credentials)),
            Self::PerCall(apple_id) => ibridge_auth::call_credentials(|credentials| {
                (credentials.apple_id == *apple_id).then(|| read(credentials))
            })
            .flatten()
            // A call without credentials, or with another account's, is a bug in the caller.
            .ok_or_else(|| CoreError::Protocol("no credentials for this call".to_owned())),
        }
    }
}

impl SmtpClient {
    /// iCloud SMTP on `smtp.mail.me.com:587` with STARTTLS required.
    #[must_use]
    pub fn icloud(credentials: Credentials) -> Self {
        Self {
            credentials: Login::Owned(credentials),
            host: "smtp.mail.me.com".to_owned(),
            port: 587,
            starttls: true,
        }
    }

    /// iCloud SMTP for a server that must not keep the password between calls.
    ///
    /// Each send signs in with the credentials of the call that makes it
    /// (see `ibridge_auth::with_call_credentials`). A call without credentials,
    /// or with another account's, fails before anything leaves.
    #[must_use]
    pub fn icloud_per_call(apple_id: ibridge_core::AppleId) -> Self {
        Self {
            credentials: Login::PerCall(apple_id),
            host: "smtp.mail.me.com".to_owned(),
            port: 587,
            starttls: true,
        }
    }

    /// Cleartext SMTP for a loopback test server.
    ///
    /// An allowlisted iCloud host is refused: lettre would send `AUTH` with no TLS.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::HostNotAllowed`] when `host` is not a loopback name.
    /// The port is not part of that check.
    #[cfg(any(test, feature = "test-hosts"))]
    pub(crate) fn plain(
        credentials: Credentials,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, CoreError> {
        let host = host.into();
        if !is_loopback(&host) {
            return Err(CoreError::HostNotAllowed);
        }
        Ok(Self {
            credentials: Login::Owned(credentials),
            host,
            port,
            starttls: false,
        })
    }

    /// Cleartext per-call SMTP for a loopback test server. See [`Self::icloud_per_call`].
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::HostNotAllowed`] when `host` is not a loopback name.
    #[cfg(any(test, feature = "test-hosts"))]
    pub fn plain_per_call(
        apple_id: ibridge_core::AppleId,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, CoreError> {
        let mut client = Self::plain(
            Credentials::new(apple_id.clone(), String::new()),
            host,
            port,
        )?;
        client.credentials = Login::PerCall(apple_id);
        Ok(client)
    }

    /// Address used for `AUTH`. This is the full Apple ID, not [`OutgoingMail::from`].
    #[must_use]
    pub(crate) fn login_address(&self) -> &str {
        self.credentials.apple_id().as_str()
    }

    /// Sends `mail`.
    ///
    /// The login name is the full Apple ID. `MAIL FROM` and the `From` header
    /// use [`OutgoingMail::from`], which may be a custom-domain alias.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Auth`] when the server rejects the password,
    /// [`CoreError::InvalidInput`] for an address the protocol cannot carry,
    /// [`CoreError::Network`] when the connection fails, and
    /// [`CoreError::Protocol`] for any other SMTP failure. Protocol text from
    /// the server is not copied into the error.
    pub async fn send(&self, mail: &OutgoingMail) -> Result<(), CoreError> {
        self.transmit(mail).await.map(|_| ())
    }

    /// Sends `mail` and returns the exact bytes that were transmitted.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub(crate) async fn transmit(&self, mail: &OutgoingMail) -> Result<Vec<u8>, CoreError> {
        let message = build_message(mail)?;
        let envelope = build_envelope(mail)?;
        let transport = self.transport()?;
        let span = tracing::debug_span!(
            "smtp_send",
            host = %self.host,
            port = self.port,
            recipients = mail.to.len(),
        );
        let sent = transport
            .send_raw(&envelope, &message)
            .instrument(span)
            .await;
        match sent {
            // A send that finished got past `AUTH`.
            Ok(_) => ibridge_auth::report_login(ibridge_auth::LoginVerdict::Accepted),
            Err(error) => {
                let mapped = map_smtp(&error);
                // Only a refused password counts. A dropped connection or another
                // refusal says nothing about it.
                if matches!(mapped, CoreError::Auth) {
                    ibridge_auth::report_login(ibridge_auth::LoginVerdict::Rejected);
                }
                return Err(mapped);
            }
        }
        Ok(message)
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, CoreError> {
        let smtp_credentials = self.credentials.for_auth()?;
        let builder = if self.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
                .map_err(|_| CoreError::Network)?
                .port(self.port)
                .credentials(smtp_credentials)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.host.clone())
                .port(self.port)
                // A paused test clock makes lettre's 60s connect timeout fire at once.
                .timeout(None)
                .credentials(smtp_credentials)
        };
        Ok(builder.build())
    }
}

#[cfg(any(test, feature = "test-hosts"))]
fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

pub(crate) fn build_message(mail: &OutgoingMail) -> Result<Vec<u8>, CoreError> {
    check_headers(mail)?;
    let message_id = fresh_message_id();
    let mut builder = mail_builder::MessageBuilder::new()
        .from(mail.from.as_str())
        .to(mail.to.iter().map(String::as_str).collect::<Vec<_>>())
        .subject(mail.subject.as_str())
        .text_body(mail.body.as_str())
        .message_id(bare_id(&message_id));
    if let Some(reply) = &mail.in_reply_to {
        builder = builder.in_reply_to(bare_id(reply));
    }
    let references = reference_ids(mail);
    if !references.is_empty() {
        let bare: Vec<&str> = references.iter().map(|id| bare_id(id)).collect();
        builder = builder.references(bare);
    }
    builder
        .write_to_vec()
        .map_err(|_| CoreError::Protocol("smtp command failed".to_owned()))
}

/// `mail-builder` writes the angle brackets itself.
fn bare_id(value: &str) -> &str {
    value
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or(value)
}

fn reference_ids(mail: &OutgoingMail) -> Vec<String> {
    if mail.references.is_empty() {
        mail.in_reply_to.iter().cloned().collect()
    } else {
        mail.references.clone()
    }
}

fn fresh_message_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{nanos}@ibridge")
}

fn build_envelope(mail: &OutgoingMail) -> Result<Envelope, CoreError> {
    let from = parse_mailbox(&mail.from)?;
    let mut recipients = Vec::with_capacity(mail.to.len());
    for recipient in &mail.to {
        recipients.push(parse_mailbox(recipient)?);
    }
    Envelope::new(Some(from), recipients)
        .map_err(|_| CoreError::InvalidInput("a message needs at least one recipient".to_owned()))
}

fn parse_mailbox(value: &str) -> Result<Address, CoreError> {
    value
        .parse()
        .map_err(|_| CoreError::InvalidInput("address is not a mailbox".to_owned()))
}

fn check_headers(mail: &OutgoingMail) -> Result<(), CoreError> {
    if mail.to.is_empty() {
        return Err(CoreError::InvalidInput(
            "a message needs at least one recipient".to_owned(),
        ));
    }
    let mut values = vec![mail.from.as_str(), mail.subject.as_str()];
    values.extend(mail.to.iter().map(String::as_str));
    if let Some(reply) = &mail.in_reply_to {
        values.push(reply);
    }
    values.extend(mail.references.iter().map(String::as_str));
    if values.iter().any(|value| has_break(value)) {
        return Err(CoreError::InvalidInput(
            "a header contains a line break".to_owned(),
        ));
    }
    Ok(())
}

fn has_break(value: &str) -> bool {
    value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

fn map_smtp(error: &lettre::transport::smtp::Error) -> CoreError {
    // `status` is only the three-digit code. The server text stays in `source`
    // and is not copied: it can echo the mailbox or, on a bad server, more.
    if matches!(error.status().map(u16::from), Some(535 | 534)) {
        return CoreError::Auth;
    }
    if error.is_permanent() || error.is_transient() || error.is_client() || error.is_response() {
        CoreError::Protocol("smtp command failed".to_owned())
    } else {
        CoreError::Network
    }
}

/// Bytes of `mail`, for the round-trip test.
#[cfg(test)]
fn message_bytes(mail: &OutgoingMail) -> Vec<u8> {
    build_message(mail).expect("message")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::Engine;
    use ibridge_core::AppleId;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    use proptest::prelude::*;

    use super::{OutgoingMail, SmtpClient};

    const PASSWORD: &str = "test-secret";

    /// How the capture server answers `AUTH`.
    #[derive(Clone, Copy)]
    enum AuthReply {
        Accept,
        Reject,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Seen {
        username: String,
        password: String,
        mail_from: String,
        rcpt: Vec<String>,
        data: String,
    }

    pub(crate) struct SmtpCapture {
        host: String,
        port: u16,
        seen: Arc<Mutex<Seen>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl SmtpCapture {
        pub(crate) async fn start() -> Self {
            Self::start_failing(0).await
        }

        /// The first `times` connections are refused. Later ones speak SMTP.
        pub(crate) async fn start_failing(times: usize) -> Self {
            Self::start_with(times, AuthReply::Accept).await
        }

        /// Every `AUTH` is answered 535.
        async fn start_rejecting_auth() -> Self {
            Self::start_with(0, AuthReply::Reject).await
        }

        async fn start_with(times: usize, auth: AuthReply) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("local addr").port();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let slot = Arc::clone(&seen);
            let fails_left = Arc::new(AtomicUsize::new(times));
            let task = tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    let slot = Arc::clone(&slot);
                    let fails_left = Arc::clone(&fails_left);
                    tokio::spawn(async move {
                        let _ = serve(socket, slot, fails_left, auth).await;
                    });
                }
            });
            Self {
                host: "127.0.0.1".to_owned(),
                port,
                seen,
                task,
            }
        }

        fn seen(&self) -> Seen {
            self.seen.lock().expect("seen").clone()
        }

        pub(crate) fn host(&self) -> &str {
            &self.host
        }

        pub(crate) const fn port(&self) -> u16 {
            self.port
        }

        pub(crate) fn message(&self) -> String {
            self.seen.lock().expect("seen").data.clone()
        }

        pub(crate) fn mail_from(&self) -> String {
            self.seen.lock().expect("seen").mail_from.clone()
        }

        /// Envelope recipients of the last message.
        pub(crate) fn rcpts(&self) -> Vec<String> {
            self.seen.lock().expect("seen").rcpt.clone()
        }

        pub(crate) fn username(&self) -> String {
            self.seen.lock().expect("seen").username.clone()
        }

        pub(crate) fn password(&self) -> String {
            self.seen.lock().expect("seen").password.clone()
        }
    }

    impl Drop for SmtpCapture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(
        socket: TcpStream,
        seen: Arc<Mutex<Seen>>,
        fails_left: Arc<AtomicUsize>,
        auth: AuthReply,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(socket);
        let refuse = fails_left
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if refuse {
            write_line(&mut reader, "550 refused\r\n").await?;
            return Ok(());
        }
        write_line(&mut reader, "220 localhost ESMTP\r\n").await?;
        let mut captured = Seen::default();
        loop {
            let Ok(line) = read_line(&mut reader).await else {
                break;
            };
            if starts_with_cmd(&line, "EHLO") || starts_with_cmd(&line, "HELO") {
                write_line(
                    &mut reader,
                    "250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
                )
                .await?;
            } else if let Some(initial) = strip_cmd(&line, "AUTH PLAIN") {
                if initial.is_empty() {
                    write_line(&mut reader, "334 \r\n").await?;
                    let encoded = read_line(&mut reader).await?;
                    (captured.username, captured.password) =
                        plain_login(&encoded).unwrap_or_default();
                } else {
                    (captured.username, captured.password) =
                        plain_login(initial).unwrap_or_default();
                }
                write_auth_result(&mut reader, auth).await?;
            } else if let Some(initial) = strip_cmd(&line, "AUTH LOGIN") {
                let username = if initial.is_empty() {
                    write_line(&mut reader, "334 VXNlcm5hbWU6\r\n").await?;
                    decode_utf8(&read_line(&mut reader).await?)
                } else {
                    decode_utf8(initial)
                };
                captured.username = username.unwrap_or_default();
                write_line(&mut reader, "334 UGFzc3dvcmQ6\r\n").await?;
                captured.password = decode_utf8(&read_line(&mut reader).await?).unwrap_or_default();
                write_auth_result(&mut reader, auth).await?;
            } else if let Some(rest) = strip_prefix_ignore(&line, "MAIL FROM:") {
                captured.mail_from = angle_addr(rest);
                write_line(&mut reader, "250 ok\r\n").await?;
            } else if let Some(rest) = strip_prefix_ignore(&line, "RCPT TO:") {
                captured.rcpt.push(angle_addr(rest));
                write_line(&mut reader, "250 ok\r\n").await?;
            } else if starts_with_cmd(&line, "DATA") {
                write_line(&mut reader, "354 go\r\n").await?;
                captured.data = read_data(&mut reader).await?;
                *seen.lock().expect("seen") = captured.clone();
                write_line(&mut reader, "250 queued\r\n").await?;
            } else if starts_with_cmd(&line, "QUIT") {
                write_line(&mut reader, "221 bye\r\n").await?;
                break;
            } else if starts_with_cmd(&line, "RSET") || starts_with_cmd(&line, "NOOP") {
                write_line(&mut reader, "250 ok\r\n").await?;
            } else {
                write_line(&mut reader, "502 unimplemented\r\n").await?;
            }
        }
        Ok(())
    }

    async fn write_auth_result(
        reader: &mut BufReader<TcpStream>,
        auth: AuthReply,
    ) -> std::io::Result<()> {
        let line = match auth {
            AuthReply::Reject => "535 5.7.8 authentication failed\r\n",
            AuthReply::Accept => "235 ok\r\n",
        };
        write_line(reader, line).await
    }

    async fn read_data(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
        // Keep the bytes the client sent. The terminating `\r\n.\r\n` is the
        // SMTP end marker, not part of the message.
        let mut raw = Vec::new();
        let mut tmp = [0_u8; 1024];
        loop {
            let read = reader.read(&mut tmp).await?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&tmp[..read]);
            if let Some(end) = raw.windows(5).position(|window| window == b"\r\n.\r\n") {
                raw.truncate(end);
                break;
            }
        }
        Ok(String::from_utf8_lossy(&unstuff_dots(&raw)).into_owned())
    }

    fn unstuff_dots(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len());
        let mut at_line_start = true;
        for &byte in raw {
            if at_line_start && byte == b'.' {
                at_line_start = false;
                continue;
            }
            at_line_start = byte == b'\n';
            out.push(byte);
        }
        out
    }

    async fn read_line(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
        let mut buf = Vec::new();
        let read = reader.read_until(b'\n', &mut buf).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "smtp client closed",
            ));
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn write_line(reader: &mut BufReader<TcpStream>, line: &str) -> std::io::Result<()> {
        let socket = reader.get_mut();
        socket.write_all(line.as_bytes()).await?;
        socket.flush().await
    }

    fn starts_with_cmd(line: &str, cmd: &str) -> bool {
        strip_cmd(line, cmd).is_some()
    }

    fn strip_cmd<'a>(line: &'a str, cmd: &str) -> Option<&'a str> {
        let rest = strip_prefix_ignore(line, cmd)?;
        if rest.is_empty() {
            return Some(rest);
        }
        rest.strip_prefix(|ch: char| ch.is_ascii_whitespace())
            .map(str::trim)
    }

    fn strip_prefix_ignore<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            Some(&line[prefix.len()..])
        } else {
            None
        }
    }

    fn angle_addr(value: &str) -> String {
        let value = value.trim();
        value
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .map_or_else(
                || {
                    value
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                },
                |(addr, _)| addr.to_owned(),
            )
    }

    fn plain_login(encoded: &str) -> Option<(String, String)> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let mut parts = text.split('\0');
        let _authzid = parts.next()?;
        let username = parts.next()?.to_owned();
        Some((username, parts.next()?.to_owned()))
    }

    fn decode_utf8(encoded: &str) -> Option<String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        String::from_utf8(bytes).ok()
    }

    fn credentials() -> ibridge_auth::Credentials {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        ibridge_auth::Credentials::new(apple_id, PASSWORD)
    }

    fn sample(from: &str) -> OutgoingMail {
        OutgoingMail {
            from: from.to_owned(),
            to: vec!["bob@example.com".to_owned()],
            subject: "Picnic".to_owned(),
            body: "Bring napkins.".to_owned(),
            in_reply_to: None,
            references: Vec::new(),
        }
    }

    async fn send_to_capture(mail: OutgoingMail) -> Seen {
        let capture = SmtpCapture::start().await;
        let client = SmtpClient::plain(credentials(), &capture.host, capture.port)
            .expect("loopback host is allowed");
        tokio::time::timeout(Duration::from_secs(5), client.send(&mail))
            .await
            .expect("send timed out")
            .expect("send");
        capture.seen()
    }

    fn refuses_password(seen: &Seen) {
        assert!(
            !seen.username.contains(PASSWORD) && !seen.data.contains(PASSWORD),
            "the password must not appear in the captured username or message"
        );
    }

    fn header_has(data: &str, name: &str, value: &str) -> bool {
        let headers = data.split_once("\r\n\r\n").map_or(data, |(head, _)| head);
        let mut unfolded = String::new();
        for line in headers.split("\r\n") {
            if line.starts_with([' ', '\t']) {
                unfolded.push(' ');
                unfolded.push_str(line.trim());
            } else {
                unfolded.push_str("\r\n");
                unfolded.push_str(line);
            }
        }
        unfolded.split("\r\n").any(|line| {
            line.split_once(':')
                .is_some_and(|(key, rest)| key.eq_ignore_ascii_case(name) && rest.contains(value))
        })
    }

    #[test]
    fn plain_refuses_a_non_loopback_host() {
        let err = SmtpClient::plain(credentials(), "smtp.mail.me.com", 587)
            .expect_err("cleartext SMTP is only for a loopback test server");
        assert!(
            matches!(err, ibridge_core::CoreError::HostNotAllowed),
            "an allowlisted host must not receive the password in cleartext, got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_uses_full_address_login() {
        let seen = send_to_capture(sample("ada@icloud.com")).await;
        refuses_password(&seen);
        assert_eq!(
            seen.username, "ada@icloud.com",
            "SMTP AUTH uses the full Apple ID, not the local part"
        );
    }

    #[tokio::test]
    async fn send_from_custom_alias_sets_mail_from() {
        let seen = send_to_capture(sample("coach@example.com")).await;
        refuses_password(&seen);
        assert_eq!(
            seen.username, "ada@icloud.com",
            "login stays the primary Apple ID"
        );
        assert_eq!(
            seen.mail_from, "coach@example.com",
            "MAIL FROM is the custom-domain alias"
        );
        assert!(
            header_has(&seen.data, "From", "coach@example.com"),
            "the From header is the custom-domain alias, got {}",
            seen.data
        );
    }

    #[tokio::test]
    async fn send_reply_sets_in_reply_to_and_references() {
        let mut mail = sample("ada@icloud.com");
        mail.in_reply_to = Some("<parent@example.com>".to_owned());
        mail.references = vec![
            "<root@example.com>".to_owned(),
            "<parent@example.com>".to_owned(),
        ];
        let seen = send_to_capture(mail).await;
        assert!(
            header_has(&seen.data, "In-Reply-To", "<parent@example.com>"),
            "In-Reply-To is missing, got {}",
            seen.data
        );
        assert!(
            header_has(&seen.data, "References", "<root@example.com>"),
            "References is missing the root id, got {}",
            seen.data
        );
        assert!(
            header_has(&seen.data, "References", "<parent@example.com>"),
            "References is missing the parent id, got {}",
            seen.data
        );
    }

    proptest! {
        #[test]
        fn mime_build_parse_roundtrip(
            local in "[a-z]{1,8}",
            subject in "[A-Za-z0-9][A-Za-z0-9 ]{0,24}",
            body in "[A-Za-z0-9][A-Za-z0-9 ]{0,40}",
        ) {
            let from = format!("{local}@example.com");
            let to = format!("bob@{local}.example");
            let mail = OutgoingMail {
                from: from.clone(),
                to: vec![to.clone()],
                subject: subject.clone(),
                body: body.clone(),
                in_reply_to: None,
                references: Vec::new(),
            };
            let parsed = crate::mime::read_message(&super::message_bytes(&mail), 0);
            let parsed = parsed.expect("built MIME should parse");
            prop_assert_eq!(parsed.from, from);
            prop_assert_eq!(parsed.to, vec![to]);
            prop_assert_eq!(parsed.subject, subject);
            prop_assert_eq!(parsed.body, body);
        }
    }

    async fn as_call<T>(
        credentials: ibridge_auth::Credentials,
        work: impl std::future::Future<Output = T>,
    ) -> T {
        ibridge_auth::with_call_credentials(
            std::sync::Arc::new(credentials),
            std::sync::Arc::new(ibridge_auth::LoginLog::new()),
            work,
        )
        .await
    }

    fn ada_id() -> AppleId {
        AppleId::try_from("ada@icloud.com").expect("apple id")
    }

    #[tokio::test]
    async fn smtp_per_call_uses_call_credential() {
        let capture = SmtpCapture::start().await;
        let client = SmtpClient::plain_per_call(ada_id(), &capture.host, capture.port)
            .expect("loopback host is allowed");
        let mail = sample("ada@icloud.com");
        as_call(credentials(), client.send(&mail))
            .await
            .expect("the call's credentials sign the send");
        assert_eq!(capture.username(), "ada@icloud.com");
        assert_eq!(
            capture.password(),
            PASSWORD,
            "AUTH used the password the call carried"
        );
    }

    #[tokio::test]
    async fn smtp_per_call_without_credential_fails() {
        let capture = SmtpCapture::start().await;
        let client = SmtpClient::plain_per_call(ada_id(), &capture.host, capture.port)
            .expect("loopback host is allowed");
        let mail = sample("ada@icloud.com");
        as_call(credentials(), client.send(&mail))
            .await
            .expect("a call with credentials works");

        let error = client
            .send(&mail)
            .await
            .expect_err("a send with no call credential must fail, not reuse one");
        assert!(
            matches!(error, ibridge_core::CoreError::Protocol(_)),
            "no credential is a protocol error, got {error:?}"
        );
    }

    #[tokio::test]
    async fn smtp_per_call_rejects_other_account() {
        let capture = SmtpCapture::start().await;
        let client = SmtpClient::plain_per_call(ada_id(), &capture.host, capture.port)
            .expect("loopback host is allowed");
        let bob = ibridge_auth::Credentials::new(
            AppleId::try_from("bob@icloud.com").expect("apple id"),
            "bobs-secret",
        );
        let error = as_call(bob, client.send(&sample("ada@icloud.com")))
            .await
            .expect_err("bob's credentials are not for ada's client");
        assert!(
            matches!(error, ibridge_core::CoreError::Protocol(_)),
            "another account's call is a protocol error, got {error:?}"
        );
        assert!(
            capture.username().is_empty() && capture.password().is_empty(),
            "another account's password is never sent"
        );
    }

    #[tokio::test]
    async fn smtp_per_call_reports_login_verdicts() {
        let calls = |capture: &SmtpCapture| {
            SmtpClient::plain_per_call(ada_id(), &capture.host, capture.port)
                .expect("loopback host is allowed")
        };
        let call_with_log = |client: SmtpClient| async move {
            let log = Arc::new(ibridge_auth::LoginLog::new());
            let outcome = ibridge_auth::with_call_credentials(
                Arc::new(credentials()),
                Arc::clone(&log),
                async { client.send(&sample("ada@icloud.com")).await },
            )
            .await;
            (outcome, log)
        };

        let rejecting = SmtpCapture::start_rejecting_auth().await;
        let (outcome, log) = call_with_log(calls(&rejecting)).await;
        assert!(
            matches!(outcome, Err(ibridge_core::CoreError::Auth)),
            "a 535 is an auth failure, got {outcome:?}"
        );
        assert!(log.rejected(), "a refused AUTH is reported as rejected");
        assert!(!log.accepted());

        let accepting = SmtpCapture::start().await;
        let (outcome, log) = call_with_log(calls(&accepting)).await;
        outcome.expect("send");
        assert!(log.accepted(), "a send that got past AUTH is accepted");
        assert!(!log.rejected());
    }
}
