// SPDX-License-Identifier: Apache-2.0

//! SMTP send. Login uses the full Apple ID. `MAIL FROM` may be a custom domain.

use std::time::{SystemTime, UNIX_EPOCH};

use ibridge_auth::{Credentials, is_allowed_host};
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
/// [`Self::plain`] is cleartext for a loopback test server.
#[derive(Debug)]
pub struct SmtpClient {
    credentials: Credentials,
    host: String,
    port: u16,
    starttls: bool,
}

impl SmtpClient {
    /// iCloud SMTP on `smtp.mail.me.com:587` with STARTTLS required.
    #[must_use]
    pub fn icloud(credentials: Credentials) -> Self {
        Self {
            credentials,
            host: "smtp.mail.me.com".to_owned(),
            port: 587,
            starttls: true,
        }
    }

    /// Cleartext SMTP. The host must still be loopback or on the iCloud allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::HostNotAllowed`] when `host` is not loopback and not
    /// an allowlisted iCloud host. The port is not part of that check.
    pub fn plain(
        credentials: Credentials,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, CoreError> {
        let host = host.into();
        if !host_allowed(&host) {
            return Err(CoreError::HostNotAllowed);
        }
        Ok(Self {
            credentials,
            host,
            port,
            starttls: false,
        })
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
        let message = build_message(mail)?;
        let envelope = build_envelope(mail)?;
        let transport = self.transport()?;
        let span = tracing::debug_span!(
            "smtp_send",
            host = %self.host,
            port = self.port,
            recipients = mail.to.len(),
        );
        transport
            .send_raw(&envelope, &message)
            .instrument(span)
            .await
            .map_err(|error| map_smtp(&error))?;
        Ok(())
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, CoreError> {
        let login = self.credentials.apple_id.as_str().to_owned();
        let smtp_credentials = self
            .credentials
            .with_secret(|secret| SmtpCredentials::new(login, secret.to_owned()));
        let builder = if self.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
                .map_err(|_| CoreError::Network)?
                .port(self.port)
                .credentials(smtp_credentials)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.host.clone())
                .port(self.port)
                .credentials(smtp_credentials)
        };
        Ok(builder.build())
    }
}

fn host_allowed(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1") || is_allowed_host(host)
}

fn build_message(mail: &OutgoingMail) -> Result<Vec<u8>, CoreError> {
    check_headers(mail)?;
    let message_id = fresh_message_id();
    let mut builder = mail_builder::MessageBuilder::new()
        .from(mail.from.as_str())
        .to(mail.to.iter().map(String::as_str).collect::<Vec<_>>())
        .subject(mail.subject.as_str())
        .text_body(mail.body.as_str())
        .message_id(message_id.as_str());
    if let Some(reply) = &mail.in_reply_to {
        builder = builder.in_reply_to(reply.as_str());
    }
    let references = reference_ids(mail);
    if !references.is_empty() {
        builder = builder.references(references);
    }
    builder
        .write_to_vec()
        .map_err(|_| CoreError::Protocol("smtp command failed".to_owned()))
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
    format!("<{nanos}@ibridge>")
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::Engine;
    use ibridge_core::AppleId;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    use super::{OutgoingMail, SmtpClient};

    const PASSWORD: &str = "test-secret";

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Seen {
        username: String,
        mail_from: String,
        data: String,
    }

    struct SmtpCapture {
        host: String,
        port: u16,
        seen: Arc<Mutex<Seen>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl SmtpCapture {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("local addr").port();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let slot = Arc::clone(&seen);
            let task = tokio::spawn(async move {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let _ = serve(socket, slot).await;
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
    }

    impl Drop for SmtpCapture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(socket: TcpStream, seen: Arc<Mutex<Seen>>) -> std::io::Result<()> {
        let mut reader = BufReader::new(socket);
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
                    captured.username = plain_username(&encoded).unwrap_or_default();
                } else {
                    captured.username = plain_username(initial).unwrap_or_default();
                }
                write_line(&mut reader, "235 ok\r\n").await?;
            } else if let Some(initial) = strip_cmd(&line, "AUTH LOGIN") {
                let username = if initial.is_empty() {
                    write_line(&mut reader, "334 VXNlcm5hbWU6\r\n").await?;
                    decode_utf8(&read_line(&mut reader).await?)
                } else {
                    decode_utf8(initial)
                };
                captured.username = username.unwrap_or_default();
                write_line(&mut reader, "334 UGFzc3dvcmQ6\r\n").await?;
                let _password = read_line(&mut reader).await?;
                write_line(&mut reader, "235 ok\r\n").await?;
            } else if let Some(rest) = strip_prefix_ignore(&line, "MAIL FROM:") {
                captured.mail_from = angle_addr(rest);
                write_line(&mut reader, "250 ok\r\n").await?;
            } else if strip_prefix_ignore(&line, "RCPT TO:").is_some() {
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

    async fn read_data(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
        let mut data = String::new();
        loop {
            let line = read_line(reader).await?;
            if line == "." {
                break;
            }
            let line = line.strip_prefix('.').unwrap_or(&line);
            data.push_str(line);
            data.push_str("\r\n");
        }
        Ok(data)
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

    fn plain_username(encoded: &str) -> Option<String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let mut parts = text.split('\0');
        let _authzid = parts.next()?;
        Some(parts.next()?.to_owned())
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
}
