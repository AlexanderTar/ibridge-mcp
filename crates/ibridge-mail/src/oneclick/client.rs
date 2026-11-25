// SPDX-License-Identifier: Apache-2.0

//! The one-click POST: HTTP/1.1 over TLS to one resolved, checked address.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ibridge_core::OneClickFailure;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use super::guard::{AddressPolicy, is_public};

/// How long resolving, connecting, the handshake and reading the status may take together.
const TIMEOUT: Duration = Duration::from_secs(10);
const PORT: u16 = 443;
const MAX_URI: usize = 2_048;
/// RFC 8058's fixed body.
const BODY: &str = "List-Unsubscribe=One-Click";
/// `HTTP/1.1 ` and a three digit code, then a space or the end of the line.
const STATUS_LEN: usize = 13;

/// Looks a host name up. Called once per POST; tests swap it for a fixed answer.
pub(crate) trait Resolve: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
}

struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host, 0)).await?;
            Ok(found.map(|address| address.ip()).collect())
        })
    }
}

/// Posts RFC 8058 one-click unsubscribes.
#[derive(Clone)]
pub(crate) struct OneClick {
    tls: TlsConnector,
    policy: AddressPolicy,
    resolver: Arc<dyn Resolve>,
    port: u16,
    timeout: Duration,
}

impl std::fmt::Debug for OneClick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OneClick").finish_non_exhaustive()
    }
}

impl OneClick {
    /// Trusts the system root certificates and allows public addresses only.
    ///
    /// # Errors
    ///
    /// Returns an error when no usable root certificate is installed.
    pub(crate) fn new() -> io::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(io::Error::other("no system root certificates"));
        }
        Self::with_roots(roots)
    }

    fn with_roots(roots: rustls::RootCertStore) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
            policy: Arc::new(is_public),
            resolver: Arc::new(SystemResolver),
            port: PORT,
            timeout: TIMEOUT,
        })
    }

    /// POSTs `List-Unsubscribe=One-Click` to `uri` and reports whether the sender accepted it.
    ///
    /// Sends no credentials, cookies or other headers of the account, follows no redirect and
    /// reads only the status line of the answer.
    ///
    /// # Errors
    ///
    /// Returns the [`OneClickFailure`] class; it never carries text from the server.
    pub(crate) async fn post(&self, uri: &str) -> Result<(), OneClickFailure> {
        let link = Link::parse(uri)?;
        tokio::time::timeout(self.timeout, self.exchange(&link))
            .await
            .map_err(|_elapsed| OneClickFailure::Timeout)?
    }

    async fn exchange(&self, link: &Link) -> Result<(), OneClickFailure> {
        let addresses = self.addresses(&link.host).await?;
        let tcp = connect(&addresses, self.port).await?;
        let mut tls = self
            .tls
            .connect(link.server_name.clone(), tcp)
            .await
            .map_err(|_error| OneClickFailure::Tls)?;
        tls.write_all(&link.request())
            .await
            .map_err(|_error| OneClickFailure::Unreachable)?;
        tls.flush()
            .await
            .map_err(|_error| OneClickFailure::Unreachable)?;
        let status = read_status(&mut tls).await?;
        // The answer is not read past its status line. Closing is best effort.
        let _ = tls.shutdown().await;
        match status {
            200..=299 => Ok(()),
            300..=399 => Err(OneClickFailure::Redirected),
            400..=599 => Err(OneClickFailure::Rejected),
            _ => Err(OneClickFailure::BadResponse),
        }
    }

    /// The addresses of `host`, every one of which the policy allows.
    ///
    /// One bad address refuses the whole answer, so a hostile name cannot hide a private
    /// address among public ones. The caller connects to these addresses and never looks
    /// the name up again.
    async fn addresses(&self, host: &Host) -> Result<Vec<IpAddr>, OneClickFailure> {
        let addresses = match host {
            Host::Address(address) => vec![*address],
            Host::Name(name) => self
                .resolver
                .resolve(name)
                .await
                .map_err(|_error| OneClickFailure::Unreachable)?,
        };
        if addresses.is_empty() {
            return Err(OneClickFailure::Unreachable);
        }
        if addresses.iter().any(|address| !(self.policy)(*address)) {
            return Err(OneClickFailure::Blocked);
        }
        Ok(addresses)
    }
}

enum Host {
    Name(String),
    Address(IpAddr),
}

/// A link that passed the checks, ready to send.
struct Link {
    host: Host,
    server_name: ServerName<'static>,
    /// `Host` header value.
    authority: String,
    /// Path and query, as the `url` crate serialises them.
    target: String,
}

impl Link {
    /// Accepts only `https` on the default port, with no user name or password.
    fn parse(uri: &str) -> Result<Self, OneClickFailure> {
        // The URL parser forgives a lot (stray slashes, backslashes, tabs and newlines
        // it drops). The link is from a header, so ask for a plain one before parsing.
        let plain = uri.len() <= MAX_URI
            && uri
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            && uri
                .get(..8)
                .is_some_and(|head| head.eq_ignore_ascii_case("https://"))
            && !uri[8..].starts_with('/');
        if !plain {
            return Err(OneClickFailure::InvalidLink);
        }
        let url = Url::parse(uri).map_err(|_error| OneClickFailure::InvalidLink)?;
        if url.scheme() != "https"
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(OneClickFailure::InvalidLink);
        }
        let (host, server_name, authority) = match url.host() {
            Some(url::Host::Domain(name)) => (
                Host::Name(name.to_owned()),
                ServerName::try_from(name.to_owned())
                    .map_err(|_error| OneClickFailure::InvalidLink)?,
                name.to_owned(),
            ),
            Some(url::Host::Ipv4(address)) => (
                Host::Address(IpAddr::V4(address)),
                ServerName::IpAddress(IpAddr::V4(address).into()),
                address.to_string(),
            ),
            Some(url::Host::Ipv6(address)) => (
                Host::Address(IpAddr::V6(address)),
                ServerName::IpAddress(IpAddr::V6(address).into()),
                format!("[{address}]"),
            ),
            None => return Err(OneClickFailure::InvalidLink),
        };
        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        // The url crate escapes these, so this holds; the request line depends on it.
        if !target.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(OneClickFailure::InvalidLink);
        }
        Ok(Self {
            host,
            server_name,
            authority,
            target,
        })
    }

    /// The whole request. No `Authorization`, `Cookie` or other header is ever added.
    fn request(&self) -> Vec<u8> {
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ibridge\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            self.target,
            self.authority,
            BODY.len(),
        )
        .into_bytes()
    }
}

/// Connects to the first of `addresses` that answers, on `port`.
async fn connect(addresses: &[IpAddr], port: u16) -> Result<TcpStream, OneClickFailure> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(SocketAddr::new(*address, port)).await {
            return Ok(stream);
        }
    }
    Err(OneClickFailure::Unreachable)
}

/// Reads only the status code from the first bytes of the answer.
async fn read_status<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u16, OneClickFailure> {
    let mut head = [0_u8; STATUS_LEN];
    let mut filled = 0;
    while filled < STATUS_LEN {
        match stream.read(&mut head[filled..]).await {
            Ok(0) | Err(_) => return Err(OneClickFailure::BadResponse),
            Ok(read) => filled += read,
        }
    }
    let valid_version = head.starts_with(b"HTTP/1.1 ") || head.starts_with(b"HTTP/1.0 ");
    let digits = &head[9..12];
    let valid_end = head[12] == b' ' || head[12] == b'\r';
    if !(valid_version && valid_end && digits.iter().all(u8::is_ascii_digit)) {
        return Err(OneClickFailure::BadResponse);
    }
    Ok(digits
        .iter()
        .fold(0, |code, digit| code * 10 + u16::from(digit - b'0')))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::io;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ibridge_core::OneClickFailure;
    use ibridge_testkit::tls_fake::{TlsFake, TlsReply};
    use rustls::pki_types::CertificateDer;

    use super::{OneClick, Resolve};
    use crate::oneclick::guard::{AddressPolicy, is_public};

    const HOST: &str = "news.example.test";
    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// Answers every lookup with one address and counts the lookups.
    struct Fixed {
        address: IpAddr,
        calls: Arc<AtomicUsize>,
    }

    impl Resolve for Fixed {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(vec![self.address]) })
        }
    }

    fn roots(fake: &TlsFake) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(fake.root_der()))
            .expect("fake root");
        roots
    }

    fn allow_loopback() -> AddressPolicy {
        Arc::new(|address: IpAddr| address.is_loopback() || is_public(address))
    }

    /// A client that trusts `fake`, resolves every name to loopback, lets loopback through
    /// and connects to the fake's port.
    fn client(fake: &TlsFake) -> (OneClick, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = OneClick::with_roots(roots(fake)).expect("client");
        client.policy = allow_loopback();
        client.resolver = Arc::new(Fixed {
            address: LOOPBACK,
            calls: Arc::clone(&calls),
        });
        client.port = fake.port();
        client.timeout = Duration::from_secs(5);
        (client, calls)
    }

    fn ok_reply() -> TlsReply {
        TlsReply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
    }

    fn status_reply(line: &str) -> TlsReply {
        TlsReply::Bytes(format!("{line}\r\nContent-Length: 0\r\n\r\n").into_bytes())
    }

    fn text(request: &[u8]) -> String {
        String::from_utf8_lossy(request).into_owned()
    }

    #[tokio::test]
    async fn posts_the_exact_rfc_8058_request() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (client, _calls) = client(&fake);
        client
            .post("https://news.example.test/unsub?id=1&t=a%20b#frag")
            .await
            .expect("a 200 is success");
        let requests = fake.requests();
        assert_eq!(requests.len(), 1, "one request");
        let request = text(&requests[0]);
        assert!(
            request.starts_with("POST /unsub?id=1&t=a%20b HTTP/1.1\r\n"),
            "method, target without the fragment and version, got {request:?}"
        );
        let (head, body) = request.split_once("\r\n\r\n").expect("head and body");
        assert_eq!(body, "List-Unsubscribe=One-Click", "the RFC 8058 body");
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("\r\ncontent-type: application/x-www-form-urlencoded")
                && lower.contains("\r\ncontent-length: 26")
                && lower.contains("\r\nhost: news.example.test"),
            "content type, length and host, got {head:?}"
        );
    }

    #[tokio::test]
    async fn sends_no_credentials_cookies_or_other_headers() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (client, _calls) = client(&fake);
        client
            .post("https://news.example.test/u")
            .await
            .expect("posted");
        let request = text(&fake.requests()[0]);
        let head = request.split_once("\r\n\r\n").expect("head").0;
        let names: BTreeSet<String> = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, _value)| name.to_ascii_lowercase())
            .collect();
        let allowed: BTreeSet<String> = [
            "host",
            "user-agent",
            "content-type",
            "content-length",
            "connection",
        ]
        .map(str::to_owned)
        .into();
        assert_eq!(names, allowed, "no authorization, cookie or other header");
    }

    #[tokio::test]
    async fn refuses_links_that_are_not_plain_https_on_443() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (client, calls) = client(&fake);
        let long = format!("https://news.example.test/{}", "a".repeat(2_100));
        for uri in [
            "http://news.example.test/u",
            "https://news.example.test:8443/u",
            "https://user:pw@news.example.test/u",
            "https://user@news.example.test/u",
            "mailto:a@example.com",
            "https:///u",
            "not a uri",
            long.as_str(),
        ] {
            assert_eq!(
                client.post(uri).await,
                Err(OneClickFailure::InvalidLink),
                "{uri}"
            );
        }
        assert_eq!(fake.connections(), 0, "nothing was contacted");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing was resolved");
    }

    #[tokio::test]
    async fn a_redirect_is_a_failure_and_is_not_followed() {
        let fake = TlsFake::start(
            HOST,
            TlsReply::Bytes(
                b"HTTP/1.1 302 Found\r\nLocation: https://news.example.test/next\r\n\r\n".to_vec(),
            ),
        )
        .await;
        let (client, _calls) = client(&fake);
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Redirected)
        );
        assert_eq!(fake.requests().len(), 1, "the Location was not requested");
        assert_eq!(fake.connections(), 1, "no second connection");
    }

    #[tokio::test]
    async fn only_a_2xx_status_is_success() {
        for (line, expected) in [
            ("HTTP/1.1 200 OK", Ok(())),
            ("HTTP/1.1 204 No Content", Ok(())),
            ("HTTP/1.0 202 Accepted", Ok(())),
            ("HTTP/1.1 400 Bad Request", Err(OneClickFailure::Rejected)),
            ("HTTP/1.1 404 Not Found", Err(OneClickFailure::Rejected)),
            ("HTTP/1.1 500 Oops", Err(OneClickFailure::Rejected)),
            ("HTTP/1.1 301 Moved", Err(OneClickFailure::Redirected)),
            ("HTTP/1.1 100 Continue", Err(OneClickFailure::BadResponse)),
            ("garbage", Err(OneClickFailure::BadResponse)),
            ("HTTP/1.1 2xx x", Err(OneClickFailure::BadResponse)),
        ] {
            let fake = TlsFake::start(HOST, status_reply(line)).await;
            let (client, _calls) = client(&fake);
            assert_eq!(
                client.post("https://news.example.test/u").await,
                expected,
                "{line}"
            );
        }
    }

    #[tokio::test]
    async fn a_reply_that_ends_early_is_a_bad_response() {
        let fake = TlsFake::start(HOST, TlsReply::Bytes(b"HTTP/1".to_vec())).await;
        let (client, _calls) = client(&fake);
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::BadResponse)
        );
    }

    #[tokio::test]
    async fn the_response_body_is_never_read_or_surfaced() {
        let mut reply = b"HTTP/1.1 500 Internal Server Error\r\n\r\nSERVER-SECRET".to_vec();
        reply.extend(std::iter::repeat_n(b'x', 4_000_000));
        let fake = TlsFake::start(HOST, TlsReply::Bytes(reply)).await;
        let (client, _calls) = client(&fake);
        let failure = client
            .post("https://news.example.test/u")
            .await
            .expect_err("a 500 fails");
        let shown = format!("{failure} {failure:?}");
        assert!(
            !shown.contains("SERVER-SECRET") && !shown.contains("Internal Server Error"),
            "no server text in the failure, got {shown}"
        );
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out() {
        let fake = TlsFake::start(HOST, TlsReply::Hang).await;
        let (mut client, _calls) = client(&fake);
        client.timeout = Duration::from_millis(300);
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Timeout)
        );
    }

    #[tokio::test]
    async fn the_policy_sees_the_resolved_address_and_the_client_connects_to_it() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (mut client, calls) = client(&fake);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        client.policy = Arc::new(move |address| {
            recorder.lock().expect("seen lock").push(address);
            true
        });
        client
            .post("https://news.example.test/u")
            .await
            .expect("posted");
        assert_eq!(*seen.lock().expect("seen lock"), vec![LOOPBACK]);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the name is resolved once and the connection uses that answer"
        );
        assert_eq!(fake.connections(), 1);
    }

    #[tokio::test]
    async fn an_address_the_policy_refuses_is_never_connected_to() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (mut client, _calls) = client(&fake);
        client.policy = Arc::new(|_address| false);
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Blocked)
        );
        assert_eq!(fake.connections(), 0);
    }

    #[tokio::test]
    async fn the_production_policy_refuses_loopback_and_private_hosts() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (mut client, calls) = client(&fake);
        client.policy = Arc::new(is_public);
        // A name that resolves to loopback, and literals that need no lookup.
        for uri in [
            "https://news.example.test/u",
            "https://127.0.0.1/u",
            "https://[::1]/u",
            "https://10.1.2.3/u",
            "https://169.254.169.254/latest/meta-data",
            "https://[::ffff:127.0.0.1]/u",
            "https://0.0.0.0/u",
        ] {
            assert_eq!(
                client.post(uri).await,
                Err(OneClickFailure::Blocked),
                "{uri}"
            );
        }
        assert_eq!(fake.connections(), 0, "no connection was attempted");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the name was looked up"
        );
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let fake = TlsFake::start("other.example.test", ok_reply()).await;
        let (client, _calls) = client(&fake);
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Tls)
        );
        assert!(fake.requests().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn a_certificate_from_an_untrusted_authority_is_refused() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let stranger = TlsFake::start(HOST, ok_reply()).await;
        let (mut client, _calls) = client(&stranger);
        client.port = fake.port();
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Tls)
        );
        assert!(fake.requests().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn a_server_that_is_not_listening_is_unreachable() {
        let fake = TlsFake::start(HOST, ok_reply()).await;
        let (mut client, _calls) = client(&fake);
        client.port = 1;
        assert_eq!(
            client.post("https://news.example.test/u").await,
            Err(OneClickFailure::Unreachable)
        );
    }
}
