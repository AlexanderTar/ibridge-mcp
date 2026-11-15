// SPDX-License-Identifier: Apache-2.0

//! Client ID Metadata Documents: the client's id is an https URL we fetch.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use tower::Service;
use url::{Host, Url};

use super::client::{ClientInfo, valid_redirect_uri};

/// Largest document we read.
pub(crate) const MAX_DOCUMENT: usize = 5 * 1024;
/// Most redirect URIs a document may list.
const MAX_REDIRECTS: usize = 10;
/// Longest client name the sign-in page shows.
const MAX_NAME_CHARS: usize = 100;
/// Longest the whole fetch may take.
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Body = UnsyncBoxBody<Bytes, BoxError>;
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a client document was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CimdError {
    #[error("the client id is not a usable URL")]
    BadClientId,
    #[error("the client id is not https")]
    NotHttps,
    #[error("the client id points at a private address")]
    PrivateAddress,
    #[error("the document is larger than {MAX_DOCUMENT} bytes")]
    TooLarge,
    #[error("the fetch took too long")]
    Timeout,
    #[error("the fetch did not return the document")]
    Fetch,
    #[error("the document is not a valid client description")]
    InvalidDocument,
}

/// Sends one GET for the fetcher. Tests replace it; production uses [`HttpsTransport`].
pub(crate) trait Transport: Send + Sync {
    fn get(&self, url: &Url) -> BoxFuture<'_, Result<Response<Body>, CimdError>>;
}

/// Looks a client up by its id.
pub(crate) trait ClientSource: Send + Sync {
    fn resolve<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<ClientInfo, CimdError>>;
}

/// Fetches and checks metadata documents.
#[derive(Debug)]
pub(crate) struct CimdFetcher<T> {
    transport: T,
}

impl<T: Transport> CimdFetcher<T> {
    pub(crate) fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Fetches the document `client_id` names and checks it describes that client.
    pub(crate) async fn fetch(&self, client_id: &str) -> Result<ClientInfo, CimdError> {
        let url = parse_client_id(client_id)?;
        let bytes = tokio::time::timeout(FETCH_TIMEOUT, self.read(&url))
            .await
            .map_err(|_| CimdError::Timeout)??;
        parse_document(client_id, &bytes)
    }

    async fn read(&self, url: &Url) -> Result<Bytes, CimdError> {
        let response = self.transport.get(url).await?;
        // Redirects are not followed: a 3xx is as unusable as a 404.
        if response.status() != StatusCode::OK {
            return Err(CimdError::Fetch);
        }
        let declared = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared.is_some_and(|length| length > MAX_DOCUMENT) {
            return Err(CimdError::TooLarge);
        }
        // Counted by hand: `Limited` trips a Send inference bug on boxed bodies.
        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| CimdError::Fetch)?;
            if let Some(data) = frame.data_ref() {
                if collected.len() + data.len() > MAX_DOCUMENT {
                    return Err(CimdError::TooLarge);
                }
                collected.extend_from_slice(data);
            }
        }
        Ok(Bytes::from(collected))
    }
}

impl<T: Transport> ClientSource for CimdFetcher<T> {
    fn resolve<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<ClientInfo, CimdError>> {
        Box::pin(self.fetch(client_id))
    }
}

/// A client id is an https URL with a path, on a public host.
fn parse_client_id(client_id: &str) -> Result<Url, CimdError> {
    let url = Url::parse(client_id).map_err(|_| CimdError::BadClientId)?;
    if url.scheme() != "https" {
        return Err(if url.scheme() == "http" {
            CimdError::NotHttps
        } else {
            CimdError::BadClientId
        });
    }
    match url.host() {
        Some(Host::Ipv4(ip)) if !public_ip(IpAddr::V4(ip)) => {
            return Err(CimdError::PrivateAddress);
        }
        Some(Host::Ipv6(ip)) if !public_ip(IpAddr::V6(ip)) => {
            return Err(CimdError::PrivateAddress);
        }
        Some(Host::Domain(name)) if local_name(name) => return Err(CimdError::PrivateAddress),
        Some(_) => {}
        None => return Err(CimdError::BadClientId),
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path() == "/"
    {
        return Err(CimdError::BadClientId);
    }
    Ok(url)
}

/// Names that never resolve to a public host.
fn local_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "localhost"
        || [
            "localhost",
            "local",
            "internal",
            "localdomain",
            "lan",
            "home.arpa",
        ]
        .iter()
        .any(|suffix| name.ends_with(&format!(".{suffix}")))
}

/// True for an address a client could legitimately be hosted at.
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_v4(mapped);
            }
            let segments = ip.segments();
            let unique_local = segments[0] & 0xfe00 == 0xfc00;
            let link_local = segments[0] & 0xffc0 == 0xfe80;
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            // 6to4 and NAT64 wrap an IPv4 address that could be private.
            let embeds_v4 =
                segments[0] == 0x2002 || (segments[0] == 0x0064 && segments[1] == 0xff9b);
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || unique_local
                || link_local
                || documentation
                || embeds_v4)
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let carrier_grade_nat = a == 100 && (64..128).contains(&b);
    let protocol_assignments = a == 192 && b == 0 && c == 0;
    let benchmarking = a == 198 && (18..20).contains(&b);
    let reserved = a >= 240;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || carrier_grade_nat
        || protocol_assignments
        || benchmarking
        || reserved)
}

/// Keeps resolved addresses only when every one is public.
pub(crate) fn public_only(addrs: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    if addrs.is_empty() || addrs.iter().any(|addr| !public_ip(addr.ip())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the host does not resolve to public addresses only",
        ));
    }
    Ok(addrs)
}

fn parse_document(client_id: &str, bytes: &[u8]) -> Result<ClientInfo, CimdError> {
    let document: Value = serde_json::from_slice(bytes).map_err(|_| CimdError::InvalidDocument)?;
    let object = document.as_object().ok_or(CimdError::InvalidDocument)?;
    // The document must name the URL it was fetched from, or anyone could
    // point a client id at someone else's document.
    if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(CimdError::InvalidDocument);
    }
    // A public client has no secret.
    if object.contains_key("client_secret") || object.contains_key("client_secret_expires_at") {
        return Err(CimdError::InvalidDocument);
    }
    match object.get("token_endpoint_auth_method") {
        None => {}
        Some(Value::String(method)) if method == "none" => {}
        Some(_) => return Err(CimdError::InvalidDocument),
    }
    let redirect_uris: Vec<String> = object
        .get("redirect_uris")
        .and_then(Value::as_array)
        .ok_or(CimdError::InvalidDocument)?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or(CimdError::InvalidDocument)?;
    if redirect_uris.is_empty()
        || redirect_uris.len() > MAX_REDIRECTS
        || !redirect_uris.iter().all(|uri| valid_redirect_uri(uri))
    {
        return Err(CimdError::InvalidDocument);
    }
    let name = object
        .get("client_name")
        .and_then(Value::as_str)
        .map(display_name)
        .filter(|name| !name.is_empty())
        .or_else(|| Url::parse(client_id).ok()?.host_str().map(str::to_owned))
        .ok_or(CimdError::InvalidDocument)?;
    Ok(ClientInfo {
        id: client_id.to_owned(),
        name,
        redirect_uris,
    })
}

/// A client-chosen name, cut to a length that fits the page and stripped of control characters.
pub(super) fn display_name(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The production transport: https only, and every DNS answer must be public.
pub(crate) struct HttpsTransport {
    client: Client<Connector, Empty<Bytes>>,
}

impl fmt::Debug for HttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsTransport")
    }
}

type Connector = hyper_rustls::HttpsConnector<HttpConnector<PublicResolver>>;

/// DNS lookup that refuses hosts resolving to anything but public addresses.
///
/// The connector dials exactly the addresses this returns, so a second lookup
/// cannot swap in a private one.
#[derive(Clone, Copy, Debug)]
struct PublicResolver;

impl Service<Name> for PublicResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<Self::Response>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        resolve_public(name)
    }
}

fn resolve_public(name: Name) -> BoxFuture<'static, io::Result<std::vec::IntoIter<SocketAddr>>> {
    Box::pin(async move {
        let found: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
        public_only(found).map(Vec::into_iter)
    })
}

impl HttpsTransport {
    pub(crate) fn new() -> Result<Self, CimdError> {
        let mut http = HttpConnector::new_with_resolver(PublicResolver);
        // The https connector wraps this one and needs it to allow the https scheme.
        http.enforce_http(false);
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| CimdError::Fetch)?
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }
}

impl Transport for HttpsTransport {
    fn get(&self, url: &Url) -> BoxFuture<'_, Result<Response<Body>, CimdError>> {
        let request = Request::get(url.as_str())
            .header(header::ACCEPT, "application/json")
            .body(Empty::new());
        Box::pin(async move {
            let request = request.map_err(|_| CimdError::BadClientId)?;
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| CimdError::Fetch)?;
            Ok(response.map(|body| body.map_err(BoxError::from).boxed_unsync()))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http::{Response, StatusCode, header};
    use http_body_util::{BodyExt, Full};
    use url::Url;

    use super::{
        Body, BoxFuture, CimdError, CimdFetcher, FETCH_TIMEOUT, MAX_DOCUMENT, Transport,
        public_only,
    };

    const CLIENT: &str = "https://client.example/oauth/client.json";

    fn document(extra: &str) -> String {
        format!(
            r#"{{"client_id":"{CLIENT}","client_name":"Claude Test","redirect_uris":["http://127.0.0.1/cb","https://client.example/cb"]{extra}}}"#
        )
    }

    struct Canned {
        status: StatusCode,
        length: Option<usize>,
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    impl Canned {
        fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: StatusCode::OK,
                length: None,
                body: body.into(),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Transport for Canned {
        fn get(&self, _url: &Url) -> BoxFuture<'_, Result<Response<Body>, CimdError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut builder = Response::builder().status(self.status);
            if let Some(length) = self.length {
                builder = builder.header(header::CONTENT_LENGTH, length);
            }
            let body = Full::new(Bytes::from(self.body.clone()))
                .map_err(|never| match never {})
                .boxed_unsync();
            let response = builder.body(body).expect("response");
            Box::pin(async move { Ok(response) })
        }
    }

    struct Hang;

    impl Transport for Hang {
        fn get(&self, _url: &Url) -> BoxFuture<'_, Result<Response<Body>, CimdError>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn fetches_a_valid_document() {
        let fetcher = CimdFetcher::new(Canned::ok(document("")));
        let client = fetcher.fetch(CLIENT).await.expect("a valid document");
        assert_eq!(client.id, CLIENT);
        assert_eq!(client.name, "Claude Test");
        assert_eq!(
            client.redirect_uris,
            ["http://127.0.0.1/cb", "https://client.example/cb"]
        );
    }

    #[tokio::test]
    async fn cimd_fetch_rejects_private_ip_http_and_oversize() {
        let canned = Canned::ok(document(""));
        let fetcher = CimdFetcher::new(canned);
        let refused_before_connecting = [
            (
                "http://client.example/oauth/client.json",
                CimdError::NotHttps,
            ),
            ("https://127.0.0.1/client.json", CimdError::PrivateAddress),
            ("https://10.1.2.3/client.json", CimdError::PrivateAddress),
            ("https://172.16.0.9/client.json", CimdError::PrivateAddress),
            ("https://192.168.1.1/client.json", CimdError::PrivateAddress),
            ("https://169.254.169.254/latest", CimdError::PrivateAddress),
            ("https://100.64.0.1/client.json", CimdError::PrivateAddress),
            ("https://0.0.0.0/client.json", CimdError::PrivateAddress),
            ("https://[::1]/client.json", CimdError::PrivateAddress),
            ("https://[fe80::1]/client.json", CimdError::PrivateAddress),
            ("https://[fd00::1]/client.json", CimdError::PrivateAddress),
            (
                "https://[::ffff:10.0.0.1]/client.json",
                CimdError::PrivateAddress,
            ),
            ("https://localhost/client.json", CimdError::PrivateAddress),
            (
                "https://printer.local/client.json",
                CimdError::PrivateAddress,
            ),
            (
                "https://user@client.example/client.json",
                CimdError::BadClientId,
            ),
            ("https://client.example/", CimdError::BadClientId),
            ("https://client.example/c.json#frag", CimdError::BadClientId),
            ("not a url", CimdError::BadClientId),
        ];
        for (client_id, expected) in refused_before_connecting {
            assert_eq!(
                fetcher.fetch(client_id).await.expect_err(client_id),
                expected,
                "{client_id}"
            );
        }
        assert_eq!(
            fetcher.transport.calls(),
            0,
            "a refused id never reaches the network"
        );

        // The body limit applies whether or not the server declares a length.
        let big = vec![b' '; MAX_DOCUMENT + 1];
        let undeclared = CimdFetcher::new(Canned::ok(big.clone()));
        assert_eq!(
            undeclared.fetch(CLIENT).await.expect_err("oversize body"),
            CimdError::TooLarge
        );
        let declared = CimdFetcher::new(Canned {
            length: Some(big.len()),
            ..Canned::ok(big)
        });
        assert_eq!(
            declared.fetch(CLIENT).await.expect_err("declared size"),
            CimdError::TooLarge
        );

        // Redirects are never followed and errors are not documents.
        for status in [StatusCode::FOUND, StatusCode::NOT_FOUND] {
            let fetcher = CimdFetcher::new(Canned {
                status,
                ..Canned::ok(document(""))
            });
            assert_eq!(
                fetcher.fetch(CLIENT).await.expect_err("bad status"),
                CimdError::Fetch,
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn dns_answers_must_all_be_public() {
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 0);
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 0);
        assert_eq!(public_only(vec![public]).expect("public"), vec![public]);
        assert!(
            public_only(vec![public, private]).is_err(),
            "one private answer refuses all"
        );
        assert!(public_only(vec![]).is_err(), "no answer is no answer");
    }

    #[tokio::test]
    async fn the_resolver_refuses_a_name_that_resolves_to_loopback() {
        let name: hyper_util::client::legacy::connect::dns::Name =
            "localhost".parse().expect("a host name");
        let refused = super::resolve_public(name).await;
        assert!(refused.is_err(), "localhost resolves to a private address");
    }

    #[tokio::test]
    async fn rejects_documents_that_do_not_describe_this_client() {
        let bad_documents = [
            r#"{"client_id":"https://other.example/c.json","client_name":"x","redirect_uris":["https://client.example/cb"]}"#.to_owned(),
            document(r#","client_secret":"s3cret""#),
            document(r#","token_endpoint_auth_method":"client_secret_basic""#),
            format!(r#"{{"client_id":"{CLIENT}","client_name":"x","redirect_uris":[]}}"#),
            format!(r#"{{"client_id":"{CLIENT}","client_name":"x","redirect_uris":["http://client.example/cb"]}}"#),
            "[]".to_owned(),
            "not json".to_owned(),
        ];
        for body in bad_documents {
            let fetcher = CimdFetcher::new(Canned::ok(body.clone()));
            assert_eq!(
                fetcher.fetch(CLIENT).await.expect_err(&body),
                CimdError::InvalidDocument,
                "{body}"
            );
        }
        let fetcher = CimdFetcher::new(Canned::ok(document(
            r#","token_endpoint_auth_method":"none""#,
        )));
        assert!(
            fetcher.fetch(CLIENT).await.is_ok(),
            "none is the one allowed method"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cimd_timeout_3s() {
        assert_eq!(FETCH_TIMEOUT.as_secs(), 3, "the limit is three seconds");
        let fetcher = CimdFetcher::new(Hang);
        let started = tokio::time::Instant::now();
        let result = fetcher.fetch(CLIENT).await;
        assert_eq!(result.expect_err("a hung server"), CimdError::Timeout);
        assert_eq!(
            started.elapsed(),
            FETCH_TIMEOUT,
            "the fetch gives up after exactly the limit"
        );
    }
}
