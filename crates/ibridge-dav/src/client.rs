// SPDX-License-Identifier: Apache-2.0

//! Credential-safe HTTP calls: preemptive Basic auth, retries, no HTTP/3.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ibridge_auth::Credentials;
use tracing::Instrument;

use crate::error::DavError;
use crate::redirect::{host_is_allowed, is_redirect, location_target, resolve_location};

/// Attempts before a 429, 503 or transport failure becomes the caller's error.
const MAX_ATTEMPTS: u32 = 3;

/// Redirects followed before the call fails. Discovery is only a few hops.
const MAX_REDIRECTS: u32 = 5;

/// A completed HTTP response with its body buffered.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body.
    pub body: Bytes,
    /// URL the response came from, after redirects.
    pub url: Uri,
}

/// The raw network. The guard in [`execute`] attaches credentials and follows redirects.
pub(crate) trait Transport: Send + Sync {
    /// Send one request and return the response, without adding credentials.
    fn dispatch(
        &self,
        request: Request<String>,
    ) -> impl Future<Output = Result<Response<Full<Bytes>>, DavError>> + Send;
}

/// HTTP client that sends the app-specific password only to allowlisted hosts.
///
/// `Debug` prints the Apple ID and nothing else. The password stays inside
/// [`Credentials`].
pub struct DavClient {
    credentials: Arc<Credentials>,
    http: Client<Connector, Full<Bytes>>,
}

impl std::fmt::Debug for DavClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DavClient")
            .field("apple_id", &self.credentials.apple_id)
            .finish_non_exhaustive()
    }
}

impl DavClient {
    /// Builds a client on HTTP/1.1 and HTTP/2. It does not speak HTTP/3.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::Network`] when the TLS roots cannot be loaded.
    pub fn new(credentials: Credentials) -> Result<Self, DavError> {
        Self::from_shared(Arc::new(credentials))
    }

    pub(crate) fn from_shared(credentials: Arc<Credentials>) -> Result<Self, DavError> {
        Ok(Self {
            credentials,
            http: http_client()?,
        })
    }

    /// Sends one DAV request with preemptive Basic auth, retries and redirects.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::HostNotAllowed`] when the URL or a redirect leaves the
    /// allowlist, [`DavError::RateLimited`] when the server keeps answering 429
    /// or 503, and [`DavError::Network`] when the connection fails.
    pub async fn request(&self, request: Request<String>) -> Result<Exchange, DavError> {
        execute(self, &self.credentials, request).await
    }

    /// Sync a collection. A caller-supplied limit is not sent.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::Protocol`] when the report cannot be read and
    /// [`DavError::Network`] when the connection fails.
    pub async fn sync_collection(
        &self,
        collection_url: &str,
        token: Option<&str>,
        limit: Option<u32>,
    ) -> Result<crate::SyncReport, DavError> {
        crate::sync::sync_collection(self, &self.credentials, collection_url, token, limit).await
    }

    /// Create a resource with `If-None-Match: *`.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::Conflict`] when the server answers 412.
    pub async fn put_new(
        &self,
        resource_url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<ibridge_core::ETag, DavError> {
        crate::sync::put_new(self, &self.credentials, resource_url, body, content_type).await
    }

    /// Replace a resource with `If-Match`.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::Conflict`] when the server answers 412.
    pub async fn put_if_match(
        &self,
        resource_url: &str,
        body: &str,
        content_type: &str,
        etag: &ibridge_core::ETag,
    ) -> Result<ibridge_core::ETag, DavError> {
        crate::sync::put_if_match(
            self,
            &self.credentials,
            resource_url,
            body,
            content_type,
            etag,
        )
        .await
    }
}

impl Transport for DavClient {
    async fn dispatch(&self, request: Request<String>) -> Result<Response<Full<Bytes>>, DavError> {
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, Full::new(Bytes::from(body)));
        let response = self
            .http
            .request(request)
            .await
            .map_err(|_| DavError::Network)?;
        let (parts, incoming) = response.into_parts();
        let bytes = incoming
            .collect()
            .await
            .map_err(|_| DavError::Network)?
            .to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
}

/// Send `request` with credentials, retries and the redirect policy.
///
/// # Errors
///
/// Returns [`DavError::HostNotAllowed`] when a redirect leaves the allowlist,
/// [`DavError::RateLimited`] when the server keeps answering 429 or 503, and
/// [`DavError::Network`] when the transport fails.
pub(crate) async fn execute(
    transport: &impl Transport,
    credentials: &Credentials,
    request: Request<String>,
) -> Result<Exchange, DavError> {
    let (parts, body) = request.into_parts();
    let mut outgoing = Outgoing {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        body,
    };
    outgoing.headers.remove(http::header::AUTHORIZATION);

    let mut redirects = 0_u32;
    loop {
        if !host_is_allowed(&outgoing.uri) {
            return Err(DavError::HostNotAllowed);
        }
        let span = tracing::debug_span!(
            "dav_request",
            method = %outgoing.method,
            host = outgoing.uri.host().unwrap_or(""),
        );
        attach_basic(&mut outgoing.headers, credentials)?;
        let response = send_with_retry(transport, &outgoing)
            .instrument(span)
            .await?;
        let status = response.status();
        let location = location_target(response.headers()).map(str::to_owned);
        if is_redirect(status)
            && let Some(location) = location
        {
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(DavError::Protocol);
            }
            let next = resolve_location(&outgoing.uri, &location)?;
            drop(response);
            if !host_is_allowed(&next) {
                return Err(DavError::HostNotAllowed);
            }
            outgoing.uri = next;
            outgoing.headers.remove(http::header::AUTHORIZATION);
            continue;
        }
        return exchange_from(response, outgoing.uri.clone()).await;
    }
}

/// Fetch `url` twice with the production HTTP stack.
///
/// The stack is HTTP/1.1 and HTTP/2 only. It does not follow `Alt-Svc` to HTTP/3.
///
/// # Errors
///
/// Returns [`DavError::Network`] when a connection fails and [`DavError::Protocol`]
/// when `url` is not a usable URI.
#[cfg(test)]
pub(crate) async fn fetch_twice(url: &str) -> Result<(), DavError> {
    let client = http_client()?;
    for _ in 0..2 {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))
            .map_err(|_| DavError::Protocol)?;
        let response = client
            .request(request)
            .await
            .map_err(|_| DavError::Network)?;
        let _body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| DavError::Network)?;
    }
    Ok(())
}

struct Outgoing {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
}

impl Outgoing {
    fn to_request(&self) -> Result<Request<String>, DavError> {
        let mut request = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .body(self.body.clone())
            .map_err(|_| DavError::Protocol)?;
        *request.headers_mut() = self.headers.clone();
        Ok(request)
    }
}

fn attach_basic(headers: &mut HeaderMap, credentials: &Credentials) -> Result<(), DavError> {
    let mut raw = format!("{}:", credentials.apple_id);
    credentials.with_secret(|secret| raw.push_str(secret));
    let token = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw.as_bytes());
    // The copy of the password has to live in the header. Drop the source string here.
    raw.clear();
    let value = HeaderValue::try_from(format!("Basic {token}"))
        .map_err(|_| DavError::InvalidInput("credentials are not valid header text".to_owned()))?;
    headers.insert(http::header::AUTHORIZATION, value);
    Ok(())
}

async fn send_with_retry(
    transport: &impl Transport,
    outgoing: &Outgoing,
) -> Result<Response<Full<Bytes>>, DavError> {
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        let request = outgoing.to_request()?;
        match transport.dispatch(request).await {
            Err(_) if attempt < MAX_ATTEMPTS => {
                tokio::time::sleep(jitter(attempt)).await;
            }
            Err(_) => return Err(DavError::Network),
            Ok(response) if is_throttled(response.status()) => {
                let retry_after = retry_after(response.headers());
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(retry_after.unwrap_or_else(|| jitter(attempt))).await;
                    continue;
                }
                return Err(DavError::RateLimited { retry_after });
            }
            Ok(response) => return Ok(response),
        }
    }
}

fn is_throttled(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE
}

/// Delta-seconds only.
///
/// ponytail: an HTTP-date `Retry-After` is treated as absent. iCloud sends a
/// delay in seconds. Parse dates with the `httpdate` crate if a server sends one.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

fn jitter(attempt: u32) -> Duration {
    let shift = attempt.min(5);
    let base_ms = 200_u64.saturating_mul(1_u64 << shift);
    let extra = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::from(elapsed.subsec_nanos() % 200));
    Duration::from_millis(base_ms.saturating_add(extra).min(30_000))
}

async fn exchange_from(response: Response<Full<Bytes>>, url: Uri) -> Result<Exchange, DavError> {
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|_| DavError::Network)?
        .to_bytes();
    Ok(Exchange {
        status: parts.status,
        headers: parts.headers,
        body,
        url,
    })
}

type Connector = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

fn http_client() -> Result<Client<Connector, Full<Bytes>>, DavError> {
    // HTTP/1.1 and HTTP/2 only. hyper-rustls has no HTTP/3 switch, and this
    // builder does not advertise or follow an `Alt-Svc: h3` upgrade.
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|_| DavError::Network)?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::Full;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use http::StatusCode;

    use super::{execute, fetch_twice};
    use crate::error::DavError;
    use crate::test_support::{Script, credentials, expected_basic};

    fn propfind(uri: &'static str) -> Request<String> {
        Request::builder()
            .method("PROPFIND")
            .uri(uri)
            .body(String::new())
            .expect("request")
    }

    fn empty(status: u16) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::new()))
            .expect("response")
    }

    #[tokio::test]
    async fn basic_auth_sent_preemptively() {
        let script = Script::new(|_request| empty(200));
        let exchange = execute(
            &script,
            &credentials(),
            propfind("https://contacts.icloud.com/"),
        )
        .await
        .expect("preemptive basic should succeed without a 401 challenge");
        assert_eq!(exchange.status, StatusCode::OK);
        let seen = script.requests();
        assert_eq!(seen.len(), 1, "must not wait for a challenge, saw {seen:?}");
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some(expected_basic().as_str()),
            "first request must already carry Basic auth"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_honours_retry_after() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = Script::new({
            let calls = Arc::clone(&calls);
            move |_request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Response::builder()
                        .status(503)
                        .header("retry-after", "9")
                        .body(Full::new(Bytes::new()))
                        .expect("response")
                } else {
                    empty(200)
                }
            }
        });
        let exchange = execute(
            &script,
            &credentials(),
            propfind("https://caldav.icloud.com/"),
        )
        .await
        .expect("503 with Retry-After should be retried and then succeed");
        assert_eq!(exchange.status.as_u16(), 200);
        let seen = script.requests();
        assert_eq!(seen.len(), 2, "one retry after the 503, saw {seen:?}");
        let waited = seen[1].at.saturating_duration_since(seen[0].at);
        assert!(
            waited >= Duration::from_secs(9),
            "second request was sent after {waited:?}, before Retry-After of 9s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn status_429_503_map_to_rate_limited() {
        for (status, delay) in [(429_u16, 12_u64), (503, 3)] {
            let script = Script::new(move |_request| {
                Response::builder()
                    .status(status)
                    .header("retry-after", delay.to_string())
                    .body(Full::new(Bytes::new()))
                    .expect("response")
            });
            let error = execute(
                &script,
                &credentials(),
                propfind("https://caldav.icloud.com/"),
            )
            .await
            .expect_err("a persistent throttle must not succeed");
            assert_eq!(
                error,
                DavError::RateLimited {
                    retry_after: Some(Duration::from_secs(delay)),
                },
                "status {status}"
            );
        }
    }

    #[tokio::test]
    async fn no_h3() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let record = Arc::clone(&lines);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 2048];
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let line = text.lines().next().unwrap_or("").to_owned();
                    record
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(line);
                    let response = b"\
                        HTTP/1.1 200 OK\r\n\
                        Alt-Svc: h3=\":443\"; ma=2592000\r\n\
                        Content-Length: 0\r\n\
                        Connection: close\r\n\
                        \r\n";
                    let _ = stream.write_all(response).await;
                });
            }
        });

        let url = format!("http://{addr}/dav");
        let _ = fetch_twice(&url).await;
        let lines = lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            lines.len(),
            2,
            "both requests must stay on this TCP server after Alt-Svc h3, got {lines:?}"
        );
        for line in lines.iter() {
            assert!(
                line.contains("HTTP/1.1"),
                "request left HTTP/1.1, which means an h3 upgrade: {line}"
            );
        }
    }
}
