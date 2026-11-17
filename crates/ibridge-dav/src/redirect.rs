// SPDX-License-Identifier: Apache-2.0

//! Redirects stay on the iCloud allowlist, or the call fails with no credentials sent.

use http::{HeaderMap, StatusCode, Uri};
use ibridge_auth::is_allowed_host;

use crate::error::DavError;

/// 301, 302, 307 and 308. The method and body are kept; DAV discovery is a `PROPFIND`.
pub(crate) fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 307 | 308)
}

/// `Location` value, when the header is visible ASCII.
pub(crate) fn location_target(headers: &HeaderMap) -> Option<&str> {
    headers.get(http::header::LOCATION)?.to_str().ok()
}

/// Resolve `location` against `current`.
///
/// # Errors
///
/// Returns [`DavError::Protocol`] when the result is not a URI.
pub(crate) fn resolve_location(current: &Uri, location: &str) -> Result<Uri, DavError> {
    let location = location.trim();
    if location.contains("://") {
        return location.parse().map_err(|_| DavError::Protocol);
    }
    let scheme = current.scheme_str().ok_or(DavError::Protocol)?;
    let authority = current.authority().ok_or(DavError::Protocol)?;
    let path = if let Some(absolute) = location.strip_prefix('/') {
        format!("/{absolute}")
    } else {
        let dir = current.path().rsplit_once('/').map_or("", |(dir, _)| dir);
        format!("{dir}/{location}")
    };
    format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|_| DavError::Protocol)
}

/// The URI host, including a non-default port, is on the iCloud allowlist.
///
/// iCloud hosts must be `https`. Cleartext to those names is refused before
/// any credentials are attached. `127.0.0.1` and `localhost` are allowed only
/// for tests and the `test-hosts` feature, on `http` or `https`.
pub(crate) fn host_is_allowed(uri: &Uri) -> bool {
    if test_loopback(uri) {
        return matches!(uri.scheme_str(), Some("http" | "https"));
    }
    uri.scheme_str() == Some("https") && icloud_host(uri)
}

/// ponytail: loopback is test-only. A production build never reaches it.
/// Other crates turn it on with the `test-hosts` feature for Radicale.
#[cfg(any(test, feature = "test-hosts"))]
fn test_loopback(uri: &Uri) -> bool {
    matches!(uri.host(), Some("127.0.0.1" | "localhost"))
}

#[cfg(not(any(test, feature = "test-hosts")))]
fn test_loopback(_uri: &Uri) -> bool {
    false
}

fn icloud_host(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    match uri.port_u16() {
        Some(port) => is_allowed_host(&format!("{host}:{port}")),
        None => is_allowed_host(host),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;

    use crate::client::execute;
    use crate::error::DavError;
    use crate::test_support::{Script, credentials, expected_basic};

    fn propfind(uri: &'static str) -> http::Request<String> {
        http::Request::builder()
            .method("PROPFIND")
            .uri(uri)
            .body(String::new())
            .expect("request")
    }

    fn response(status: u16, location: Option<&str>) -> Response<Full<Bytes>> {
        let mut builder = Response::builder().status(status);
        if let Some(location) = location {
            builder = builder.header("location", location);
        }
        builder.body(Full::new(Bytes::new())).expect("response")
    }

    #[tokio::test]
    async fn redirect_to_foreign_host_drops_auth_and_fails() {
        let script = Script::new(|request| {
            if request.uri().host() == Some("evil.example") {
                return response(200, None);
            }
            response(302, Some("http://evil.example/steal"))
        });
        let result = execute(
            &script,
            &credentials(),
            propfind("https://caldav.icloud.com/"),
        )
        .await;
        let seen = script.requests();
        for request in &seen {
            if request.uri.host() == Some("evil.example") {
                assert!(
                    request.authorization.is_none(),
                    "credentials were sent to a foreign host: {request:?}"
                );
            }
        }
        assert!(
            matches!(result, Err(DavError::HostNotAllowed)),
            "an off-allowlist redirect must fail, got {result:?}"
        );
    }

    #[tokio::test]
    async fn redirect_to_shard_keeps_auth() {
        let script = Script::new(|request| {
            if request.uri().host() == Some("p15-caldav.icloud.com") {
                return response(200, None);
            }
            response(302, Some("https://p15-caldav.icloud.com/42/calendars/"))
        });
        let exchange = execute(
            &script,
            &credentials(),
            propfind("https://caldav.icloud.com/"),
        )
        .await
        .expect("a redirect onto an iCloud shard should succeed");
        assert_eq!(exchange.status.as_u16(), 200);
        let seen = script.requests();
        assert_eq!(
            seen.len(),
            2,
            "should follow the shard redirect, saw {seen:?}"
        );
        assert_eq!(seen[1].uri.host(), Some("p15-caldav.icloud.com"));
        assert_eq!(
            seen[1].authorization.as_deref(),
            Some(expected_basic().as_str()),
            "shard request must keep Basic auth"
        );
        assert_eq!(seen[0].authorization, seen[1].authorization);
    }

    #[tokio::test]
    async fn redirect_to_http_shard_sends_no_authorization() {
        let script = Script::new(|request| {
            if request.uri().scheme_str() != Some("https") {
                return response(200, None);
            }
            response(302, Some("http://p15-caldav.icloud.com/42/calendars/"))
        });
        let result = execute(
            &script,
            &credentials(),
            propfind("https://caldav.icloud.com/"),
        )
        .await;
        let seen = script.requests();
        assert!(
            seen.iter().all(|request| {
                request.uri.host() != Some("p15-caldav.icloud.com")
                    || request.authorization.is_none()
            }),
            "an http shard must not receive credentials, saw {seen:?}"
        );
        assert!(
            matches!(result, Err(DavError::HostNotAllowed)),
            "a redirect onto cleartext http must fail, got {result:?}"
        );
    }
}
