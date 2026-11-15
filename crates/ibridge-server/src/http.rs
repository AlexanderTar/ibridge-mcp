// SPDX-License-Identifier: Apache-2.0

//! Streamable HTTP wiring shared by the local daemon and the hosted router.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;

pub use axum::Router;

/// Answers whether a presented bearer token is accepted.
pub type Verifier = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Why the HTTP server could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The address is not on the loopback interface.
    #[error("{0} is not a loopback address; the local daemon only listens on 127.0.0.1 or ::1")]
    NotLoopback(SocketAddr),
    /// The socket could not be opened or served.
    #[error("could not use the HTTP socket: {0}")]
    Io(#[from] std::io::Error),
}

/// Checks that `addr` is a loopback address.
///
/// # Errors
///
/// Returns [`HttpError::NotLoopback`] for any other address.
pub fn check_loopback(addr: SocketAddr) -> Result<SocketAddr, HttpError> {
    if addr.ip().is_loopback() {
        Ok(addr)
    } else {
        Err(HttpError::NotLoopback(addr))
    }
}

/// Binds `addr` after checking that it is a loopback address.
///
/// # Errors
///
/// Returns [`HttpError::NotLoopback`] for any other address, or the I/O error from binding.
pub async fn bind_loopback(addr: SocketAddr) -> Result<TcpListener, HttpError> {
    Ok(TcpListener::bind(check_loopback(addr)?).await?)
}

/// The Streamable HTTP settings both modes share: JSON responses, with
/// sessions for clients that negotiate a protocol older than 2026-07-28.
#[must_use]
pub fn base_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(true)
        .with_json_response(true)
}

/// Wraps `factory` in the Streamable HTTP service.
pub fn mcp_service<S>(
    factory: impl Fn() -> S + Send + Sync + 'static,
    config: StreamableHttpServerConfig,
) -> StreamableHttpService<S, LocalSessionManager>
where
    S: ServerHandler + Send + 'static,
{
    StreamableHttpService::new(move || Ok(factory()), Arc::default(), config)
}

/// The local daemon's router: `/mcp` behind the Origin check, then the bearer check.
///
/// A request with a foreign `Origin` gets 403 whatever its token. Every other
/// request needs `Authorization: Bearer <token>` with a token `verify` accepts,
/// and gets 401 without one.
pub fn local_router<S>(
    service: StreamableHttpService<S, LocalSessionManager>,
    verify: Verifier,
) -> Router
where
    S: ServerHandler + Send + 'static,
{
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(verify, require_bearer))
        .layer(middleware::from_fn(require_loopback_origin))
}

/// Answers 403 to a request whose `Origin` is not a loopback page.
///
/// A client with no `Origin` header (a CLI, an SDK) passes: only browsers send one.
async fn require_loopback_origin(request: Request, next: Next) -> Response {
    match request.headers().get(header::ORIGIN) {
        None => next.run(request).await,
        Some(origin) if origin.to_str().is_ok_and(is_loopback_origin) => next.run(request).await,
        Some(_) => (StatusCode::FORBIDDEN, "Forbidden: Origin is not allowed").into_response(),
    }
}

fn is_loopback_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    let web = matches!(uri.scheme_str(), Some("http" | "https"));
    let bare = uri.path_and_query().is_none_or(|path| path.as_str() == "/");
    let host = uri.authority().is_some_and(|authority| {
        // `http::Uri` treats `user@host` as userinfo; an Origin never has any.
        !authority.as_str().contains('@')
            && matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]")
    });
    web && bare && host
}

/// Answers 401 unless the request carries a bearer token `verify` accepts.
async fn require_bearer(State(verify): State<Verifier>, request: Request, next: Next) -> Response {
    if bearer_token(request.headers()).is_some_and(|token| verify(token)) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "Unauthorized",
        )
            .into_response()
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(token)
}

/// Serves `app` on `listener` until `shutdown` finishes.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), HttpError> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
