// SPDX-License-Identifier: Apache-2.0

//! The loopback HTTP guards: bind address, Origin and bearer token.

use std::net::SocketAddr;
use std::sync::Arc;

use ibridge_server::http::{
    HttpError, base_config, bind_loopback, check_loopback, local_router, mcp_service, serve,
};
use ibridge_testkit::http::{Reply, send};
use rmcp::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerConfig};
use tokio::sync::oneshot;

const TOKEN: &str = "s3cret-token";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

#[derive(Clone)]
struct Quiet;

impl ServerHandler for Quiet {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// A running server and the way to stop it.
struct Running {
    url: String,
    stop: Option<oneshot::Sender<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn running() -> Running {
    let listener = bind_loopback("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("loopback binds");
    let addr = listener.local_addr().expect("bound address");
    let service = mcp_service(|| Quiet, base_config());
    let app = local_router(service, Arc::new(|token| token == TOKEN));
    let (stop, stopped) = oneshot::channel();
    tokio::spawn(async move {
        let _ = serve(listener, app, async move {
            let _ = stopped.await;
        })
        .await;
    });
    Running {
        url: format!("http://{addr}/mcp"),
        stop: Some(stop),
    }
}

async fn init(server: &Running, extra: &[(&str, &str)]) -> Reply {
    let mut headers = vec![
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
    ];
    headers.extend_from_slice(extra);
    send("POST", &server.url, &headers, INIT).await
}

#[tokio::test]
async fn binds_loopback_only() {
    for ok in ["127.0.0.1:8080", "[::1]:8080", "127.0.0.2:0"] {
        let addr: SocketAddr = ok.parse().expect("address");
        assert_eq!(check_loopback(addr).expect("loopback is allowed"), addr);
    }
    for bad in [
        "0.0.0.0:8080",
        "[::]:8080",
        "192.168.1.20:8080",
        "8.8.8.8:80",
    ] {
        let addr: SocketAddr = bad.parse().expect("address");
        assert!(
            matches!(check_loopback(addr), Err(HttpError::NotLoopback(_))),
            "{bad} is not loopback and must be refused"
        );
    }
    let refused = bind_loopback("0.0.0.0:0".parse().expect("address")).await;
    assert!(
        matches!(refused, Err(HttpError::NotLoopback(_))),
        "binding a wildcard address is refused before any socket opens"
    );
}

#[tokio::test]
async fn rejects_foreign_origin_403() {
    let server = running().await;
    let bearer = format!("Bearer {TOKEN}");
    let auth = ("authorization", bearer.as_str());
    for origin in [
        "https://evil.example",
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example:8080",
        "http://localhost@evil.example",
        "null",
        "not an origin",
    ] {
        let reply = init(&server, &[auth, ("origin", origin)]).await;
        assert_eq!(reply.status, 403, "Origin {origin} is refused");
    }
    let no_token = init(&server, &[("origin", "https://evil.example")]).await;
    assert_eq!(
        no_token.status, 403,
        "a foreign Origin is refused before the token is looked at"
    );
    for origin in [
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://[::1]:9",
    ] {
        let reply = init(&server, &[auth, ("origin", origin)]).await;
        assert_eq!(reply.status, 200, "loopback Origin {origin} is accepted");
    }
    let plain = init(&server, &[auth]).await;
    assert_eq!(
        plain.status, 200,
        "a client with no Origin header is accepted"
    );
}

#[tokio::test]
async fn requires_bearer_401() {
    let server = running().await;
    let missing = init(&server, &[]).await;
    assert_eq!(missing.status, 401, "no Authorization header");
    assert_eq!(
        missing.header("www-authenticate"),
        Some("Bearer"),
        "the 401 names the scheme"
    );
    for header in [
        "Bearer wrong-token",
        "Bearer s3cret-token-and-more",
        "Bearer s3cret",
        "Bearer ",
        "s3cret-token",
        "Basic czNjcmV0LXRva2Vu",
    ] {
        let reply = init(&server, &[("authorization", header)]).await;
        assert_eq!(reply.status, 401, "Authorization: {header}");
        assert!(
            !reply.body.contains(TOKEN),
            "the rejection never echoes the token"
        );
    }
    let bearer = format!("Bearer {TOKEN}");
    let accepted = init(&server, &[("authorization", bearer.as_str())]).await;
    assert_eq!(accepted.status, 200, "the exact token is accepted");
}
