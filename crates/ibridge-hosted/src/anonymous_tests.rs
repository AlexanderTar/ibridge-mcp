// SPDX-License-Identifier: Apache-2.0

//! Discovery without a token, end to end over the whole hosted router.
//!
//! `initialize`, `notifications/initialized`, `ping` and `tools/list` are answered
//! to a caller with no token. Everything else keeps today's 401 challenge.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};

use crate::store::{Scope, Store};
use crate::test_app::{
    HOST, Reply, app_over, rpc_request, send, token, token_after_check, tool_request,
};

/// The challenge a caller with no credentials gets.
const BARE_CHALLENGE: &str = r#"Bearer resource_metadata="https://ibridge.example/.well-known/oauth-protected-resource/mcp""#;

/// A POST to `/mcp` with `body` and no `Authorization` header.
fn anonymous(body: &Value) -> Request<Body> {
    Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A JSON-RPC request in the stateless 2026-07-28 form, with no token.
fn anonymous_stateless(method: &str, params: Value) -> Request<Body> {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut request = anonymous(&body);
    request
        .headers_mut()
        .insert("mcp-protocol-version", "2026-07-28".parse().expect("value"));
    request
        .headers_mut()
        .insert("mcp-method", method.parse().expect("value"));
    request
}

/// A tokenless message on the session `initialize` opened, in the legacy session form.
fn in_session(session: &str, body: &Value) -> Request<Body> {
    let mut request = anonymous(body);
    request
        .headers_mut()
        .insert("mcp-session-id", session.parse().expect("value"));
    request
        .headers_mut()
        .insert("mcp-protocol-version", "2025-06-18".parse().expect("value"));
    request
}

fn legacy_initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        },
    })
}

/// The JSON in a reply, which may arrive as a bare object or as event-stream `data:` lines
/// (the first of which can be an empty priming event).
fn json_of(reply: &Reply) -> Value {
    let payload = reply
        .text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .find(|data| !data.is_empty())
        .unwrap_or(reply.text.as_str());
    serde_json::from_str(payload)
        .unwrap_or_else(|error| panic!("a JSON body ({error}): {}", reply.text))
}

fn tool_names(reply: &Reply) -> Vec<String> {
    json_of(reply)["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a tool list, got {}", reply.text))
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

async fn rig() -> (Store, Router) {
    let store = Store::memory().await.expect("store");
    let app = app_over(&store).await;
    (store, app)
}

fn assert_bare_challenge(reply: &Reply, what: &str) {
    assert_eq!(
        reply.status,
        StatusCode::UNAUTHORIZED,
        "{what}: {}",
        reply.text
    );
    assert_eq!(
        reply.headers[header::WWW_AUTHENTICATE],
        BARE_CHALLENGE,
        "{what}: the same challenge as before"
    );
}

#[tokio::test]
async fn anonymous_initialize_opens_a_session() {
    let (_store, app) = rig().await;

    let reply = send(&app, anonymous(&legacy_initialize())).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert!(
        reply.headers.contains_key("mcp-session-id"),
        "a session id comes back, got {:?}",
        reply.headers
    );
    assert_eq!(
        json_of(&reply)["result"]["serverInfo"]["name"],
        "ibridge",
        "the server says who it is: {}",
        reply.text
    );
}

#[tokio::test]
async fn anonymous_initialized_notification_and_ping_succeed() {
    let (_store, app) = rig().await;
    let opened = send(&app, anonymous(&legacy_initialize())).await;
    let session = opened.headers["mcp-session-id"]
        .to_str()
        .expect("id")
        .to_owned();

    let initialized = in_session(
        &session,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let reply = send(&app, initialized).await;
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.text);

    let ping = in_session(
        &session,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    );
    let reply = send(&app, ping).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(json_of(&reply)["result"], json!({}), "{}", reply.text);
}

#[tokio::test]
async fn anonymous_tools_list_shows_every_tool_a_full_account_sees() {
    let (store, app) = rig().await;

    let listed = send(&app, anonymous_stateless("tools/list", json!({}))).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    let public = tool_names(&listed);

    let bearer = token(
        &store,
        "ada@icloud.com",
        "app-pass-word-1234",
        Scope::ReadWrite,
    )
    .await;
    let signed_in = send(&app, rpc_request(&bearer, "tools/list", None, json!({}))).await;
    assert_eq!(
        public,
        tool_names(&signed_in),
        "the public list is what a signed-in read-write account with every service sees"
    );
    for tool in [
        "mail_send",
        "mail_search",
        "calendar_list_events",
        "account_status",
    ] {
        assert!(
            public.iter().any(|name| name == tool),
            "{tool} is listed: {public:?}"
        );
    }
}

#[tokio::test]
async fn anonymous_tools_list_hides_per_account_state() {
    let (store, app) = rig().await;
    // A read-only, CalDAV-only account exists; its limits must not shape the public list.
    let report = ibridge_auth::ValidationReport {
        mail: ibridge_auth::ServiceCheck::Failed {
            reason: "mail login was refused".to_owned(),
        },
        calendar: ibridge_auth::ServiceCheck::Ok,
        contacts: ibridge_auth::ServiceCheck::Ok,
    };
    let _ = token_after_check(
        &store,
        "bob@icloud.com",
        "app-pass-word-5678",
        Scope::Read,
        report,
    )
    .await;

    let reply = send(&app, anonymous_stateless("tools/list", json!({}))).await;

    let names = tool_names(&reply);
    assert!(
        names.iter().any(|name| name == "mail_send"),
        "writes are listed: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.starts_with("mail_")),
        "mail tools are listed: {names:?}"
    );
    assert!(
        !reply.text.contains("bob@icloud.com") && !reply.text.contains("ada@icloud.com"),
        "no account's address appears: {}",
        reply.text
    );
}

#[tokio::test]
async fn anonymous_tool_call_gets_the_challenge() {
    let (_store, app) = rig().await;

    let mut request = tool_request("unused", "mail_search", &json!({}));
    request.headers_mut().remove(header::AUTHORIZATION);
    let reply = send(&app, request).await;

    assert_bare_challenge(&reply, "tools/call without a token");
}

#[tokio::test]
async fn every_other_method_without_a_token_gets_the_challenge() {
    let (_store, app) = rig().await;

    for method in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
        "no/such/method",
        "",
    ] {
        let reply = send(&app, anonymous_stateless(method, json!({}))).await;
        assert_bare_challenge(&reply, &format!("method {method:?}"));
    }
}
