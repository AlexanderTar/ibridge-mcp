// SPDX-License-Identifier: Apache-2.0

//! Discovery without a token, end to end over the whole hosted router.
//!
//! `initialize`, `notifications/initialized`, `ping` and `tools/list` are answered
//! to a caller with no token. Everything else keeps today's 401 challenge.

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

use crate::limits::Guards;
use crate::oauth::ProxyTrust;
use crate::store::{Scope, Store};
use crate::test_app::{
    HOST, Reply, SECRET_SUBJECT, app_over, app_with, rpc_request, send, token, token_after_check,
    tool_request,
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

/// A `tools/call` on a legacy session.
fn session_tool_call(session: &str) -> Request<Body> {
    in_session(
        session,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "mail_search", "arguments": {}},
        }),
    )
}

fn bearing(mut request: Request<Body>, bearer: &str) -> Request<Body> {
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {bearer}").parse().expect("value"),
    );
    request
}

async fn open_session(app: &Router, bearer: Option<&str>) -> String {
    let mut request = anonymous(&legacy_initialize());
    if let Some(bearer) = bearer {
        request = bearing(request, bearer);
    }
    let reply = send(app, request).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    reply.headers["mcp-session-id"]
        .to_str()
        .expect("id")
        .to_owned()
}

#[tokio::test]
async fn a_session_opened_without_a_token_still_needs_one_to_call_tools() {
    let (store, app) = rig().await;
    let session = open_session(&app, None).await;

    let without = send(&app, session_tool_call(&session)).await;
    assert_bare_challenge(&without, "a tool call on an anonymous session");
    assert!(!without.text.contains(SECRET_SUBJECT), "{}", without.text);

    let bearer = token(
        &store,
        "ada@icloud.com",
        "app-pass-word-1234",
        Scope::ReadWrite,
    )
    .await;
    let with = send(&app, bearing(session_tool_call(&session), &bearer)).await;
    assert_eq!(with.status, StatusCode::OK, "{}", with.text);
    assert!(
        with.text.contains(SECRET_SUBJECT),
        "the token on a later request opens the account for that call: {}",
        with.text
    );
}

#[tokio::test]
async fn a_session_opened_with_a_token_does_not_carry_it_to_later_calls() {
    let (store, app) = rig().await;
    let bearer = token(
        &store,
        "ada@icloud.com",
        "app-pass-word-1234",
        Scope::ReadWrite,
    )
    .await;
    let session = open_session(&app, Some(&bearer)).await;

    let reply = send(&app, session_tool_call(&session)).await;

    assert_bare_challenge(&reply, "a tool call with no token on a signed-in session");
}

#[tokio::test]
async fn a_token_that_is_present_but_wrong_gets_401_even_on_initialize() {
    let (store, app) = rig().await;
    let good = token(
        &store,
        "ada@icloud.com",
        "app-pass-word-1234",
        Scope::ReadWrite,
    )
    .await;

    for (what, bearer) in [("an unknown token", "iba_notatokenatall"), ("garbage", "x")] {
        for body in [
            legacy_initialize(),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ] {
            let reply = send(&app, bearing(anonymous(&body), bearer)).await;
            assert_eq!(
                reply.status,
                StatusCode::UNAUTHORIZED,
                "{what}: {}",
                reply.text
            );
            let challenge = reply.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .expect("ascii");
            assert!(
                challenge.contains(r#"error="invalid_token""#),
                "{what}: a client is told to refresh, got {challenge}"
            );
        }
    }

    let mut basic = anonymous(&legacy_initialize());
    basic.headers_mut().insert(
        header::AUTHORIZATION,
        "Basic dXNlcjpwYXNz".parse().expect("value"),
    );
    let reply = send(&app, basic).await;
    assert_bare_challenge(&reply, "an Authorization header that is not a bearer");

    let reply = send(&app, bearing(anonymous(&legacy_initialize()), &good)).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "a valid token still opens a session"
    );
}

#[tokio::test]
async fn batches_are_discovery_only_when_every_message_is() {
    let (_store, app) = rig().await;
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "mail_search", "arguments": {}},
    });

    for (what, body) in [
        ("a call after a list", json!([list, call])),
        ("a call before a list", json!([call, list])),
        ("a lone call", json!([call])),
        ("an empty batch", json!([])),
        ("a batch of non-messages", json!([1, "x", null])),
    ] {
        let reply = send(&app, anonymous(&body)).await;
        assert_bare_challenge(&reply, what);
    }

    let reply = send(&app, anonymous(&json!([list, list]))).await;
    assert_ne!(
        reply.status,
        StatusCode::UNAUTHORIZED,
        "a batch of only discovery passes the gate: {}",
        reply.text
    );
}

#[tokio::test]
async fn malformed_oversized_and_ambiguous_bodies_need_a_token() {
    let (_store, app) = rig().await;
    let post = |body: String| anonymous(&Value::Null).map(|_| Body::from(body));

    let padding = "a".repeat(32 * 1024);
    let oversized = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"pad": padding},
    });
    for (what, body) in [
        ("not JSON", "tools/list".to_owned()),
        ("an empty body", String::new()),
        ("truncated JSON", r#"{"jsonrpc":"2.0","method":"tools/list""#.to_owned()),
        ("a bare string", r#""tools/list""#.to_owned()),
        ("a method that is not a string", r#"{"method":["tools/list"]}"#.to_owned()),
        ("a response, not a request", r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_owned()),
        ("a discovery method with a big body", oversized.to_string()),
        (
            "a repeated method, the call last",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"mail_search","arguments":{}}}"#
                .to_owned(),
        ),
    ] {
        let reply = send(&app, post(body)).await;
        assert_bare_challenge(&reply, what);
    }

    // The gate reads the last `method`, the MCP service may read the first. Whichever it
    // is, no mail may come back.
    let tricky = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"mail_search","arguments":{}}}"#;
    let reply = send(&app, post(tricky.to_owned())).await;
    assert!(
        !reply.text.contains(SECRET_SUBJECT),
        "no message came back: {}",
        reply.text
    );
}

#[tokio::test]
async fn the_event_stream_and_session_delete_still_need_a_token() {
    let (_store, app) = rig().await;
    let session = open_session(&app, None).await;

    for method in [Method::GET, Method::DELETE] {
        let mut request = Request::builder()
            .method(method.clone())
            .uri("/mcp")
            .header(header::HOST, HOST)
            .header(header::ACCEPT, "text/event-stream")
            .header("mcp-session-id", &session)
            .body(Body::empty())
            .expect("request");
        request
            .headers_mut()
            .insert("mcp-protocol-version", "2025-06-18".parse().expect("value"));
        let reply = send(&app, request).await;
        assert_bare_challenge(&reply, &format!("{method} without a token"));
    }
}

fn from_ip(mut request: Request<Body>, ip: &str) -> Request<Body> {
    let peer = SocketAddr::new(ip.parse().expect("ip"), 40_000);
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

#[tokio::test]
async fn anonymous_discovery_is_rate_limited_per_ip() {
    let store = Store::memory().await.expect("store");
    let guards = Guards {
        anonymous_per_minute: 3,
        ..Guards::default()
    };
    let app = app_with(&store, &guards).await;
    let list = || anonymous_stateless("tools/list", json!({}));

    for attempt in 1..=3 {
        let reply = send(&app, from_ip(list(), "203.0.113.7")).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "request {attempt}: {}",
            reply.text
        );
    }
    let refused = send(&app, from_ip(list(), "203.0.113.7")).await;
    assert_eq!(
        refused.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        refused.text
    );
    assert!(
        refused.headers.contains_key(header::RETRY_AFTER),
        "{:?}",
        refused.headers
    );

    let other = send(&app, from_ip(list(), "203.0.113.8")).await;
    assert_eq!(
        other.status,
        StatusCode::OK,
        "another address has its own budget"
    );

    // A caller with a token is not counted against the anonymous budget.
    let bearer = token(
        &store,
        "ada@icloud.com",
        "app-pass-word-1234",
        Scope::ReadWrite,
    )
    .await;
    let signed_in = rpc_request(&bearer, "tools/list", None, json!({}));
    let reply = send(&app, from_ip(signed_in, "203.0.113.7")).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    // A refused request needs no token to be refused: the challenge still comes first.
    let call = {
        let mut request = tool_request("unused", "mail_search", &json!({}));
        request.headers_mut().remove(header::AUTHORIZATION);
        from_ip(request, "203.0.113.7")
    };
    assert_bare_challenge(
        &send(&app, call).await,
        "a tool call from an address over its budget",
    );
}

/// The hosted router with a budget of two tokenless requests, trusting `X-Forwarded-For` or not.
async fn app_with_two_anonymous(trust: ProxyTrust) -> Router {
    let mut config = crate::test_app::config(crate::oauth::Access::MultiTenant);
    if trust == ProxyTrust::Proxy {
        config = config.behind_proxy();
    }
    let guards = Guards {
        anonymous_per_minute: 2,
        ..Guards::default()
    };
    let store = Store::memory().await.expect("store");
    crate::app::app(
        config,
        store,
        crate::test_app::FakeBackend,
        crate::oauth::validated_by(|_: &ibridge_auth::Credentials| crate::test_app::AcceptAll),
        crate::test_app::info(),
        &guards,
    )
    .await
    .expect("app")
}

fn forwarded(request: Request<Body>, client: &str) -> Request<Body> {
    let mut request = from_ip(request, "10.0.0.1");
    request
        .headers_mut()
        .insert("x-forwarded-for", client.parse().expect("value"));
    request
}

#[tokio::test]
async fn behind_a_proxy_the_budget_follows_the_forwarded_client() {
    let app = app_with_two_anonymous(ProxyTrust::Proxy).await;
    let list = || anonymous_stateless("tools/list", json!({}));

    for _ in 0..2 {
        // The first entry is the caller's claim; the last is what the proxy saw.
        let reply = send(&app, forwarded(list(), "1.1.1.1, 198.51.100.1")).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    }
    let spent = send(&app, forwarded(list(), "9.9.9.9, 198.51.100.1")).await;
    assert_eq!(
        spent.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a made-up first entry buys no budget"
    );
    let other = send(&app, forwarded(list(), "198.51.100.2")).await;
    assert_eq!(
        other.status,
        StatusCode::OK,
        "another client behind the proxy"
    );
}

#[tokio::test]
async fn without_a_proxy_forwarded_for_is_ignored() {
    let app = app_with_two_anonymous(ProxyTrust::Direct).await;
    let list = || anonymous_stateless("tools/list", json!({}));

    for client in ["198.51.100.1", "198.51.100.2"] {
        let reply = send(&app, forwarded(list(), client)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    }
    let spent = send(&app, forwarded(list(), "198.51.100.3")).await;
    assert_eq!(
        spent.status,
        StatusCode::TOO_MANY_REQUESTS,
        "one socket peer, one budget, whatever the header says"
    );
}
