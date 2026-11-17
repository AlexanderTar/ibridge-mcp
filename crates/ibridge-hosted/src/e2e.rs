// SPDX-License-Identifier: Apache-2.0

//! The hosted server end to end: sign in through OAuth, then call tools with the token.

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use url::Url;

use crate::limits::Guards;
use crate::oauth::Access;
use crate::store::Store;
use crate::test_app::{HOST, PUBLIC_URL, config, rpc_request};
use crate::testing::{FakeImapBackend, accept_all, info};

const REDIRECT: &str = "http://127.0.0.1:53682/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub(crate) const PASSWORD: &str = "abcd-efgh-ijkl-mnop";

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) text: String,
}

impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.text)
            .unwrap_or_else(|error| panic!("a JSON body ({error}): {}", self.text))
    }

    /// The `value` of the form input called `name`.
    fn input(&self, name: &str) -> Option<String> {
        let marker = format!(r#"name="{name}" value=""#);
        let start = self.text.find(&marker)? + marker.len();
        let end = self.text[start..].find('"')?;
        Some(self.text[start..start + end].to_owned())
    }
}

pub(crate) async fn send(app: &Router, mut request: Request<Body>) -> Reply {
    let ip: IpAddr = "203.0.113.9".parse().expect("an ip");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    Reply {
        status,
        headers,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// A hosted app over `imap`, open to any address.
async fn hosted(imap: &FakeImap) -> Router {
    hosted_over(FakeImapBackend(imap.clone())).await
}

/// A hosted app over `backend`, open to any address.
pub(crate) async fn hosted_over(backend: impl crate::provider::Backend) -> Router {
    let store = Store::memory().await.expect("store");
    crate::app::app(
        config(Access::MultiTenant),
        store,
        backend,
        accept_all(),
        info(),
        &Guards::default(),
    )
    .await
    .expect("app")
}

/// Registers a client, signs in with `password` and trades the code for an access token.
pub(crate) async fn sign_in(app: &Router, apple_id: &str, password: &str) -> String {
    let client_id = register(app).await;
    let code = authorize(app, &client_id, apple_id, password).await;
    redeem(app, &client_id, &code).await
}

async fn register(app: &Router) -> String {
    let registration = send(
        app,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "client_name": "e2e",
                    "redirect_uris": [REDIRECT],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(
        registration.status,
        StatusCode::CREATED,
        "{}",
        registration.text
    );
    registration.json()["client_id"]
        .as_str()
        .expect("a client id")
        .to_owned()
}

/// Fills in the sign-in page and returns the authorization code it redirects with.
async fn authorize(app: &Router, client_id: &str, apple_id: &str, password: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
            ("scope", "icloud.read icloud.write"),
            ("resource", &format!("{PUBLIC_URL}/mcp")),
        ])
        .finish();
    let page = send(
        app,
        Request::get(format!("/authorize?{query}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    let cookie = page
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .expect("a cookie")
        .to_owned();

    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for name in [
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "state",
        "scope",
        "resource",
        "response_type",
        "csrf",
    ] {
        if let Some(value) = page.input(name) {
            form.append_pair(name, &value);
        }
    }
    form.append_pair("apple_id", apple_id);
    form.append_pair("password", password);
    let submitted = send(
        app,
        Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(form.finish()))
            .expect("request"),
    )
    .await;
    let location = submitted
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("a redirect, got {}: {}", submitted.status, submitted.text));
    Url::parse(location)
        .expect("a URL")
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.into_owned())
        .expect("a code")
}

async fn redeem(app: &Router, client_id: &str, code: &str) -> String {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", VERIFIER),
        ])
        .finish();
    let tokens = send(
        app,
        Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("request"),
    )
    .await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.text);
    tokens.json()["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned()
}

#[tokio::test]
async fn oauth_then_tool_call() {
    let imap = FakeImap::spawn(FakeScript {
        accepts_password: Some(PASSWORD.to_owned()),
        ..FakeScript::default()
    });
    let app = hosted(&imap).await;

    let unauthenticated = send(
        &app,
        rpc_request("not-a-token", "tools/list", None, json!({})),
    )
    .await;
    assert_eq!(
        unauthenticated.status,
        StatusCode::UNAUTHORIZED,
        "a stranger is turned away"
    );

    let bearer = sign_in(&app, "ada@icloud.com", PASSWORD).await;

    let status = send(
        &app,
        rpc_request(
            &bearer,
            "tools/call",
            Some("account_status"),
            json!({"name": "account_status", "arguments": {}}),
        ),
    )
    .await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.text);
    assert!(
        status.text.contains("ada@icloud.com"),
        "account_status names the signed-in account: {}",
        status.text
    );

    let mailboxes = send(
        &app,
        rpc_request(
            &bearer,
            "tools/call",
            Some("mail_list_mailboxes"),
            json!({"name": "mail_list_mailboxes", "arguments": {}}),
        ),
    )
    .await;
    let message = mailboxes.json();
    assert!(
        message.get("error").is_none() && message["result"]["isError"] != json!(true),
        "the tool call worked: {message}"
    );
    assert_eq!(imap.login_count(), 1, "the call logged in to IMAP once");
    assert!(
        imap.saw("INBOX"),
        "and listed the fake server's mailboxes: {:?}",
        imap.lines()
    );
    assert_eq!(
        HOST, "ibridge.example",
        "the requests carried the public host"
    );
}

#[tokio::test]
async fn hosted_tools_list_lacks_save_attachment() {
    let imap = FakeImap::spawn(FakeScript::default());
    let app = hosted(&imap).await;
    let bearer = sign_in(&app, "ada@icloud.com", PASSWORD).await;

    let listing = send(&app, rpc_request(&bearer, "tools/list", None, json!({}))).await;
    assert_eq!(listing.status, StatusCode::OK, "{}", listing.text);
    let tools = listing.json();
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(
        names.contains(&"mail_get_attachment"),
        "reads attachments: {names:?}"
    );
    assert!(names.contains(&"account_status"), "{names:?}");
    assert!(
        !names.contains(&"mail_save_attachment"),
        "a hosted server never writes files: {names:?}"
    );
}
