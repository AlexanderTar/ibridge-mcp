// SPDX-License-Identifier: Apache-2.0

//! The token endpoint: codes and refresh tokens in, access and refresh tokens out.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use axum::extract::rejection::FormRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use base64::Engine;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::Shared;
use crate::store::{IssuedTokens, StoreError};

const MAX_FORM: usize = 8 * 1024;

pub(super) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/token", post(token))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .with_state(Arc::clone(shared))
}

/// The token request. It has no `Debug`, so codes, verifiers and refresh tokens stay out of logs.
#[derive(Deserialize)]
struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

async fn token(
    State(shared): State<Arc<Shared>>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
    // Only form bodies are accepted, as RFC 6749 requires; JSON gets the same error as junk.
    let Ok(Form(request)) = form else {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "send application/x-www-form-urlencoded",
        );
    };
    match request.grant_type.as_deref() {
        Some("authorization_code") => exchange_code(&shared, &request).await,
        Some("refresh_token") => refresh(&shared, &request).await,
        Some(_) => failure(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        ),
        None => failure(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "grant_type is required",
        ),
    }
}

async fn exchange_code(shared: &Shared, request: &TokenRequest) -> Response {
    let (Some(code), Some(verifier), Some(client_id), Some(redirect_uri)) = (
        request.code.as_deref(),
        request.code_verifier.as_deref(),
        request.client_id.as_deref(),
        request.redirect_uri.as_deref(),
    ) else {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, code_verifier, client_id and redirect_uri are required",
        );
    };
    let invalid = || {
        failure(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the code is not valid",
        )
    };
    // Taking the binding uses the code up, so a wrong guess cannot be retried.
    let Some(pending) = shared.codes.take(code, Instant::now()) else {
        // A code that is no longer pending may have been exchanged already; if so, OAuth 2.1
        // 4.1.3 has the replay revoke the grant. The store only revokes here, never issues.
        if let Err(error) = shared.store.revoke_if_code_spent(code).await {
            tracing::error!(%error, "token request failed");
        }
        return invalid();
    };
    if pending.client_id != client_id
        || pending.redirect_uri != redirect_uri
        || !verifier_matches(verifier, &pending.challenge)
    {
        return invalid();
    }
    match shared.store.exchange_code(code, SystemTime::now()).await {
        Ok(tokens) => issued(shared, &tokens),
        Err(error) => store_failure(&error),
    }
}

async fn refresh(shared: &Shared, request: &TokenRequest) -> Response {
    let Some(refresh_token) = request.refresh_token.as_deref() else {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    // ponytail: the refresh token is not bound to a client id. Rotation with
    // reuse detection is what protects it; binding needs a client column in the
    // grants table.
    match shared.store.refresh(refresh_token, SystemTime::now()).await {
        Ok(tokens) => issued(shared, &tokens),
        Err(error) => store_failure(&error),
    }
}

/// PKCE S256: `BASE64URL(SHA256(verifier))` must equal the challenge from the authorization request.
fn verifier_matches(verifier: &str, challenge: &str) -> bool {
    let unreserved =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
    if !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(unreserved) {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// Every refusal the caller can cause is `invalid_grant`, which is the signal that
/// makes a client run sign-in again. Only a store fault is a server error.
fn store_failure(error: &StoreError) -> Response {
    match error {
        StoreError::Internal { .. } => {
            tracing::error!(%error, "token request failed");
            let mut response = failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "try again in a moment",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            response
        }
        _ => failure(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the grant is not valid",
        ),
    }
}

fn issued(shared: &Shared, tokens: &IssuedTokens) -> Response {
    no_store(
        Json(json!({
            "access_token": tokens.access.expose_secret(),
            "token_type": "Bearer",
            "expires_in": tokens.expires_in.as_secs(),
            "refresh_token": tokens.refresh.expose_secret(),
            "scope": tokens.scope.as_str(),
            "iss": shared.config.issuer(),
        }))
        .into_response(),
    )
}

fn failure(status: StatusCode, error: &str, description: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({"error": error, "error_description": description})),
        )
            .into_response(),
    )
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use rmcp::transport::auth::{AuthorizationRequest, OAuthState};
    use secrecy::ExposeSecret;

    use ibridge_testkit::http::send;

    use crate::oauth::test_support::{
        ADA, ASP_ALL, CLIENT_ID, Harness, LOOPBACK_REDIRECT, PUBLIC, VERIFIER, harness,
        harness_configured,
    };
    use crate::oauth::{Access, Evict, OAuthConfig};
    use crate::provider::AccountCache;
    use crate::server::mcp_router;
    use crate::store::Scope;
    use crate::store::Store;
    use crate::test_app::{FakeBackend, info};

    fn field(reply: &crate::oauth::test_support::Reply, name: &str) -> String {
        reply.json()[name].as_str().unwrap_or_default().to_owned()
    }

    #[tokio::test]
    async fn code_exchange_returns_access_refresh_and_iss() {
        let h = harness(Access::MultiTenant).await;
        let code = h.sign_in_for_code("203.0.113.9").await;
        let reply = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let body = reply.json();
        assert!(
            field(&reply, "access_token").starts_with("iba_"),
            "an opaque access token"
        );
        assert!(
            field(&reply, "refresh_token").starts_with("ibf_"),
            "a refresh token"
        );
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600, "access tokens last an hour");
        assert_eq!(body["scope"], "icloud.read icloud.write");
        assert_eq!(body["iss"], PUBLIC, "the issuer rides along");
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(reply.headers[header::PRAGMA], "no-cache");

        // The access token opens the account for a call.
        let call = h
            .store
            .open_for_call(&field(&reply, "access_token"), SystemTime::now())
            .await
            .expect("the access token opens the grant");
        assert_eq!(call.apple_id.as_str(), ADA);
        assert_eq!(call.secret.expose_secret(), ASP_ALL);
        assert_eq!(call.scope, Scope::ReadWrite);

        // A code works once.
        let again = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await;
        assert_eq!(again.status, StatusCode::BAD_REQUEST);
        assert_eq!(again.json()["error"], "invalid_grant", "a spent code");

        // OAuth 2.1 4.1.3: presenting a spent code revokes what it issued.
        let access = field(&reply, "access_token");
        assert!(
            h.store
                .open_for_call(&access, SystemTime::now())
                .await
                .is_err(),
            "the replay revoked the grant, so the first access token no longer opens"
        );
        let refreshed = h
            .post_token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &field(&reply, "refresh_token")),
            ])
            .await;
        assert_eq!(refreshed.status, StatusCode::BAD_REQUEST);
        assert_eq!(refreshed.json()["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn failed_attempt_does_not_revoke_or_issue() {
        // A wrong verifier burns the binding but never reaches the store: no tokens
        // are issued, and a later try with the right verifier cannot succeed either.
        let h = harness(Access::MultiTenant).await;
        let code = h.sign_in_for_code("203.0.113.9").await;
        let wrong = h
            .post_token(&Harness::exchange_pairs(
                &code,
                "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww",
            ))
            .await;
        assert_eq!(wrong.json()["error"], "invalid_grant");
        let retry = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await;
        assert_eq!(retry.status, StatusCode::BAD_REQUEST);
        assert_eq!(retry.json()["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn code_is_bound_to_its_client_and_redirect() {
        let h = harness(Access::MultiTenant).await;
        for (name, value) in [
            ("client_id", "https://markup.example/oauth/client.json"),
            ("redirect_uri", "http://127.0.0.1:9/callback"),
        ] {
            let code = h.sign_in_for_code("203.0.113.9").await;
            let mut pairs = Harness::exchange_pairs(&code, VERIFIER);
            pairs.retain(|(key, _)| *key != name);
            pairs.push((name, value));
            let reply = h.post_token(&pairs).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
            assert_eq!(reply.json()["error"], "invalid_grant", "{name}");
        }
    }

    #[tokio::test]
    async fn pkce_s256_required() {
        let h = harness(Access::MultiTenant).await;

        let code = h.sign_in_for_code("203.0.113.9").await;
        let mut missing = Harness::exchange_pairs(&code, VERIFIER);
        missing.retain(|(name, _)| *name != "code_verifier");
        let reply = h.post_token(&missing).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.json()["error"],
            "invalid_request",
            "no verifier at all"
        );

        let wrong = h
            .post_token(&Harness::exchange_pairs(
                &code,
                "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww",
            ))
            .await;
        assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            wrong.json()["error"],
            "invalid_grant",
            "a verifier that does not match the challenge"
        );
        let burned = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await;
        assert_eq!(
            burned.json()["error"],
            "invalid_grant",
            "a failed attempt uses the code up, so a verifier cannot be guessed"
        );

        let code = h.sign_in_for_code("203.0.113.9").await;
        let short = h.post_token(&Harness::exchange_pairs(&code, "short")).await;
        assert_eq!(
            short.json()["error"],
            "invalid_grant",
            "a verifier below 43 characters"
        );

        let code = h.sign_in_for_code("203.0.113.9").await;
        let ok = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await;
        assert_eq!(
            ok.status,
            StatusCode::OK,
            "the matching verifier redeems the code"
        );
    }

    #[tokio::test]
    async fn form_urlencoded_only() {
        let h = harness(Access::MultiTenant).await;
        let code = h.sign_in_for_code("203.0.113.9").await;
        let json = serde_json::json!({
            "grant_type": "authorization_code", "code": code, "redirect_uri": LOOPBACK_REDIRECT,
            "client_id": CLIENT_ID, "code_verifier": VERIFIER,
        });
        for content_type in [Some("application/json"), Some("text/plain"), None] {
            let mut request = Request::post("/token");
            if let Some(content_type) = content_type {
                request = request.header(header::CONTENT_TYPE, content_type);
            }
            let request = request.body(Body::from(json.to_string())).expect("request");
            let reply = h.send(request, "203.0.113.50").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{content_type:?}");
            assert_eq!(reply.json()["error"], "invalid_request", "{content_type:?}");
        }
        // The code was never touched, so the proper form still works with a charset parameter.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(Harness::exchange_pairs(&code, VERIFIER))
            .finish();
        let request = Request::post("/token")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body(Body::from(body))
            .expect("request");
        assert_eq!(h.send(request, "203.0.113.50").await.status, StatusCode::OK);

        let unsupported = h
            .post_token(&[("grant_type", "password"), ("username", ADA)])
            .await;
        assert_eq!(unsupported.json()["error"], "unsupported_grant_type");
        let none = h.post_token(&[]).await;
        assert_eq!(none.json()["error"], "invalid_request", "no grant_type");
    }

    #[tokio::test]
    async fn dead_refresh_invalid_grant() {
        let h = harness(Access::MultiTenant).await;
        let code = h.sign_in_for_code("203.0.113.9").await;
        let tokens = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await
            .json();
        let refresh = tokens["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_owned();

        for dead in ["ibf_not-a-real-token", "garbage", ""] {
            let reply = h
                .post_token(&[("grant_type", "refresh_token"), ("refresh_token", dead)])
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{dead:?}");
            assert_eq!(reply.json()["error"], "invalid_grant", "{dead:?}");
        }

        // A live refresh token rotates.
        let rotated = h
            .post_token(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)])
            .await;
        assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.text);
        let next = rotated.json();
        assert_ne!(
            next["refresh_token"], tokens["refresh_token"],
            "the refresh token rotates"
        );
        assert!(
            next["access_token"]
                .as_str()
                .expect("access")
                .starts_with("iba_")
        );
        assert_eq!(next["iss"], PUBLIC);

        // A grant revoked after three failed logins over 15 minutes refuses its refresh token.
        let revoked = h.sign_in_for_code("203.0.113.9").await;
        let issued = h
            .post_token(&Harness::exchange_pairs(&revoked, VERIFIER))
            .await
            .json();
        let access = issued["access_token"].as_str().expect("access");
        let grant = h
            .store
            .open_for_call(access, SystemTime::now())
            .await
            .expect("open")
            .grant_id;
        let now = SystemTime::now();
        for minutes in [20_u64, 10, 0] {
            h.store
                .note_auth_failure(grant, now - Duration::from_secs(minutes * 60))
                .await
                .expect("failure noted");
        }
        let dead = h
            .post_token(&[
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    issued["refresh_token"].as_str().expect("refresh"),
                ),
            ])
            .await;
        assert_eq!(dead.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            dead.json()["error"],
            "invalid_grant",
            "the documented signal that makes a client sign in again"
        );
        assert_eq!(
            dead.headers[header::CACHE_CONTROL],
            "no-store",
            "errors are not cached either"
        );
    }

    /// Collects tracing output so a test can search it.
    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn codes_and_tokens_never_logged() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), "203.0.113.9")
            .await;
        let csrf = page.input("csrf");
        let reply = h.post_form(&page, "203.0.113.9", ADA, ASP_ALL, None).await;
        let code = reply
            .location()
            .query_pairs()
            .find(|(name, _)| name == "code")
            .map(|(_, value)| value.into_owned())
            .expect("a code");
        let tokens = h
            .post_token(&Harness::exchange_pairs(&code, VERIFIER))
            .await
            .json();
        let access = tokens["access_token"].as_str().expect("access").to_owned();
        let refresh = tokens["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_owned();
        let refreshed = h
            .post_token(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)])
            .await
            .json();
        let rotated = refreshed["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_owned();
        // A token in the Authorization header and in the query string, as a careless client might send.
        let request = Request::get(format!("/mcp?access_token={access}&code={code}"))
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::empty())
            .expect("request");
        let _ = h.send(request, "203.0.113.9").await;

        let logs =
            String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("utf8 logs");
        for needle in ["/authorize", "/token", "/mcp"] {
            assert!(
                logs.contains(needle),
                "requests to {needle} are logged, or this test proves nothing:\n{logs}"
            );
        }
        for (what, secret) in [
            ("the app-specific password", ASP_ALL),
            ("the authorization code", code.as_str()),
            ("the access token", access.as_str()),
            ("the refresh token", refresh.as_str()),
            ("the rotated refresh token", rotated.as_str()),
            ("the PKCE verifier", VERIFIER),
            ("the CSRF token", csrf.as_str()),
            ("a code prefix", "ibc_"),
            ("an access prefix", "iba_"),
            ("a refresh prefix", "ibf_"),
        ] {
            assert!(
                !logs.contains(secret),
                "{what} appears in the logs:\n{logs}"
            );
        }
    }

    /// The whole hosted router on a real socket, with the real `/mcp` over a fake mail
    /// backend behind the same bearer check production uses. Returns it and its origin.
    async fn serve_hosted() -> (Harness, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let base = format!("http://127.0.0.1:{port}");
        // The real `/mcp` over a fake mail backend, behind the same bearer check production uses.
        let config = OAuthConfig::new(&base, Access::MultiTenant).expect("public url");
        let store = Store::memory().await.expect("store");
        let cache = Arc::new(AccountCache::new(
            FakeBackend,
            store.clone(),
            config.url("/account"),
        ));
        let mcp = mcp_router(cache, info(), &config);
        let evict: Evict = Arc::new(|_| {});
        let h = harness_configured(config, store, evict, mcp).await;
        let served = h.app.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                served.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        (h, base)
    }

    /// Claude.ai's path: a legacy session (initialize, `Mcp-Session-Id`, protocol 2025-11-25)
    /// opened and used with `access`, a token the OAuth flow issued.
    async fn legacy_session_call(base: &str, access: &str) {
        let mcp_url = format!("{base}/mcp");
        let bearer = format!("Bearer {access}");
        let session_headers = |session: &str| {
            vec![
                ("authorization", bearer.clone()),
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json, text/event-stream".to_owned()),
                ("mcp-protocol-version", "2025-11-25".to_owned()),
                ("mcp-session-id", session.to_owned()),
            ]
        };
        let rpc = |headers: &[(String, String)], body: serde_json::Value| {
            let headers: Vec<(String, String)> = headers.to_vec();
            let url = mcp_url.clone();
            async move {
                let pairs: Vec<(&str, &str)> = headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect();
                send("POST", &url, &pairs, &body.to_string()).await
            }
        };
        let owned = |headers: Vec<(&str, String)>| -> Vec<(String, String)> {
            headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect()
        };
        let initialize = rpc(
            &owned(vec![
                ("authorization", bearer.clone()),
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json, text/event-stream".to_owned()),
            ]),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "legacy test client", "version": "1.0"},
                },
            }),
        )
        .await;
        assert_eq!(initialize.status, 200, "{}", initialize.body);
        let session = initialize
            .header("mcp-session-id")
            .expect("a legacy session id")
            .to_owned();
        // A session's first answer arrives as an event stream; the JSON is its `data:` line.
        let reply: serde_json::Value = initialize
            .body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .find_map(|data| serde_json::from_str(data.trim()).ok())
            .unwrap_or_else(|| panic!("a JSON initialize answer: {}", initialize.body));
        assert_eq!(
            reply["result"]["protocolVersion"], "2025-11-25",
            "the session speaks the protocol the client asked for: {reply}"
        );
        let headers = owned(session_headers(&session));
        let ready = rpc(
            &headers,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        assert_eq!(ready.status, 202, "{}", ready.body);
        let status = rpc(
            &headers,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "account_status", "arguments": {}},
            }),
        )
        .await;
        assert_eq!(status.status, 200, "{}", status.body);
        assert!(
            status.body.contains("signed in as ada@icloud.com"),
            "the call ran as the account the token opens: {}",
            status.body
        );
        // The session id is not a credential: a call that leaves the token out is refused.
        let tokenless: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| name != "authorization")
            .cloned()
            .collect();
        let refused = rpc(
            &tokenless,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "account_status", "arguments": {}},
            }),
        )
        .await;
        assert_eq!(refused.status, 401, "{}", refused.body);
    }

    #[tokio::test]
    async fn full_flow_with_rmcp_oauth_client() {
        let (h, base) = serve_hosted().await;

        // Discovery starts from the 401 challenge, as an MCP client's first request would.
        let probe = h
            .send(
                Request::get("/mcp").body(Body::empty()).expect("request"),
                "203.0.113.9",
            )
            .await;
        assert_eq!(probe.status, StatusCode::UNAUTHORIZED);
        let challenge = probe.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .expect("ascii")
            .to_owned();

        let redirect = "http://127.0.0.1:38417/callback";
        let mut client = OAuthState::new(format!("{base}/mcp"), None)
            .await
            .expect("client");
        client
            .start_authorization(
                AuthorizationRequest::new(redirect)
                    .with_scopes(["icloud.read", "icloud.write"])
                    .with_client_name("rmcp test client")
                    .with_challenge(challenge),
            )
            .await
            .expect("discovery, registration and the authorization URL");
        let auth_url = url::Url::parse(&client.get_authorization_url().await.expect("auth url"))
            .expect("a URL");
        assert_eq!(auth_url.path(), "/authorize");

        // The person at the browser: open the page, sign in.
        let path_and_query = format!("{}?{}", auth_url.path(), auth_url.query().expect("a query"));
        let page = h.get_authorize(&path_and_query, "203.0.113.9").await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text);
        assert!(
            page.text.contains("rmcp test client"),
            "the registered name is shown"
        );
        let signed_in = h.post_form(&page, "203.0.113.9", ADA, ASP_ALL, None).await;
        assert_eq!(
            signed_in.status,
            StatusCode::SEE_OTHER,
            "{}",
            signed_in.text
        );
        let callback = signed_in.location();
        assert!(callback.as_str().starts_with(redirect), "{callback}");

        // The client takes the redirect, checks `iss`, and exchanges the code with PKCE.
        client
            .handle_callback_url(callback.as_str())
            .await
            .expect("the code exchange completes");
        let (client_id, credentials) = client.get_credentials().await.expect("credentials");
        assert!(
            client_id.starts_with("dcr_"),
            "registered through DCR: {client_id}"
        );
        let held = serde_json::to_value(credentials.expect("a token response")).expect("json");
        let access = held["access_token"]
            .as_str()
            .expect("an access token")
            .to_owned();
        assert!(access.starts_with("iba_"));
        assert!(
            held["refresh_token"]
                .as_str()
                .is_some_and(|token| token.starts_with("ibf_")),
            "the client got a refresh token: {held}"
        );

        // Signing in marks the registration as used, so the sweep of unused ones keeps it.
        let used: Option<i64> =
            sqlx::query_scalar("SELECT used_at FROM oauth_clients WHERE client_id = ?")
                .bind(&client_id)
                .fetch_one(h.store.pool())
                .await
                .expect("the registration exists");
        assert!(used.is_some(), "a completed sign-in marks the client used");

        // The token it holds opens the account for a call.
        let call = h
            .store
            .open_for_call(&access, SystemTime::now())
            .await
            .expect("opens");
        assert_eq!(call.apple_id.as_str(), ADA);
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            1,
            "one live check for one sign-in"
        );

        legacy_session_call(&base, &access).await;
    }
}
