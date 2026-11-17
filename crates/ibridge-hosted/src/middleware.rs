// SPDX-License-Identifier: Apache-2.0

//! Bearer and API-key authentication for `/mcp`.
//!
//! The token is the key to the sealed password, so each call opens the password
//! afresh and drops it when the call ends. Nothing here keeps a password between calls,
//! and nothing here logs a header.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use ibridge_auth::Credentials;
use ibridge_core::AppleId;

use crate::store::{GrantId, Scope, Store, StoreError};

/// Who is calling and what the call may do, with the password open for this call only.
///
/// The middleware puts one in each authenticated request's extensions. The
/// password inside is zeroized when the last clone drops, which is when the call ends.
#[derive(Clone)]
pub struct CallAuth {
    grant: GrantId,
    scope: Scope,
    credentials: Arc<Credentials>,
}

impl CallAuth {
    /// The grant or API key that presented the token.
    #[must_use]
    pub fn grant(&self) -> GrantId {
        self.grant
    }

    /// What the grant may do.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The account the password belongs to.
    #[must_use]
    pub fn apple_id(&self) -> &AppleId {
        &self.credentials.apple_id
    }

    /// The account's credentials, open for this call.
    #[must_use]
    pub fn credentials(&self) -> &Arc<Credentials> {
        &self.credentials
    }
}

impl fmt::Debug for CallAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallAuth")
            .field("grant", &self.grant)
            .field("scope", &self.scope)
            .field("apple_id", self.apple_id())
            .finish_non_exhaustive()
    }
}

struct Gate {
    store: Store,
    metadata_url: String,
}

/// Puts `mcp` behind the token check.
///
/// `metadata_url` is the protected resource metadata a client is pointed at.
pub(crate) fn protect(mcp: Router, store: Store, metadata_url: String) -> Router {
    let gate = Arc::new(Gate {
        store,
        metadata_url,
    });
    mcp.route_layer(middleware::from_fn_with_state(gate, authenticate))
}

async fn authenticate(State(gate): State<Arc<Gate>>, mut request: Request, next: Next) -> Response {
    let Some(token) = bearer(request.headers()) else {
        return challenge(&gate, None);
    };
    // Opened afresh for every call: the store keeps only ciphertext, and so does this layer.
    match gate.store.open_for_call(token, SystemTime::now()).await {
        Ok(opened) => {
            request.extensions_mut().insert(CallAuth {
                grant: opened.grant_id,
                scope: opened.scope,
                credentials: Arc::new(Credentials::new(opened.apple_id, opened.secret)),
            });
            // The token is a key. Nothing downstream, including the MCP service that
            // copies request headers into its context, gets to hold or print it.
            request.headers_mut().remove(header::AUTHORIZATION);
            next.run(request).await
        }
        Err(
            StoreError::InvalidToken
            | StoreError::Expired
            | StoreError::InvalidGrant
            | StoreError::Suspended,
        ) => challenge(&gate, Some("invalid_token")),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then_some(token.trim())
}

fn challenge(gate: &Gate, error: Option<&str>) -> Response {
    let value = match error {
        Some(error) => format!(
            r#"Bearer error="{error}", resource_metadata="{}""#,
            gate.metadata_url
        ),
        None => format!(r#"Bearer resource_metadata="{}""#, gate.metadata_url),
    };
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex, Weak};
    use std::time::SystemTime;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::{Request, State};
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;
    use axum::routing::any;
    use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
    use ibridge_core::AppleId;
    use ibridge_server::{AccountSnapshot, IbridgeServer, ServiceStatus};
    use secrecy::{ExposeSecret as _, SecretString};
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::{CallAuth, protect};
    use crate::oauth::{Access, OAuthConfig};
    use crate::server::{ScopedServers, ServerSource, mcp_router};
    use crate::store::{IssuedTokens, Scope, Store, ValidatedCredentials};
    use crate::test_mail::IdleMail;

    const ASP: &str = "abcd-efgh-ijkl-mnop";
    const METADATA: &str = "https://ibridge.example/.well-known/oauth-protected-resource/mcp";

    fn ada() -> AppleId {
        AppleId::try_from("ada@icloud.com").expect("apple id")
    }

    async fn tokens(store: &Store, scope: Scope) -> IssuedTokens {
        let now = SystemTime::now();
        let code = store
            .seal_under_code(&ada(), &SecretString::from(ASP), scope, now)
            .await
            .expect("seal");
        store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .expect("exchange")
    }

    struct Accepts;

    impl Validator for Accepts {
        #[expect(clippy::unused_async_trait_impl, reason = "answers at once")]
        async fn validate(&self) -> Result<ValidationReport, AuthError> {
            Ok(ValidationReport {
                mail: ServiceCheck::Ok,
                calendar: ServiceCheck::Ok,
                contacts: ServiceCheck::Ok,
            })
        }
    }

    async fn api_key(store: &Store, scope: Scope) -> String {
        let validated =
            ValidatedCredentials::from_check(Credentials::new(ada(), ASP.to_owned()), |_| Accepts)
                .await
                .expect("validated");
        let key = store
            .mint_api_key(&validated, "test key", scope, SystemTime::now())
            .await
            .expect("key");
        key.key.expose_secret().to_owned()
    }

    /// What the probe route saw in one request.
    struct Seen {
        apple_id: String,
        password: String,
        scope: Scope,
        authorization_visible: bool,
        credentials: Weak<Credentials>,
        pointer: usize,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    async fn probe(State(log): State<Log>, request: Request) -> axum::response::Response {
        let Some(auth) = request.extensions().get::<CallAuth>() else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        log.lock().expect("log").push(Seen {
            apple_id: auth.apple_id().as_str().to_owned(),
            password: auth.credentials().with_secret(ToOwned::to_owned),
            scope: auth.scope(),
            authorization_visible: request.headers().contains_key(header::AUTHORIZATION),
            credentials: Arc::downgrade(auth.credentials()),
            pointer: Arc::as_ptr(auth.credentials()).addr(),
        });
        StatusCode::OK.into_response()
    }

    fn probe_app(store: &Store) -> (Router, Log) {
        let log = Log::default();
        let inner = Router::new().route("/mcp", any(probe).with_state(Arc::clone(&log)));
        (protect(inner, store.clone(), METADATA.to_owned()), log)
    }

    async fn call(app: &Router, bearer: Option<&str>) -> axum::response::Response {
        let mut request = Request::post("/mcp");
        if let Some(bearer) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        app.clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn bearer_resolves_grant_and_opens_creds_per_call() {
        let store = Store::memory().await.expect("store");
        let issued = tokens(&store, Scope::ReadWrite).await;
        let (app, log) = probe_app(&store);

        for _ in 0..2 {
            let response = call(&app, Some(issued.access.expose_secret())).await;
            assert_eq!(response.status(), StatusCode::OK, "a valid access token");
        }

        let seen = log.lock().expect("log");
        assert_eq!(seen.len(), 2, "both calls reached the endpoint");
        for call in seen.iter() {
            assert_eq!(call.apple_id, "ada@icloud.com", "the grant's account");
            assert_eq!(call.password, ASP, "the password opened for the call");
            assert_eq!(call.scope, Scope::ReadWrite, "the grant's scope");
            assert!(
                !call.authorization_visible,
                "the token does not travel on to the MCP service"
            );
            assert!(
                call.credentials.upgrade().is_none(),
                "the opened password is dropped when the call ends"
            );
        }
        assert_ne!(
            seen[0].pointer, seen[1].pointer,
            "each call opens its own copy; none is kept between calls"
        );
    }

    #[tokio::test]
    async fn apikey_bearer_supported() {
        let store = Store::memory().await.expect("store");
        let read_write = api_key(&store, Scope::ReadWrite).await;
        let read_only = api_key(&store, Scope::Read).await;
        let (app, log) = probe_app(&store);

        for key in [&read_write, &read_only] {
            assert!(key.starts_with("ibr_"), "an API key");
            let response = call(&app, Some(key)).await;
            assert_eq!(response.status(), StatusCode::OK, "an API key is a bearer");
        }
        let seen = log.lock().expect("log");
        assert_eq!(seen[0].password, ASP, "the key opens its own copy");
        assert_eq!(seen[0].scope, Scope::ReadWrite);
        assert_eq!(seen[1].scope, Scope::Read, "the key's scope is kept");
    }

    #[tokio::test]
    async fn invalid_token_401() {
        let store = Store::memory().await.expect("store");
        let issued = tokens(&store, Scope::ReadWrite).await;
        let (app, log) = probe_app(&store);

        for (what, bearer) in [
            ("an unknown token", Some("iba_notatokenatall")),
            ("a refresh token", Some(issued.refresh.expose_secret())),
            ("garbage", Some("x")),
        ] {
            let response = call(&app, bearer).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{what}");
            let challenge = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .expect("a challenge")
                .to_str()
                .expect("ascii");
            assert!(
                challenge.contains(r#"error="invalid_token""#),
                "{what}: the challenge says invalid_token, got {challenge}"
            );
            assert!(
                challenge.contains(METADATA),
                "{what}: the challenge still names the resource metadata"
            );
        }

        let none = call(&app, None).await;
        assert_eq!(none.status(), StatusCode::UNAUTHORIZED, "no token");
        let challenge = none.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .expect("ascii")
            .to_owned();
        assert!(
            !challenge.contains("error="),
            "a request with no credentials gets a bare challenge, got {challenge}"
        );
        assert!(log.lock().expect("log").is_empty(), "no call got through");
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
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
    async fn bearer_header_never_logged() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let store = Store::memory().await.expect("store");
        let issued = tokens(&store, Scope::ReadWrite).await;
        let key = api_key(&store, Scope::Read).await;
        let (inner, _log) = probe_app(&store);
        let app = inner.layer(crate::oauth::tracing_layer());

        let access = issued.access.expose_secret().to_owned();
        let refresh = issued.refresh.expose_secret().to_owned();
        for bearer in [
            access.as_str(),
            key.as_str(),
            "iba_rejectedtokenvalue",
            refresh.as_str(),
        ] {
            let _ = call(&app, Some(bearer)).await;
        }
        let logs =
            String::from_utf8(capture.0.lock().expect("log lock").clone()).expect("utf8 logs");
        assert!(
            logs.contains("/mcp"),
            "requests to /mcp are logged, or this test proves nothing:\n{logs}"
        );
        for (what, secret) in [
            ("the access token", access.as_str()),
            ("the API key", key.as_str()),
            ("a rejected token", "iba_rejectedtokenvalue"),
            ("the refresh token", refresh.as_str()),
            ("the password", ASP),
            ("a token prefix", "iba_"),
            ("an API key prefix", "ibr_"),
            ("the Bearer scheme", "Bearer"),
        ] {
            assert!(
                !logs.contains(secret),
                "{what} appears in the logs:\n{logs}"
            );
        }
    }

    /// Serves one fixed account, so the scope tests need no provider cache.
    struct Fixed(Arc<ScopedServers<IbridgeServer<IdleMail>>>);

    impl ServerSource for Fixed {
        type Server = IbridgeServer<IdleMail>;

        fn servers(&self, _call: &CallAuth) -> Arc<ScopedServers<Self::Server>> {
            Arc::clone(&self.0)
        }
    }

    fn fixed_app(store: &Store) -> Router {
        let account = AccountSnapshot {
            apple_id: ada(),
            mail: ServiceStatus::On,
            calendar: ServiceStatus::On,
            contacts: ServiceStatus::On,
        };
        let mail = Arc::new(IdleMail);
        let servers = Arc::new(ScopedServers {
            read_only: IbridgeServer::read_only(account.clone(), Arc::clone(&mail)),
            read_write: IbridgeServer::read_write(account, mail),
        });
        let info = rmcp::ServerHandler::get_info(&servers.read_only);
        let config =
            OAuthConfig::new("https://ibridge.example", Access::MultiTenant).expect("public url");
        protect(
            mcp_router(Arc::new(Fixed(servers)), info, &config),
            store.clone(),
            METADATA.to_owned(),
        )
    }

    async fn list_tools(app: &Router, bearer: &str) -> Vec<String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }},
        });
        let request = Request::post("/mcp")
            .header(header::HOST, "ibridge.example")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/list")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        assert_eq!(
            status,
            StatusCode::OK,
            "tools/list is served, got {}",
            String::from_utf8_lossy(&bytes)
        );
        let message: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("a JSON reply, got {bytes:?}: {error}"));
        message["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a tool list, got {message}"))
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect()
    }

    #[tokio::test]
    async fn scope_read_only_hides_writes() {
        let store = Store::memory().await.expect("store");
        let read_only = tokens(&store, Scope::Read).await;
        let read_write = api_key(&store, Scope::ReadWrite).await;
        let app = fixed_app(&store);

        let names = list_tools(&app, read_only.access.expose_secret()).await;
        for write in ["mail_send", "mail_move", "mail_create_draft"] {
            assert!(
                !names.iter().any(|name| name == write),
                "a read-only grant does not see {write}, got {names:?}"
            );
        }
        assert!(
            names.iter().any(|name| name == "mail_search"),
            "reads stay, got {names:?}"
        );

        let names = list_tools(&app, &read_write).await;
        assert!(
            names.iter().any(|name| name == "mail_send"),
            "a read-write key sees writes, got {names:?}"
        );
    }
}
