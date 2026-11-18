// SPDX-License-Identifier: Apache-2.0

//! Fake Apple and Firebase servers on loopback, for tests.
//!
//! The clients are pointed at them through a test-only base URL, so no test reaches a real
//! host. Firebase's fake signs its ID tokens with the fixed test key in [`super::jwt::test_key`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use url::Url;

use super::IdentityConfig;
use super::jwt::test_key;

/// The moment the fakes treat as now: tokens they issue are valid around it.
pub const FAKE_NOW_SECS: u64 = 1_800_000_000;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A server that stops when dropped.
#[derive(Debug)]
struct Served {
    base: Url,
    task: JoinHandle<()>,
}

impl Served {
    async fn start(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let base = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("address")
        ))
        .expect("a url");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Self { base, task }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Settings with a fresh Apple key, naming `project` as the Firebase project.
///
/// # Panics
///
/// Never, unless the system random source fails.
#[must_use]
pub fn identity_config(project: &str) -> IdentityConfig {
    IdentityConfig {
        apple_services_id: "fyi.ibridge.signin".to_owned(),
        apple_team_id: "TEAM123456".to_owned(),
        apple_key_id: "KEY1234567".to_owned(),
        apple_private_key: secrecy::SecretString::from(test_key::es256_pem()),
        firebase_project_id: project.to_owned(),
        firebase_api_key: secrecy::SecretString::from("test-api-key"),
    }
}

#[derive(Debug, Default)]
struct AppleState {
    tokens: Mutex<Vec<HashMap<String, String>>>,
    revokes: Mutex<Vec<HashMap<String, String>>>,
    revoke_failure: Mutex<Option<StatusCode>>,
}

/// A fake `appleid.apple.com`: `/auth/token` and `/auth/revoke`.
///
/// A code of `bad-code` is refused as Apple refuses a spent one. Any other code yields the
/// tokens `apple-id-<code>` and `apple-access-<code>`, plus a refresh token a client must ignore.
#[derive(Debug)]
pub struct FakeApple {
    served: Served,
    state: Arc<AppleState>,
}

impl FakeApple {
    /// Starts the server.
    pub async fn start() -> Self {
        let state = Arc::new(AppleState::default());
        let app = Router::new()
            .route("/auth/token", post(apple_token))
            .route("/auth/revoke", post(apple_revoke))
            .with_state(Arc::clone(&state));
        Self {
            served: Served::start(app).await,
            state,
        }
    }

    /// Where the client sends its calls.
    #[must_use]
    pub fn base(&self) -> Url {
        self.served.base.clone()
    }

    /// The forms `/auth/token` received.
    #[must_use]
    pub fn token_requests(&self) -> Vec<HashMap<String, String>> {
        lock(&self.state.tokens).clone()
    }

    /// The forms `/auth/revoke` received.
    #[must_use]
    pub fn revoke_requests(&self) -> Vec<HashMap<String, String>> {
        lock(&self.state.revokes).clone()
    }

    /// Makes `/auth/revoke` answer `status`, still recording what it was sent.
    pub fn fail_revoke(&self, status: StatusCode) {
        *lock(&self.state.revoke_failure) = Some(status);
    }
}

async fn apple_token(
    State(state): State<Arc<AppleState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let code = form.get("code").cloned().unwrap_or_default();
    lock(&state.tokens).push(form);
    if code == "bad-code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }
    Json(json!({
        "access_token": format!("apple-access-{code}"),
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "apple-refresh-must-be-ignored",
        "id_token": format!("apple-id-{code}"),
    }))
    .into_response()
}

async fn apple_revoke(
    State(state): State<Arc<AppleState>>,
    Form(form): Form<HashMap<String, String>>,
) -> StatusCode {
    lock(&state.revokes).push(form);
    lock(&state.revoke_failure).unwrap_or(StatusCode::OK)
}

type ClaimsEdit = Box<dyn Fn(&mut Value) + Send + Sync>;

struct FirebaseState {
    project: String,
    api_key: String,
    uid: String,
    apple_sub: String,
    email: String,
    kid: Mutex<String>,
    edit: Mutex<Option<ClaimsEdit>>,
    failure: Mutex<Option<(StatusCode, String)>>,
    sign_ins: Mutex<Vec<Value>>,
    deletes: Mutex<Vec<Value>>,
    delete_failure: Mutex<Option<StatusCode>>,
    key_fetches: AtomicUsize,
    max_age: AtomicU64,
    real_time: AtomicBool,
}

/// A fake Firebase: `accounts:signInWithIdp`, `accounts:delete` and Google's key set.
pub struct FakeFirebase {
    served: Served,
    state: Arc<FirebaseState>,
}

impl std::fmt::Debug for FakeFirebase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeFirebase")
            .field("base", &self.served.base)
            .finish_non_exhaustive()
    }
}

impl FakeFirebase {
    /// The uid the fake gives every Apple sign-in.
    pub const UID: &'static str = "firebase-uid-ada";
    /// The Apple `sub` it reports.
    pub const APPLE_SUB: &'static str = "000123.apple.sub";
    /// The email it reports.
    pub const EMAIL: &'static str = "ada@privaterelay.appleid.com";

    /// Starts a fake for `project` that wants `api_key` on every call.
    pub async fn start(project: &str, api_key: &str) -> Self {
        let state = Arc::new(FirebaseState {
            project: project.to_owned(),
            api_key: api_key.to_owned(),
            uid: Self::UID.to_owned(),
            apple_sub: Self::APPLE_SUB.to_owned(),
            email: Self::EMAIL.to_owned(),
            kid: Mutex::new(test_key::KID.to_owned()),
            edit: Mutex::new(None),
            failure: Mutex::new(None),
            sign_ins: Mutex::new(Vec::new()),
            deletes: Mutex::new(Vec::new()),
            delete_failure: Mutex::new(None),
            key_fetches: AtomicUsize::new(0),
            max_age: AtomicU64::new(3600),
            real_time: AtomicBool::new(false),
        });
        let app = Router::new()
            .route("/v1/accounts:signInWithIdp", post(firebase_sign_in))
            .route("/v1/accounts:delete", post(firebase_delete))
            .route(
                "/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
                get(firebase_keys),
            )
            .with_state(Arc::clone(&state));
        Self {
            served: Served::start(app).await,
            state,
        }
    }

    /// Where the client sends its calls.
    #[must_use]
    pub fn base(&self) -> Url {
        self.served.base.clone()
    }

    /// Issues tokens valid around the real clock instead of [`FAKE_NOW_SECS`], for a server
    /// that checks them against its own clock.
    pub fn issue_at_real_time(&self) {
        self.state.real_time.store(true, Ordering::SeqCst);
    }

    /// Changes the claims of the next ID tokens, for a token the client must refuse.
    pub fn edit_claims(&self, edit: impl Fn(&mut Value) + Send + Sync + 'static) {
        *lock(&self.state.edit) = Some(Box::new(edit));
    }

    /// Signs the next ID tokens under `kid`, which the key set does not publish unless it is
    /// the test key's own.
    pub fn sign_with_kid(&self, kid: &str) {
        kid.clone_into(&mut lock(&self.state.kid));
    }

    /// Makes `signInWithIdp` fail with `status` and Firebase's error `message`.
    pub fn fail_sign_in(&self, status: StatusCode, message: &str) {
        *lock(&self.state.failure) = Some((status, message.to_owned()));
    }

    /// Makes `accounts:delete` answer `status`, still recording what it was sent.
    pub fn fail_delete(&self, status: StatusCode) {
        *lock(&self.state.delete_failure) = Some(status);
    }

    /// Sets the `max-age` the key set is served with.
    pub fn set_key_max_age(&self, seconds: u64) {
        self.state.max_age.store(seconds, Ordering::SeqCst);
    }

    /// The JSON bodies `signInWithIdp` received.
    #[must_use]
    pub fn sign_ins(&self) -> Vec<Value> {
        lock(&self.state.sign_ins).clone()
    }

    /// The JSON bodies `accounts:delete` received.
    #[must_use]
    pub fn deletes(&self) -> Vec<Value> {
        lock(&self.state.deletes).clone()
    }

    /// How many times the key set was fetched.
    #[must_use]
    pub fn key_fetches(&self) -> usize {
        self.state.key_fetches.load(Ordering::SeqCst)
    }
}

fn wrong_key(state: &FirebaseState, query: &HashMap<String, String>) -> Option<Response> {
    (query.get("key") != Some(&state.api_key)).then(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": 400, "message": "API_KEY_INVALID" } })),
        )
            .into_response()
    })
}

async fn firebase_sign_in(
    State(state): State<Arc<FirebaseState>>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(refusal) = wrong_key(&state, &query) {
        return refusal;
    }
    lock(&state.sign_ins).push(body);
    if let Some((status, message)) = lock(&state.failure).clone() {
        return (
            status,
            Json(json!({ "error": { "code": status.as_u16(), "message": message } })),
        )
            .into_response();
    }
    let issued = if state.real_time.load(Ordering::SeqCst) {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(FAKE_NOW_SECS, |elapsed| elapsed.as_secs())
    } else {
        FAKE_NOW_SECS
    };
    let mut claims = json!({
        "iss": format!("https://securetoken.google.com/{}", state.project),
        "aud": state.project,
        "sub": state.uid,
        "user_id": state.uid,
        "iat": issued,
        "auth_time": issued,
        "exp": issued + 3600,
        "email": state.email,
        "firebase": {
            "identities": { "apple.com": [state.apple_sub], "email": [state.email] },
            "sign_in_provider": "apple.com"
        }
    });
    if let Some(edit) = lock(&state.edit).as_ref() {
        edit(&mut claims);
    }
    let kid = lock(&state.kid).clone();
    Json(json!({
        "kind": "identitytoolkit#VerifyAssertionResponse",
        "idToken": test_key::sign(&kid, "RS256", &claims),
        "localId": state.uid,
        "federatedId": format!("https://appleid.apple.com/{}", state.apple_sub),
        "email": state.email,
        "providerId": "apple.com",
        "isNewUser": true,
    }))
    .into_response()
}

async fn firebase_delete(
    State(state): State<Arc<FirebaseState>>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(refusal) = wrong_key(&state, &query) {
        return refusal;
    }
    lock(&state.deletes).push(body);
    if let Some(status) = *lock(&state.delete_failure) {
        return (
            status,
            Json(json!({ "error": { "code": status.as_u16(), "message": "FAILED" } })),
        )
            .into_response();
    }
    Json(json!({ "kind": "identitytoolkit#DeleteAccountResponse" })).into_response()
}

async fn firebase_keys(State(state): State<Arc<FirebaseState>>) -> impl IntoResponse {
    state.key_fetches.fetch_add(1, Ordering::SeqCst);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        format!(
            "public, max-age={}, must-revalidate",
            state.max_age.load(Ordering::SeqCst)
        )
        .parse()
        .expect("a header value"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("a header value"),
    );
    (headers, test_key::jwks(test_key::KID))
}
