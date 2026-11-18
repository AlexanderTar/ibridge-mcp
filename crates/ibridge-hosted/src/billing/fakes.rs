// SPDX-License-Identifier: Apache-2.0

//! A fake `api.stripe.com` on loopback, for tests.
//!
//! The client is pointed at it through a test-only base URL, so no test reaches a real host.
//! Its replies are the objects the Stripe sandbox returned at [`STRIPE_API_VERSION`] (kept in
//! `fixtures/`), with the fields a test scripts replaced, so where a field lives (the item's
//! `current_period_end`, an invoice's `parent.subscription_details.subscription`) comes from
//! real data. Like Stripe, it refuses a request without the pinned `Stripe-Version`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use ring::hmac;
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use url::Url;

use super::stripe::STRIPE_API_VERSION;

const CUSTOMER: &str = include_str!("fixtures/customer.json");
const SESSION_MANAGED: &str = include_str!("fixtures/checkout-session-managed.json");
const SESSION_AUTOMATIC: &str = include_str!("fixtures/checkout-session-automatic-mp-off.json");
const SUBSCRIPTION: &str = include_str!("fixtures/subscription.json");
const SUBSCRIPTION_LIST: &str = include_str!("fixtures/subscription-list.json");

/// The key the fake accepts.
pub const FAKE_SECRET_KEY: &str = "sk_test_fake_key_for_tests";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("a fixture is JSON")
}

/// One request the fake received.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// The HTTP method.
    pub method: String,
    /// The path, such as `/v1/customers`.
    pub path: String,
    /// The `Stripe-Version` header, when sent.
    pub version: Option<String>,
    /// The `Idempotency-Key` header, when sent.
    pub idempotency: Option<String>,
    /// The form fields of the body.
    pub form: HashMap<String, String>,
}

impl Recorded {
    /// The form field `name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.form.get(name).map(String::as_str)
    }
}

#[derive(Default)]
struct FakeState {
    requests: Mutex<Vec<Recorded>>,
    customers: Mutex<HashMap<String, String>>,
    sessions: Mutex<HashMap<String, Value>>,
    subscriptions: Mutex<HashMap<String, Value>>,
    counter: AtomicUsize,
    refuse: Mutex<Option<StatusCode>>,
    refuse_cancel: Mutex<HashMap<String, StatusCode>>,
    last_session: Mutex<Option<String>>,
}

/// A fake Stripe API. Stops when dropped.
pub struct FakeStripe {
    base: Url,
    task: JoinHandle<()>,
    state: Arc<FakeState>,
}

impl std::fmt::Debug for FakeStripe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeStripe")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Drop for FakeStripe {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeStripe {
    /// Starts the server.
    ///
    /// # Panics
    ///
    /// When loopback cannot be bound.
    pub async fn start() -> Self {
        let state = Arc::new(FakeState::default());
        let app = Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&state));
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
        Self { base, task, state }
    }

    /// Where the client sends its calls.
    #[must_use]
    pub fn base(&self) -> Url {
        self.base.clone()
    }

    /// Every request received so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<Recorded> {
        lock(&self.state.requests).clone()
    }

    /// The requests received on `method` and `path`.
    #[must_use]
    pub fn requests_to(&self, method: &str, path: &str) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == method && request.path == path)
            .collect()
    }

    /// Makes every later request fail with `status`, as a Stripe outage would.
    pub fn refuse_with(&self, status: StatusCode) {
        *lock(&self.state.refuse) = Some(status);
    }

    /// Ends an outage started by [`FakeStripe::refuse_with`].
    pub fn recover(&self) {
        *lock(&self.state.refuse) = None;
    }

    /// Makes the cancel (DELETE) of subscription `id` fail with `status`, while every other call works.
    pub fn refuse_cancel_of(&self, id: &str, status: StatusCode) {
        lock(&self.state.refuse_cancel).insert(id.to_owned(), status);
    }

    /// Undoes [`FakeStripe::refuse_cancel_of`] for subscription `id`.
    pub fn allow_cancel_of(&self, id: &str) {
        lock(&self.state.refuse_cancel).remove(id);
    }

    /// Stores a subscription the client can fetch: the sandbox's, with these fields set.
    pub fn put_subscription(&self, id: &str, customer: &str, status: &str, period_end: i64) {
        let mut object = fixture(SUBSCRIPTION);
        object["id"] = json!(id);
        object["customer"] = json!(customer);
        object["status"] = json!(status);
        object["items"]["data"][0]["subscription"] = json!(id);
        object["items"]["data"][0]["current_period_end"] = json!(period_end);
        lock(&self.state.subscriptions).insert(id.to_owned(), object);
    }

    /// Stores a Checkout Session as Stripe would hold it after a payment: complete, for
    /// `customer` and `reference`, with `subscription` made. For tests of a session that
    /// was not made through this server's checkout.
    pub fn put_session(&self, id: &str, customer: &str, reference: &str, subscription: &str) {
        let mut object = fixture(SESSION_MANAGED);
        object["id"] = json!(id);
        object["customer"] = json!(customer);
        object["client_reference_id"] = json!(reference);
        object["status"] = json!("complete");
        object["payment_status"] = json!("paid");
        object["subscription"] = json!(subscription);
        lock(&self.state.sessions).insert(id.to_owned(), object);
    }

    /// Marks a Checkout Session paid and attached to `subscription`, as it is once the person pays.
    ///
    /// # Panics
    ///
    /// When no such session was created.
    pub fn complete_session(&self, id: &str, subscription: &str) {
        let mut sessions = lock(&self.state.sessions);
        let session = sessions.get_mut(id).expect("the session was created");
        session["status"] = json!("complete");
        session["payment_status"] = json!("paid");
        session["subscription"] = json!(subscription);
    }

    /// The id of the Checkout Session created last.
    #[must_use]
    pub fn last_session(&self) -> Option<String> {
        lock(&self.state.last_session).clone()
    }
}

fn stripe_error(status: StatusCode, kind: &str) -> Response {
    (
        status,
        axum::Json(json!({ "error": { "type": kind, "message": "fake stripe refused" } })),
    )
        .into_response()
}

fn form_of(body: &Bytes) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

async fn handle(
    State(state): State<Arc<FakeState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let form = form_of(&body);
    lock(&state.requests).push(Recorded {
        method: method.to_string(),
        path: uri.path().to_owned(),
        version: text("stripe-version"),
        idempotency: text("idempotency-key"),
        form: form.clone(),
    });
    if let Some(status) = *lock(&state.refuse) {
        return stripe_error(status, "api_error");
    }
    if text("authorization").as_deref() != Some(&format!("Bearer {FAKE_SECRET_KEY}")) {
        return stripe_error(StatusCode::UNAUTHORIZED, "invalid_request_error");
    }
    if text("stripe-version").as_deref() != Some(STRIPE_API_VERSION) {
        return stripe_error(StatusCode::BAD_REQUEST, "invalid_request_error");
    }
    let segments: Vec<&str> = uri.path().trim_matches('/').split('/').collect();
    let next = || state.counter.fetch_add(1, Ordering::SeqCst) + 1;
    match (method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "customers"]) => {
            let key = text("idempotency-key").unwrap_or_else(|| format!("none-{}", next()));
            let mut customers = lock(&state.customers);
            let id = customers
                .entry(key)
                .or_insert_with(|| format!("cus_fake_{}", next()))
                .clone();
            let mut object = fixture(CUSTOMER);
            object["id"] = json!(id);
            object["email"] = form.get("email").map_or(Value::Null, |email| json!(email));
            object["metadata"] = json!({ "user_id": form.get("metadata[user_id]") });
            axum::Json(object).into_response()
        }
        ("POST", ["v1", "checkout", "sessions"]) => {
            // The sandbox refuses Stripe Tax for a customer with no address unless Checkout
            // may save the address it collects: "Automatic tax calculation in Checkout
            // requires a valid address on the Customer ...". The fake's customers have none.
            if form.get("automatic_tax[enabled]").map(String::as_str) == Some("true")
                && form.get("customer_update[address]").map(String::as_str) != Some("auto")
            {
                return stripe_error(StatusCode::BAD_REQUEST, "invalid_request_error");
            }
            let managed = form.get("managed_payments[enabled]").map(String::as_str) == Some("true");
            let mut object = fixture(if managed {
                SESSION_MANAGED
            } else {
                SESSION_AUTOMATIC
            });
            let id = format!("cs_test_fake_{}", next());
            object["id"] = json!(id);
            object["url"] = json!(format!("https://checkout.stripe.test/c/pay/{id}"));
            object["customer"] = form.get("customer").map_or(Value::Null, |v| json!(v));
            object["client_reference_id"] = form
                .get("client_reference_id")
                .map_or(Value::Null, |v| json!(v));
            object["success_url"] = form.get("success_url").map_or(Value::Null, |v| json!(v));
            object["cancel_url"] = form.get("cancel_url").map_or(Value::Null, |v| json!(v));
            *lock(&state.last_session) = Some(id.clone());
            lock(&state.sessions).insert(id, object.clone());
            axum::Json(object).into_response()
        }
        ("GET", ["v1", "checkout", "sessions", id]) => match lock(&state.sessions).get(*id) {
            Some(object) => axum::Json(object.clone()).into_response(),
            None => stripe_error(StatusCode::NOT_FOUND, "invalid_request_error"),
        },
        ("POST", ["v1", "billing_portal", "sessions"]) => {
            let id = format!("bps_fake_{}", next());
            // Stripe's documented shape; the sandbox task did not capture a portal session.
            axum::Json(json!({
                "id": id,
                "object": "billing_portal.session",
                "customer": form.get("customer"),
                "return_url": form.get("return_url"),
                "url": format!("https://billing.stripe.test/p/session/{id}"),
            }))
            .into_response()
        }
        ("GET", ["v1", "subscriptions", id]) => match lock(&state.subscriptions).get(*id) {
            Some(object) => axum::Json(object.clone()).into_response(),
            None => stripe_error(StatusCode::NOT_FOUND, "invalid_request_error"),
        },
        ("GET", ["v1", "subscriptions"]) => list_subscriptions(&state, &uri),
        ("DELETE", ["v1", "subscriptions", id]) => cancel_subscription(&state, id),
        _ => stripe_error(StatusCode::NOT_FOUND, "invalid_request_error"),
    }
}

/// `DELETE /v1/subscriptions/{id}`.
fn cancel_subscription(state: &FakeState, id: &str) -> Response {
    if let Some(status) = lock(&state.refuse_cancel).get(id) {
        return stripe_error(*status, "api_error");
    }
    match lock(&state.subscriptions).get_mut(id) {
        // Real Stripe (sandbox, 2026-11-18) answers a DELETE on an already-canceled
        // subscription with 404 and code `resource_missing`, though a GET still finds it.
        Some(object) if object["status"] == "canceled" => {
            stripe_error(StatusCode::NOT_FOUND, "invalid_request_error")
        }
        Some(object) => {
            object["status"] = json!("canceled");
            axum::Json(object.clone()).into_response()
        }
        None => stripe_error(StatusCode::NOT_FOUND, "invalid_request_error"),
    }
}

/// `GET /v1/subscriptions`. Like Stripe, it takes `customer` and `status` (`all` includes
/// ended subscriptions; no status leaves them out).
fn list_subscriptions(state: &FakeState, uri: &Uri) -> Response {
    let query: HashMap<String, String> = uri.query().map_or_default(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect()
    });
    let mut found: Vec<(String, Value)> = lock(&state.subscriptions)
        .iter()
        .filter(|(_, object)| {
            query
                .get("customer")
                .is_none_or(|customer| object["customer"] == json!(customer))
                && match query.get("status").map(String::as_str) {
                    Some("all") => true,
                    Some(status) => object["status"] == json!(status),
                    None => object["status"] != "canceled",
                }
        })
        .map(|(id, object)| (id.clone(), object.clone()))
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    let mut list = fixture(SUBSCRIPTION_LIST);
    list["data"] = Value::Array(found.into_iter().map(|(_, object)| object).collect());
    axum::Json(list).into_response()
}

/// The `Stripe-Signature` header value for `body` at `timestamp`, signed with `secret`.
#[must_use]
pub fn sign(secret: &str, timestamp: u64, body: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, format!("{timestamp}.{body}").as_bytes());
    let hex = crate::identity::apple::hex(tag.as_ref());
    format!("t={timestamp},v1={hex}")
}
