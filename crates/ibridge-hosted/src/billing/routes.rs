// SPDX-License-Identifier: Apache-2.0

//! `/billing/*`: the webhook, and the pages that send a person to Stripe and back.
//!
//! The routes exist only when the billing settings are present.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use secrecy::ExposeSecret;
use serde::Deserialize;

use super::stripe::BillingError;
use super::{Access, Plan, access, webhook};
use crate::oauth::pending::PENDING_COOKIE;
use crate::oauth::{Peer, Shared};
use crate::pages::account::{Session, checked_session, session_of};
use crate::store::{User, UserId};
use crate::web::{cookie_value, message, see_other};

/// The largest event body read. Stripe's events are a few kilobytes.
const MAX_EVENT: usize = 256 * 1024;

pub(crate) fn routes(shared: &Arc<Shared>) -> Router {
    if shared.billing.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/billing/checkout", post(checkout))
        .route("/billing/return", get(back))
        .route("/billing/portal", post(portal))
        .route("/billing/webhook", post(receive))
        .layer(DefaultBodyLimit::max(MAX_EVENT))
        .with_state(Arc::clone(shared))
}

const EXPIRED: &str = "Go to your account page and sign in again.";
const STRIPE_TROUBLE: &str = "We could not reach our payment provider. Try again in a moment.";

#[derive(Deserialize)]
struct CheckoutForm {
    #[serde(default)]
    csrf: String,
    plan: String,
    pending: Option<String>,
}

#[derive(Deserialize)]
struct PortalForm {
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
struct Back {
    session_id: Option<String>,
    pending: Option<String>,
}

fn too_many() -> Response {
    message(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests",
        "Wait a minute, then try again.",
    )
}

fn expired() -> Response {
    message(StatusCode::FORBIDDEN, "This page expired", EXPIRED)
}

/// The signed-in user behind a request, or the page to answer with.
async fn user_of(shared: &Shared, session: Option<Session>) -> Result<User, Box<Response>> {
    let Some(id) = session.and_then(|session| session.principal.user()) else {
        return Err(Box::new(expired()));
    };
    match shared.store.user(id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(Box::new(expired())),
        Err(error) => {
            tracing::error!(%error, "could not read a signed-in user");
            Err(Box::new(message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Something went wrong on our side. Try again in a moment.",
            )))
        }
    }
}

/// The pending `/authorize` id the request names, when this browser stored it.
///
/// `Ok(None)` when none is named; the refusal page when one is named that this browser
/// did not store (or that expired), so another person's request is never resumed or leaked.
fn owned_pending(
    shared: &Shared,
    headers: &HeaderMap,
    named: Option<&str>,
) -> Result<Option<String>, Box<Response>> {
    let Some(id) = named.filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let owned = cookie_value(headers, PENDING_COOKIE)
        .and_then(|owner| shared.pending_authorize.get(id, owner, Instant::now()))
        .is_some();
    if owned {
        Ok(Some(id.to_owned()))
    } else {
        Err(Box::new(message(
            StatusCode::FORBIDDEN,
            "This page expired",
            "This page expired. Go back to the app and start the sign-in again.",
        )))
    }
}

fn encoded(id: &str) -> String {
    url::form_urlencoded::byte_serialize(id.as_bytes()).collect()
}

/// Sends a signed-in user without a plan to Stripe Checkout.
async fn checkout(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<CheckoutForm>,
) -> Response {
    let Some(billing) = shared.billing.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return too_many();
    }
    let session = checked_session(&shared, &headers, &form.csrf).map(|(_, session)| session);
    let user = match user_of(&shared, session).await {
        Ok(user) => user,
        Err(page) => return *page,
    };
    if access(&user) == Access::Allowed {
        return message(
            StatusCode::CONFLICT,
            "You already have a plan",
            "Your plan is active. Open your account page to manage it.",
        );
    }
    // Nobody pays for a service they cannot join, whichever page the button was on.
    match super::room_for(&shared, &user).await {
        Ok(room) => {
            if let Some((title, text)) = room.refusal() {
                return message(StatusCode::SERVICE_UNAVAILABLE, title, text);
            }
        }
        Err(error) => {
            tracing::error!(user = %user.id, %error, "could not count accounts");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Something went wrong on our side. Try again in a moment.",
            );
        }
    }
    let Some(plan) = Plan::from_form(form.plan.trim()) else {
        return message(
            StatusCode::BAD_REQUEST,
            "Choose a plan",
            "Go back and choose monthly or yearly.",
        );
    };
    let pending = match owned_pending(&shared, &headers, form.pending.as_deref()) {
        Ok(pending) => pending,
        Err(page) => return *page,
    };
    // The customer is made, and stored, before the session, so a person who pays has one
    // we know even if the return page is never reached.
    let customer = match billing.stripe.ensure_customer(&user).await {
        Ok(customer) => customer,
        Err(error) => return stripe_failed(user.id, error),
    };
    if user.stripe_customer.is_none()
        && let Err(error) = shared.store.set_customer(user.id, &customer).await
    {
        tracing::error!(user = %user.id, %error, "could not store a Stripe customer");
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Something went wrong on our side. Try again in a moment.",
        );
    }
    let user = User {
        stripe_customer: Some(customer),
        ..user
    };
    let (success, cancel) = match &pending {
        Some(id) => (
            shared.config.url(&format!(
                "/billing/return?session_id={{CHECKOUT_SESSION_ID}}&pending={}",
                encoded(id)
            )),
            shared
                .config
                .url(&format!("/authorize/resume?pending={}", encoded(id))),
        ),
        None => (
            shared
                .config
                .url("/billing/return?session_id={CHECKOUT_SESSION_ID}"),
            shared.config.url("/account"),
        ),
    };
    match billing
        .stripe
        .checkout(&user, plan, &success, &cancel)
        .await
    {
        Ok(url) => see_other(&url),
        Err(error) => stripe_failed(user.id, error),
    }
}

fn stripe_failed(user: UserId, error: BillingError) -> Response {
    tracing::error!(%user, %error, "a Stripe call failed");
    message(
        StatusCode::BAD_GATEWAY,
        "Payment is not available",
        STRIPE_TROUBLE,
    )
}

/// Where Stripe sends the person after paying: reads the Checkout Session from Stripe,
/// stores the subscription it made, and goes on. It does not wait for the webhook.
async fn back(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Query(query): Query<Back>,
) -> Response {
    let Some(billing) = shared.billing.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return too_many();
    }
    let session = session_of(&shared, &headers).map(|(_, session)| session);
    let user = match user_of(&shared, session).await {
        Ok(user) => user,
        Err(page) => return *page,
    };
    // Local checks first: nothing is asked of Stripe for a request that is not this
    // browser's own.
    let pending = match owned_pending(&shared, &headers, query.pending.as_deref()) {
        Ok(pending) => pending,
        Err(page) => return *page,
    };
    let Some(session_id) = query.session_id.as_deref().filter(|id| !id.is_empty()) else {
        return not_valid();
    };
    let checkout = match billing.stripe.checkout_session(session_id).await {
        Ok(checkout) => checkout,
        Err(BillingError::BadId) => return not_valid(),
        Err(error) => return stripe_failed(user.id, error),
    };
    let mine = user.stripe_customer.is_some()
        && checkout.customer == user.stripe_customer
        && checkout.client_reference_id.as_deref() == Some(user.id.get().to_string().as_str());
    if !mine {
        tracing::warn!(user = %user.id, "a checkout return named another customer's session");
        return message(
            StatusCode::FORBIDDEN,
            "Cannot confirm this payment",
            "This payment does not belong to your account.",
        );
    }
    let Some(subscription) = checkout.subscription else {
        return message(
            StatusCode::BAD_REQUEST,
            "Payment not finished",
            "Your payment was not completed. Go back and try again.",
        );
    };
    let fetched = match billing.stripe.subscription(&subscription).await {
        Ok(fetched) => fetched,
        Err(error) => return stripe_failed(user.id, error),
    };
    match webhook::adopt(&shared.store, &user, &fetched).await {
        Ok(applied) => {
            tracing::info!(user = %user.id, status = %fetched.status, ?applied, "checkout return");
        }
        Err(error) => {
            tracing::error!(user = %user.id, %error, "could not store a subscription");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Something went wrong on our side. Try again in a moment.",
            );
        }
    }
    match pending {
        Some(id) => see_other(&format!("/authorize/resume?pending={}", encoded(&id))),
        None => see_other("/account"),
    }
}

fn not_valid() -> Response {
    message(
        StatusCode::BAD_REQUEST,
        "Cannot confirm this payment",
        "This payment link is not valid. Open your account page to see your plan.",
    )
}

/// Sends a user with a Stripe customer to the Customer Portal.
async fn portal(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<PortalForm>,
) -> Response {
    let Some(billing) = shared.billing.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return too_many();
    }
    let session = checked_session(&shared, &headers, &form.csrf).map(|(_, session)| session);
    let user = match user_of(&shared, session).await {
        Ok(user) => user,
        Err(page) => return *page,
    };
    let Some(customer) = user.stripe_customer.as_deref() else {
        return message(
            StatusCode::BAD_REQUEST,
            "No billing yet",
            "You have no subscription to manage yet.",
        );
    };
    match billing
        .stripe
        .portal(customer, &shared.config.url("/account"))
        .await
    {
        Ok(url) => see_other(&url),
        Err(error) => stripe_failed(user.id, error),
    }
}

/// Stripe's webhook. The answer says only whether to send the event again.
async fn receive(State(shared): State<Arc<Shared>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let Some(billing) = shared.billing.as_ref() else {
        return StatusCode::NOT_FOUND;
    };
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::BAD_REQUEST;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let event = match webhook::verify(
        signature,
        &body,
        billing.webhook_secret.expose_secret(),
        now,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(%error, "a Stripe webhook was refused");
            return StatusCode::BAD_REQUEST;
        }
    };
    match shared.store.event_seen(&event.id).await {
        Ok(false) => {}
        Ok(true) => return StatusCode::OK,
        Err(error) => {
            tracing::error!(%error, event = %event.id, "could not look up a Stripe event");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    match webhook::apply(&shared.store, &billing.stripe, &event).await {
        Ok(applied) => {
            tracing::info!(event = %event.id, kind = %event.kind, ?applied, "a Stripe event was handled");
            // Only a handled event is remembered, so a failed one is tried again when Stripe
            // resends it. Handling is idempotent, so two deliveries at once do no harm.
            match shared.store.record_event(&event.id).await {
                Ok(()) => StatusCode::OK,
                Err(error) => {
                    tracing::error!(%error, event = %event.id, "could not record a Stripe event");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }
        Err(error) => {
            tracing::error!(%error, event = %event.id, kind = %event.kind, "could not handle a Stripe event");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use secrecy::SecretString;
    use serde_json::Value;

    use crate::billing::fakes::{FAKE_SECRET_KEY, FakeStripe, sign};
    use crate::billing::{Billing, BillingConfig, TaxMode};
    use crate::identity::Identity;
    use crate::identity::fakes::{FakeApple, FakeFirebase, identity_config};
    use crate::oauth::Shared;
    use crate::oauth::authorize::Params;
    use crate::oauth::pending::PENDING_COOKIE;
    use crate::oauth::test_support::{
        CLIENT_ID, Harness, PUBLIC, Reply, harness_billing, harness_with_shared,
    };
    use crate::pages::account::{Principal, SESSION_COOKIE};
    use crate::store::{Store, User};

    const WEBHOOK_SECRET: &str = "whsec_route_tests";
    const IP: &str = "198.51.100.7";
    const PAID: &str = include_str!("fixtures/invoice.paid-1.json");
    const FAILED: &str = include_str!("fixtures/invoice.payment_failed-1.json");
    const UPDATED: &str = include_str!("fixtures/customer.subscription.updated-4-past_due.json");
    const DELETED: &str = include_str!("fixtures/customer.subscription.deleted.json");
    const COMPLETED: &str =
        include_str!("fixtures/checkout.session.completed-subscription-nomp.json");

    /// The sandbox customer and subscription the captured invoice and subscription events name.
    const CUSTOMER: &str = "cus_VeNbiflBa3F0jq";
    const SUBSCRIPTION: &str = "sub_1Ud4qLK0opCePIM6sx1ITyi7";
    /// The customer and subscription of the captured Checkout Session event.
    const SESSION_CUSTOMER: &str = "cus_VeNd2iTJjtIABu";
    const SESSION_SUBSCRIPTION: &str = "sub_1Ud4s4K0opCePIM622SSRzig";

    fn billing_config() -> BillingConfig {
        BillingConfig {
            secret_key: SecretString::from(FAKE_SECRET_KEY),
            webhook_secret: SecretString::from(WEBHOOK_SECRET),
            price_monthly: "price_month".to_owned(),
            price_yearly: "price_year".to_owned(),
            tax: TaxMode::Managed,
        }
    }

    pub(crate) struct Rig {
        pub(crate) harness: Harness,
        pub(crate) shared: Arc<Shared>,
        pub(crate) stripe: FakeStripe,
        pub(crate) user: User,
        _apple: FakeApple,
        _firebase: FakeFirebase,
    }

    pub(crate) async fn rig() -> Rig {
        let apple = FakeApple::start().await;
        let firebase = FakeFirebase::start("ibridge-fyi", "test-api-key").await;
        let identity = Identity::with_bases(
            &identity_config("ibridge-fyi"),
            PUBLIC,
            apple.base(),
            firebase.base(),
        )
        .expect("identity");
        let stripe = FakeStripe::start().await;
        let billing = Billing::with_base(&billing_config(), stripe.base()).expect("billing");
        let store = Store::memory().await.expect("store");
        let user = store
            .upsert_user("uid-1", "sub-1", Some("ada@privaterelay.appleid.com"))
            .await
            .expect("user");
        store
            .set_customer(user.id, CUSTOMER)
            .await
            .expect("customer");
        let user = store.user(user.id).await.expect("read").expect("user");
        let (harness, shared) = harness_billing(identity, billing, store).await;
        Rig {
            harness,
            shared,
            stripe,
            user,
            _apple: apple,
            _firebase: firebase,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    impl Rig {
        /// Posts `body` with a signature made at `at` under `secret`.
        async fn deliver_as(&self, body: &str, secret: &str, at: u64) -> Reply {
            let request = Request::post("/billing/webhook")
                .header("stripe-signature", sign(secret, at, body))
                .body(Body::from(body.to_owned()))
                .expect("request");
            self.harness.send(request, IP).await
        }

        async fn deliver(&self, body: &str) -> Reply {
            self.deliver_as(body, WEBHOOK_SECRET, now()).await
        }

        async fn stored(&self) -> User {
            self.harness
                .store
                .user(self.user.id)
                .await
                .expect("read")
                .expect("user")
        }
    }

    /// `event` with its id replaced, so a fixture can be delivered as a new event.
    fn with_id(event: &str, id: &str) -> String {
        let mut value: Value = serde_json::from_str(event).expect("json");
        value["id"] = Value::String(id.to_owned());
        value.to_string()
    }

    #[tokio::test]
    async fn webhook_bad_signature_changes_nothing_and_is_refused() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_000);
        let forged = rig.deliver_as(PAID, "whsec_not_the_secret", now()).await;
        assert_eq!(forged.status, StatusCode::BAD_REQUEST, "{}", forged.text);
        let stale = rig.deliver_as(PAID, WEBHOOK_SECRET, now() - 301).await;
        assert_eq!(stale.status, StatusCode::BAD_REQUEST, "{}", stale.text);
        let unsigned = rig
            .harness
            .send(
                Request::post("/billing/webhook")
                    .body(Body::from(PAID))
                    .expect("request"),
                IP,
            )
            .await;
        assert_eq!(unsigned.status, StatusCode::BAD_REQUEST);
        assert_eq!(rig.stored().await.status, None, "nothing was stored");
        assert!(
            rig.stripe.requests().is_empty(),
            "Stripe was not asked about a refused event"
        );
    }

    #[tokio::test]
    async fn invoice_paid_and_payment_failed_take_subscription_from_invoice() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_111);
        for (event, id) in [(PAID, "evt_paid"), (FAILED, "evt_failed")] {
            let reply = rig.deliver(&with_id(event, id)).await;
            assert_eq!(reply.status, StatusCode::OK, "{id}: {}", reply.text);
            let asked: Vec<String> = rig
                .stripe
                .requests()
                .iter()
                .map(|r| r.path.clone())
                .collect();
            assert_eq!(
                asked.last().map(String::as_str),
                Some(format!("/v1/subscriptions/{SUBSCRIPTION}").as_str()),
                "{id}: the subscription id comes from parent.subscription_details, not the invoice id: {asked:?}"
            );
        }
        let user = rig.stored().await;
        assert_eq!(user.stripe_subscription.as_deref(), Some(SUBSCRIPTION));
        assert_eq!(user.status.as_deref(), Some("active"));
        assert_eq!(
            user.period_end,
            Some(1_900_000_111),
            "from the subscription item"
        );
    }

    #[tokio::test]
    async fn subscription_updated_and_deleted_take_own_id() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "past_due", 1_900_000_222);
        let reply = rig.deliver(UPDATED).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        assert_eq!(rig.stored().await.status.as_deref(), Some("past_due"));
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "canceled", 1_900_000_222);
        let reply = rig.deliver(DELETED).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let user = rig.stored().await;
        assert_eq!(user.status.as_deref(), Some("canceled"));
        assert_eq!(user.stripe_subscription.as_deref(), Some(SUBSCRIPTION));
    }

    #[tokio::test]
    async fn checkout_session_completed_takes_subscription_from_session() {
        let rig = rig().await;
        // The captured session belongs to another customer, so this user is that customer's.
        rig.harness
            .store
            .set_customer(rig.user.id, SESSION_CUSTOMER)
            .await
            .expect("customer");
        rig.stripe.put_subscription(
            SESSION_SUBSCRIPTION,
            SESSION_CUSTOMER,
            "active",
            1_900_000_333,
        );
        let reply = rig.deliver(COMPLETED).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let user = rig.stored().await;
        assert_eq!(
            user.stripe_subscription.as_deref(),
            Some(SESSION_SUBSCRIPTION)
        );
        assert_eq!(user.status.as_deref(), Some("active"));
        assert_eq!(user.period_end, Some(1_900_000_333));
    }

    #[tokio::test]
    async fn out_of_order_events_end_with_fetched_status() {
        let rig = rig().await;
        // Stripe now says the subscription is canceled. A late "updated" event, whose own
        // body says past_due, arrives after the "deleted" one: the stored status is Stripe's.
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "canceled", 1_900_000_222);
        assert_eq!(rig.deliver(DELETED).await.status, StatusCode::OK);
        assert_eq!(rig.deliver(UPDATED).await.status, StatusCode::OK);
        assert_eq!(rig.stored().await.status.as_deref(), Some("canceled"));
        // And the other way round: an event that says canceled cannot take away a live plan.
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_999);
        let reply = rig.deliver(&with_id(DELETED, "evt_late_deleted")).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        assert_eq!(rig.stored().await.status.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn duplicate_event_ignored() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_001);
        assert_eq!(rig.deliver(PAID).await.status, StatusCode::OK);
        let fetches = rig.stripe.requests().len();
        assert_eq!(fetches, 1, "the first delivery fetched the subscription");
        // Stripe changes the subscription, then redelivers the same event.
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "canceled", 1_900_000_002);
        let again = rig.deliver(PAID).await;
        assert_eq!(again.status, StatusCode::OK, "a duplicate is acknowledged");
        assert_eq!(
            rig.stripe.requests().len(),
            fetches,
            "and not handled again"
        );
        assert_eq!(rig.stored().await.status.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn a_failed_fetch_is_answered_with_an_error_and_the_retry_is_handled() {
        let rig = rig().await;
        rig.stripe.refuse_with(StatusCode::SERVICE_UNAVAILABLE);
        let reply = rig.deliver(PAID).await;
        assert_eq!(
            reply.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stripe should retry"
        );
        assert_eq!(rig.stored().await.status, None);
        rig.stripe.recover();
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_001);
        let retry = rig.deliver(PAID).await;
        assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
        assert_eq!(
            rig.stored().await.status.as_deref(),
            Some("active"),
            "the failed attempt did not use up the event id"
        );
    }

    #[tokio::test]
    async fn unknown_customer_acknowledged_and_ignored() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, "cus_nobody", "active", 1_900_000_001);
        let mut event: Value = serde_json::from_str(PAID).expect("json");
        event["data"]["object"]["customer"] = Value::String("cus_nobody".to_owned());
        let reply = rig.deliver(&event.to_string()).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "acknowledged so Stripe stops retrying"
        );
        assert_eq!(rig.stored().await.status, None, "no user changed");
        assert!(
            rig.stripe.requests().is_empty(),
            "nothing is fetched for a stranger"
        );
    }

    #[tokio::test]
    async fn a_user_is_found_by_metadata_when_the_customer_is_not_stored() {
        let rig = rig().await;
        let other = rig
            .harness
            .store
            .upsert_user("uid-2", "sub-2", None)
            .await
            .expect("user");
        rig.stripe
            .put_subscription(SUBSCRIPTION, "cus_new", "active", 1_900_000_001);
        let mut event: Value = serde_json::from_str(PAID).expect("json");
        event["data"]["object"]["customer"] = Value::String("cus_new".to_owned());
        event["data"]["object"]["parent"]["subscription_details"]["metadata"] =
            serde_json::json!({ "user_id": other.id.get().to_string() });
        let reply = rig.deliver(&event.to_string()).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let found = rig
            .harness
            .store
            .user(other.id)
            .await
            .expect("read")
            .expect("user");
        assert_eq!(found.status.as_deref(), Some("active"));
        assert_eq!(
            found.stripe_customer.as_deref(),
            Some("cus_new"),
            "the customer is now known"
        );
        assert_eq!(
            rig.stored().await.status,
            None,
            "the other user is untouched"
        );
    }

    #[tokio::test]
    async fn a_late_event_for_an_old_subscription_does_not_replace_the_current_one() {
        let rig = rig().await;
        rig.harness
            .store
            .set_subscription(rig.user.id, "sub_current", "active", Some(1_900_000_500))
            .await
            .expect("set");
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "canceled", 1_800_000_000);
        let reply = rig.deliver(DELETED).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let user = rig.stored().await;
        assert_eq!(user.stripe_subscription.as_deref(), Some("sub_current"));
        assert_eq!(user.status.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn a_stale_incomplete_fetch_does_not_replace_a_stored_paying_status() {
        // /billing/return already stored `active`; a slow webhook fetched the subscription
        // when it was still `incomplete`.
        let rig = rig().await;
        rig.harness
            .store
            .set_subscription(rig.user.id, SUBSCRIPTION, "active", Some(1_900_000_500))
            .await
            .expect("set");
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "incomplete", 1_800_000_000);
        let reply = rig.deliver(UPDATED).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let user = rig.stored().await;
        assert_eq!(user.status.as_deref(), Some("active"));
        assert_eq!(
            user.period_end,
            Some(1_900_000_500),
            "the period is kept too"
        );
    }

    #[tokio::test]
    async fn a_user_read_before_the_fetch_does_not_hide_a_newer_stored_status() {
        // The webhook read the user (no plan yet), then waited on Stripe; the return route
        // stored `active` in between. The decision is made on what is stored now.
        let rig = rig().await;
        let stale = rig.stored().await;
        rig.harness
            .store
            .set_subscription(rig.user.id, SUBSCRIPTION, "active", Some(1_900_000_500))
            .await
            .expect("set");
        let fetched = crate::billing::stripe::Subscription {
            id: SUBSCRIPTION.to_owned(),
            customer: CUSTOMER.to_owned(),
            status: "incomplete".to_owned(),
            period_end: Some(1_800_000_000),
        };
        crate::billing::webhook::adopt(&rig.harness.store, &stale, &fetched)
            .await
            .expect("adopt");
        assert_eq!(rig.stored().await.status.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn real_status_changes_still_replace_the_stored_one() {
        let rig = rig().await;
        let store = &rig.harness.store;
        store
            .set_subscription(rig.user.id, SUBSCRIPTION, "incomplete", None)
            .await
            .expect("set");
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_000);
        assert_eq!(rig.deliver(UPDATED).await.status, StatusCode::OK);
        assert_eq!(rig.stored().await.status.as_deref(), Some("active"));
        // Payment fails later: active becomes past_due, which is a real change.
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "past_due", 1_900_000_000);
        assert_eq!(
            rig.deliver(&with_id(UPDATED, "evt_later")).await.status,
            StatusCode::OK
        );
        assert_eq!(rig.stored().await.status.as_deref(), Some("past_due"));
    }

    #[tokio::test]
    async fn an_event_that_names_no_subscription_or_a_foreign_one_changes_nothing() {
        let rig = rig().await;
        rig.stripe
            .put_subscription(SUBSCRIPTION, "cus_someone_else", "active", 1_900_000_001);
        // The fetched subscription belongs to another customer than the event's user.
        assert_eq!(rig.deliver(UPDATED).await.status, StatusCode::OK);
        assert_eq!(
            rig.stored().await.status,
            None,
            "a mismatched customer is not adopted"
        );
        let mut other: Value = serde_json::from_str(PAID).expect("json");
        other["id"] = Value::String("evt_other".to_owned());
        other["type"] = Value::String("invoice.created".to_owned());
        assert_eq!(rig.deliver(&other.to_string()).await.status, StatusCode::OK);
        let mut payment: Value = serde_json::from_str(PAID).expect("json");
        payment["id"] = Value::String("evt_no_sub".to_owned());
        payment["data"]["object"]["parent"] = Value::Null;
        assert_eq!(
            rig.deliver(&payment.to_string()).await.status,
            StatusCode::OK
        );
        assert_eq!(rig.stored().await.status, None);
    }

    #[tokio::test]
    async fn webhook_route_absent_when_billing_unset() {
        let (harness, _shared) = harness_with_shared().await;
        let request = Request::post("/billing/webhook")
            .header("stripe-signature", sign(WEBHOOK_SECRET, now(), "{}"))
            .body(Body::from("{}"))
            .expect("request");
        let reply = harness.send(request, IP).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
    }

    /// A signed-in browser: its cookies and the form token its session was given.
    struct Browser {
        cookie: String,
        csrf: String,
    }

    const OWNER: &str = "pending-owner-cookie-a";

    fn stored_params() -> Params {
        serde_json::from_value(serde_json::json!({ "client_id": CLIENT_ID, "state": "xyz" }))
            .expect("params")
    }

    impl Rig {
        fn browser(&self, user: &User, owner: Option<&str>) -> Browser {
            let (token, csrf) = self
                .shared
                .sessions
                .start(Principal::User(user.id), Instant::now())
                .expect("a session");
            let cookie = match owner {
                Some(owner) => format!("{SESSION_COOKIE}={token}; {PENDING_COOKIE}={owner}"),
                None => format!("{SESSION_COOKIE}={token}"),
            };
            Browser { cookie, csrf }
        }

        fn pending(&self, owner: &str) -> String {
            self.shared
                .pending_authorize
                .put(stored_params(), owner, Instant::now())
                .expect("stored")
        }

        async fn post(
            &self,
            path: &str,
            browser: Option<&Browser>,
            fields: &[(&str, &str)],
        ) -> Reply {
            let mut all: Vec<(&str, &str)> = Vec::new();
            if let Some(browser) = browser {
                all.push(("csrf", browser.csrf.as_str()));
            }
            all.extend_from_slice(fields);
            self.harness
                .post_path(
                    path,
                    IP,
                    browser.map(|browser| browser.cookie.as_str()),
                    &all,
                )
                .await
        }

        async fn get(&self, path: &str, browser: Option<&Browser>) -> Reply {
            self.harness
                .get_path(path, IP, browser.map(|browser| browser.cookie.as_str()))
                .await
        }

        /// A second user with their own Stripe customer.
        async fn other_user(&self) -> User {
            let other = self
                .harness
                .store
                .upsert_user("uid-2", "sub-2", None)
                .await
                .expect("user");
            self.harness
                .store
                .set_customer(other.id, "cus_other")
                .await
                .expect("customer");
            self.harness
                .store
                .user(other.id)
                .await
                .expect("read")
                .expect("user")
        }
    }

    fn location(reply: &Reply) -> String {
        reply
            .headers
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("a Location header on {}: {}", reply.status, reply.text))
            .to_owned()
    }

    #[tokio::test]
    async fn checkout_refused_when_access_already_allowed() {
        let rig = rig().await;
        for (status, complimentary) in [
            (Some("active"), false),
            (Some("past_due"), false),
            (None, true),
        ] {
            if let Some(status) = status {
                rig.harness
                    .store
                    .set_subscription(rig.user.id, "sub_1", status, Some(1))
                    .await
                    .expect("set");
            }
            rig.harness
                .store
                .set_complimentary(rig.user.id, complimentary)
                .await
                .expect("set");
            let browser = rig.browser(&rig.user, None);
            let reply = rig
                .post("/billing/checkout", Some(&browser), &[("plan", "monthly")])
                .await;
            assert_eq!(
                reply.status,
                StatusCode::CONFLICT,
                "{status:?}/{complimentary}: {}",
                reply.text
            );
        }
        assert!(
            rig.stripe.requests().is_empty(),
            "nothing was created at Stripe"
        );
    }

    #[tokio::test]
    async fn checkout_creates_customer_then_session_and_redirects() {
        let rig = rig().await;
        let fresh = rig
            .harness
            .store
            .upsert_user("uid-9", "sub-9", Some("eve@example.com"))
            .await
            .expect("user");
        assert_eq!(fresh.stripe_customer, None);
        let pending = rig.pending(OWNER);
        let browser = rig.browser(&fresh, Some(OWNER));
        let reply = rig
            .post(
                "/billing/checkout",
                Some(&browser),
                &[("plan", "yearly"), ("pending", pending.as_str())],
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        let session = rig.stripe.last_session().expect("a session");
        assert_eq!(
            location(&reply),
            format!("https://checkout.stripe.test/c/pay/{session}")
        );

        let order: Vec<String> = rig
            .stripe
            .requests()
            .iter()
            .map(|request| format!("{} {}", request.method, request.path))
            .collect();
        assert_eq!(
            order,
            ["POST /v1/customers", "POST /v1/checkout/sessions"],
            "customer first"
        );
        let stored = rig
            .harness
            .store
            .user(fresh.id)
            .await
            .expect("read")
            .expect("user");
        let customer = stored
            .stripe_customer
            .clone()
            .expect("the customer id was stored");
        let sent = &rig.stripe.requests_to("POST", "/v1/checkout/sessions")[0];
        assert_eq!(sent.field("customer"), Some(customer.as_str()));
        assert_eq!(sent.field("line_items[0][price]"), Some("price_year"));
        assert_eq!(
            sent.field("success_url").map(str::to_owned),
            Some(format!(
                "{PUBLIC}/billing/return?session_id={{CHECKOUT_SESSION_ID}}&pending={pending}"
            ))
        );
        assert_eq!(
            sent.field("cancel_url").map(str::to_owned),
            Some(format!("{PUBLIC}/authorize/resume?pending={pending}"))
        );

        // Without a pending request the person comes back to the account page.
        let plain = rig.browser(&stored, None);
        let reply = rig
            .post("/billing/checkout", Some(&plain), &[("plan", "monthly")])
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        let second = &rig.stripe.requests_to("POST", "/v1/checkout/sessions")[1];
        assert_eq!(
            second.field("cancel_url"),
            Some(format!("{PUBLIC}/account").as_str())
        );
        assert_eq!(
            second.field("success_url").map(str::to_owned),
            Some(format!(
                "{PUBLIC}/billing/return?session_id={{CHECKOUT_SESSION_ID}}"
            ))
        );
        assert_eq!(
            rig.stripe.requests_to("POST", "/v1/customers").len(),
            1,
            "the customer is made once"
        );
    }

    #[tokio::test]
    async fn checkout_requires_session_and_csrf() {
        let rig = rig().await;
        let browser = rig.browser(&rig.user, None);
        let forged = Browser {
            cookie: browser.cookie.clone(),
            csrf: "forged".to_owned(),
        };
        let no_session = Browser {
            cookie: "unrelated=1".to_owned(),
            csrf: browser.csrf.clone(),
        };
        for (what, browser) in [
            ("forged csrf", Some(&forged)),
            ("no session", Some(&no_session)),
            ("no cookie", None),
        ] {
            let reply = rig
                .post("/billing/checkout", browser, &[("plan", "monthly")])
                .await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "{what}: {}",
                reply.text
            );
        }
        let portal = rig.post("/billing/portal", Some(&forged), &[]).await;
        assert_eq!(portal.status, StatusCode::FORBIDDEN, "{}", portal.text);
        // A GET never starts a checkout.
        assert_eq!(
            rig.get("/billing/checkout", Some(&browser)).await.status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // A password session has no user to bill.
        let (token, csrf) = rig
            .shared
            .sessions
            .start(
                Principal::Password("ada@icloud.com".try_into().expect("address")),
                Instant::now(),
            )
            .expect("session");
        let password = Browser {
            cookie: format!("{SESSION_COOKIE}={token}"),
            csrf,
        };
        let reply = rig
            .post("/billing/checkout", Some(&password), &[("plan", "monthly")])
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text);
        assert!(rig.stripe.requests().is_empty());
    }

    #[tokio::test]
    async fn checkout_refuses_an_unknown_plan_and_a_pending_id_it_does_not_own() {
        let rig = rig().await;
        let pending = rig.pending("someone-elses-owner-cookie");
        let browser = rig.browser(&rig.user, Some(OWNER));
        let unknown = rig
            .post("/billing/checkout", Some(&browser), &[("plan", "lifetime")])
            .await;
        assert_eq!(unknown.status, StatusCode::BAD_REQUEST, "{}", unknown.text);
        let foreign = rig
            .post(
                "/billing/checkout",
                Some(&browser),
                &[("plan", "monthly"), ("pending", pending.as_str())],
            )
            .await;
        assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.text);
        let missing = rig
            .post(
                "/billing/checkout",
                Some(&browser),
                &[("plan", "monthly"), ("pending", "nope")],
            )
            .await;
        assert_eq!(missing.status, StatusCode::FORBIDDEN, "{}", missing.text);
        assert!(
            rig.stripe.requests().is_empty(),
            "a refused checkout creates nothing at Stripe"
        );
    }

    #[tokio::test]
    async fn checkout_failure_at_stripe_is_a_page_not_a_crash() {
        let rig = rig().await;
        rig.stripe.refuse_with(StatusCode::SERVICE_UNAVAILABLE);
        let browser = rig.browser(&rig.user, None);
        let reply = rig
            .post("/billing/checkout", Some(&browser), &[("plan", "monthly")])
            .await;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.text);
        assert!(!reply.text.contains("sk_"), "no key in the page");
    }

    /// Starts a checkout as `user` and returns the Checkout Session id.
    async fn started(rig: &Rig, user: &User, owner: Option<&str>, pending: Option<&str>) -> String {
        let browser = rig.browser(user, owner);
        let mut fields = vec![("plan", "monthly")];
        if let Some(pending) = pending {
            fields.push(("pending", pending));
        }
        let reply = rig.post("/billing/checkout", Some(&browser), &fields).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        rig.stripe.last_session().expect("a session")
    }

    #[tokio::test]
    async fn return_reads_session_stores_status_and_resumes_pending_authorize() {
        let rig = rig().await;
        let pending = rig.pending(OWNER);
        let session = started(&rig, &rig.user, Some(OWNER), Some(&pending)).await;
        // The person pays; no webhook is delivered.
        rig.stripe.complete_session(&session, SUBSCRIPTION);
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_444);
        let browser = rig.browser(&rig.user, Some(OWNER));
        let reply = rig
            .get(
                &format!("/billing/return?session_id={session}&pending={pending}"),
                Some(&browser),
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert_eq!(
            location(&reply),
            format!("/authorize/resume?pending={pending}")
        );
        let user = rig.stored().await;
        assert_eq!(user.status.as_deref(), Some("active"));
        assert_eq!(user.stripe_subscription.as_deref(), Some(SUBSCRIPTION));
        assert_eq!(user.period_end, Some(1_900_000_444));

        // Without a pending request it goes to the account page.
        let plain = rig
            .get(
                &format!("/billing/return?session_id={session}"),
                Some(&browser),
            )
            .await;
        assert_eq!(plain.status, StatusCode::SEE_OTHER, "{}", plain.text);
        assert_eq!(location(&plain), "/account");
    }

    #[tokio::test]
    async fn return_before_payment_stores_nothing() {
        let rig = rig().await;
        let session = started(&rig, &rig.user, None, None).await;
        let browser = rig.browser(&rig.user, None);
        let reply = rig
            .get(
                &format!("/billing/return?session_id={session}"),
                Some(&browser),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text);
        assert_eq!(rig.stored().await.status, None);
        assert!(
            rig.stripe
                .requests_to("GET", &format!("/v1/subscriptions/{SUBSCRIPTION}"))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn return_session_of_other_customer_refused() {
        let rig = rig().await;
        let other = rig.other_user().await;
        let theirs = started(&rig, &other, None, None).await;
        rig.stripe.complete_session(&theirs, SUBSCRIPTION);
        rig.stripe
            .put_subscription(SUBSCRIPTION, "cus_other", "active", 1_900_000_444);
        let browser = rig.browser(&rig.user, None);
        let reply = rig
            .get(
                &format!("/billing/return?session_id={theirs}"),
                Some(&browser),
            )
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text);
        assert_eq!(
            rig.stored().await.status,
            None,
            "the signed-in user got nothing"
        );
        let owner = rig
            .harness
            .store
            .user(other.id)
            .await
            .expect("read")
            .expect("user");
        assert_eq!(
            owner.status, None,
            "and the session's owner was not changed by someone else"
        );
        assert!(
            rig.stripe
                .requests_to("GET", &format!("/v1/subscriptions/{SUBSCRIPTION}"))
                .is_empty(),
            "the subscription is not even fetched"
        );
    }

    #[tokio::test]
    async fn return_session_for_another_user_id_refused_even_with_the_right_customer() {
        let rig = rig().await;
        rig.stripe
            .put_session("cs_test_crafted", CUSTOMER, "999", SUBSCRIPTION);
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_444);
        let browser = rig.browser(&rig.user, None);
        let reply = rig
            .get("/billing/return?session_id=cs_test_crafted", Some(&browser))
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text);
        assert_eq!(rig.stored().await.status, None);
        // The same session for this user id is accepted.
        rig.stripe.put_session(
            "cs_test_mine",
            CUSTOMER,
            &rig.user.id.get().to_string(),
            SUBSCRIPTION,
        );
        let reply = rig
            .get("/billing/return?session_id=cs_test_mine", Some(&browser))
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert_eq!(rig.stored().await.status.as_deref(), Some("active"));
    }

    #[tokio::test]
    async fn return_pending_id_of_other_session_refused() {
        let rig = rig().await;
        let theirs = rig.pending("another-browsers-owner-cookie");
        let session = started(&rig, &rig.user, None, None).await;
        rig.stripe.complete_session(&session, SUBSCRIPTION);
        rig.stripe
            .put_subscription(SUBSCRIPTION, CUSTOMER, "active", 1_900_000_444);
        let calls = rig.stripe.requests().len();
        for owner in [Some(OWNER), None] {
            let browser = rig.browser(&rig.user, owner);
            let reply = rig
                .get(
                    &format!("/billing/return?session_id={session}&pending={theirs}"),
                    Some(&browser),
                )
                .await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "{owner:?}: {}",
                reply.text
            );
        }
        assert_eq!(rig.stored().await.status, None, "nothing was stored");
        assert_eq!(rig.stripe.requests().len(), calls, "Stripe was not asked");
    }

    #[tokio::test]
    async fn return_needs_a_signed_in_user_and_a_real_session_id() {
        let rig = rig().await;
        let anonymous = rig.get("/billing/return?session_id=cs_test_x", None).await;
        assert_eq!(
            anonymous.status,
            StatusCode::FORBIDDEN,
            "{}",
            anonymous.text
        );
        let browser = rig.browser(&rig.user, None);
        for bad in ["", "x/../y", "cs test"] {
            let encoded: String = url::form_urlencoded::byte_serialize(bad.as_bytes()).collect();
            let reply = rig
                .get(
                    &format!("/billing/return?session_id={encoded}"),
                    Some(&browser),
                )
                .await;
            assert_eq!(
                reply.status,
                StatusCode::BAD_REQUEST,
                "{bad:?}: {}",
                reply.text
            );
        }
        let missing = rig.get("/billing/return", Some(&browser)).await;
        assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.text);
        assert!(rig.stripe.requests().is_empty());
    }

    #[tokio::test]
    async fn portal_redirects_for_customer() {
        let rig = rig().await;
        let browser = rig.browser(&rig.user, None);
        let reply = rig.post("/billing/portal", Some(&browser), &[]).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert!(
            location(&reply).starts_with("https://billing.stripe.test/p/session/bps_"),
            "{}",
            location(&reply)
        );
        let sent = &rig
            .stripe
            .requests_to("POST", "/v1/billing_portal/sessions")[0];
        assert_eq!(sent.field("customer"), Some(CUSTOMER));
        assert_eq!(
            sent.field("return_url").map(str::to_owned),
            Some(format!("{PUBLIC}/account"))
        );
    }

    #[tokio::test]
    async fn portal_without_customer_refused() {
        let rig = rig().await;
        let fresh = rig
            .harness
            .store
            .upsert_user("uid-9", "sub-9", None)
            .await
            .expect("user");
        let browser = rig.browser(&fresh, None);
        let reply = rig.post("/billing/portal", Some(&browser), &[]).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text);
        assert!(
            rig.stripe.requests().is_empty(),
            "no customer is made just to open a portal"
        );
    }
}
