// SPDX-License-Identifier: Apache-2.0

//! `/billing/*`: the webhook, and the pages that send a person to Stripe and back.
//!
//! The routes exist only when the billing settings are present.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use secrecy::ExposeSecret;

use super::webhook;
use crate::oauth::Shared;

/// The largest event body read. Stripe's events are a few kilobytes.
const MAX_EVENT: usize = 256 * 1024;

pub(crate) fn routes(shared: &Arc<Shared>) -> Router {
    if shared.billing.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/billing/webhook", post(receive))
        .layer(DefaultBodyLimit::max(MAX_EVENT))
        .with_state(Arc::clone(shared))
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use secrecy::SecretString;
    use serde_json::Value;

    use crate::billing::fakes::{FAKE_SECRET_KEY, FakeStripe, sign};
    use crate::billing::{Billing, BillingConfig, TaxMode};
    use crate::identity::Identity;
    use crate::identity::fakes::{FakeApple, FakeFirebase, identity_config};
    use crate::oauth::test_support::{
        Harness, PUBLIC, Reply, harness_billing, harness_with_shared,
    };
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
        let (harness, _shared) = harness_billing(identity, billing, store).await;
        Rig {
            harness,
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
}
