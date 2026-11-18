// SPDX-License-Identifier: Apache-2.0

//! A small form-encoded Stripe client: customers, Checkout and portal sessions, subscriptions.
//!
//! Every request sends [`STRIPE_API_VERSION`], so Stripe answers in the shape the code was
//! written against whatever the account's default version becomes. Hosts are fixed in code;
//! ids that reach a path are checked first.

use bytes::Bytes;
use http::{HeaderValue, Method, Request, header};
use http_body_util::Full;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;

use super::{BillingConfig, Plan, TaxMode};
use crate::identity::http::Http;
use crate::store::User;

/// The Stripe API version every request pins, as recorded by the sandbox task.
pub const STRIPE_API_VERSION: &str = "2026-10-28.endive";

/// Why a Stripe call failed. The text is safe to log: it never holds a key or a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BillingError {
    /// Stripe could not be reached, or did not answer in time.
    #[error("Stripe could not be reached")]
    Unreachable,
    /// Stripe answered with an error status.
    #[error("Stripe refused the request (HTTP {0})")]
    Refused(u16),
    /// Stripe's reply was not the object that was asked for.
    #[error("Stripe sent an unexpected reply")]
    Malformed,
    /// The call needs a Stripe customer and the user has none yet.
    #[error("the user has no Stripe customer")]
    NoCustomer,
    /// An id is not shaped like a Stripe id, so it is not put in a URL.
    #[error("not a Stripe id")]
    BadId,
}

/// A subscription as Stripe reports it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The subscription id.
    pub id: String,
    /// The customer it belongs to.
    pub customer: String,
    /// Stripe's status, such as `active` or `past_due`.
    pub status: String,
    /// When the current period ends, as Unix seconds, read from the subscription item.
    pub period_end: Option<i64>,
}

/// A Checkout Session as Stripe reports it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSession {
    /// The customer the session was made for.
    pub customer: Option<String>,
    /// The subscription it created, once the person has paid.
    pub subscription: Option<String>,
    /// The ibridge user id the session was made for.
    pub client_reference_id: Option<String>,
}

/// Talks to `api.stripe.com`.
#[derive(Debug)]
pub struct Stripe {
    key: SecretString,
    price_monthly: String,
    price_yearly: String,
    tax: TaxMode,
    base: Url,
    http: Http,
}

impl Stripe {
    /// A client for the real Stripe.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Unreachable`] when the system's root certificates cannot be loaded.
    pub fn new(config: &BillingConfig) -> Result<Self, BillingError> {
        let base = Url::parse("https://api.stripe.com").map_err(|_| BillingError::Malformed)?;
        let http = Http::https().map_err(|_| BillingError::Unreachable)?;
        Ok(Self::build(config, base, http))
    }

    /// A client that talks to a fake on loopback.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Unreachable`] when the system's root certificates cannot be loaded.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_base(config: &BillingConfig, base: Url) -> Result<Self, BillingError> {
        let http = Http::loopback().map_err(|_| BillingError::Unreachable)?;
        Ok(Self::build(config, base, http))
    }

    fn build(config: &BillingConfig, base: Url, http: Http) -> Self {
        Self {
            key: config.secret_key.clone(),
            price_monthly: config.price_monthly.clone(),
            price_yearly: config.price_yearly.clone(),
            tax: config.tax,
            base,
            http,
        }
    }

    /// The user's Stripe customer id, creating the customer first when there is none.
    ///
    /// The call carries an idempotency key made from the user id, so two clicks at once
    /// make one customer. The caller stores the id.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] when Stripe cannot be reached or refuses.
    pub async fn ensure_customer(&self, user: &User) -> Result<String, BillingError> {
        if let Some(customer) = &user.stripe_customer {
            return Ok(customer.clone());
        }
        let id = user.id.get().to_string();
        let mut form = vec![("metadata[user_id]", id.as_str())];
        if let Some(email) = user.email.as_deref() {
            form.push(("email", email));
        }
        // ponytail: a repeat within Stripe's 24 hours with a changed email is refused as an
        // idempotency conflict; the person retries. Upgrade: look the customer up by metadata.
        let key = format!("ibridge-customer-{id}");
        let made: Created = self
            .call(Method::POST, "/v1/customers", &form, Some(&key))
            .await?;
        Ok(made.id)
    }

    /// Starts a Checkout Session for `plan` and returns the page's URL.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::NoCustomer`] when the user has no customer yet, and the
    /// other [`BillingError`]s when Stripe cannot be reached or refuses.
    pub async fn checkout(
        &self,
        user: &User,
        plan: Plan,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String, BillingError> {
        let customer = user
            .stripe_customer
            .as_deref()
            .ok_or(BillingError::NoCustomer)?;
        let price = match plan {
            Plan::Monthly => &self.price_monthly,
            Plan::Yearly => &self.price_yearly,
        };
        let id = user.id.get().to_string();
        let mut form = vec![
            ("mode", "subscription"),
            ("customer", customer),
            ("line_items[0][price]", price.as_str()),
            ("line_items[0][quantity]", "1"),
            ("client_reference_id", id.as_str()),
            ("subscription_data[metadata][user_id]", id.as_str()),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
        ];
        match self.tax {
            TaxMode::Managed => form.push(("managed_payments[enabled]", "true")),
            // Managed Payments is on by default on the account, so Stripe Tax needs it off.
            TaxMode::Automatic => {
                form.push(("managed_payments[enabled]", "false"));
                form.push(("automatic_tax[enabled]", "true"));
                // Stripe Tax needs an address, and a customer made here has none: let
                // Checkout save the address it collects (the sandbox refuses without it).
                form.push(("customer_update[address]", "auto"));
            }
        }
        let session: Hosted = self
            .call(Method::POST, "/v1/checkout/sessions", &form, None)
            .await?;
        Ok(session.url)
    }

    /// Starts a Customer Portal session and returns its URL.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] when Stripe cannot be reached or refuses.
    pub async fn portal(&self, customer: &str, return_url: &str) -> Result<String, BillingError> {
        let form = [("customer", customer), ("return_url", return_url)];
        let session: Hosted = self
            .call(Method::POST, "/v1/billing_portal/sessions", &form, None)
            .await?;
        Ok(session.url)
    }

    /// The subscription `id` as Stripe has it now.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::BadId`] for an id that is not shaped like one, and the other
    /// [`BillingError`]s when Stripe cannot be reached or refuses.
    pub async fn subscription(&self, id: &str) -> Result<Subscription, BillingError> {
        let path = format!("/v1/subscriptions/{}", checked_id(id)?);
        let raw: RawSubscription = self.call(Method::GET, &path, &[], None).await?;
        Ok(Subscription {
            id: raw.id,
            customer: raw.customer,
            status: raw.status,
            // The subscription has no period of its own; each item carries it.
            period_end: raw
                .items
                .data
                .first()
                .and_then(|item| item.current_period_end),
        })
    }

    /// The Checkout Session `id` as Stripe has it now.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::BadId`] for an id that is not shaped like one, and the other
    /// [`BillingError`]s when Stripe cannot be reached or refuses.
    pub async fn checkout_session(&self, id: &str) -> Result<CheckoutSession, BillingError> {
        let path = format!("/v1/checkout/sessions/{}", checked_id(id)?);
        let raw: RawSession = self.call(Method::GET, &path, &[], None).await?;
        Ok(CheckoutSession {
            customer: raw.customer,
            subscription: raw.subscription,
            client_reference_id: raw.client_reference_id,
        })
    }

    /// Cancels the subscription now, without waiting for the period to end.
    ///
    /// A subscription that is already canceled counts as done: Stripe answers that DELETE
    /// with 404 `resource_missing`, and the path is a checked id, so a 404 can mean nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::BadId`] for an id that is not shaped like one, and the other
    /// [`BillingError`]s when Stripe cannot be reached or refuses.
    pub async fn cancel_now(&self, subscription_id: &str) -> Result<(), BillingError> {
        let path = format!("/v1/subscriptions/{}", checked_id(subscription_id)?);
        match self
            .call::<IgnoredReply>(Method::DELETE, &path, &[], None)
            .await
        {
            Ok(_) | Err(BillingError::Refused(404)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// One call: pinned version, key, form body, reply parsed as `T`.
    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        form: &[(&str, &str)],
        idempotency: Option<&str>,
    ) -> Result<T, BillingError> {
        let mut url = self.base.clone();
        url.set_path(path);
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", self.key.expose_secret()))
                .map_err(|_| BillingError::Malformed)?;
        authorization.set_sensitive(true);
        let mut request = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(header::AUTHORIZATION, authorization)
            .header("stripe-version", STRIPE_API_VERSION)
            .header(header::ACCEPT, "application/json");
        if let Some(key) = idempotency {
            request = request.header("idempotency-key", key);
        }
        let body = if form.is_empty() {
            Bytes::new()
        } else {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Bytes::from(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            )
        };
        let request = request
            .body(Full::new(body))
            .map_err(|_| BillingError::Malformed)?;
        let reply = self
            .http
            .send(request)
            .await
            .map_err(|_| BillingError::Unreachable)?;
        if !reply.status.is_success() {
            return Err(BillingError::Refused(reply.status.as_u16()));
        }
        serde_json::from_slice(&reply.body).map_err(|_| BillingError::Malformed)
    }
}

/// `id` when it can only be one path segment: letters, digits and underscores.
fn checked_id(id: &str) -> Result<&str, BillingError> {
    let fine = !id.is_empty()
        && id.len() <= 255
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    fine.then_some(id).ok_or(BillingError::BadId)
}

#[derive(Deserialize)]
struct Created {
    id: String,
}

#[derive(Deserialize)]
struct Hosted {
    url: String,
}

/// A reply whose content nobody reads, but which must still be a JSON object.
#[derive(Debug, Deserialize)]
struct IgnoredReply {}

#[derive(Deserialize)]
struct RawSubscription {
    id: String,
    customer: String,
    status: String,
    items: RawItems,
}

#[derive(Deserialize)]
struct RawItems {
    data: Vec<RawItem>,
}

#[derive(Deserialize)]
struct RawItem {
    current_period_end: Option<i64>,
}

#[derive(Deserialize)]
struct RawSession {
    customer: Option<String>,
    subscription: Option<String>,
    client_reference_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{BillingError, STRIPE_API_VERSION, Stripe};
    use crate::billing::fakes::{FAKE_SECRET_KEY, FakeStripe};
    use crate::billing::{BillingConfig, Plan, TaxMode};
    use crate::store::{User, UserId};

    fn config(tax: TaxMode) -> BillingConfig {
        BillingConfig {
            secret_key: SecretString::from(FAKE_SECRET_KEY),
            webhook_secret: SecretString::from("whsec_unused"),
            price_monthly: "price_month".to_owned(),
            price_yearly: "price_year".to_owned(),
            tax,
        }
    }

    fn user(customer: Option<&str>) -> User {
        User {
            id: UserId::from_raw(7),
            firebase_uid: "uid-7".to_owned(),
            apple_sub: "sub-7".to_owned(),
            email: Some("ada@privaterelay.appleid.com".to_owned()),
            account: None,
            stripe_customer: customer.map(str::to_owned),
            stripe_subscription: None,
            status: None,
            period_end: None,
            complimentary: false,
        }
    }

    async fn client(tax: TaxMode) -> (Stripe, FakeStripe) {
        let fake = FakeStripe::start().await;
        let stripe = Stripe::with_base(&config(tax), fake.base()).expect("client");
        (stripe, fake)
    }

    #[tokio::test]
    async fn every_request_sends_pinned_stripe_version() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        fake.put_subscription("sub_1", "cus_1", "active", 1_900_000_000);
        let ada = user(None);
        let customer = stripe.ensure_customer(&ada).await.expect("customer");
        let with_customer = user(Some(&customer));
        let page = stripe
            .checkout(
                &with_customer,
                Plan::Monthly,
                "https://x.test/ok",
                "https://x.test/no",
            )
            .await
            .expect("checkout");
        assert!(page.starts_with("https://"), "{page}");
        let session = fake.last_session().expect("a session");
        stripe
            .portal(&customer, "https://x.test/account")
            .await
            .expect("portal");
        stripe.subscription("sub_1").await.expect("subscription");
        stripe.checkout_session(&session).await.expect("session");
        stripe.cancel_now("sub_1").await.expect("cancel");

        let seen = fake.requests();
        assert_eq!(seen.len(), 6, "one request per call: {seen:?}");
        for request in &seen {
            assert_eq!(
                request.version.as_deref(),
                Some(STRIPE_API_VERSION),
                "{} {}",
                request.method,
                request.path
            );
        }
        assert_eq!(
            STRIPE_API_VERSION, "2026-10-28.endive",
            "the version the sandbox task recorded"
        );
    }

    #[tokio::test]
    async fn a_wrong_key_is_refused_without_the_key_in_the_error() {
        let fake = FakeStripe::start().await;
        let mut wrong = config(TaxMode::Managed);
        wrong.secret_key = SecretString::from("sk_test_wrong");
        let stripe = Stripe::with_base(&wrong, fake.base()).expect("client");
        let error = stripe.subscription("sub_1").await.expect_err("refused");
        assert_eq!(error, BillingError::Refused(401));
        for text in [
            error.to_string(),
            format!("{error:?}"),
            format!("{stripe:?}"),
        ] {
            assert!(!text.contains("sk_test_wrong"), "{text}");
        }
    }

    #[tokio::test]
    async fn subscription_period_end_read_from_item() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        fake.put_subscription("sub_1", "cus_1", "past_due", 1_900_000_123);
        let subscription = stripe.subscription("sub_1").await.expect("subscription");
        assert_eq!(subscription.id, "sub_1");
        assert_eq!(subscription.customer, "cus_1");
        assert_eq!(subscription.status, "past_due");
        assert_eq!(
            subscription.period_end,
            Some(1_900_000_123),
            "the real payload has no top-level current_period_end; the item carries it"
        );
    }

    #[tokio::test]
    async fn subscription_ids_that_could_change_the_path_are_refused_without_a_call() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        for bad in ["", "sub_1/../customers", "sub 1", "sub_1?x=1", "../x"] {
            assert_eq!(
                stripe.subscription(bad).await.expect_err("refused"),
                BillingError::BadId,
                "{bad:?}"
            );
            assert_eq!(
                stripe.checkout_session(bad).await.expect_err("refused"),
                BillingError::BadId,
                "{bad:?}"
            );
            assert_eq!(
                stripe.cancel_now(bad).await.expect_err("refused"),
                BillingError::BadId,
                "{bad:?}"
            );
        }
        assert!(fake.requests().is_empty(), "nothing reached Stripe");
    }

    #[tokio::test]
    async fn checkout_managed_sends_managed_payments_and_user_metadata() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        let url = stripe
            .checkout(
                &user(Some("cus_9")),
                Plan::Yearly,
                "https://ibridge.example/billing/return?session_id={CHECKOUT_SESSION_ID}",
                "https://ibridge.example/account",
            )
            .await
            .expect("checkout");
        let session = fake.last_session().expect("a session");
        assert_eq!(url, format!("https://checkout.stripe.test/c/pay/{session}"));
        let sent = &fake.requests_to("POST", "/v1/checkout/sessions")[0];
        assert_eq!(sent.field("mode"), Some("subscription"));
        assert_eq!(sent.field("customer"), Some("cus_9"));
        assert_eq!(sent.field("line_items[0][price]"), Some("price_year"));
        assert_eq!(sent.field("line_items[0][quantity]"), Some("1"));
        assert_eq!(sent.field("client_reference_id"), Some("7"));
        assert_eq!(
            sent.field("subscription_data[metadata][user_id]"),
            Some("7")
        );
        assert_eq!(sent.field("managed_payments[enabled]"), Some("true"));
        assert_eq!(sent.field("automatic_tax[enabled]"), None);
        assert_eq!(
            sent.field("success_url"),
            Some("https://ibridge.example/billing/return?session_id={CHECKOUT_SESSION_ID}")
        );
        assert_eq!(
            sent.field("cancel_url"),
            Some("https://ibridge.example/account")
        );
        stripe
            .checkout(
                &user(Some("cus_9")),
                Plan::Monthly,
                "https://x.test/ok",
                "https://x.test/no",
            )
            .await
            .expect("checkout");
        let second = &fake.requests_to("POST", "/v1/checkout/sessions")[1];
        assert_eq!(second.field("line_items[0][price]"), Some("price_month"));
    }

    #[tokio::test]
    async fn checkout_automatic_sends_automatic_tax() {
        let (stripe, fake) = client(TaxMode::Automatic).await;
        stripe
            .checkout(
                &user(Some("cus_9")),
                Plan::Monthly,
                "https://x.test/ok",
                "https://x.test/no",
            )
            .await
            .expect("checkout");
        let sent = &fake.requests_to("POST", "/v1/checkout/sessions")[0];
        assert_eq!(sent.field("automatic_tax[enabled]"), Some("true"));
        assert_eq!(
            sent.field("customer_update[address]"),
            Some("auto"),
            "Stripe Tax needs an address, and a new customer has none: Checkout saves the one it collects"
        );
        assert_eq!(
            sent.field("managed_payments[enabled]"),
            Some("false"),
            "Managed Payments is on by default on the account, so automatic mode turns it off"
        );
    }

    #[tokio::test]
    async fn checkout_without_a_customer_is_refused_without_a_call() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        let error = stripe
            .checkout(
                &user(None),
                Plan::Monthly,
                "https://x.test/ok",
                "https://x.test/no",
            )
            .await
            .expect_err("no customer");
        assert_eq!(error, BillingError::NoCustomer);
        assert!(fake.requests().is_empty());
    }

    #[tokio::test]
    async fn ensure_customer_creates_once_with_user_id_metadata() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        let first = stripe.ensure_customer(&user(None)).await.expect("customer");
        let again = stripe.ensure_customer(&user(None)).await.expect("customer");
        assert_eq!(
            first, again,
            "the idempotency key makes a repeat the same customer"
        );
        let sent = fake.requests_to("POST", "/v1/customers");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].field("metadata[user_id]"), Some("7"));
        assert_eq!(sent[0].field("email"), Some("ada@privaterelay.appleid.com"));
        assert_eq!(sent[0].idempotency.as_deref(), Some("ibridge-customer-7"));
        assert_eq!(sent[0].idempotency, sent[1].idempotency);

        let known = stripe
            .ensure_customer(&user(Some("cus_known")))
            .await
            .expect("customer");
        assert_eq!(known, "cus_known");
        assert_eq!(
            fake.requests_to("POST", "/v1/customers").len(),
            2,
            "a user with a customer makes no call"
        );
    }

    #[tokio::test]
    async fn portal_returns_url() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        let url = stripe
            .portal("cus_9", "https://ibridge.example/account")
            .await
            .expect("portal");
        assert!(
            url.starts_with("https://billing.stripe.test/p/session/bps_"),
            "{url}"
        );
        let sent = &fake.requests_to("POST", "/v1/billing_portal/sessions")[0];
        assert_eq!(sent.field("customer"), Some("cus_9"));
        assert_eq!(
            sent.field("return_url"),
            Some("https://ibridge.example/account")
        );
    }

    #[tokio::test]
    async fn checkout_session_reads_customer_subscription_and_reference() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        stripe
            .checkout(
                &user(Some("cus_9")),
                Plan::Monthly,
                "https://x.test/ok",
                "https://x.test/no",
            )
            .await
            .expect("checkout");
        let id = fake.last_session().expect("a session");
        let open = stripe.checkout_session(&id).await.expect("session");
        assert_eq!(open.customer.as_deref(), Some("cus_9"));
        assert_eq!(open.client_reference_id.as_deref(), Some("7"));
        assert_eq!(open.subscription, None, "nothing is paid yet");
        fake.complete_session(&id, "sub_77");
        let paid = stripe.checkout_session(&id).await.expect("session");
        assert_eq!(paid.subscription.as_deref(), Some("sub_77"));
    }

    #[tokio::test]
    async fn cancel_now_deletes_subscription() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        fake.put_subscription("sub_1", "cus_1", "active", 1_900_000_000);
        stripe.cancel_now("sub_1").await.expect("cancel");
        assert_eq!(
            fake.requests_to("DELETE", "/v1/subscriptions/sub_1").len(),
            1
        );
        let after = stripe.subscription("sub_1").await.expect("subscription");
        assert_eq!(after.status, "canceled");
    }

    #[tokio::test]
    async fn a_second_cancel_is_refused_like_real_stripe() {
        // Real Stripe (sandbox, 2026-11-18): DELETE on an already-canceled subscription
        // answers 404 with error code `resource_missing`.
        let (stripe, fake) = client(TaxMode::Managed).await;
        fake.put_subscription("sub_1", "cus_1", "active", 1_900_000_000);
        let delete = || {
            stripe.call::<super::IgnoredReply>(
                super::Method::DELETE,
                "/v1/subscriptions/sub_1",
                &[],
                None,
            )
        };
        delete().await.expect("the first cancel");
        assert_eq!(
            delete().await.expect_err("the second cancel"),
            BillingError::Refused(404)
        );
        // The client reads that as done, not as a failure.
        stripe
            .cancel_now("sub_1")
            .await
            .expect("already canceled is done");
    }

    #[tokio::test]
    async fn a_stripe_error_status_is_refused_and_an_outage_is_not_a_panic() {
        let (stripe, fake) = client(TaxMode::Managed).await;
        assert_eq!(
            stripe
                .subscription("sub_missing")
                .await
                .expect_err("unknown"),
            BillingError::Refused(404)
        );
        fake.refuse_with(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            stripe
                .portal("cus_9", "https://x.test")
                .await
                .expect_err("outage"),
            BillingError::Refused(503)
        );
    }
}

/// A round trip against the iBridge Stripe sandbox, run by hand or by the deploy runbook.
///
/// It proves only what an API-only test can: the pinned API version is accepted, a customer
/// can be made, a Checkout Session can be made for each price in the configured tax mode
/// and read back, a portal session can be made, and a real subscription (made on a test
/// clock with `pm_card_visa`, outside Checkout) parses, with its period end read from its
/// item. It does not prove paying through Checkout under Managed Payments, switching plans in
/// the portal, cancelling a Managed Payments subscription, or webhooks: those are the
/// deploy runbook's sandbox stage.
#[cfg(test)]
mod sandbox {
    use std::time::{SystemTime, UNIX_EPOCH};

    use http::Method;
    use secrecy::SecretString;
    use serde_json::Value;

    use super::{STRIPE_API_VERSION, Stripe};
    use crate::billing::{BillingConfig, Plan, TaxMode};
    use crate::store::{User, UserId};

    fn setting(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!("{name} is not set; load ~/.config/ibridge/stripe-sandbox.env first")
        })
    }

    async fn raw(stripe: &Stripe, method: Method, path: &str, form: &[(&str, &str)]) -> Value {
        stripe
            .call(method.clone(), path, form, None)
            .await
            .unwrap_or_else(|error| panic!("{method} {path}: {error}"))
    }

    /// The Checkout Session id in a hosted page URL, `https://checkout.stripe.com/c/pay/<id>#...`.
    fn session_id(url: &str) -> &str {
        let tail = url.rsplit("/pay/").next().unwrap_or_default();
        tail.split(['#', '?']).next().unwrap_or_default()
    }

    /// The settings the test reads, refusing anything but a test-mode key.
    fn config() -> BillingConfig {
        let key = setting("IBRIDGE_TEST_STRIPE_SECRET_KEY");
        assert!(
            key.starts_with("sk_test_") || key.starts_with("rk_test_"),
            "the sandbox round trip only runs with a test-mode key"
        );
        assert_eq!(
            setting("IBRIDGE_TEST_STRIPE_API_VERSION"),
            STRIPE_API_VERSION,
            "the sandbox env file and the pinned version agree"
        );
        let tax = match setting("IBRIDGE_TEST_STRIPE_TAX").as_str() {
            "managed" => TaxMode::Managed,
            "automatic" => TaxMode::Automatic,
            other => panic!("IBRIDGE_TEST_STRIPE_TAX is {other:?}, not managed or automatic"),
        };
        BillingConfig {
            secret_key: SecretString::from(key),
            webhook_secret: SecretString::from("whsec_unused_by_this_test"),
            price_monthly: setting("IBRIDGE_TEST_STRIPE_PRICE_MONTHLY"),
            price_yearly: setting("IBRIDGE_TEST_STRIPE_PRICE_YEARLY"),
            tax,
        }
    }

    fn unix_now() -> i64 {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        i64::try_from(secs).expect("a time that fits")
    }

    /// A Checkout Session for each price in the configured tax mode, read back.
    async fn check_checkout(stripe: &Stripe, user: &User, customer: &str) {
        for plan in [Plan::Monthly, Plan::Yearly] {
            let page = stripe
                .checkout(
                    user,
                    plan,
                    "https://ibridge.fyi/billing/return?session_id={CHECKOUT_SESSION_ID}",
                    "https://ibridge.fyi/account",
                )
                .await
                .unwrap_or_else(|error| panic!("checkout {plan:?}: {error}"));
            assert!(page.starts_with("https://checkout.stripe.com/"), "{plan:?}");
            let session = stripe
                .checkout_session(session_id(&page))
                .await
                .expect("the session reads back");
            assert_eq!(session.customer.as_deref(), Some(customer));
            assert_eq!(
                session.client_reference_id.as_deref(),
                Some(user.id.get().to_string().as_str())
            );
            assert_eq!(session.subscription, None, "nobody has paid");
        }
    }

    /// A real subscription, made outside Checkout on a test clock with a test card, then
    /// parsed and cancelled. A test clock takes its customers with it when deleted.
    async fn check_subscription(stripe: &Stripe, monthly_price: &str) {
        let now = unix_now();
        let id_of = |reply: &Value| reply["id"].as_str().expect("an id").to_owned();
        let clock = id_of(
            &raw(
                stripe,
                Method::POST,
                "/v1/test_helpers/test_clocks",
                &[
                    ("frozen_time", &now.to_string()),
                    ("name", "ibridge round trip"),
                ],
            )
            .await,
        );
        let customer = id_of(
            &raw(
                stripe,
                Method::POST,
                "/v1/customers",
                &[
                    ("test_clock", &clock),
                    ("payment_method", "pm_card_visa"),
                    ("invoice_settings[default_payment_method]", "pm_card_visa"),
                ],
            )
            .await,
        );
        let made = id_of(
            &raw(
                stripe,
                Method::POST,
                "/v1/subscriptions",
                &[("customer", &customer), ("items[0][price]", monthly_price)],
            )
            .await,
        );

        let subscription = stripe.subscription(&made).await.expect("subscription");
        assert_eq!(subscription.id, made);
        assert_eq!(subscription.customer, customer);
        assert_eq!(subscription.status, "active");
        let period_end = subscription
            .period_end
            .expect("the item carries the period end");
        assert!(
            period_end > now && period_end < now + 32 * 24 * 60 * 60,
            "a monthly period ends within a month: {period_end}"
        );

        // Cancelling now is what account deletion does.
        stripe.cancel_now(&made).await.expect("cancel now");
        assert_eq!(
            stripe
                .subscription(&made)
                .await
                .expect("subscription")
                .status,
            "canceled"
        );
        raw(
            stripe,
            Method::DELETE,
            &format!("/v1/test_helpers/test_clocks/{clock}"),
            &[],
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "talks to the Stripe sandbox; run with the env from ~/.config/ibridge/stripe-sandbox.env"]
    async fn stripe_sandbox_round_trip() {
        let config = config();
        let stripe = Stripe::new(&config).expect("a client for api.stripe.com");
        let now = unix_now();
        let mut user = User {
            id: UserId::from_raw(now),
            firebase_uid: format!("sandbox-{now}"),
            apple_sub: "sandbox".to_owned(),
            email: Some(format!("sandbox-round-trip-{now}@example.com")),
            account: None,
            stripe_customer: None,
            stripe_subscription: None,
            status: None,
            period_end: None,
            complimentary: false,
        };

        // A customer, made once for the user.
        let customer = stripe.ensure_customer(&user).await.expect("customer");
        assert!(customer.starts_with("cus_"), "{customer}");
        user.stripe_customer = Some(customer.clone());

        check_checkout(&stripe, &user, &customer).await;

        // A portal session (the sandbox has a default portal configuration).
        let portal = stripe
            .portal(&customer, "https://ibridge.fyi/account")
            .await
            .expect("portal");
        assert!(
            portal.starts_with("https://billing.stripe.com/"),
            "{portal}"
        );

        check_subscription(&stripe, &config.price_monthly).await;
        raw(
            &stripe,
            Method::DELETE,
            &format!("/v1/customers/{customer}"),
            &[],
        )
        .await;
    }
}
