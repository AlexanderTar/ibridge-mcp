// SPDX-License-Identifier: Apache-2.0

//! Stripe's webhook: the signature check, and what each event type does to a user.
//!
//! An event is only a nudge. Stripe does not promise order, so the handler never reads a
//! status out of an event: it takes the subscription id the event names, fetches that
//! subscription, and stores what Stripe says it is now.

use ring::hmac;
use serde_json::Value;

use super::grants_access;
use super::stripe::{BillingError, Stripe, Subscription};
use crate::store::{Store, StoreError, User, UserId};

/// How far an event's timestamp may be from now, in seconds, either way.
pub(crate) const TOLERANCE_SECS: u64 = 300;

/// Why an event was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum WebhookError {
    /// The `Stripe-Signature` header is missing, or not `t=...,v1=...`.
    #[error("the signature header is malformed")]
    BadHeader,
    /// No `v1` signature matches the body under the secret.
    #[error("the signature does not match")]
    BadSignature,
    /// The signature is right but its timestamp is too far from now.
    #[error("the event is too old or from the future")]
    Stale,
    /// The body is signed but is not an event.
    #[error("the body is not an event")]
    BadBody,
}

/// A verified event.
#[derive(Debug, Clone)]
pub(crate) struct Event {
    /// The event id, `evt_...`.
    pub(crate) id: String,
    /// The event type, such as `invoice.paid`.
    pub(crate) kind: String,
    /// The object the event is about (`data.object`).
    pub(crate) object: Value,
}

/// Checks `header` against `body` and returns the event.
///
/// The header is `t=<unix seconds>,v1=<hex>[,v1=<hex>...]`. A `v1` is the HMAC-SHA256 of
/// `t.body` under `secret`. Any one matching `v1` is enough (Stripe sends two while a
/// secret is being rolled), compared in constant time. `now` is Unix seconds.
///
/// # Errors
///
/// Returns the [`WebhookError`] that says why the event is refused.
pub(crate) fn verify(
    header: &str,
    body: &[u8],
    secret: &str,
    now: u64,
) -> Result<Event, WebhookError> {
    let (timestamp, signatures) = parse_header(header)?;
    if secret.is_empty() {
        return Err(WebhookError::BadSignature);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut signed = format!("{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    // `hmac::verify` compares in constant time.
    let matched = signatures.iter().any(|signature| {
        unhex(signature).is_some_and(|tag| hmac::verify(&key, &signed, &tag).is_ok())
    });
    if !matched {
        return Err(WebhookError::BadSignature);
    }
    if now.abs_diff(timestamp) > TOLERANCE_SECS {
        return Err(WebhookError::Stale);
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| WebhookError::BadBody)?;
    let text = |pointer: &str| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    match (text("/id"), text("/type"), value.pointer("/data/object")) {
        (Some(id), Some(kind), Some(object)) if object.is_object() => Ok(Event {
            id,
            kind,
            object: object.clone(),
        }),
        _ => Err(WebhookError::BadBody),
    }
}

/// The timestamp and every `v1` signature in the header.
fn parse_header(header: &str) -> Result<(u64, Vec<&str>), WebhookError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", value)) if timestamp.is_none() => {
                timestamp = Some(value.parse::<u64>().map_err(|_| WebhookError::BadHeader)?);
            }
            Some(("v1", value)) => signatures.push(value),
            _ => {}
        }
    }
    match timestamp {
        Some(timestamp) if !signatures.is_empty() => Ok((timestamp, signatures)),
        _ => Err(WebhookError::BadHeader),
    }
}

/// The bytes a hex string spells, or `None` when it is not hex of even length.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// What handling an event did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Applied {
    /// A user's stored subscription was refreshed from Stripe.
    Refreshed,
    /// The event needed no change, for the reason given.
    Ignored(&'static str),
}

/// Why an event could not be handled. Stripe should send it again.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ApplyError {
    /// Stripe could not be asked for the subscription.
    #[error(transparent)]
    Stripe(#[from] BillingError),
    /// The database could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Refreshes the user an event is about from Stripe's current subscription.
///
/// # Errors
///
/// Returns [`ApplyError`] when Stripe or the database fails, so the caller answers with a
/// failure and Stripe retries.
pub(crate) async fn apply(
    store: &Store,
    stripe: &Stripe,
    event: &Event,
) -> Result<Applied, ApplyError> {
    let Some(subscription) = subscription_of(event) else {
        return Ok(Applied::Ignored("the event names no subscription"));
    };
    let Some(user) = find_user(store, event).await? else {
        return Ok(Applied::Ignored("the event is not about a known user"));
    };
    let fetched = stripe.subscription(subscription).await?;
    let applied = adopt(store, &user, &fetched).await?;
    if applied == Applied::Refreshed {
        tracing::info!(user = %user.id, event = %event.id, status = %fetched.status, "subscription refreshed");
    }
    Ok(applied)
}

/// Stores `fetched`, Stripe's current word on a subscription, as `user`'s plan.
///
/// A subscription of another customer is never adopted. A late report of an old
/// subscription must not push out the one the user has now: it is stored only when the
/// user has none, it is the one stored, or it grants access.
pub(crate) async fn adopt(
    store: &Store,
    user: &User,
    fetched: &Subscription,
) -> Result<Applied, StoreError> {
    if user.stripe_customer.as_deref() != Some(fetched.customer.as_str()) {
        return Ok(Applied::Ignored(
            "the subscription belongs to another customer",
        ));
    }
    let replaces = user
        .stripe_subscription
        .as_deref()
        .is_none_or(|current| current == fetched.id);
    if !replaces && !grants_access(&fetched.status) {
        return Ok(Applied::Ignored("the subscription is an older one"));
    }
    store
        .set_subscription(user.id, &fetched.id, &fetched.status, fetched.period_end)
        .await?;
    Ok(Applied::Refreshed)
}

/// The id of the subscription the event is about, found where its type keeps it.
fn subscription_of(event: &Event) -> Option<&str> {
    let object = &event.object;
    let found = match event.kind.as_str() {
        "checkout.session.completed" => object.get("subscription"),
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => object.get("id"),
        // An invoice has no `subscription` of its own at this API version.
        "invoice.paid" | "invoice.payment_failed" => {
            object.pointer("/parent/subscription_details/subscription")
        }
        _ => None,
    };
    found.and_then(Value::as_str)
}

/// The user the event is about: by Stripe customer, else by the user id we put in metadata.
async fn find_user(store: &Store, event: &Event) -> Result<Option<User>, StoreError> {
    let object = &event.object;
    let customer = object.get("customer").and_then(Value::as_str);
    if let Some(customer) = customer
        && let Some(user) = store.user_by_customer(customer).await?
    {
        return Ok(Some(user));
    }
    let hint = match event.kind.as_str() {
        "checkout.session.completed" => object.get("client_reference_id"),
        "invoice.paid" | "invoice.payment_failed" => {
            object.pointer("/parent/subscription_details/metadata/user_id")
        }
        _ => object.pointer("/metadata/user_id"),
    };
    let Some(id) = hint
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<i64>().ok())
    else {
        return Ok(None);
    };
    let Some(user) = store.user(UserId::from_raw(id)).await? else {
        return Ok(None);
    };
    match (user.stripe_customer.as_deref(), customer) {
        (Some(known), Some(sent)) if known != sent => Ok(None),
        (None, Some(sent)) => {
            store.set_customer(user.id, sent).await?;
            store.user(user.id).await
        }
        _ => Ok(Some(user)),
    }
}

#[cfg(test)]
mod tests {
    use super::{WebhookError, verify};
    use crate::billing::fakes::sign;

    const SECRET: &str = "whsec_test_secret";
    const NOW: u64 = 1_800_000_000;
    const BODY: &str = r#"{"id":"evt_1","type":"invoice.paid","data":{"object":{"id":"in_1"}}}"#;

    #[test]
    fn signature_valid_accepted() {
        let header = sign(SECRET, NOW, BODY);
        let event = verify(&header, BODY.as_bytes(), SECRET, NOW).expect("accepted");
        assert_eq!(event.id, "evt_1");
        assert_eq!(event.kind, "invoice.paid");
        assert_eq!(event.object["id"], "in_1");
    }

    #[test]
    fn signature_any_of_two_v1_accepted() {
        let good = sign(SECRET, NOW, BODY);
        let good_v1 = good.split("v1=").nth(1).expect("a v1");
        let old = sign("whsec_the_old_secret", NOW, BODY);
        let old_v1 = old.split("v1=").nth(1).expect("a v1");
        for header in [
            format!("t={NOW},v1={old_v1},v1={good_v1}"),
            format!("t={NOW},v1={good_v1},v1={old_v1}"),
            format!("t={NOW},v0=deadbeef,v1={good_v1}"),
            format!("v1={good_v1}, t={NOW}"),
        ] {
            verify(&header, BODY.as_bytes(), SECRET, NOW)
                .unwrap_or_else(|error| panic!("{header}: {error}"));
        }
    }

    #[test]
    fn signature_bad_rejected() {
        let good = sign(SECRET, NOW, BODY);
        let tampered = BODY.replace("in_1", "in_2");
        let wrong_time =
            sign(SECRET, NOW + 1, BODY).replace(&format!("t={}", NOW + 1), &format!("t={NOW}"));
        for (what, header, body, expected) in [
            (
                "tampered body",
                good.clone(),
                tampered.as_str(),
                WebhookError::BadSignature,
            ),
            (
                "wrong secret",
                sign("whsec_other", NOW, BODY),
                BODY,
                WebhookError::BadSignature,
            ),
            (
                "signature of another timestamp",
                wrong_time,
                BODY,
                WebhookError::BadSignature,
            ),
            (
                "not hex",
                format!("t={NOW},v1=zz"),
                BODY,
                WebhookError::BadSignature,
            ),
            (
                "empty v1",
                format!("t={NOW},v1="),
                BODY,
                WebhookError::BadSignature,
            ),
            (
                "only a v0",
                format!("t={NOW},v0=abcd"),
                BODY,
                WebhookError::BadHeader,
            ),
            (
                "no timestamp",
                "v1=abcd".to_owned(),
                BODY,
                WebhookError::BadHeader,
            ),
            (
                "no signature",
                format!("t={NOW}"),
                BODY,
                WebhookError::BadHeader,
            ),
            ("garbage", "hello".to_owned(), BODY, WebhookError::BadHeader),
            ("empty", String::new(), BODY, WebhookError::BadHeader),
            (
                "bad timestamp",
                "t=soon,v1=abcd".to_owned(),
                BODY,
                WebhookError::BadHeader,
            ),
        ] {
            assert_eq!(
                verify(&header, body.as_bytes(), SECRET, NOW).expect_err(what),
                expected,
                "{what}"
            );
        }
        assert!(
            verify(&good, BODY.as_bytes(), "", NOW).is_err(),
            "an empty secret accepts nothing"
        );
    }

    #[test]
    fn timestamp_older_than_300s_rejected() {
        let signed_at = |t: u64| sign(SECRET, t, BODY);
        verify(&signed_at(NOW - 300), BODY.as_bytes(), SECRET, NOW)
            .expect("300 seconds old is fine");
        verify(&signed_at(NOW + 300), BODY.as_bytes(), SECRET, NOW)
            .expect("300 seconds ahead is fine");
        for t in [NOW - 301, NOW + 301, 0] {
            assert_eq!(
                verify(&signed_at(t), BODY.as_bytes(), SECRET, NOW).expect_err("stale"),
                WebhookError::Stale,
                "t={t}"
            );
        }
    }

    #[test]
    fn a_signed_body_that_is_not_an_event_is_refused() {
        for body in [
            "not json",
            "{}",
            r#"{"id":"evt_1"}"#,
            r#"{"id":"evt_1","type":"x"}"#,
        ] {
            let header = sign(SECRET, NOW, body);
            assert_eq!(
                verify(&header, body.as_bytes(), SECRET, NOW).expect_err("not an event"),
                WebhookError::BadBody,
                "{body}"
            );
        }
    }
}
