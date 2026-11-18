// SPDX-License-Identifier: Apache-2.0

//! Deleting an account that signed in with Apple: a fresh sign-in first, then every provider and every row.

use axum::http::{StatusCode, header};
use tracing::Level;

use super::test_rig::{Browser, Captured, IP, Rig};
use crate::billing::fakes::Recorded;
use crate::identity::fakes::FakeFirebase;
use crate::logging::json_subscriber;
use crate::oauth::test_support::{ADA, ASP_ALL, Reply};
use crate::store::{Scope, User};

const SESSION: &str = "__Host-ibridge_session";

async fn count(rig: &Rig, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(rig.harness.store.pool())
        .await
        .expect("count")
}

/// Rows that belong to a user and what they connected.
async fn rows(rig: &Rig) -> [i64; 4] {
    [
        count(rig, "SELECT COUNT(*) FROM users").await,
        count(rig, "SELECT COUNT(*) FROM accounts").await,
        count(rig, "SELECT COUNT(*) FROM grants").await,
        count(rig, "SELECT COUNT(*) FROM seals").await,
    ]
}

/// A signed-in user linked to `ADA`, with an API key.
async fn member(rig: &Rig) -> (Browser, User) {
    let browser = rig.sign_in("first-code").await;
    let user = rig.signed_in_user().await;
    rig.link(&user, ADA).await;
    let credentials = ibridge_auth::Credentials::new(
        ibridge_core::AppleId::try_from(ADA).expect("address"),
        secrecy::SecretString::from(ASP_ALL),
    );
    let validated = crate::store::ValidatedCredentials::from_check(credentials, |_: &_| {
        crate::test_app::AcceptAll
    })
    .await
    .expect("accepted");
    rig.harness
        .store
        .mint_api_key(
            &validated,
            "laptop",
            Scope::ReadWrite,
            std::time::SystemTime::now(),
            Some(user.id),
        )
        .await
        .expect("key");
    (browser, rig.reload(&user).await)
}

fn session_cleared(reply: &Reply) -> bool {
    reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&format!("{SESSION}=")) && value.contains("Max-Age=0"))
}

fn stripe_deletes(rig: &Rig) -> Vec<Recorded> {
    rig.stripe_requests()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .collect()
}

#[tokio::test]
async fn delete_requires_fresh_apple_sign_in() {
    let rig = Rig::billing().await;
    let (browser, user) = member(&rig).await;
    rig.subscribe(&user, "active").await;
    let before = rows(&rig).await;
    assert_eq!(before[0], 1, "one user");

    // Ticking the box is not enough: the page sends the person to Apple again.
    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    assert_eq!(begun.status, StatusCode::SEE_OTHER, "{}", begun.text);
    assert_eq!(begun.location().path(), "/auth/authorize", "back to Apple");
    assert_eq!(rows(&rig).await, before, "nothing is deleted yet");
    assert_eq!(rig.apple.revoke_requests().len(), 0);
    assert_eq!(rig.firebase.deletes().len(), 0);
    assert_eq!(stripe_deletes(&rig).len(), 0);

    // Without the box ticked nothing starts.
    let unticked = rig.post("/account/delete", &browser, &[]).await;
    assert_eq!(
        unticked.status,
        StatusCode::BAD_REQUEST,
        "{}",
        unticked.text
    );
    assert!(unticked.error_text().is_some(), "{}", unticked.text);

    // A link cannot start a deletion: this sign-in only goes back to the account page.
    let linked = rig.start_sign_in("?next=delete").await;
    let done = rig.callback(&linked, "another-code").await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.text);
    assert_eq!(rows(&rig).await, before, "a plain sign-in deletes nothing");
    assert_eq!(rig.apple.revoke_requests().len(), 0);

    // The same session finishing the fresh sign-in is what deletes.
    let started = super::test_rig::Started::of(&begun);
    let finished = rig.callback(&started, "fresh-code").await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);
    assert_eq!(rows(&rig).await, [0, 0, 0, 0]);
}

#[tokio::test]
async fn delete_with_another_apple_identity_refused() {
    let rig = Rig::billing().await;
    let (browser, user) = member(&rig).await;
    rig.subscribe(&user, "active").await;
    let before = rows(&rig).await;

    // Signed in as someone else at Apple: not the person who asked.
    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    rig.firebase
        .edit_claims(|claims| claims["sub"] = serde_json::json!("some-other-uid"));
    let other = rig.callback(&started, "other-code").await;
    assert_ne!(other.status, StatusCode::OK, "{}", other.text);
    assert_eq!(
        rows(&rig).await,
        before,
        "nothing of either user is deleted"
    );
    assert_eq!(rig.firebase.deletes().len(), 0);
}

#[tokio::test]
async fn delete_revokes_apple_deletes_firebase_cancels_stripe_and_rows() {
    let rig = Rig::billing().await;
    let (browser, user) = member(&rig).await;
    rig.subscribe(&user, "active").await;
    assert_eq!(rows(&rig).await[0], 1);

    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    let done = rig.callback(&started, "fresh-code").await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert!(done.text.contains("Account deleted"), "{}", done.text);
    assert!(
        !done.text.contains(r#"role="alert""#),
        "a deletion that worked is not shown as an error: {}",
        done.text
    );
    assert!(session_cleared(&done), "the session ends");

    // Apple: the grant from this fresh sign-in is revoked.
    let revokes = rig.apple.revoke_requests();
    assert_eq!(revokes.len(), 1, "{revokes:?}");
    assert_eq!(
        revokes[0].get("token").map(String::as_str),
        Some("apple-access-fresh-code"),
        "the access token from the fresh sign-in"
    );
    // Firebase: the user is deleted with the ID token from the fresh sign-in.
    let deletes = rig.firebase.deletes();
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    let token = deletes[0]["idToken"].as_str().expect("an ID token");
    assert_eq!(token.split('.').count(), 3, "a JWT");
    // Stripe: the subscription is cancelled at once.
    let cancels = stripe_deletes(&rig);
    assert_eq!(cancels.len(), 1, "{cancels:?}");
    assert_eq!(cancels[0].path, "/v1/subscriptions/sub_page");
    // Rows: the user, the account, its grants and seals.
    assert_eq!(rows(&rig).await, [0, 0, 0, 0]);
    // Pooled sessions of the account are closed, and the old session is dead.
    let evicted = rig.harness.evicted.lock().expect("log").clone();
    assert_eq!(
        evicted
            .iter()
            .map(ibridge_core::AppleId::as_str)
            .collect::<Vec<_>>(),
        [ADA]
    );
    let after = rig.get("/account", Some(&browser)).await;
    assert!(
        after.text.contains("Sign in with Apple") && !after.text.contains(ADA),
        "{}",
        after.text
    );
}

#[tokio::test]
async fn delete_still_removes_rows_when_a_provider_call_fails() {
    let logs = Captured::default();
    let _guard = tracing::subscriber::set_default(json_subscriber(logs.clone(), Level::TRACE));
    let rig = Rig::billing().await;
    let (browser, user) = member(&rig).await;
    // A status that no longer gives access: a failed cancel is reported, not a stop.
    rig.subscribe(&user, "unpaid").await;
    let stripe = rig.stripe.as_ref().expect("stripe");
    stripe.refuse_with(StatusCode::INTERNAL_SERVER_ERROR);
    rig.apple.fail_revoke(StatusCode::BAD_REQUEST);
    rig.firebase.fail_delete(StatusCode::BAD_REQUEST);

    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    let done = rig.callback(&started, "fresh-code").await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert_eq!(rows(&rig).await, [0, 0, 0, 0], "the rows are gone anyway");
    assert!(session_cleared(&done));
    assert!(
        done.text.contains("Stripe, Apple and Google"),
        "the failed providers read as a list: {}",
        done.text
    );
    assert!(
        done.text.contains("billing may continue"),
        "a failed Stripe cancel says the subscription may still renew: {}",
        done.text
    );
    for provider in ["Apple", "Google", "Stripe"] {
        assert!(
            done.text.contains(provider),
            "the page says {provider} could not be finished: {}",
            done.text
        );
    }
    // Each provider was still tried.
    assert_eq!(rig.apple.revoke_requests().len(), 1);
    assert_eq!(rig.firebase.deletes().len(), 1);

    // The failures are logged by internal user id, and nothing else that identifies the person.
    let text = logs.text();
    assert!(
        text.contains(&format!("\"user\":\"{}\"", user.id)),
        "{text}"
    );
    for secret in [
        FakeFirebase::EMAIL,
        FakeFirebase::UID,
        FakeFirebase::APPLE_SUB,
        "fresh-code",
        "apple-access-",
        "apple-id-",
        "sub_page",
        "cus_page",
        ADA,
    ] {
        assert!(
            !text.contains(secret),
            "a log line carries {secret:?}:\n{text}"
        );
    }
}

#[tokio::test]
async fn delete_without_subscription_skips_stripe() {
    // Stripe on, but this user never paid.
    let rig = Rig::billing().await;
    let (browser, _) = member(&rig).await;
    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    let done = rig.callback(&started, "fresh-code").await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert_eq!(
        rig.stripe_requests().len(),
        0,
        "no subscription, no Stripe call"
    );
    assert_eq!(rig.apple.revoke_requests().len(), 1);
    assert_eq!(rig.firebase.deletes().len(), 1);
    assert_eq!(rows(&rig).await, [0, 0, 0, 0]);

    // Stripe off, and a user who never connected an iCloud address.
    let rig = Rig::identity_only().await;
    let browser = rig.sign_in("first-code").await;
    assert_eq!(rows(&rig).await[0], 1);
    let begun = rig
        .post("/account/delete", &browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    let done = rig.callback(&started, "fresh-code").await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert_eq!(rows(&rig).await, [0, 0, 0, 0]);
    assert!(
        !done.text.contains("Stripe"),
        "nothing to say about a provider that was never involved: {}",
        done.text
    );
    let _ = IP;
}

/// Starts a deletion and finishes it with the fresh Apple sign-in.
async fn delete_now(rig: &Rig, browser: &Browser) -> Reply {
    let begun = rig
        .post("/account/delete", browser, &[("confirm", "delete")])
        .await;
    let started = super::test_rig::Started::of(&begun);
    rig.callback(&started, "fresh-code").await
}

#[tokio::test]
async fn failed_cancel_of_a_paying_subscription_deletes_nothing() {
    for status in ["active", "past_due"] {
        let rig = Rig::billing().await;
        let (browser, user) = member(&rig).await;
        rig.subscribe(&user, status).await;
        let before = rows(&rig).await;
        rig.stripe
            .as_ref()
            .expect("stripe")
            .refuse_with(StatusCode::INTERNAL_SERVER_ERROR);

        let done = delete_now(&rig, &browser).await;
        assert_eq!(
            done.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{status}: {}",
            done.text
        );
        assert!(
            done.text.contains("Nothing was deleted"),
            "{status}: {}",
            done.text
        );
        assert_eq!(rows(&rig).await, before, "{status}: rows stay");
        assert_eq!(rig.apple.revoke_requests().len(), 0, "{status}");
        assert_eq!(rig.firebase.deletes().len(), 0, "{status}");
        assert!(!session_cleared(&done), "{status}: still signed in");

        // Stripe comes back and the person tries again.
        rig.stripe.as_ref().expect("stripe").recover();
        let again = delete_now(&rig, &browser).await;
        assert_eq!(again.status, StatusCode::OK, "{status}: {}", again.text);
        assert_eq!(rows(&rig).await, [0, 0, 0, 0], "{status}");
    }
}

#[tokio::test]
async fn terminal_subscription_is_not_cancelled_again() {
    for status in ["canceled", "incomplete_expired"] {
        let rig = Rig::billing().await;
        let (browser, user) = member(&rig).await;
        rig.subscribe(&user, status).await;
        let done = delete_now(&rig, &browser).await;
        assert_eq!(done.status, StatusCode::OK, "{status}: {}", done.text);
        assert!(
            !done.text.contains("Stripe"),
            "{status}: nothing to finish at Stripe: {}",
            done.text
        );
        assert_eq!(stripe_deletes(&rig).len(), 0, "{status}: no cancel call");
        assert_eq!(rows(&rig).await, [0, 0, 0, 0], "{status}");
    }
}

#[tokio::test]
async fn subscription_already_cancelled_at_stripe_counts_as_done() {
    let rig = Rig::billing().await;
    let (browser, user) = member(&rig).await;
    // Our row still says active (the webhook has not landed); Stripe has ended it.
    rig.subscribe(&user, "active").await;
    rig.stripe.as_ref().expect("stripe").put_subscription(
        "sub_page",
        "cus_page",
        "canceled",
        1_900_000_000,
    );
    let done = delete_now(&rig, &browser).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert!(
        !done.text.contains("Stripe"),
        "an already-ended subscription is not a failure: {}",
        done.text
    );
    assert_eq!(rows(&rig).await, [0, 0, 0, 0]);
}
