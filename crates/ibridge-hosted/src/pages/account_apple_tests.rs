// SPDX-License-Identifier: Apache-2.0

//! `/account` for a Sign in with Apple user: the login page, the page content, and keys that link.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;

use super::test_rig::{IP, Rig, Setup};
use crate::oauth::Access;
use crate::oauth::test_support::{ADA, ASP_ALL, harness};

const BEA: &str = "bea@icloud.com";
const PRICE: &str = "US$1.99 per month or US$19.99 per year";

async fn count(rig: &Rig, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(rig.harness.store.pool())
        .await
        .expect("count")
}

#[tokio::test]
async fn account_login_page_shows_only_sign_in_with_apple_when_identity_on() {
    let rig = Rig::identity_only().await;
    let page = rig.get("/account", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains(r#"href="/signin/apple""#),
        "a Sign in with Apple link: {}",
        page.text
    );
    assert!(
        !page.text.contains(r#"name="password""#) && !page.text.contains(r#"name="apple_id""#),
        "no password form beside it: {}",
        page.text
    );

    // The password login is gone: a posted password signs nobody in.
    let forged = rig
        .harness
        .post_path(
            "/account/login",
            IP,
            Some("__Host-ibridge_account_csrf=t"),
            &[("csrf", "t"), ("apple_id", ADA), ("password", ASP_ALL)],
        )
        .await;
    assert!(
        !forged
            .headers
            .get_all("set-cookie")
            .iter()
            .any(|value| value
                .to_str()
                .is_ok_and(|cookie| cookie.starts_with("__Host-ibridge_session="))),
        "no session from a password while Sign in with Apple is on"
    );
    assert_ne!(forged.status, StatusCode::SEE_OTHER, "{}", forged.text);
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        0,
        "the password was never checked with iCloud"
    );
}

#[tokio::test]
async fn account_login_keeps_app_password_when_identity_off() {
    let h = harness(Access::MultiTenant).await;
    let page = h.get_path("/account", IP, None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.text.contains(r#"name="apple_id""#) && page.text.contains(r#"name="password""#),
        "the app-password form: {}",
        page.text
    );
    assert!(
        !page.text.contains("/signin/apple"),
        "no Sign in with Apple link: {}",
        page.text
    );
}

#[tokio::test]
async fn account_page_shows_email_linked_address_status_price_and_billing_button() {
    let rig = Rig::billing().await;
    let user = rig
        .linked_user("uid-1", "ada@privaterelay.appleid.com", ADA)
        .await;
    let browser = rig.browser(&user);

    // No plan: the price and a button for each plan.
    let page = rig.get("/account", Some(&browser)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    for expected in [
        "ada@privaterelay.appleid.com",
        ADA,
        "No plan",
        PRICE,
        r#"action="/billing/checkout""#,
        r#"name="plan" value="monthly""#,
        r#"name="plan" value="yearly""#,
    ] {
        assert!(page.text.contains(expected), "{expected} on: {}", page.text);
    }
    assert!(
        !page.text.contains(r#"action="/billing/portal""#),
        "nothing to manage yet"
    );

    // An active plan: its status and a way to manage it, and no checkout.
    rig.subscribe(&user, "active").await;
    let page = rig.get("/account", Some(&browser)).await;
    assert!(page.text.contains("Active"), "{}", page.text);
    assert!(
        page.text.contains(r#"action="/billing/portal""#),
        "{}",
        page.text
    );
    assert!(
        page.text.contains("Manage billing"),
        "the portal button: {}",
        page.text
    );
    assert!(
        !page.text.contains(r#"action="/billing/checkout""#),
        "an active plan is not asked to subscribe: {}",
        page.text
    );

    // Complimentary access names itself and has no billing to manage.
    let comped = rig.user("uid-2", Some("bea@example.com")).await;
    rig.harness
        .store
        .set_complimentary(comped.id, true)
        .await
        .expect("comp");
    let page = rig.get("/account", Some(&rig.browser(&comped))).await;
    assert!(page.text.contains("Complimentary"), "{}", page.text);
    assert!(
        !page.text.contains(r#"action="/billing/checkout""#),
        "{}",
        page.text
    );
}

#[tokio::test]
async fn account_page_without_billing_shows_email_and_link_but_no_price() {
    let rig = Rig::identity_only().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let page = rig.get("/account", Some(&rig.browser(&user))).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(page.text.contains("ada@example.com"), "{}", page.text);
    assert!(page.text.contains(ADA), "{}", page.text);
    assert!(
        !page.text.contains("US$") && !page.text.contains("/billing/"),
        "billing is off, so no price and no billing button: {}",
        page.text
    );
}

#[tokio::test]
async fn account_page_for_user_with_no_address_says_so_and_asks_for_one_in_the_key_form() {
    let rig = Rig::identity_only().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let page = rig.get("/account", Some(&rig.browser(&user))).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains("No iCloud address connected yet"),
        "{}",
        page.text
    );
    assert!(
        page.text.contains(r#"name="apple_id""#),
        "the key form asks for the address on a first connect: {}",
        page.text
    );
}

#[tokio::test]
async fn mint_key_with_linked_address_requires_its_password() {
    let rig = Rig::identity_only().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let browser = rig.browser(&user);
    let page = rig.get("/account", Some(&browser)).await;
    assert!(
        !page.text.contains(r#"name="apple_id""#),
        "a linked user is not asked for an address: {}",
        page.text
    );

    let wrong = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("password", "wrong-wrong-wrong")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", wrong.text);
    assert_eq!(
        count(&rig, "SELECT COUNT(*) FROM grants WHERE kind = 'api_key'").await,
        0,
        "a wrong password makes no key"
    );

    let checks = rig.harness.checks.load(Ordering::SeqCst);
    let right = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(right.status, StatusCode::OK, "{}", right.text);
    assert!(right.text.contains(r#"id="new-key""#), "{}", right.text);
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        checks + 1,
        "the password was checked with iCloud"
    );
    assert_eq!(
        count(&rig, "SELECT COUNT(*) FROM grants WHERE kind = 'api_key'").await,
        1
    );
}

#[tokio::test]
async fn mint_key_before_link_takes_address_and_links_it() {
    let rig = Rig::identity_only().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let browser = rig.browser(&user);

    let missing = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.text);
    assert!(
        rig.reload(&user).await.account.is_none(),
        "no address, no link"
    );

    let made = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("apple_id", ADA), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text);
    assert_eq!(
        rig.reload(&user)
            .await
            .account
            .as_ref()
            .map(ibridge_core::AppleId::as_str),
        Some(ADA),
        "the first key linked the address"
    );

    // The same session, with no new sign-in, now shows the link and keeps working.
    let page = rig.get("/account", Some(&browser)).await;
    assert!(page.text.contains(ADA), "{}", page.text);
    assert!(
        !page.text.contains("No iCloud address connected yet"),
        "{}",
        page.text
    );
    assert!(page.text.contains("API key: laptop"), "{}", page.text);
}

#[tokio::test]
async fn mint_key_other_address_refused() {
    let rig = Rig::identity_only().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let browser = rig.browser(&user);
    let checks = rig.harness.checks.load(Ordering::SeqCst);

    let refused = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("apple_id", BEA), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    let error = refused.error_text().expect("an error message");
    assert!(error.contains(ADA), "names the linked address: {error}");
    assert!(!error.contains(BEA), "does not echo the other one: {error}");
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        checks,
        "the other address was never checked with iCloud"
    );
    assert_eq!(
        count(&rig, "SELECT COUNT(*) FROM grants").await,
        1,
        "only the grant that linked ada exists"
    );
}

#[tokio::test]
async fn mint_key_for_linked_address_off_the_allowlist_refused() {
    // The operator closed the service to BEA only, after ada linked ADA.
    let rig = Setup::default().only(&[BEA]).build().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let browser = rig.browser(&user);
    let checks = rig.harness.checks.load(Ordering::SeqCst);
    let grants = count(&rig, "SELECT COUNT(*) FROM grants").await;

    let refused = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    assert!(refused.error_text().is_some(), "{}", refused.text);
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        checks,
        "an address that may not sign in is never checked with iCloud"
    );
    assert_eq!(
        count(&rig, "SELECT COUNT(*) FROM grants").await,
        grants,
        "no key was made"
    );
}

#[tokio::test]
async fn mint_key_address_of_other_user_refused_without_detail() {
    let rig = Rig::identity_only().await;
    let _owner = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let intruder = rig.user("uid-2", Some("bea@example.com")).await;
    let browser = rig.browser(&intruder);

    let refused = rig
        .post(
            "/account/keys",
            &browser,
            &[("name", "laptop"), ("apple_id", ADA), ("password", ASP_ALL)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    let error = refused.error_text().expect("an error message");
    assert!(
        !error.contains("uid-1") && !error.contains("ada@example.com"),
        "says nothing about who has it: {error}"
    );
    assert!(
        rig.reload(&intruder).await.account.is_none(),
        "nothing was linked"
    );
    assert_eq!(
        count(&rig, "SELECT COUNT(*) FROM grants WHERE kind = 'api_key'").await,
        0,
        "no key was made"
    );
}

#[tokio::test]
async fn account_page_and_checkout_refuse_a_service_that_cannot_be_joined() {
    // Full: one account exists and the cap is one. A user with no address cannot join.
    let full = Setup::default().billing().cap(1).build().await;
    let taken = full.linked_user("uid-0", "bea@example.com", BEA).await;
    let user = full.user("uid-1", Some("ada@example.com")).await;
    let browser = full.browser(&user);
    let page = full.get("/account", Some(&browser)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        !page.text.contains(r#"action="/billing/checkout""#) && !page.text.contains("US$"),
        "nobody is offered a plan for a service they cannot join: {}",
        page.text
    );
    assert!(
        page.text.contains("not taking new accounts"),
        "the page says why: {}",
        page.text
    );
    let posted = full
        .post("/billing/checkout", &browser, &[("plan", "monthly")])
        .await;
    assert_eq!(
        posted.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        posted.text
    );
    assert!(
        full.stripe_requests().is_empty(),
        "nothing was asked of Stripe: {:?}",
        full.stripe_requests()
    );

    // Closed: only the listed address may connect, so a user with no address cannot join, and
    // the wording is about a closed service, not a full one.
    let closed = Setup::default().billing().only(&[BEA]).build().await;
    let user = closed.user("uid-1", Some("ada@example.com")).await;
    let browser = closed.browser(&user);
    let page = closed.get("/account", Some(&browser)).await;
    assert!(
        !page.text.contains(r#"action="/billing/checkout""#),
        "{}",
        page.text
    );
    assert!(
        page.text.contains("private") && !page.text.contains("full"),
        "{}",
        page.text
    );
    let posted = closed
        .post("/billing/checkout", &browser, &[("plan", "yearly")])
        .await;
    assert_eq!(
        posted.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        posted.text
    );
    assert!(closed.stripe_requests().is_empty());

    // A user whose own address is already linked can still subscribe on a full service.
    let page = full.get("/account", Some(&full.browser(&taken))).await;
    assert!(
        page.text.contains(r#"action="/billing/checkout""#),
        "a linked user is not shut out by a full service: {}",
        page.text
    );
}

#[tokio::test]
async fn account_page_says_nothing_of_a_plan_when_billing_is_off() {
    let rig = Rig::identity_only().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let page = rig.get("/account", Some(&rig.browser(&user))).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    for word in [" plan", "subscription", "Subscription"] {
        assert!(
            !page.text.contains(word),
            "no plan exists with billing off, yet the page says {word:?}: {}",
            page.text
        );
    }
    // With billing on, both sentences are there.
    let rig = Rig::billing().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let page = rig.get("/account", Some(&rig.browser(&user))).await;
    assert!(page.text.contains("Your plan covers one iCloud address"));
    assert!(page.text.contains("ends your subscription at once"));
}

#[tokio::test]
async fn account_page_shows_when_the_paid_period_ends() {
    let rig = Rig::billing().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    let browser = rig.browser(&user);
    // 1_900_000_000 is 2030-03-17 in UTC.
    rig.subscribe(&user, "active").await;
    let page = rig.get("/account", Some(&browser)).await;
    assert!(
        page.text.contains("Active, current period ends 2030-03-17"),
        "an active plan shows the end of its period: {}",
        page.text
    );
    // With no plan there is no period to show.
    let other = rig.user("uid-2", Some("bea@example.com")).await;
    let page = rig.get("/account", Some(&rig.browser(&other))).await;
    assert!(!page.text.contains("period ends"), "{}", page.text);
}
