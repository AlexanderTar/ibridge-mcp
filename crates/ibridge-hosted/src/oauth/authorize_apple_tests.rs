// SPDX-License-Identifier: Apache-2.0

//! `/authorize` with Sign in with Apple on: sign in, then a plan if billing is on, then the app password.

use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::http::{StatusCode, header};

use crate::oauth::test_support::{
    ADA, ASP_ALL, CLIENT_ID, Harness, LOOPBACK_REDIRECT, Reply, harness,
};
use crate::pages::test_rig::{Browser, IP, OWNER, Rig, Setup};

const BEA: &str = "bea@icloud.com";
const PRICE: &str = "US$1.99 per month or US$19.99 per year";
const SESSION: &str = "__Host-ibridge_session";
const PENDING: &str = "__Host-ibridge_pending";
const FORM_CSRF: &str = "__Host-ibridge_csrf";

fn path() -> String {
    Harness::authorize_path(&[], &[])
}

/// The `name=value` of the `Set-Cookie` named `name`, for sending back.
fn cookie_named(reply: &Reply, name: &str) -> Option<String> {
    reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
        .filter(|pair| !pair.ends_with('='))
}

/// The pending id a page links to or posts.
fn pending_id(reply: &Reply) -> String {
    let marker = "pending=";
    let start = reply.text.find(marker).expect("a pending id") + marker.len();
    let end = reply.text[start..]
        .find(['"', '&'])
        .expect("the end of the id");
    reply.text[start..start + end].to_owned()
}

impl Rig {
    /// Opens `/authorize` as `browser`.
    async fn authorize(&self, browser: &Browser) -> Reply {
        self.get(&path(), Some(browser)).await
    }

    /// Posts the connect form shown on `page` as `browser`, typing `address`.
    async fn connect(&self, browser: &Browser, page: &Reply, address: &str) -> Reply {
        let form_csrf = cookie_named(page, FORM_CSRF).expect("the form's csrf cookie");
        let cookie = format!("{}; {form_csrf}", browser.cookie);
        self.harness
            .post_raw(
                IP,
                Some(&cookie),
                &page.form_fields(),
                &page.input("csrf"),
                address,
                ASP_ALL,
                None,
            )
            .await
    }
}

fn code_of(reply: &Reply) -> Option<String> {
    (reply.status == StatusCode::SEE_OTHER)
        .then(|| reply.location())
        .and_then(|location| {
            location
                .query_pairs()
                .find(|(name, _)| name == "code")
                .map(|(_, value)| value.into_owned())
        })
}

#[tokio::test]
async fn authorize_not_signed_in_shows_apple_button_and_resumes_after_signin() {
    let rig = Rig::identity_only().await;
    let first = rig.get(&path(), None).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert!(
        first.text.contains("Sign in with Apple"),
        "step 1 offers Apple: {}",
        first.text
    );
    assert!(
        !first.text.contains(r#"name="password""#) && !first.text.contains(r#"name="apple_id""#),
        "and nothing else yet: {}",
        first.text
    );
    let id = pending_id(&first);
    let owner = cookie_named(&first, PENDING).expect("an owner cookie for the stored request");
    let cookie = first
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{PENDING}=")))
        .expect("the cookie");
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attribute), "{attribute} in {cookie}");
    }

    // The link starts a sign-in that comes back to this request.
    let started = rig
        .harness
        .get_path(
            &format!("/signin/apple?next=authorize&pending={id}"),
            IP,
            Some(&owner),
        )
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.text);
    let binder = cookie_named(&started, "__Host-ibridge_siwa").expect("a binder");
    let state = started
        .location()
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .expect("a state");
    let finished = rig
        .harness
        .post_path(
            "/signin/apple/callback",
            IP,
            Some(&binder),
            &[("code", "good-code"), ("state", &state)],
        )
        .await;
    assert_eq!(finished.status, StatusCode::SEE_OTHER, "{}", finished.text);
    let session = cookie_named(&finished, SESSION).expect("a session");
    let back = finished
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("a location")
        .to_owned();
    assert_eq!(back, format!("/authorize/resume?pending={id}"));

    // Resumed in the same browser, the request is where it was, now at the password step.
    let resumed = rig
        .harness
        .get_path(&back, IP, Some(&format!("{session}; {owner}")))
        .await;
    assert_eq!(resumed.status, StatusCode::OK, "{}", resumed.text);
    assert!(
        resumed.text.contains(r#"name="password""#),
        "{}",
        resumed.text
    );
    assert_eq!(resumed.input("client_id"), CLIENT_ID);
    assert_eq!(resumed.input("redirect_uri"), LOOPBACK_REDIRECT);
}

#[tokio::test]
async fn authorize_identity_on_billing_off_goes_from_signin_to_password() {
    let rig = Rig::identity_only().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains(r#"name="password""#) && page.text.contains(r#"name="apple_id""#),
        "straight to the password: {}",
        page.text
    );
    assert!(
        !page.text.contains("US$") && !page.text.contains("/billing/"),
        "billing is off, so no plan step: {}",
        page.text
    );
    let made = rig.connect(&browser, &page, ADA).await;
    assert!(code_of(&made).is_some(), "{}: {}", made.status, made.text);
}

#[tokio::test]
async fn authorize_no_access_shows_both_prices_and_checkout_buttons() {
    let rig = Rig::billing().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    for expected in [
        PRICE,
        r#"action="/billing/checkout""#,
        r#"name="plan" value="monthly""#,
        r#"name="plan" value="yearly""#,
    ] {
        assert!(page.text.contains(expected), "{expected} on: {}", page.text);
    }
    assert!(
        !page.text.contains(r#"name="password""#),
        "no password before a plan: {}",
        page.text
    );
    // Checkout carries the session's own token and the stored request, which this browser owns.
    assert_eq!(page.input("csrf"), browser.csrf);
    let id = page.input("pending");
    assert!(
        rig.shared
            .pending_authorize
            .get(&id, OWNER, Instant::now())
            .is_some(),
        "the request waits for the payment"
    );

    // Once a plan is active the same request goes on to the password step.
    rig.subscribe(&user, "active").await;
    let resumed = rig
        .get(&format!("/authorize/resume?pending={id}"), Some(&browser))
        .await;
    assert!(
        resumed.text.contains(r#"name="password""#) && !resumed.text.contains("US$"),
        "{}",
        resumed.text
    );
}

#[tokio::test]
async fn authorize_complimentary_user_skips_the_plan_step() {
    let rig = Rig::billing().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    rig.harness
        .store
        .set_complimentary(user.id, true)
        .await
        .expect("comp");
    let page = rig.authorize(&rig.browser(&user)).await;
    assert!(page.text.contains(r#"name="password""#), "{}", page.text);
}

#[tokio::test]
async fn authorize_closed_or_full_service_refuses_before_checkout() {
    // Full: one account exists and the cap is one.
    let full = Setup::default().billing().cap(1).build().await;
    let taken = full.linked_user("uid-0", "bea@example.com", BEA).await;
    let user = full.user("uid-1", Some("ada@example.com")).await;
    let page = full.authorize(&full.browser(&user)).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.text
    );
    assert!(
        !page.text.contains("/billing/checkout") && !page.text.contains("US$"),
        "nobody pays for a service they cannot join: {}",
        page.text
    );
    assert!(
        full.stripe_requests().is_empty(),
        "nothing was asked of Stripe"
    );

    // Closed: only the listed address may connect.
    let closed = Setup::default().billing().only(&[BEA]).build().await;
    let user = closed.user("uid-1", Some("ada@example.com")).await;
    let page = closed.authorize(&closed.browser(&user)).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.text
    );
    assert!(!page.text.contains("/billing/checkout"), "{}", page.text);

    // A user whose own address is already linked is not shut out by a full service.
    let linked = full.reload(&taken).await;
    let page = full.authorize(&full.browser(&linked)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains("/billing/checkout"),
        "a linked user can still subscribe: {}",
        page.text
    );
}

#[tokio::test]
async fn authorize_active_first_connect_links_address() {
    let rig = Rig::billing().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    rig.subscribe(&user, "active").await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;
    assert!(
        page.text.contains(r#"name="apple_id""#),
        "a first connect asks for the address: {}",
        page.text
    );
    let made = rig.connect(&browser, &page, ADA).await;
    assert!(code_of(&made).is_some(), "{}: {}", made.status, made.text);
    assert_eq!(
        rig.reload(&user)
            .await
            .account
            .as_ref()
            .map(ibridge_core::AppleId::as_str),
        Some(ADA),
        "the first connect linked the address"
    );

    // The next connect names the address and does not ask for one.
    let again = rig.authorize(&browser).await;
    assert!(again.text.contains(ADA), "{}", again.text);
    assert!(
        !again.text.contains(r#"type="email""#),
        "no address field once linked: {}",
        again.text
    );
    let second = rig.connect(&browser, &again, ADA).await;
    assert!(code_of(&second).is_some(), "{}", second.text);
}

#[tokio::test]
async fn authorize_active_other_address_refused_naming_linked_address() {
    let rig = Rig::billing().await;
    let user = rig.linked_user("uid-1", "ada@example.com", ADA).await;
    rig.subscribe(&user, "active").await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;
    let checks = rig.harness.checks.load(Ordering::SeqCst);

    let refused = rig.connect(&browser, &page, BEA).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    assert!(code_of(&refused).is_none());
    let error = refused.error_text().expect("an error message");
    assert!(error.contains(ADA), "names the linked address: {error}");
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        checks,
        "the other address never reached iCloud"
    );
}

#[tokio::test]
async fn authorize_address_taken_by_other_user_refused_without_detail() {
    let rig = Rig::billing().await;
    let _owner = rig.linked_user("uid-0", "bea@example.com", ADA).await;
    let user = rig.user("uid-1", Some("cy@example.com")).await;
    rig.subscribe(&user, "active").await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;

    let refused = rig.connect(&browser, &page, ADA).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    assert!(code_of(&refused).is_none());
    let error = refused.error_text().expect("an error message");
    assert!(
        !error.contains("bea@example.com") && !error.contains("uid-0"),
        "says nothing about who has it: {error}"
    );
    assert!(rig.reload(&user).await.account.is_none(), "not linked");
}

#[tokio::test]
async fn authorize_post_needs_a_session_and_a_plan() {
    let rig = Rig::billing().await;
    let user = rig.user("uid-1", Some("ada@example.com")).await;
    rig.subscribe(&user, "active").await;
    let browser = rig.browser(&user);
    let page = rig.authorize(&browser).await;
    let form_csrf = cookie_named(&page, FORM_CSRF).expect("the form's csrf cookie");
    let checks = rig.harness.checks.load(Ordering::SeqCst);

    // The right form and token, but no session: nobody is signed in.
    let anonymous = rig
        .harness
        .post_raw(
            IP,
            Some(&form_csrf),
            &page.form_fields(),
            &page.input("csrf"),
            ADA,
            ASP_ALL,
            None,
        )
        .await;
    assert!(code_of(&anonymous).is_none(), "{}", anonymous.text);

    // A session without a plan: the plan step cannot be skipped by posting.
    let unpaid = rig.user("uid-2", None).await;
    let unpaid_browser = rig.browser(&unpaid);
    let cookie = format!("{}; {form_csrf}", unpaid_browser.cookie);
    let skipped = rig
        .harness
        .post_raw(
            IP,
            Some(&cookie),
            &page.form_fields(),
            &page.input("csrf"),
            ADA,
            ASP_ALL,
            None,
        )
        .await;
    assert!(code_of(&skipped).is_none(), "{}", skipped.text);
    assert_eq!(
        rig.harness.checks.load(Ordering::SeqCst),
        checks,
        "neither reached iCloud"
    );
    assert!(rig.reload(&unpaid).await.account.is_none());
}

#[tokio::test]
async fn authorize_identity_off_unchanged() {
    let h = harness(crate::oauth::Access::MultiTenant).await;
    let page = h.get_authorize(&path(), IP).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains(r#"name="apple_id""#) && page.text.contains(r#"name="password""#),
        "the password form, as before: {}",
        page.text
    );
    assert!(
        !page.text.contains("Sign in with Apple") && cookie_named(&page, PENDING).is_none(),
        "no Apple step and no pending request: {}",
        page.text
    );
}
