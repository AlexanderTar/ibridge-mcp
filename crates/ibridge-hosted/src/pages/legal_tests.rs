// SPDX-License-Identifier: Apache-2.0

//! The landing, terms and privacy pages: the price and the subscription and provider text when
//! billing or Sign in with Apple is on, and the same pages as before when both are off.

use axum::http::StatusCode;

use super::test_rig::{IP, Rig, Setup};
use crate::oauth::Access;
use crate::oauth::test_support::{Reply, harness};

const PRICE: &str = "US$1.99 per month or US$19.99 per year";
const CONTACT: &str = "support@ibridge.example";

/// The page's `<main>`, which is the text of the page; the stylesheet around it is not.
/// Blank lines are dropped: the template's conditionals leave some, and a browser shows none.
fn main_of(page: &Reply) -> String {
    let start = page.text.find("<main").expect("a main element");
    let end = page.text.find("</main>").expect("its end") + "</main>".len();
    squeezed(&page.text[start..end])
}

fn squeezed(html: &str) -> String {
    html.lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn billing_rig() -> Rig {
    Setup::default().billing().contact(CONTACT).build().await
}

#[tokio::test]
async fn landing_shows_price_when_billing_on() {
    let rig = billing_rig().await;
    let page = rig.get("/", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(page.text.contains(PRICE), "{}", page.text);
    assert!(
        page.text.contains("Sign in with Apple"),
        "the connect steps start with Apple: {}",
        page.text
    );
}

#[tokio::test]
async fn landing_has_no_price_when_billing_off() {
    // Sign in with Apple on, Stripe off: sign-in is described, a price is not.
    let rig = Rig::identity_only().await;
    let page = rig.get("/", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(!page.text.contains("US$"), "{}", page.text);
    assert!(page.text.contains("Sign in with Apple"), "{}", page.text);

    // Both off: the page is exactly what it was.
    let h = harness(Access::MultiTenant).await;
    let page = h.get_path("/", IP, None).await;
    assert!(!page.text.contains("US$"), "{}", page.text);
    assert_eq!(
        main_of(&page),
        squeezed(include_str!("golden/landing-off.html")),
        "the landing page is unchanged when both are off"
    );
}

#[tokio::test]
async fn terms_show_subscription_terms_when_billing_on() {
    let rig = billing_rig().await;
    let page = rig.get("/terms", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    for expected in [
        "Subscription and payment",
        PRICE,
        "billing period",
        "renews automatically",
        "cancel at any time",
        "end of the period you have paid for",
        "seller of record",
        "refund",
        "If you cancel",
        "connections and API keys are kept",
        CONTACT,
    ] {
        assert!(page.text.contains(expected), "{expected} in: {}", page.text);
    }
}

#[tokio::test]
async fn terms_do_not_call_stripe_the_seller_when_the_operator_collects_tax() {
    // `IBRIDGE_STRIPE_TAX=automatic`: Stripe takes the payment, but the operator is the seller.
    let rig = Setup::default()
        .billing_automatic_tax()
        .contact(CONTACT)
        .build()
        .await;
    let page = rig.get("/terms", None).await;
    assert!(
        page.text.contains("Subscription and payment"),
        "{}",
        page.text
    );
    assert!(
        !page.text.contains("seller of record"),
        "Stripe is not the seller here: {}",
        page.text
    );
    assert!(
        page.text.contains(CONTACT),
        "refunds go to the operator: {}",
        page.text
    );
}

#[tokio::test]
async fn privacy_lists_outside_services_when_identity_or_billing_on() {
    let rig = billing_rig().await;
    let page = rig.get("/privacy", None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    for expected in [
        "Apple",
        "appleid.apple.com",
        "Google",
        "Firebase",
        "identitytoolkit.googleapis.com",
        "Stripe",
        "api.stripe.com",
        "your email",
        "payment details",
        "None of them receives your app-specific password",
        "content of your mail, calendar, reminders or contacts",
    ] {
        assert!(page.text.contains(expected), "{expected} in: {}", page.text);
    }
    assert!(
        !page.text.contains("We use no other service"),
        "the old sentence is false now: {}",
        page.text
    );

    // Sign in with Apple alone: Apple and Google are listed, Stripe is not.
    let rig = Rig::identity_only().await;
    let page = rig.get("/privacy", None).await;
    assert!(page.text.contains("appleid.apple.com"), "{}", page.text);
    assert!(page.text.contains("Firebase"), "{}", page.text);
    assert!(!page.text.contains("Stripe"), "{}", page.text);
}

#[tokio::test]
async fn privacy_and_terms_unchanged_when_both_off() {
    let h = harness(Access::MultiTenant).await;
    let privacy = h.get_path("/privacy", IP, None).await;
    assert_eq!(
        main_of(&privacy),
        squeezed(include_str!("golden/privacy-off.html")),
        "the privacy policy is unchanged when both are off"
    );
    let terms = h.get_path("/terms", IP, None).await;
    assert_eq!(
        main_of(&terms),
        squeezed(include_str!("golden/terms-off.html")),
        "the terms are unchanged when both are off"
    );
}
