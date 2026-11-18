// SPDX-License-Identifier: Apache-2.0

//! The public pages: what the service is (`/`), its privacy policy (`/privacy`) and its terms (`/terms`).
//!
//! The privacy and terms text are drafts for the operator to review. They describe what the
//! code does, so change them when the code changes, and have them read by someone who can
//! give legal advice before the service opens to the public.

use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;

use crate::billing::{PRICE_TEXT, TaxMode};
use crate::oauth::Shared;
use crate::web::html;

pub(crate) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(landing))
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .with_state(Arc::clone(shared))
}

#[derive(Template)]
#[template(path = "landing.html")]
struct Landing {
    connector: String,
    /// Sign in with Apple is the login.
    identity: bool,
    /// The price, when billing is on.
    price: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "privacy.html")]
struct Privacy<'a> {
    issuer: String,
    contact: Option<&'a str>,
    contact_link: Option<String>,
    /// Apple and Google (Firebase) take part in sign-in.
    identity: bool,
    /// Stripe takes part in payment.
    billing: bool,
    /// Stripe is the seller of record.
    stripe_sells: bool,
}

#[derive(Template)]
#[template(path = "terms.html")]
struct Terms<'a> {
    issuer: String,
    contact: Option<&'a str>,
    contact_link: Option<String>,
    /// Billing is on, so there are subscription terms.
    billing: bool,
    /// Stripe is the seller of record.
    stripe_sells: bool,
    price: &'static str,
}

/// A `mailto:` link when `contact` is a bare email address, and no link for anything else.
fn mailto(contact: &str) -> Option<String> {
    let bare = contact.contains('@')
        && !contact.contains(|c: char| {
            c.is_whitespace() || matches!(c, '/' | '<' | '>' | '"' | '?' | '&')
        });
    bare.then(|| format!("mailto:{contact}"))
}

/// Whether Stripe is the seller of record: under Managed Payments it is, and under Stripe Tax
/// the operator is, so the terms must not say it is.
fn stripe_sells(shared: &Shared) -> bool {
    shared
        .billing
        .as_ref()
        .is_some_and(|billing| billing.tax == TaxMode::Managed)
}

async fn landing(State(shared): State<Arc<Shared>>) -> Response {
    html(
        StatusCode::OK,
        Landing {
            connector: shared.config.url("/mcp"),
            identity: shared.identity.is_some(),
            price: shared.billing.as_ref().map(|_| PRICE_TEXT),
        }
        .render(),
    )
}

async fn privacy(State(shared): State<Arc<Shared>>) -> Response {
    let contact = shared.config.contact_address();
    html(
        StatusCode::OK,
        Privacy {
            issuer: shared.config.issuer(),
            contact,
            contact_link: contact.and_then(mailto),
            identity: shared.identity.is_some(),
            billing: shared.billing.is_some(),
            stripe_sells: stripe_sells(&shared),
        }
        .render(),
    )
}

async fn terms(State(shared): State<Arc<Shared>>) -> Response {
    let contact = shared.config.contact_address();
    html(
        StatusCode::OK,
        Terms {
            issuer: shared.config.issuer(),
            contact,
            contact_link: contact.and_then(mailto),
            billing: shared.billing.is_some(),
            stripe_sells: stripe_sells(&shared),
            price: PRICE_TEXT,
        }
        .render(),
    )
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};

    use crate::oauth::test_support::{Harness, harness, harness_configured};
    use crate::oauth::{Access, Evict, OAuthConfig};
    use crate::store::Store;

    const IP: &str = "203.0.113.7";

    async fn with_contact(contact: Option<&str>) -> Harness {
        let config = OAuthConfig::new("https://ibridge.example", Access::MultiTenant).expect("url");
        let config = match contact {
            Some(contact) => config.contact(contact),
            None => config,
        };
        let evict: Evict = std::sync::Arc::new(|_| {});
        let mcp =
            axum::Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
        harness_configured(config, Store::memory().await.expect("store"), evict, mcp).await
    }

    #[tokio::test]
    async fn pages_render_and_link_from_authorize() {
        let h = harness(Access::MultiTenant).await;
        for (path, heading) in [
            ("/", "ibridge"),
            ("/privacy", "Privacy"),
            ("/terms", "Terms"),
        ] {
            let page = h.get_path(path, IP, None).await;
            assert_eq!(page.status, StatusCode::OK, "{path}: {}", page.text);
            let kind = page.headers[header::CONTENT_TYPE].to_str().expect("ascii");
            assert!(kind.starts_with("text/html"), "{path}: {kind}");
            assert!(
                page.text.contains(heading),
                "{path} has its heading: {}",
                page.text
            );
            assert!(
                page.headers.get(header::SET_COOKIE).is_none(),
                "{path} sets no cookie"
            );
        }

        let landing = h.get_path("/", IP, None).await.text;
        assert!(
            landing.contains("https://ibridge.example/mcp"),
            "it gives the connector URL: {landing}"
        );
        assert!(
            landing.contains("not affiliated with Apple")
                || landing.contains("Not affiliated with Apple"),
            "it says it is unofficial"
        );
        assert!(landing.contains("Claude"), "it says how to connect Claude");
        for link in [
            r#"href="/account""#,
            r#"href="/privacy""#,
            r#"href="/terms""#,
        ] {
            assert!(landing.contains(link), "the landing page links {link}");
        }
        assert!(
            !landing.contains("noindex"),
            "the landing page may be indexed"
        );

        let authorize = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await
            .text;
        for link in [r#"href="/privacy""#, r#"href="/terms""#] {
            assert!(authorize.contains(link), "the sign-in page links {link}");
        }
        let account = h.get_path("/account", IP, None).await.text;
        assert!(
            account.contains(r#"href="/privacy""#),
            "so does the account page"
        );
        let terms = h.get_path("/terms", IP, None).await.text;
        for word in ["as is", "suspend", "Apple"] {
            assert!(terms.contains(word), "the terms mention {word}: {terms}");
        }
    }

    #[tokio::test]
    async fn privacy_mentions_cannot_decrypt_and_revoke_at_apple() {
        let h = with_contact(Some("privacy@ibridge.example")).await;
        let page = h.get_path("/privacy", IP, None).await.text;
        for (needle, why) in [
            (
                "cannot decrypt",
                "says stored passwords cannot be decrypted",
            ),
            ("while you sign in", "names the risk at sign-in"),
            (
                "changes the code",
                "says a changed server could capture a password",
            ),
            (
                "revoke the app-specific password at Apple",
                "tells users to revoke at Apple",
            ),
            ("/account", "points to deletion on the account page"),
            ("7 days", "states backup retention"),
            ("90 days", "states how long an unused connection lasts"),
            ("privacy@ibridge.example", "shows the contact address"),
            (
                "mailto:privacy@ibridge.example",
                "links the contact address",
            ),
        ] {
            assert!(page.contains(needle), "privacy {why} ({needle}): {page}");
        }
        let terms = h.get_path("/terms", IP, None).await.text;
        assert!(
            terms.contains("privacy@ibridge.example"),
            "the terms give the same contact"
        );

        let none = with_contact(None).await;
        let page = none.get_path("/privacy", IP, None).await.text;
        assert!(
            page.contains("has not published a contact address"),
            "no address is invented: {page}"
        );
        assert!(!page.contains("mailto:"), "and none is linked");
        let odd = with_contact(Some("<b>x</b>")).await;
        let page = odd.get_path("/privacy", IP, None).await.text;
        assert!(
            !page.contains("<b>x</b>"),
            "the contact is text, never markup"
        );
    }
}
