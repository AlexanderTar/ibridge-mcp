// SPDX-License-Identifier: Apache-2.0

//! The sign-in, authorize, account and message pages are built from the design system's
//! components and call the product iBridge. Behaviour (fields, tokens, routes) is covered by
//! the tests next to each page; this pins what a person sees.

use axum::http::{StatusCode, header};

use super::test_rig::{IP, Rig};
use crate::oauth::Access;
use crate::oauth::test_support::{ADA, ASP_ALL, Harness, Reply, harness};

/// The text a person reads: tags and their attributes removed.
fn visible_text(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    text
}

/// What every page of this group shares.
fn assert_styled(name: &str, page: &Reply) {
    assert_eq!(page.status, StatusCode::OK, "{name}: {}", page.text);
    let html = &page.text;
    let text = visible_text(html);
    assert!(
        !text.contains("ibridge") && !html.contains("<title>Your ibridge"),
        "{name} says iBridge in what people read: {text}"
    );
    for old in [
        r#"class="button""#,
        r#"class="secondary""#,
        r#"class="error""#,
        "<button type=\"submit\">",
    ] {
        assert!(
            !html.contains(old),
            "{name} still uses the old markup {old}: {html}"
        );
    }
    for button in html.split("<button").skip(1) {
        let tag = button.split('>').next().unwrap_or_default();
        assert!(
            tag.contains(r#"class="btn btn--"#),
            "{name}: a button without a component class: <button{tag}>"
        );
    }
    for input in html.split("<input").skip(1) {
        let tag = input.split('>').next().unwrap_or_default();
        if tag.contains(r#"type="hidden""#) || tag.contains(r#"type="checkbox""#) {
            continue;
        }
        let id = tag
            .split(r#"id=""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("{name}: an input with no id: {tag}"));
        assert!(
            html.contains(&format!(r#"<label for="{id}""#)),
            "{name}: input {id} has a label"
        );
        assert!(
            html.contains(&format!(r#"<div class="field"><label for="{id}""#)),
            "{name}: input {id} sits in a field"
        );
    }
    assert!(html.contains("<h1 class="), "{name} has a heading");
}

#[tokio::test]
async fn the_password_sign_in_and_dashboard_use_the_components() {
    let h = harness(Access::MultiTenant).await;
    let login = h.get_path("/account", IP, None).await;
    assert_styled("account login", &login);
    assert!(
        login.text.contains(r#"class="btn btn--primary btn--lg""#),
        "the submit is a primary button: {}",
        login.text
    );

    let wrong = h
        .post_path(
            "/account/login",
            IP,
            Some(&login.cookie_pair()),
            &[
                ("csrf", &login.input("csrf")),
                ("apple_id", ADA),
                ("password", "wrong"),
            ],
        )
        .await;
    assert!(
        wrong.text.contains(r#"<p class="alert" role="alert">"#),
        "a failed sign-in shows an alert: {}",
        wrong.text
    );

    let ok = h
        .post_path(
            "/account/login",
            IP,
            Some(&login.cookie_pair()),
            &[
                ("csrf", &login.input("csrf")),
                ("apple_id", ADA),
                ("password", ASP_ALL),
            ],
        )
        .await;
    let cookie = ok
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("__Host-ibridge_session="))
        .and_then(|value| value.split(';').next())
        .expect("a session")
        .to_owned();
    let dashboard = h.get_path("/account", IP, Some(&cookie)).await;
    assert_styled("account (empty)", &dashboard);
    let csrf = dashboard.input("csrf");

    let key = h
        .post_path(
            "/account/keys",
            IP,
            Some(&cookie),
            &[("csrf", &csrf), ("name", "laptop"), ("password", ASP_ALL)],
        )
        .await;
    assert_styled("account key", &key);
    assert!(
        key.text.contains(r#"<code class="key" id="new-key">"#),
        "the key is in the key box: {}",
        key.text
    );

    let dashboard = h.get_path("/account", IP, Some(&cookie)).await;
    assert_styled("account (with a key)", &dashboard);
    for wanted in [
        r#"<ul class="grants">"#,
        r#"class="btn btn--secondary""#,
        r#"<label class="check" for=""#,
    ] {
        assert!(
            dashboard.text.contains(wanted),
            "dashboard has {wanted}: {}",
            dashboard.text
        );
    }

    let missing = h.get_authorize("/authorize?client_id=unknown", IP).await;
    assert!(
        missing.text.contains(r#"<p class="alert" role="alert">"#),
        "a refused request is an alert: {}",
        missing.text
    );
    assert!(
        !visible_text(&missing.text).contains("ibridge"),
        "the message page says iBridge: {}",
        missing.text
    );
}

#[tokio::test]
async fn the_authorize_page_uses_the_components() {
    let h = harness(Access::MultiTenant).await;
    let page = h
        .get_authorize(&Harness::authorize_path(&[], &[]), IP)
        .await;
    assert_styled("authorize", &page);
    for wanted in [
        r#"class="btn btn--primary btn--lg""#,
        r#"<label class="check" for=""#,
        r#"<div class="field"><label for="apple_id">"#,
        r#"<div class="field"><label for="password">"#,
    ] {
        assert!(
            page.text.contains(wanted),
            "authorize has {wanted}: {}",
            page.text
        );
    }
}

#[tokio::test]
async fn the_apple_sign_in_and_plan_pages_use_the_components() {
    let rig = Rig::identity_only().await;
    let path = Harness::authorize_path(&[], &[]);
    let apple = rig.harness.get_authorize(&path, IP).await;
    assert_styled("authorize with Apple", &apple);
    assert!(
        apple
            .text
            .contains(r#"<a class="btn btn--primary btn--lg" href="/signin/apple?next=authorize"#),
        "Sign in with Apple is a primary button: {}",
        apple.text
    );
    let login = rig.get("/account", None).await;
    assert_styled("account login with Apple", &login);

    let rig = Rig::billing().await;
    let browser = rig.sign_in("plan-code").await;
    let dashboard = rig.get("/account", Some(&browser)).await;
    assert_styled("account with a plan to buy", &dashboard);
    assert!(
        dashboard
            .text
            .contains(r#"class="btn btn--primary" type="submit" name="plan" value="monthly""#),
        "subscribing is the primary action: {}",
        dashboard.text
    );
}

#[tokio::test]
async fn the_public_pages_spell_the_name_and_link_the_product_site() {
    let h = harness(Access::MultiTenant).await;
    for (path, title) in [
        ("/", "<title>iBridge: iCloud for AI assistants</title>"),
        ("/privacy", "<title>Privacy policy</title>"),
        ("/terms", "<title>Terms of use</title>"),
    ] {
        let page = h.get_path(path, IP, None).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        assert!(page.text.contains(title), "{path} title: {}", page.text);
        // The name is spelled iBridge wherever a person reads it. Lowercase stays in the
        // `ibridge` command and in addresses such as https://ibridge.example/mcp.
        let text = visible_text(&page.text)
            .replace("claude mcp add --transport http ibridge", "")
            .replace("ibridge.example", "")
            .replace("ibridge.fyi", "");
        assert!(
            !text.contains("ibridge"),
            "{path} spells the name wrong: {text}"
        );
        assert!(text.contains("iBridge"), "{path} names the product");
        assert!(
            page.text.contains(r#"<h1 class="h1">"#) && page.text.contains(r#"<h2 class="h3">"#),
            "{path} uses the design system's type roles"
        );
    }
    let landing = h.get_path("/", IP, None).await.text;
    assert!(
        landing.contains(r#"<a href="https://ibridge.fyi">ibridge.fyi</a>"#),
        "the landing page links the product site: {landing}"
    );
    assert!(
        landing.contains(r#"<ol class="steps">"#),
        "the connect steps use the steps component: {landing}"
    );
}
