// SPDX-License-Identifier: Apache-2.0

//! The sign-in, authorize, account and message pages are built from the design system's
//! components and call the product iBridge. Behaviour (fields, tokens, routes) is covered by
//! the tests next to each page; this pins what a person sees.

use axum::http::{StatusCode, header};

use super::test_rig::{IP, Rig, Setup};
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
    assert!(
        !text.to_lowercase().contains("seal"),
        "{name} uses the technical word seal in what people read: {text}"
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

/// The delete button is the design system's destructive button, and it follows the box:
/// the stylesheet greys it out until `confirm` is ticked (CSS only, the CSP allows no script),
/// so the box has to sit in the same form as the button.
fn assert_delete_is_a_danger_button(html: &str, label: &str) {
    let form = html
        .split(r#"<form method="post" action="/account/delete">"#)
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .unwrap_or_else(|| panic!("a delete form: {html}"));
    assert!(
        form.contains(r#"name="confirm" type="checkbox""#),
        "the confirmation box is in the delete form: {form}"
    );
    assert!(
        form.contains(&format!(
            r#"<button class="btn btn--danger" type="submit">{label}</button>"#
        )),
        "{label} is the destructive button: {form}"
    );
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
    assert!(
        dashboard.text.contains(
            "Your app-specific password is stored encrypted, and only this key can unlock it. Enter it again so we can check it with iCloud."
        ),
        "the key form explains the password in plain words: {}",
        dashboard.text
    );
    assert_delete_is_a_danger_button(&dashboard.text, "Delete everything");
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
            .contains(r#"<a class="btn-apple" href="/signin/apple?next=authorize"#),
        "Sign in with Apple is Apple's button style, not a design-system button: {}",
        apple.text
    );
    let login = rig.get("/account", None).await;
    assert_styled("account login with Apple", &login);
    assert!(
        login
            .text
            .contains(r#"<a class="btn-apple" href="/signin/apple">Sign in with Apple</a>"#),
        "the account page has the same button, titled Sign in with Apple: {}",
        login.text
    );

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
    assert_delete_is_a_danger_button(&dashboard.text, "Delete my account");
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
            !text.to_lowercase().contains("seal"),
            "{path} uses the technical word seal: {text}"
        );
        assert!(
            page.text.contains(r#"<h1 class="h1">"#) && page.text.contains(r#"<h2 class="h3">"#),
            "{path} uses the design system's type roles"
        );
    }
    let landing = h.get_path("/", IP, None).await.text;
    assert!(
        landing.contains(r#"<a href="https://ibridge.fyi" rel="noopener noreferrer" target="_blank">ibridge.fyi</a>"#),
        "the landing page links the product site: {landing}"
    );
    assert!(
        landing.contains(r#"<ol class="steps">"#),
        "the connect steps use the steps component: {landing}"
    );
}

#[tokio::test]
async fn the_public_pages_do_not_offer_a_read_only_choice_on_the_connect_page() {
    let h = harness(Access::MultiTenant).await;
    let landing = h.get_path("/", IP, None).await.text;
    assert!(
        !landing.to_lowercase().contains("read-only"),
        "the landing page no longer tells people to pick read-only access: {landing}"
    );
    let terms = h.get_path("/terms", IP, None).await.text;
    assert!(
        terms.contains("unless the connection is read-only"),
        "the terms do not say the person chose read-only on the connect page: {terms}"
    );
    assert!(!terms.contains("unless you chose read-only access"));
}

#[tokio::test]
async fn links_to_other_sites_open_in_a_new_tab_without_opener() {
    let rig = Setup::default()
        .billing()
        .contact("support@ibridge.example")
        .build()
        .await;
    let mut pages = Vec::new();
    for path in ["/", "/privacy", "/terms", "/account"] {
        pages.push((path, rig.get(path, None).await.text));
    }
    let authorize = rig
        .harness
        .get_authorize(&Harness::authorize_path(&[], &[]), IP)
        .await;
    pages.push(("/authorize", authorize.text));
    let plain = harness(Access::MultiTenant).await;
    pages.push((
        "/account (password)",
        plain.get_path("/account", IP, None).await.text,
    ));
    pages.push((
        "/authorize (password)",
        plain
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await
            .text,
    ));
    let mut seen = 0;
    for (path, html) in &pages {
        for part in html.split("<a ").skip(1) {
            let tag = part.split('>').next().unwrap_or_default();
            if tag.contains(r#"href="https://"#) || tag.contains(r#"href="http://"#) {
                seen += 1;
                assert!(
                    tag.contains(r#"rel="noopener noreferrer""#)
                        && tag.contains(r#"target="_blank""#),
                    "{path}: an outside link opens in a new tab with rel=noopener noreferrer: <a {tag}>"
                );
            }
        }
    }
    assert!(seen >= 4, "the pages link outside at all ({seen})");
}

#[tokio::test]
async fn every_page_has_the_design_system_nav_and_footer() {
    let h = harness(Access::MultiTenant).await;
    let authorize = h
        .get_authorize(&Harness::authorize_path(&[], &[]), IP)
        .await;
    let mut pages = vec![("/authorize", authorize)];
    for path in ["/", "/privacy", "/terms", "/account"] {
        pages.push((path, h.get_path(path, IP, None).await));
    }
    for (path, page) in pages {
        let html = &page.text;
        // The nav, the page and the footer share one container edge: one width class on <body>.
        assert!(
            html.contains(r#"<body class="layout-form">"#)
                || html.contains(r#"<body class="layout-narrow">"#),
            "{path}: the body sets the layout width: {html}"
        );
        assert!(
            html.contains(r#"<div class="container nav-inner">"#)
                && html.contains(r#"<div class="container page">"#),
            "{path}: the nav and the page use the same container: {html}"
        );
        for part in [
            r#"<div class="footer-top">"#,
            r#"<a class="logo" href="/">"#,
            r#"<p class="disclaimer">iBridge is an unofficial service. It is not affiliated with or endorsed by Apple. iCloud is a trademark of Apple Inc.</p>"#,
        ] {
            let footer = html.split("<footer").nth(1).unwrap_or_default();
            assert!(
                footer.contains(part),
                "{path}: the footer has {part}: {footer}"
            );
        }
    }
    let css = h.get_path("/static/ibridge.css", IP, None).await.text;
    for drift in [
        ".nav { position: static",
        ".footer { flex: none; padding",
        "border-left-width: 4px",
        ".steps .step-body {",
    ] {
        assert!(
            !css[css.find(".shell-top").unwrap_or(0)..].contains(drift),
            "the server stylesheet does not override the design system: {drift}"
        );
    }
}

#[tokio::test]
async fn the_landing_page_uses_the_step_and_copy_box_components() {
    let h = harness(Access::MultiTenant).await;
    let landing = h.get_path("/", IP, None).await.text;
    assert!(
        landing.contains(r#"<span class="step-title">"#)
            && landing.contains(r#"<span class="step-body">"#),
        "the steps have a title and a body: {landing}"
    );
    assert!(
        landing.contains(r#"<span class="copy-box"><code>"#),
        "the connector address is in a copy box: {landing}"
    );
}

#[tokio::test]
async fn no_page_mentions_reminders() {
    let rig = Rig::identity_only().await;
    let path = Harness::authorize_path(&[], &[]);
    let authorize = rig.harness.get_authorize(&path, IP).await;
    let mut pages = vec![("authorize with Apple", authorize)];
    for page in ["/", "/privacy", "/terms", "/account"] {
        pages.push((page, rig.get(page, None).await));
    }
    let h = harness(Access::MultiTenant).await;
    pages.push((
        "authorize",
        h.get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await,
    ));
    for (name, page) in pages {
        let text = visible_text(&page.text);
        assert!(
            !text.to_lowercase().contains("reminder"),
            "{name} still mentions Reminders: {text}"
        );
    }
}

#[tokio::test]
async fn the_apple_steps_are_just_a_heading_and_the_button() {
    let rig = Rig::identity_only().await;
    let path = Harness::authorize_path(&[], &[]);
    let authorize = visible_text(&rig.harness.get_authorize(&path, IP).await.text);
    assert!(
        !authorize.contains("We never see your Apple password"),
        "the authorize step has no reassurance line: {authorize}"
    );
    assert!(
        !authorize.contains("Sign in with Apple to continue"),
        "{authorize}"
    );
    let account = visible_text(&rig.get("/account", None).await.text);
    assert!(
        !account.contains("We never see your Apple password")
            && !account.contains("asked for separately"),
        "the account step has no hint under the button: {account}"
    );
    assert!(
        account.contains("Sign in to manage your iBridge account."),
        "the account card is one short line: {account}"
    );
    assert!(
        !account.contains("to see your plan"),
        "the long line is gone: {account}"
    );
}

/// The plan prompts state the price and that one plan covers one account, and say nothing about
/// tax: the legal clause on the terms page is where tax is explained.
#[tokio::test]
async fn the_landing_account_and_authorize_plan_pages_do_not_mention_tax() {
    let rig = Rig::billing().await;
    let user = rig.user("uid-tax", Some("ada@example.com")).await;
    let browser = rig.browser(&user);
    let authorize = rig
        .get(&Harness::authorize_path(&[], &[]), Some(&browser))
        .await;
    let account = rig.get("/account", Some(&browser)).await;
    let landing = rig.get("/", None).await;
    for (name, page) in [
        ("authorize plan prompt", authorize),
        ("account with a plan to buy", account),
        ("landing", landing),
    ] {
        let text = visible_text(&page.text);
        assert!(
            text.contains("US$")
                && text
                    .to_lowercase()
                    .contains("one plan covers one icloud account"),
            "{name} still states the price and the one-account rule: {text}"
        );
        assert!(
            !text.to_lowercase().contains("tax"),
            "{name} mentions tax: {text}"
        );
    }
}
