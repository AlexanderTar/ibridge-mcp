// SPDX-License-Identifier: Apache-2.0

//! The stylesheet and icons the pages link are served by the server itself: same origin,
//! cacheable, and nothing is fetched from anywhere else.

use axum::http::{StatusCode, header};

use super::test_rig::IP;
use crate::oauth::Access;
use crate::oauth::test_support::{Harness, harness};

const CSS: &str = "/static/ibridge.css";
const FAVICON: &str = "/static/favicon.svg";
const TOUCH_ICON: &str = "/static/apple-touch-icon.png";
const MARK_LIGHT: &str = "/static/mark-light.svg";
const MARK_DARK: &str = "/static/mark-dark.svg";

#[tokio::test]
async fn assets_are_served_with_type_and_cache_headers() {
    let h = harness(Access::MultiTenant).await;
    for (path, kind) in [
        (CSS, "text/css; charset=utf-8"),
        (FAVICON, "image/svg+xml"),
        (MARK_LIGHT, "image/svg+xml"),
        (MARK_DARK, "image/svg+xml"),
        (TOUCH_ICON, "image/png"),
    ] {
        let asset = h.get_path(path, IP, None).await;
        assert_eq!(asset.status, StatusCode::OK, "{path}: {}", asset.text);
        assert_eq!(asset.headers[header::CONTENT_TYPE], kind, "{path} type");
        let cache = asset.headers[header::CACHE_CONTROL]
            .to_str()
            .expect("ascii");
        assert!(
            cache.contains("public") && cache.contains("max-age="),
            "{path} is cacheable, not no-store: {cache}"
        );
        assert_eq!(
            asset.headers[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff",
            "{path} is not sniffed"
        );
        assert!(
            asset.headers.get(header::SET_COOKIE).is_none(),
            "{path} sets no cookie"
        );
    }

    // A deploy that changes the markup must reach browsers soon: the stylesheet is at an
    // unversioned address, so its cache lifetime is short.
    let cache = h.get_path(CSS, IP, None).await.headers[header::CACHE_CONTROL]
        .to_str()
        .expect("ascii")
        .to_owned();
    let max_age: u32 = cache
        .split(',')
        .find_map(|d| d.trim().strip_prefix("max-age="))
        .and_then(|n| n.parse().ok())
        .expect("a max-age");
    assert!(
        max_age <= 3600,
        "the stylesheet is not cached for long: {cache}"
    );

    let css = h.get_path(CSS, IP, None).await.text;
    for needle in [
        "--color-brand:",
        "prefers-color-scheme: dark",
        ".btn--primary",
        ".btn-apple",
        ".field",
    ] {
        assert!(css.contains(needle), "the stylesheet has {needle}");
    }
    // The data: URIs in the design system carry an `xmlns` URL, which is a name, not a fetch.
    for fetch in ["@import", "url(http", "url(\"http", "url('http", "url(//"] {
        assert!(
            !css.contains(fetch),
            "the stylesheet loads nothing from outside: {fetch}"
        );
    }
}

#[tokio::test]
async fn every_page_links_the_assets_and_nothing_external() {
    let h = harness(Access::MultiTenant).await;
    let authorize = h
        .get_authorize(&Harness::authorize_path(&[], &[]), IP)
        .await;
    let mut pages = vec![("/authorize", authorize)];
    for path in ["/", "/privacy", "/terms", "/account"] {
        pages.push((path, h.get_path(path, IP, None).await));
    }
    for (path, page) in pages {
        assert_eq!(page.status, StatusCode::OK, "{path}: {}", page.text);
        for link in [
            format!(r#"rel="stylesheet" href="{CSS}""#),
            format!(r#"rel="icon" href="{FAVICON}""#),
            format!(r#"rel="apple-touch-icon" href="{TOUCH_ICON}""#),
            format!(r#"src="{MARK_LIGHT}""#),
            format!(r#"src="{MARK_DARK}""#),
        ] {
            assert!(
                page.text.contains(&link),
                "{path} has {link}: {}",
                page.text
            );
        }
        assert!(
            !page.text.contains("<style") && !page.text.contains("<script"),
            "{path} has no inline style or script"
        );
        for tag in ["<link", "<img"] {
            for part in page.text.split(tag).skip(1) {
                let attributes = part.split('>').next().unwrap_or_default();
                assert!(
                    !attributes.contains("http"),
                    "{path} {tag} points outside: {attributes}"
                );
            }
        }
        let csp = page.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("ascii");
        for wanted in [
            "style-src 'self'",
            "img-src 'self'",
            "frame-ancestors 'none'",
        ] {
            assert!(csp.contains(wanted), "{path} CSP has {wanted}: {csp}");
        }
        assert!(!csp.contains("unsafe-inline"), "{path} CSP: {csp}");
    }
}

const LOGO_FILES: [&str; 2] = ["apple-logo-white.svg", "apple-logo-black.svg"];

fn logo_path(file: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(file)
}

/// Apple's logo artwork is licensed, so it is never in the repository: the hosted build
/// adds `assets/apple-logo-white.svg` and `assets/apple-logo-black.svg`. With both files the
/// server serves them and the button shows the logo (white on the black light-mode button,
/// black on the white dark-mode one); with either missing the button is text-only and nothing
/// points at a missing file. Run the suite in both states.
#[tokio::test]
async fn the_apple_logo_is_used_exactly_when_its_files_are_present() {
    let present = LOGO_FILES.iter().all(|f| logo_path(f).exists());
    let h = harness(Access::MultiTenant).await;
    let css = h.get_path(CSS, IP, None).await.text;
    for file in LOGO_FILES {
        let url = format!("/static/{file}");
        assert_eq!(
            css.contains(&url),
            present,
            "the button's logo rule names {url} only when it exists"
        );
        let logo = h.get_path(&url, IP, None).await;
        if present {
            assert_eq!(logo.status, StatusCode::OK, "{url}: {}", logo.text);
            assert_eq!(logo.headers[header::CONTENT_TYPE], "image/svg+xml");
            assert_eq!(logo.text, std::fs::read_to_string(logo_path(file)).unwrap());
        } else {
            assert_eq!(logo.status, StatusCode::NOT_FOUND, "{url}: {}", logo.text);
        }
    }
}

/// The artwork must not be committable, and the hosted deploy must still upload it:
/// `railway up` skips what `.gitignore` names unless `.railwayignore` re-includes it.
#[test]
fn the_logo_files_are_ignored_by_git_and_included_in_the_railway_upload() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let gitignore = std::fs::read_to_string(root.join(".gitignore")).expect(".gitignore");
    let railwayignore =
        std::fs::read_to_string(root.join(".railwayignore")).expect(".railwayignore");
    for file in LOGO_FILES {
        let line = format!("/crates/ibridge-hosted/assets/{file}");
        assert!(
            gitignore.lines().any(|l| l == line),
            ".gitignore ignores {file}"
        );
        assert!(
            railwayignore.lines().any(|l| l == format!("!{line}")),
            ".railwayignore re-includes {file}"
        );
    }
}
