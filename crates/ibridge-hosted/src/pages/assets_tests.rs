// SPDX-License-Identifier: Apache-2.0

//! The stylesheet and icons the pages link are served by the server itself: same origin,
//! cacheable, and nothing is fetched from anywhere else.

use axum::http::{StatusCode, header};

use super::test_rig::IP;
use crate::oauth::Access;
use crate::oauth::test_support::{Harness, harness};

const CSS: &str = "/static/ibridge.css";
const STATIC_FAVICON: &str = "/static/favicon.svg";
const STATIC_TOUCH_ICON: &str = "/static/apple-touch-icon.png";
// The icon files at the server root, where Claude's connector list looks for them.
const FAVICON: &str = "/favicon.svg";
const FAVICON_PNG: &str = "/favicon-32.png";
const FAVICON_ICO: &str = "/favicon.ico";
const TOUCH_ICON: &str = "/apple-touch-icon.png";
const MARK_LIGHT: &str = "/static/mark-light.svg";
const MARK_DARK: &str = "/static/mark-dark.svg";

#[tokio::test]
async fn assets_are_served_with_type_and_cache_headers() {
    let h = harness(Access::MultiTenant).await;
    for (path, kind) in [
        (CSS, "text/css; charset=utf-8"),
        (STATIC_FAVICON, "image/svg+xml"),
        (MARK_LIGHT, "image/svg+xml"),
        (MARK_DARK, "image/svg+xml"),
        (STATIC_TOUCH_ICON, "image/png"),
        (FAVICON, "image/svg+xml"),
        (FAVICON_PNG, "image/png"),
        (FAVICON_ICO, "image/x-icon"),
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
            format!(r#"rel="icon" href="{FAVICON}" type="image/svg+xml""#),
            format!(r#"rel="icon" href="{FAVICON_PNG}" type="image/png" sizes="32x32""#),
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

/// Claude's connector list shows the root `/favicon.svg` only when it is a full-bleed square
/// with solid colours: a transparent or rounded tile, or colours chosen by a media query, show
/// as no icon. The ICO holds the three sizes browsers ask for.
#[tokio::test]
async fn the_root_favicons_are_a_square_tile_in_every_size() {
    let h = harness(Access::MultiTenant).await;
    let svg = h.get_path(FAVICON, IP, None).await.text;
    assert!(
        svg.contains(r#"<rect x="0" y="0" width="64" height="64""#),
        "a full-bleed rect: {svg}"
    );
    for forbidden in ["rx=", "@media", "<style", "stroke=\"#D5E3E6\""] {
        assert!(!svg.contains(forbidden), "no {forbidden} in the tile: {svg}");
    }

    let png = h.get_path(FAVICON_PNG, IP, None).await.bytes;
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "a PNG");
    assert_eq!(png[16..24], [0, 0, 0, 32, 0, 0, 0, 32], "32 x 32");

    let ico = h.get_path(FAVICON_ICO, IP, None).await.bytes;
    assert_eq!(ico[..4], [0, 0, 1, 0], "an ICO header");
    assert_eq!(ico[4], 3, "three images");
    let sizes: Vec<u8> = (0..3).map(|i| ico[6 + 16 * i]).collect();
    assert_eq!(sizes, [16, 32, 48], "the sizes");
}

const LOGO_FILES: [&str; 2] = ["apple-logo-white.svg", "apple-logo-black.svg"];

fn logo_path(file: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join(file)
}

/// Apple's logo artwork is in the repository as `assets/apple-logo-white.svg` and
/// `assets/apple-logo-black.svg`; a self-hoster may delete it. With both files the
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

/// The logo files are Apple's own artwork, committed unmodified (these are the sha256 of the
/// files in Apple's "Sign in with Apple - Logo Only" set), so a clean checkout and the Docker
/// build serve the logo with no step to add it. Nothing ignores them, `build.rs` turns the logo on,
/// and the notice says they are not under the Apache licence.
///
/// This guards the repository, not a fork: a self-hoster who deletes the files (the notice allows
/// it) deletes this test with them. The test above passes in both states.
#[test]
fn the_logo_files_are_apples_originals_committed_in_the_repo() {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (file, sha256) in LOGO_FILES.iter().zip([
        "fd66b19f3f09ade3650cc3289a744ee9636764068243805d9c74deeecbde191b",
        "7ee1bc1706bc228f37a937de914e2ebe1605aebba3c35f11c3963087573fc11f",
    ]) {
        let bytes = std::fs::read(logo_path(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let hex = Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut hex, byte| {
                write!(hex, "{byte:02x}").expect("writing to a String");
                hex
            });
        assert_eq!(hex, sha256, "{file} is Apple's original, unmodified");
    }
    const { assert!(cfg!(apple_logo), "build.rs turns the logo on") };

    let gitignore = std::fs::read_to_string(root.join(".gitignore")).expect(".gitignore");
    assert!(
        !gitignore.contains("apple-logo"),
        "nothing ignores the logo files"
    );
    assert!(
        !root.join(".railwayignore").exists(),
        "no .railwayignore re-include is left"
    );
    for notice in [
        root.join("NOTICE"),
        root.join("crates/ibridge-hosted/assets/NOTICE"),
    ] {
        let text = std::fs::read_to_string(&notice)
            .unwrap_or_else(|e| panic!("{notice:?}: {e}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            text.contains("apple-logo-white.svg")
                && text.contains("Apple")
                && text.contains("not covered by the Apache"),
            "{notice:?} labels the logo as Apple's artwork outside the licence: {text}"
        );
    }
}

#[tokio::test]
async fn the_stylesheet_has_a_destructive_colour_and_greys_the_delete_button_until_confirmed() {
    let h = harness(Access::MultiTenant).await;
    let css = h.get_path(CSS, IP, None).await.text;
    for token in [
        "--color-danger:",
        "--color-danger-hover:",
        "--color-on-danger:",
    ] {
        // Light, then dark under both the media query and a forced theme.
        assert!(
            css.matches(token).count() >= 3,
            "{token} is defined for light and dark: {css}"
        );
    }
    assert!(
        css.contains(".btn--danger{") || css.contains(".btn--danger {"),
        "a destructive button style"
    );
    assert!(
        css.contains(":not(:has(input[name=confirm]:checked)) .btn--danger"),
        "the button is inactive until its box is ticked, with no script"
    );
}

/// `assets/design/` holds copies of the design-system files in `site/design/`, because a
/// published crate cannot include files outside its own directory. Copy the file again when
/// the site's changes.
#[test]
fn the_design_copies_match_the_site() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (copy, original) in [
        ("tokens.css", "tokens.css"),
        ("components.css", "components.css"),
        ("b-cloud-arch-favicon.svg", "icons/b-cloud-arch-favicon.svg"),
        (
            "b-cloud-arch-mark-light.svg",
            "icons/b-cloud-arch-mark-light.svg",
        ),
        (
            "b-cloud-arch-mark-dark.svg",
            "icons/b-cloud-arch-mark-dark.svg",
        ),
    ] {
        let mine = std::fs::read(manifest.join("assets/design").join(copy))
            .unwrap_or_else(|e| panic!("assets/design/{copy}: {e}"));
        let site = std::fs::read(manifest.join("../../site/design").join(original))
            .unwrap_or_else(|e| panic!("site/design/{original}: {e}"));
        assert!(
            mine == site,
            "assets/design/{copy} differs from site/design/{original}"
        );
    }
}
