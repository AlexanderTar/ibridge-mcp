// SPDX-License-Identifier: Apache-2.0

//! The stylesheet and icons the pages link, served by the server itself.
//!
//! They are compiled in, so a self-hosted server needs no other site for its look, and the
//! pages make no outside request. The stylesheet is the design system in `site/design`
//! (tokens, then components) followed by `assets/server.css`, the few pieces the pages
//! need beyond it.

use std::sync::LazyLock;

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

const STYLESHEET: &str = concat!(
    include_str!("../../../site/design/tokens.css"),
    include_str!("../../../site/design/components.css"),
    include_str!("../assets/server.css"),
);
/// Apple's logo, which is licensed artwork and is not in the repository. When both files are
/// added, `build.rs` turns on `cfg(apple_logo)`: the server then serves them unmodified, and
/// the button shows the white logo on its black light-mode background and the black one on
/// its white dark-mode background. Each file draws its own button-coloured square, so the
/// button keeps one flat colour (no hover tint) for the square to blend into.
#[cfg(apple_logo)]
const APPLE_LOGO_WHITE: &str = include_str!("../assets/apple-logo-white.svg");
#[cfg(apple_logo)]
const APPLE_LOGO_BLACK: &str = include_str!("../assets/apple-logo-black.svg");
/// The logo files are 56 × 56 with the 44 × 44 button-coloured square inset by 6, so the image
/// is laid out at 44 × 44 and its transparent margin overhangs the button.
#[cfg(apple_logo)]
const APPLE_LOGO_CSS: &str = "
:root { --apple-logo: url(/static/apple-logo-white.svg); }
@media (prefers-color-scheme: dark) { :root:not([data-theme=\"light\"]) { --apple-logo: url(/static/apple-logo-black.svg); } }
:root[data-theme=\"dark\"] { --apple-logo: url(/static/apple-logo-black.svg); }
.btn-apple::before { content: \"\"; flex: none; width: 56px; height: 56px; margin: -6px -6px -6px -14px; background: var(--apple-logo) center / 56px 56px no-repeat; }
";
const FAVICON: &str = include_str!("../../../site/design/icons/b-cloud-arch-favicon.svg");
const MARK_LIGHT: &str = include_str!("../../../site/design/icons/b-cloud-arch-mark-light.svg");
const MARK_DARK: &str = include_str!("../../../site/design/icons/b-cloud-arch-mark-dark.svg");
/// `b-cloud-arch-tile-light.svg` at 180 × 180, because iOS ignores an SVG touch icon.
const TOUCH_ICON: &[u8] = include_bytes!("../assets/apple-touch-icon.png");

/// Five minutes. The files sit at unversioned addresses, so a longer lifetime would leave
/// browsers pairing a new page with the old stylesheet after a deploy.
const CACHE: &str = "public, max-age=300";

/// The stylesheet: the design system, the server's own rules and, when present, the logo rule.
fn stylesheet() -> &'static str {
    static CSS: LazyLock<String> = LazyLock::new(|| {
        #[cfg_attr(
            not(apple_logo),
            expect(unused_mut, reason = "only the logo rule is appended")
        )]
        let mut css = STYLESHEET.to_owned();
        #[cfg(apple_logo)]
        css.push_str(APPLE_LOGO_CSS);
        css
    });
    &CSS
}

pub(crate) fn routes() -> Router {
    let router = Router::new()
        .route(
            "/static/ibridge.css",
            get(|| async { asset("text/css; charset=utf-8", stylesheet().as_bytes()) }),
        )
        .route(
            "/static/favicon.svg",
            get(|| async { asset("image/svg+xml", FAVICON.as_bytes()) }),
        )
        .route(
            "/static/mark-light.svg",
            get(|| async { asset("image/svg+xml", MARK_LIGHT.as_bytes()) }),
        )
        .route(
            "/static/mark-dark.svg",
            get(|| async { asset("image/svg+xml", MARK_DARK.as_bytes()) }),
        )
        .route(
            "/static/apple-touch-icon.png",
            get(|| async { asset("image/png", TOUCH_ICON) }),
        );
    #[cfg(apple_logo)]
    let router = router
        .route(
            "/static/apple-logo-white.svg",
            get(|| async { asset("image/svg+xml", APPLE_LOGO_WHITE.as_bytes()) }),
        )
        .route(
            "/static/apple-logo-black.svg",
            get(|| async { asset("image/svg+xml", APPLE_LOGO_BLACK.as_bytes()) }),
        );
    router
}

fn asset(content_type: &'static str, body: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body,
    )
        .into_response()
}
