// SPDX-License-Identifier: Apache-2.0

//! What the sign-in pages (`/authorize`, `/account`) share: hardened HTML responses,
//! random tokens, `__Host-` cookies and the double-submit comparison.

use askama::Template;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use subtle::ConstantTimeEq;

/// The one message every failed or refused sign-in shows, so a page cannot be
/// used to learn which addresses exist, are allowed or are locked out.
pub(crate) const GENERIC_FAILURE: &str =
    "Sign-in failed. Check the address and app-specific password, then try again in a few minutes.";

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage<'a> {
    heading: &'a str,
    message: &'a str,
    /// Shown as a problem; otherwise as plain news.
    alert: bool,
}

/// A page that says `text` under `heading`, as a problem.
pub(crate) fn message(status: StatusCode, heading: &str, text: &str) -> Response {
    html(
        status,
        MessagePage {
            heading,
            message: text,
            alert: true,
        }
        .render(),
    )
}

/// A page that says `text` under `heading`, for something that went right.
pub(crate) fn notice(status: StatusCode, heading: &str, text: &str) -> Response {
    html(
        status,
        MessagePage {
            heading,
            message: text,
            alert: false,
        }
        .render(),
    )
}

/// `rendered` as a hardened HTML response, or a bare 500 when the template failed.
pub(crate) fn html(status: StatusCode, rendered: Result<String, askama::Error>) -> Response {
    let Ok(body) = rendered else {
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
        harden(&mut response);
        return response;
    };
    let mut response = (status, Html(body)).into_response();
    harden(&mut response);
    response
}

/// Headers every sign-in response carries: never cached, never framed, no referrer.
pub(crate) fn harden(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

/// 256 random bits as base64url, or `None` when the system has no randomness: the page is then refused, not weakened.
pub(crate) fn random_token() -> Option<String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

/// Sets a `__Host-` cookie (`Secure`, `Path=/`, no `Domain`, `SameSite=Lax`). `max_age` 0 deletes it.
pub(crate) fn set_cookie(response: &mut Response, name: &str, value: &str, max_age: u32) {
    set_cookie_same_site(response, name, value, max_age, "Lax");
}

/// [`set_cookie`] with the `SameSite` value named: `None` is for the one cookie that must
/// ride a cross-site POST, which is Apple's callback.
pub(crate) fn set_cookie_same_site(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: u32,
    same_site: &str,
) {
    debug_assert!(
        name.starts_with("__Host-"),
        "{name} needs the __Host- prefix"
    );
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite={same_site}"
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// The value of the request's cookie `name`, if it sent one.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

/// Constant-time equality of two tokens. An empty token never matches.
pub(crate) fn tokens_match(left: &str, right: &str) -> bool {
    !left.is_empty() && !right.is_empty() && left.as_bytes().ct_eq(right.as_bytes()).into()
}

/// Double-submit check: the form's token must equal the cookie `name` carries.
pub(crate) fn csrf_matches(headers: &HeaderMap, cookie: &str, from_form: &str) -> bool {
    cookie_value(headers, cookie).is_some_and(|value| tokens_match(value, from_form))
}

/// A 303 to `location`, never cached.
pub(crate) fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    harden(&mut response);
    response
}
