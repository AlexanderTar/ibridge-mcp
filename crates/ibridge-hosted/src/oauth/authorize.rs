// SPDX-License-Identifier: Apache-2.0

//! The sign-in page: `/authorize` shows it, validates the password and issues a code.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use askama::Template;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router};
use base64::Engine;
use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use url::Url;

use super::client::ClientInfo;
use super::codes::PendingCode;
use super::{Peer, Shared, address_key};
use crate::store::Scope;

const CSRF_COOKIE: &str = "__Host-ibridge_csrf";
/// The one message every failed or refused sign-in shows, so the page cannot be
/// used to learn which addresses exist, are allowed or are locked out.
const GENERIC_FAILURE: &str =
    "Sign-in failed. Check the address and app-specific password, then try again in a few minutes.";
const CSRF_LIFETIME_SECS: u32 = 30 * 60;
const MAX_FORM: usize = 8 * 1024;
const MAX_STATE: usize = 512;
const MAX_SCOPE: usize = 256;

pub(super) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/authorize", get(show).post(submit))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .with_state(Arc::clone(shared))
}

/// The authorization request, from the query string or the posted form.
#[derive(Deserialize)]
struct Params {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

/// The posted form. It has no `Debug` so the password cannot reach a log.
#[derive(Deserialize)]
struct SignIn {
    #[serde(flatten)]
    params: Params,
    csrf: String,
    apple_id: String,
    password: String,
    read_only: Option<String>,
}

/// A request that passed every check up to the password.
struct Valid {
    client: ClientInfo,
    redirect_uri: String,
    challenge: String,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    wants_write: bool,
}

/// Why a request was refused.
enum Refusal {
    /// The client or redirect cannot be trusted, so nothing is sent to it.
    Page(&'static str),
    /// The redirect is registered, so the client hears the error.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: &'static str,
        description: &'static str,
    },
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizePage<'a> {
    client_name: &'a str,
    redirect_host: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    code_challenge: &'a str,
    state: Option<&'a str>,
    scope: Option<&'a str>,
    resource: Option<&'a str>,
    csrf: &'a str,
    apple_id: &'a str,
    read_only: bool,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage<'a> {
    heading: &'a str,
    message: &'a str,
}

async fn show(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    Query(params): Query<Params>,
) -> Response {
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            GENERIC_FAILURE,
        );
    }
    match validate(&shared, &params).await {
        Err(refusal) => refuse(&shared, refusal),
        Ok(valid) => {
            let Some(token) = new_csrf_token() else {
                tracing::error!("random source failed while making a sign-in token");
                return message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    "Something went wrong on our side. Try signing in again in a moment.",
                );
            };
            let read_only = !valid.wants_write;
            let fill = Fill {
                csrf: &token,
                apple_id: "",
                read_only,
                error: None,
            };
            let mut response = form_page(&valid, &fill, StatusCode::OK);
            set_csrf_cookie(&mut response, &token, CSRF_LIFETIME_SECS);
            response
        }
    }
}

async fn submit(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<SignIn>,
) -> Response {
    if !csrf_matches(&headers, &form.csrf) {
        return message(
            StatusCode::FORBIDDEN,
            "This page expired",
            "This sign-in page expired. Go back to the app and start the sign-in again.",
        );
    }
    let apple_id = AppleId::try_from(form.apple_id.trim()).ok();
    let address = apple_id.as_ref().map(address_key);
    if !shared
        .limits
        .allow(&peer.0, address.as_deref(), Instant::now())
    {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in failed",
            GENERIC_FAILURE,
        );
    }
    let valid = match validate(&shared, &form.params).await {
        Ok(valid) => valid,
        Err(refusal) => return refuse(&shared, refusal),
    };
    let read_only = form.read_only.is_some();
    let again = |status| {
        let fill = Fill {
            csrf: &form.csrf,
            apple_id: form.apple_id.trim(),
            read_only,
            error: Some(GENERIC_FAILURE),
        };
        form_page(&valid, &fill, status)
    };
    let Some(apple_id) = apple_id.filter(|id| shared.config.may_sign_in(id)) else {
        return again(StatusCode::BAD_REQUEST);
    };
    let credentials = Credentials::new(apple_id, SecretString::from(form.password));
    let validated = match shared.checker.check(credentials).await {
        Ok(validated) => validated,
        Err(crate::store::StoreError::Rejected) => return again(StatusCode::BAD_REQUEST),
        Err(error) => {
            tracing::error!(%error, "sign-in check failed");
            return again(StatusCode::BAD_REQUEST);
        }
    };
    // A client that asked for read alone never gets write, whatever the box says.
    let scope = if read_only || !valid.wants_write {
        Scope::Read
    } else {
        Scope::ReadWrite
    };
    let issued = match shared
        .store
        .seal_validated_under_code(&validated, scope, SystemTime::now())
        .await
    {
        Ok(issued) => issued,
        Err(error) => {
            tracing::error!(%error, "could not seal the sign-in");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Something went wrong on our side. Try signing in again in a moment.",
            );
        }
    };
    let code = issued.code.expose_secret();
    shared.codes.insert(
        code,
        PendingCode {
            client_id: valid.client.id.clone(),
            redirect_uri: valid.redirect_uri.clone(),
            challenge: valid.challenge.clone(),
        },
        Instant::now(),
    );
    let mut response = redirect(
        &shared,
        &valid.redirect_uri,
        valid.state.as_deref(),
        &[("code", code)],
    );
    set_csrf_cookie(&mut response, "", 0);
    response
}

/// Checks everything about the request except the person signing in.
async fn validate(shared: &Shared, params: &Params) -> Result<Valid, Refusal> {
    let client_id = params.client_id.as_deref().ok_or(Refusal::Page(
        "The sign-in link is missing its application.",
    ))?;
    let client = shared.resolve_client(client_id).await.ok_or(Refusal::Page(
        "The application asking you to sign in is not known to this server.",
    ))?;
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .filter(|uri| client.allows_redirect(uri))
        .ok_or(Refusal::Page(
            "The application asked to return to an address it has not registered.",
        ))?
        .to_owned();
    let state = params.state.clone();
    let fail = |error, description| Refusal::Redirect {
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
        error,
        description,
    };
    if params.response_type.as_deref() != Some("code") {
        return Err(fail(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    let challenge = params
        .code_challenge
        .as_deref()
        .filter(|value| well_formed_challenge(value))
        .ok_or_else(|| fail("invalid_request", "a PKCE S256 code_challenge is required"))?
        .to_owned();
    if params.code_challenge_method.as_deref() != Some("S256") {
        return Err(fail(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    if params
        .resource
        .as_deref()
        .is_some_and(|resource| resource != shared.config.url("/mcp"))
    {
        return Err(fail(
            "invalid_target",
            "resource must be this server's MCP URL",
        ));
    }
    if state
        .as_deref()
        .is_some_and(|value| value.len() > MAX_STATE)
        || params
            .scope
            .as_deref()
            .is_some_and(|value| value.len() > MAX_SCOPE)
    {
        return Err(fail("invalid_request", "state or scope is too long"));
    }
    let asked: Vec<&str> = params
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let names_icloud = asked.iter().any(|scope| scope.starts_with("icloud."));
    let wants_write = !names_icloud || asked.contains(&"icloud.write");
    Ok(Valid {
        client,
        redirect_uri: redirect_uri.clone(),
        challenge,
        state: state.clone(),
        scope: params.scope.clone(),
        resource: params.resource.clone(),
        wants_write,
    })
}

/// A base64url SHA-256 digest: 43 characters.
fn well_formed_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn refuse(shared: &Shared, refusal: Refusal) -> Response {
    match refusal {
        Refusal::Page(text) => message(StatusCode::BAD_REQUEST, "Cannot sign in", text),
        Refusal::Redirect {
            redirect_uri,
            state,
            error,
            description,
        } => redirect(
            shared,
            &redirect_uri,
            state.as_deref(),
            &[("error", error), ("error_description", description)],
        ),
    }
}

/// Sends the browser back to the client with `pairs`, plus `state` and the issuer (RFC 9207).
fn redirect(
    shared: &Shared,
    redirect_uri: &str,
    state: Option<&str>,
    pairs: &[(&str, &str)],
) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return message(
            StatusCode::BAD_REQUEST,
            "Cannot sign in",
            "The return address is not valid.",
        );
    };
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", &shared.config.issuer());
    }
    let Ok(location) = HeaderValue::from_str(url.as_str()) else {
        return message(
            StatusCode::BAD_REQUEST,
            "Cannot sign in",
            "The return address is not valid.",
        );
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    harden(&mut response);
    response
}

/// What the form shows beyond the request itself.
struct Fill<'a> {
    csrf: &'a str,
    apple_id: &'a str,
    read_only: bool,
    error: Option<&'a str>,
}

fn form_page(valid: &Valid, fill: &Fill<'_>, status: StatusCode) -> Response {
    let host = redirect_host(&valid.redirect_uri);
    let page = AuthorizePage {
        client_name: &valid.client.name,
        redirect_host: &host,
        client_id: &valid.client.id,
        redirect_uri: &valid.redirect_uri,
        code_challenge: &valid.challenge,
        state: valid.state.as_deref(),
        scope: valid.scope.as_deref(),
        resource: valid.resource.as_deref(),
        csrf: fill.csrf,
        apple_id: fill.apple_id,
        read_only: fill.read_only,
        error: fill.error,
    };
    html(status, page.render())
}

fn message(status: StatusCode, heading: &str, text: &str) -> Response {
    html(
        status,
        MessagePage {
            heading,
            message: text,
        }
        .render(),
    )
}

fn html(status: StatusCode, rendered: Result<String, askama::Error>) -> Response {
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
fn harden(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
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

/// What to call the place the browser returns to.
fn redirect_host(redirect_uri: &str) -> String {
    let Ok(url) = Url::parse(redirect_uri) else {
        return "the application".to_owned();
    };
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => format!("the {} app", url.scheme()),
    }
}

/// A fresh token, or `None` when the system has no randomness: the page is then refused, not weakened.
fn new_csrf_token() -> Option<String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

fn set_csrf_cookie(response: &mut Response, token: &str, max_age: u32) {
    let cookie =
        format!("{CSRF_COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Double-submit check: the form's token must equal the `__Host-` cookie's.
fn csrf_matches(headers: &HeaderMap, from_form: &str) -> bool {
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(CSRF_COOKIE)?.strip_prefix('='));
    match cookie {
        Some(cookie) if !cookie.is_empty() && !from_form.is_empty() => {
            cookie.as_bytes().ct_eq(from_form.as_bytes()).into()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::SystemTime;

    use axum::http::{StatusCode, header};

    use crate::oauth::Access;
    use crate::oauth::test_support::{
        ADA, ASP_ALL, ASP_CALDAV_ONLY, ASP_MAIL_ONLY, Harness, LOOPBACK_REDIRECT, MARKUP_CLIENT_ID,
        PUBLIC, harness,
    };
    use crate::store::Scope;

    const IP: &str = "203.0.113.7";
    const GENERIC: &str = "Sign-in failed. Check the address and app-specific password, then try again in a few minutes.";

    fn code_from(location: &url::Url) -> String {
        location
            .query_pairs()
            .find(|(name, _)| name == "code")
            .map(|(_, value)| value.into_owned())
            .expect("the redirect carries a code")
    }

    fn query(location: &url::Url, name: &str) -> Option<String> {
        location
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    #[tokio::test]
    async fn authorize_shows_client_name_and_redirect_host() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text);
        assert!(page.text.contains("Claude Test"), "names the client");
        assert!(
            page.text.contains("127.0.0.1:53682"),
            "names the host the browser returns to"
        );
        assert!(page.text.contains("app-specific password"));
        assert!(
            page.text.contains("main Apple ID password"),
            "warns against the main password"
        );
        assert!(
            page.text.contains("https://support.apple.com/"),
            "links Apple's guide"
        );
        assert_eq!(
            page.headers[header::CACHE_CONTROL],
            "no-store",
            "a page with a password form is never cached"
        );
        let csp = page.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("ascii");
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "cannot be framed: {csp}"
        );

        let https = h
            .get_authorize(
                &Harness::authorize_path(&[], &[("redirect_uri", "https://client.example/cb")]),
                IP,
            )
            .await;
        assert!(
            https.text.contains("client.example"),
            "an https redirect shows its host"
        );

        let markup = h
            .get_authorize(
                &Harness::authorize_path(
                    &[],
                    &[
                        ("client_id", MARKUP_CLIENT_ID),
                        ("redirect_uri", "https://markup.example/cb"),
                    ],
                ),
                IP,
            )
            .await;
        assert_eq!(markup.status, StatusCode::OK);
        assert!(
            !markup.text.contains("<script>alert(1)</script>"),
            "a client name is text, never markup"
        );
    }

    #[tokio::test]
    async fn authorize_never_redirects_for_an_unknown_client_or_redirect() {
        let h = harness(Access::MultiTenant).await;
        for path in [
            Harness::authorize_path(&[], &[("client_id", "https://unknown.example/c.json")]),
            Harness::authorize_path(&[], &[("client_id", "dcr_nope")]),
            Harness::authorize_path(&["client_id"], &[]),
            Harness::authorize_path(&[], &[("redirect_uri", "https://evil.example/cb")]),
            Harness::authorize_path(&[], &[("redirect_uri", "http://127.0.0.1:5/other")]),
            Harness::authorize_path(&["redirect_uri"], &[]),
        ] {
            let reply = h.get_authorize(&path, IP).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
            assert!(
                reply.headers.get(header::LOCATION).is_none(),
                "{path} must not redirect"
            );
            assert!(
                reply.headers.get(header::SET_COOKIE).is_none(),
                "{path} sets no session"
            );
        }
    }

    #[tokio::test]
    async fn authorize_reports_request_errors_to_the_registered_redirect() {
        let h = harness(Access::MultiTenant).await;
        for (path, error) in [
            (
                Harness::authorize_path(&["code_challenge"], &[]),
                "invalid_request",
            ),
            (
                Harness::authorize_path(&[], &[("code_challenge_method", "plain")]),
                "invalid_request",
            ),
            (
                Harness::authorize_path(&["code_challenge_method"], &[]),
                "invalid_request",
            ),
            (
                Harness::authorize_path(&[], &[("response_type", "token")]),
                "unsupported_response_type",
            ),
            (
                Harness::authorize_path(&[], &[("resource", "https://other.example/mcp")]),
                "invalid_target",
            ),
        ] {
            let reply = h.get_authorize(&path, IP).await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER, "{path}");
            let to = reply.location();
            assert!(to.as_str().starts_with(LOOPBACK_REDIRECT), "{to}");
            assert_eq!(query(&to, "error").as_deref(), Some(error), "{path}");
            assert_eq!(query(&to, "state").as_deref(), Some("xyz"));
            assert_eq!(query(&to, "iss").as_deref(), Some(PUBLIC));
        }
    }

    #[tokio::test]
    async fn session_cookie_is_host_prefixed() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let set = page.headers[header::SET_COOKIE].to_str().expect("ascii");
        assert!(
            set.starts_with("__Host-"),
            "the cookie name carries the prefix: {set}"
        );
        for attribute in ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"] {
            assert!(set.contains(attribute), "{attribute} is set: {set}");
        }
        assert!(
            !set.contains("Domain"),
            "a __Host- cookie has no Domain: {set}"
        );
        let value = set
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, v)| v);
        assert!(
            value.is_some_and(|value| value.len() >= 32),
            "the token is long: {set}"
        );
    }

    #[tokio::test]
    async fn csrf_required() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let fields = page.form_fields();
        let csrf = page.input("csrf");
        let cookie = page.cookie_pair();

        let no_cookie = h
            .post_raw(IP, None, &fields, &csrf, ADA, ASP_ALL, None)
            .await;
        assert_eq!(no_cookie.status, StatusCode::FORBIDDEN, "no cookie");
        let wrong_field = h
            .post_raw(
                IP,
                Some(&cookie),
                &fields,
                "not-the-token",
                ADA,
                ASP_ALL,
                None,
            )
            .await;
        assert_eq!(
            wrong_field.status,
            StatusCode::FORBIDDEN,
            "wrong form token"
        );
        let wrong_cookie = h
            .post_raw(
                IP,
                Some("__Host-ibridge_csrf=forged"),
                &fields,
                &csrf,
                ADA,
                ASP_ALL,
                None,
            )
            .await;
        assert_eq!(wrong_cookie.status, StatusCode::FORBIDDEN, "wrong cookie");
        let empty = h
            .post_raw(
                IP,
                Some("__Host-ibridge_csrf="),
                &fields,
                "",
                ADA,
                ASP_ALL,
                None,
            )
            .await;
        assert_eq!(
            empty.status,
            StatusCode::FORBIDDEN,
            "empty tokens do not match"
        );
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            0,
            "a forged post never reaches iCloud"
        );

        let ok = h
            .post_raw(IP, Some(&cookie), &fields, &csrf, ADA, ASP_ALL, None)
            .await;
        assert_eq!(
            ok.status,
            StatusCode::SEE_OTHER,
            "the matching pair signs in: {}",
            ok.text
        );
    }

    #[tokio::test]
    async fn validates_via_imap_or_dav() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        for (password, signs_in) in [
            (ASP_MAIL_ONLY, true),
            (ASP_CALDAV_ONLY, true),
            (ASP_ALL, true),
            ("wrong-wrong-wrong", false),
        ] {
            let reply = h.post_form(&page, IP, ADA, password, None).await;
            if signs_in {
                assert_eq!(
                    reply.status,
                    StatusCode::SEE_OTHER,
                    "{password}: {}",
                    reply.text
                );
                assert!(reply.location().as_str().starts_with(LOOPBACK_REDIRECT));
            } else {
                assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{password}");
                assert_eq!(reply.error_text().as_deref(), Some(GENERIC));
                assert!(
                    reply.headers.get(header::LOCATION).is_none(),
                    "no code for a wrong password"
                );
            }
        }
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            4,
            "every attempt ran the live check"
        );
    }

    #[tokio::test]
    async fn caldav_only_account_signs_in() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let reply = h.post_form(&page, IP, ADA, ASP_CALDAV_ONLY, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        let to = reply.location();
        assert!(to.as_str().starts_with(LOOPBACK_REDIRECT), "{to}");
        assert_eq!(query(&to, "state").as_deref(), Some("xyz"));
        assert_eq!(query(&to, "iss").as_deref(), Some(PUBLIC), "RFC 9207 iss");
        let code = code_from(&to);
        assert!(code.starts_with("ibc_"), "a store code");
        assert!(
            reply.headers[header::CACHE_CONTROL]
                .to_str()
                .expect("ascii")
                .contains("no-store"),
            "the redirect carrying a code is not cached"
        );
        assert_eq!(reply.headers[header::REFERRER_POLICY], "no-referrer");

        // The password is sealed under that code, so exchanging it opens the account.
        let tokens = h
            .store
            .exchange_code(&code, SystemTime::now())
            .await
            .expect("the code exchanges");
        let call = h
            .store
            .open_for_call(
                secrecy::ExposeSecret::expose_secret(&tokens.access),
                SystemTime::now(),
            )
            .await
            .expect("the access token opens the grant");
        assert_eq!(call.apple_id.as_str(), ADA);
    }

    #[tokio::test]
    async fn read_only_checkbox_sets_scope() {
        let h = harness(Access::MultiTenant).await;
        let both = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let only_read = h
            .get_authorize(
                &Harness::authorize_path(&[], &[("scope", "icloud.read offline_access")]),
                IP,
            )
            .await;
        assert!(
            !both.text.contains(" checked"),
            "read-only starts unchecked when the client asked for write"
        );
        assert!(
            only_read.text.contains(" checked"),
            "read-only starts checked when the client asked for read alone"
        );

        let granted = |reply: &crate::oauth::test_support::Reply| code_from(&reply.location());
        let checked = h.post_form(&both, IP, ADA, ASP_ALL, Some("on")).await;
        let unchecked = h.post_form(&both, IP, ADA, ASP_ALL, None).await;
        let read_request = h.post_form(&only_read, IP, ADA, ASP_ALL, None).await;
        let scope_of = |code: String| {
            let store = h.store.clone();
            async move {
                store
                    .exchange_code(&code, SystemTime::now())
                    .await
                    .expect("exchange")
                    .scope
            }
        };
        assert_eq!(
            scope_of(granted(&checked)).await,
            Scope::Read,
            "the box wins"
        );
        assert_eq!(
            scope_of(granted(&unchecked)).await,
            Scope::ReadWrite,
            "write was requested and allowed"
        );
        assert_eq!(
            scope_of(granted(&read_request)).await,
            Scope::Read,
            "a client that asked for read alone never gets write"
        );
    }

    #[tokio::test]
    async fn rate_limits_ip_10_per_min_and_account_5_per_15min_generic_error() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;

        // One IP, ten different addresses: the eleventh attempt is refused.
        for n in 0..10 {
            let reply = h
                .post_form(
                    &page,
                    "198.51.100.1",
                    &format!("user{n}@icloud.com"),
                    "wrong-wrong",
                    None,
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
            assert_eq!(reply.error_text().as_deref(), Some(GENERIC));
        }
        let checks_before = h.checks.load(Ordering::SeqCst);
        let limited = h
            .post_form(&page, "198.51.100.1", "user99@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited.error_text().as_deref(),
            Some(GENERIC),
            "a limited attempt gets the same message as a wrong password"
        );
        assert!(
            limited.headers.get(header::LOCATION).is_none(),
            "even a right password gets no code"
        );
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            checks_before,
            "a limited attempt never reaches iCloud"
        );
        let elsewhere = h
            .post_form(&page, "198.51.100.2", "user99@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            elsewhere.status,
            StatusCode::SEE_OTHER,
            "another IP has its own budget"
        );

        // One address from five IPs: the sixth attempt is refused, whatever the IP.
        for n in 0..5 {
            let reply = h
                .post_form(
                    &page,
                    &format!("192.0.2.{n}"),
                    "bob@icloud.com",
                    "wrong-wrong",
                    None,
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
        }
        let locked = h
            .post_form(&page, "192.0.2.50", "Bob@iCloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            locked.status,
            StatusCode::TOO_MANY_REQUESTS,
            "the address is spent, in any letter case"
        );
        assert_eq!(locked.error_text().as_deref(), Some(GENERIC));
    }

    #[tokio::test]
    async fn ipv6_peers_share_one_budget_per_64() {
        let h = harness(Access::MultiTenant).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        // Ten addresses inside one /64 spend one budget between them.
        for n in 0..10 {
            let reply = h
                .post_form(
                    &page,
                    &format!("2001:db8:1:2::{n:x}"),
                    &format!("user{n}@icloud.com"),
                    "wrong-wrong",
                    None,
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
        }
        let limited = h
            .post_form(
                &page,
                "2001:db8:1:2:ffff::1",
                "user99@icloud.com",
                ASP_ALL,
                None,
            )
            .await;
        assert_eq!(
            limited.status,
            StatusCode::TOO_MANY_REQUESTS,
            "another address in the same /64 is limited"
        );
        let elsewhere = h
            .post_form(&page, "2001:db8:1:3::1", "user99@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            elsewhere.status,
            StatusCode::SEE_OTHER,
            "a different /64 has its own budget"
        );
        // A dual-stack socket shows IPv4 clients as mapped addresses; they stay separate hosts.
        for (n, ip) in ["::ffff:192.0.2.1", "::ffff:192.0.2.2"].iter().enumerate() {
            let reply = h
                .post_form(&page, ip, &format!("mapped{n}@icloud.com"), ASP_ALL, None)
                .await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER, "{ip}");
        }
    }

    #[tokio::test]
    async fn allowlist_enforced_in_self_host() {
        let ada = ibridge_core::AppleId::try_from(ADA).expect("ada");
        let h = harness(Access::AllowList(vec![ada])).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let allowed = h
            .post_form(&page, IP, "Ada@iCloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            allowed.status,
            StatusCode::SEE_OTHER,
            "an allowed address signs in: {}",
            allowed.text
        );
        let checks = h.checks.load(Ordering::SeqCst);

        let denied = h
            .post_form(&page, IP, "bob@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(denied.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            denied.error_text().as_deref(),
            Some(GENERIC),
            "the refusal does not say the address is off the list"
        );
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            checks,
            "an address off the list never gets its password sent to iCloud"
        );

        let open = harness(Access::MultiTenant).await;
        let page = open
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;
        let anyone = open
            .post_form(&page, IP, "bob@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            anyone.status,
            StatusCode::SEE_OTHER,
            "multi-tenant lets anyone try"
        );
    }
}
