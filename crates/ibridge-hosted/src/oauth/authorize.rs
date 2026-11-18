// SPDX-License-Identifier: Apache-2.0

//! The sign-in page: `/authorize` shows it, validates the password and issues a code.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use askama::Template;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router};
use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use super::client::ClientInfo;
use super::codes::PendingCode;
use super::pending::PENDING_COOKIE;
use super::{Peer, Shared, address_key};
use crate::billing::{Access, PRICE_TEXT, access};
use crate::pages::account::{address_to_use, link_refusal, session_of};
use crate::store::{Scope, StoreError, User};
use crate::web::{
    GENERIC_FAILURE, cookie_value, csrf_matches, harden, html, message, random_token, set_cookie,
};

const CSRF_COOKIE: &str = "__Host-ibridge_csrf";
const CSRF_LIFETIME_SECS: u32 = 30 * 60;
const MAX_FORM: usize = 8 * 1024;
const MAX_STATE: usize = 512;
const MAX_SCOPE: usize = 256;
/// A stored request waits as long as the store keeps it.
const PENDING_SECS: u32 = 60 * 60;
const TROUBLE: &str = "Something went wrong on our side. Try signing in again in a moment.";

pub(super) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/authorize", get(show).post(submit))
        .route("/authorize/resume", get(resume))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .with_state(Arc::clone(shared))
}

/// The authorization request, from the query string or the posted form.
#[derive(Clone, Deserialize)]
pub(crate) struct Params {
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
    /// Step 1: the stored request's id, to come back to after Sign in with Apple.
    sign_in: Option<&'a str>,
    /// Step 2: the plans to choose from.
    plan: Option<PlanStep<'a>>,
    /// Step 3: the iCloud address already linked to this user, who connects it again.
    linked: Option<&'a str>,
    price: &'static str,
}

/// What the plan step posts to `/billing/checkout`.
struct PlanStep<'a> {
    /// The signed-in session's own token, which checkout checks.
    csrf: &'a str,
    /// The stored request's id.
    pending: &'a str,
}

/// How far a person has got through connecting.
enum Step {
    /// Sign in with Apple is off, or the person is signed in with a plan: the password step.
    Connect(Option<User>),
    /// Not signed in with Apple yet.
    SignIn,
    /// Signed in, with no plan, and the service would take them: pick one.
    Plan { csrf: String },
}

async fn show(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Response {
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            GENERIC_FAILURE,
        );
    }
    form_for(&shared, &headers, &params, None).await
}

/// The query of `/authorize/resume`: the id a stored request was kept under.
#[derive(Deserialize)]
struct Resume {
    pending: String,
}

/// Shows a stored `/authorize` request again, to the browser that stored it and nobody else.
async fn resume(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Query(query): Query<Resume>,
) -> Response {
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            GENERIC_FAILURE,
        );
    }
    let stored = cookie_value(&headers, PENDING_COOKIE).and_then(|owner| {
        shared
            .pending_authorize
            .get(&query.pending, owner, Instant::now())
    });
    match stored {
        Some(params) => form_for(&shared, &headers, &params, Some(&query.pending)).await,
        None => message(
            StatusCode::BAD_REQUEST,
            "This page expired",
            "This sign-in page expired. Go back to the app and start the sign-in again.",
        ),
    }
}

/// Validates the request and renders the step the person is at.
///
/// `resumed` is the id of a stored request this page came back from, when it did.
async fn form_for(
    shared: &Shared,
    headers: &HeaderMap,
    params: &Params,
    resumed: Option<&str>,
) -> Response {
    let valid = match validate(shared, params).await {
        Ok(valid) => valid,
        Err(refusal) => return refuse(shared, refusal),
    };
    let step = match step_of(shared, headers).await {
        Ok(step) => step,
        Err(page) => return *page,
    };
    match step {
        Step::Connect(user) => {
            let Some(token) = random_token() else {
                tracing::error!("random source failed while making a sign-in token");
                return message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    TROUBLE,
                );
            };
            let linked = user.and_then(|user| user.account);
            let fill = Fill {
                csrf: &token,
                apple_id: "",
                read_only: !valid.wants_write,
                error: None,
                linked: linked.as_ref(),
            };
            let mut response = form_page(&valid, &fill, StatusCode::OK);
            set_csrf_cookie(&mut response, &token, CSRF_LIFETIME_SECS);
            response
        }
        Step::SignIn | Step::Plan { .. } => {
            let (id, new_owner) = match keep(shared, headers, params, resumed) {
                Ok(kept) => kept,
                Err(page) => return *page,
            };
            let (sign_in, plan) = match &step {
                Step::Plan { csrf } => (None, Some(PlanStep { csrf, pending: &id })),
                _ => (Some(id.as_str()), None),
            };
            let fill = Fill {
                csrf: "",
                apple_id: "",
                read_only: false,
                error: None,
                linked: None,
            };
            let mut response = render(&valid, &fill, sign_in, plan, StatusCode::OK);
            if let Some(owner) = new_owner {
                set_cookie(&mut response, PENDING_COOKIE, &owner, PENDING_SECS);
            }
            response
        }
    }
}

/// Where this person is: not signed in, signed in and in need of a plan, or ready to connect.
async fn step_of(shared: &Shared, headers: &HeaderMap) -> Result<Step, Box<Response>> {
    if shared.identity.is_none() {
        return Ok(Step::Connect(None));
    }
    let Some((_, session)) = session_of(shared, headers) else {
        return Ok(Step::SignIn);
    };
    let Some(user) = signed_in_user(shared, session.principal.user()).await? else {
        return Ok(Step::SignIn);
    };
    if shared.billing.is_none() || access(&user) == Access::Allowed {
        return Ok(Step::Connect(Some(user)));
    }
    // Nobody pays for a service they cannot join: this is checked before checkout is offered.
    let may_join = match &user.account {
        Some(account) => shared.config.may_sign_in(account),
        None => {
            !shared.config.is_closed()
                && shared.store.has_signup_room().await.map_err(|error| {
                    tracing::error!(%error, "could not count accounts");
                    Box::new(message(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Something went wrong",
                        TROUBLE,
                    ))
                })?
        }
    };
    if may_join {
        Ok(Step::Plan { csrf: session.csrf })
    } else {
        Err(Box::new(full()))
    }
}

async fn signed_in_user(
    shared: &Shared,
    id: Option<crate::store::UserId>,
) -> Result<Option<User>, Box<Response>> {
    let Some(id) = id else {
        return Ok(None);
    };
    shared.store.user(id).await.map_err(|error| {
        tracing::error!(%error, "could not read a signed-in user");
        Box::new(message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            TROUBLE,
        ))
    })
}

fn full() -> Response {
    message(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-ups are full",
        "This service is not taking new accounts right now. Try again later.",
    )
}

/// Stores the request so it survives Sign in with Apple and Stripe, owned by this browser.
///
/// Returns its id, and the owner value to set as a cookie when the browser had none.
fn keep(
    shared: &Shared,
    headers: &HeaderMap,
    params: &Params,
    resumed: Option<&str>,
) -> Result<(String, Option<String>), Box<Response>> {
    let too_many = || {
        Box::new(message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-ins",
            "Many people are signing in right now. Wait a minute, then try again.",
        ))
    };
    let (owner, new_owner) = if let Some(owner) = cookie_value(headers, PENDING_COOKIE) {
        (owner.to_owned(), None)
    } else {
        let owner = random_token().ok_or_else(|| {
            Box::new(message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            ))
        })?;
        (owner.clone(), Some(owner))
    };
    // A request this browser already stored keeps its id.
    if let (Some(id), None) = (resumed, &new_owner) {
        return Ok((id.to_owned(), None));
    }
    let id = shared
        .pending_authorize
        .put(params.clone(), &owner, Instant::now())
        .ok_or_else(too_many)?;
    Ok((id, new_owner))
}

async fn submit(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<SignIn>,
) -> Response {
    if !csrf_matches(&headers, CSRF_COOKIE, &form.csrf) {
        return message(
            StatusCode::FORBIDDEN,
            "This page expired",
            "This sign-in page expired. Go back to the app and start the sign-in again.",
        );
    }
    // With Sign in with Apple on, the person must be signed in, and have a plan if billing
    // is on, before anything is asked of iCloud: posting straight to this page skips no step.
    let user = match connect_user(&shared, &headers).await {
        Ok(user) => user,
        Err(page) => return *page,
    };
    // Which address the person is connecting. A linked user can connect only that one.
    let chosen = match &user {
        Some(user) => address_to_use(&shared, user.account.clone(), Some(&form.apple_id)),
        None => AppleId::try_from(form.apple_id.trim()).map_err(|_| GENERIC_FAILURE.to_owned()),
    };
    let address = chosen.as_ref().ok().map(address_key);
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
    let linked = user.as_ref().and_then(|user| user.account.as_ref());
    let again = |status, error: &str| {
        let fill = Fill {
            csrf: &form.csrf,
            apple_id: form.apple_id.trim(),
            read_only,
            error: Some(error),
            linked,
        };
        form_page(&valid, &fill, status)
    };
    // ponytail: an address off the allowlist is refused at once, while an allowed one
    // waits for the live iCloud check, so response time shows which addresses are allowed.
    // Accepted for self-host, where the sign-in page is reached by the owner's own
    // clients; a fixed minimum response time for refusals is the upgrade.
    let apple_id = match chosen {
        Ok(apple_id) if shared.config.may_sign_in(&apple_id) => apple_id,
        Ok(_) => return again(StatusCode::BAD_REQUEST, GENERIC_FAILURE),
        Err(refusal) => return again(StatusCode::BAD_REQUEST, &refusal),
    };
    let credentials = Credentials::new(apple_id, SecretString::from(form.password));
    let validated = match shared.checker.check(credentials).await {
        Ok(validated) => validated,
        Err(StoreError::Rejected) => return again(StatusCode::BAD_REQUEST, GENERIC_FAILURE),
        Err(error) => {
            tracing::error!(%error, "sign-in check failed");
            return again(StatusCode::BAD_REQUEST, GENERIC_FAILURE);
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
        .seal_validated_under_code(
            &validated,
            scope,
            SystemTime::now(),
            user.as_ref().map(|user| user.id),
        )
        .await
    {
        Ok(issued) => issued,
        Err(error) => return seal_refused(&error, again),
    };
    // A registration someone signed in through is kept; unused ones are swept.
    if let Err(error) = shared.registry.mark_used(&valid.client.id).await {
        tracing::error!(%error, "could not mark the client as used");
    }
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

/// The page for a sign-in the store would not seal.
fn seal_refused(error: &StoreError, again: impl Fn(StatusCode, &str) -> Response) -> Response {
    match error {
        // The page does not say why, so it cannot be used to learn which accounts are suspended.
        StoreError::Suspended => again(StatusCode::BAD_REQUEST, GENERIC_FAILURE),
        StoreError::LinkedToOther { .. } | StoreError::AddressTaken => {
            again(StatusCode::BAD_REQUEST, &link_refusal(error))
        }
        StoreError::SignupsFull => full(),
        _ => {
            tracing::error!(%error, "could not seal the sign-in");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            )
        }
    }
}

/// The Sign in with Apple user a connection is for: `None` when Sign in with Apple is off,
/// and the page to answer with when it is on and the person is not ready to connect.
async fn connect_user(shared: &Shared, headers: &HeaderMap) -> Result<Option<User>, Box<Response>> {
    if shared.identity.is_none() {
        return Ok(None);
    }
    let session = session_of(shared, headers).map(|(_, session)| session);
    let Some(user) =
        signed_in_user(shared, session.and_then(|session| session.principal.user())).await?
    else {
        return Err(Box::new(message(
            StatusCode::FORBIDDEN,
            "Sign in first",
            "Sign in with Apple before you connect. Go back to the app and start again.",
        )));
    };
    if shared.billing.is_some() && access(&user) == Access::Denied {
        return Err(Box::new(message(
            StatusCode::FORBIDDEN,
            "Choose a plan first",
            "Choose a plan before you connect. Go back to the app and start again.",
        )));
    }
    Ok(Some(user))
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
    /// The address linked to the signed-in user, who connects that one.
    linked: Option<&'a AppleId>,
}

/// The password step.
fn form_page(valid: &Valid, fill: &Fill<'_>, status: StatusCode) -> Response {
    render(valid, fill, None, None, status)
}

fn render(
    valid: &Valid,
    fill: &Fill<'_>,
    sign_in: Option<&str>,
    plan: Option<PlanStep<'_>>,
    status: StatusCode,
) -> Response {
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
        sign_in,
        plan,
        linked: fill.linked.map(AppleId::as_str),
        price: PRICE_TEXT,
    };
    html(status, page.render())
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

fn set_csrf_cookie(response: &mut Response, token: &str, max_age: u32) {
    set_cookie(response, CSRF_COOKIE, token, max_age);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::SystemTime;

    use axum::http::{StatusCode, header};

    use crate::oauth::Access;
    use crate::oauth::test_support::{
        ADA, ASP_ALL, ASP_CALDAV_ONLY, ASP_MAIL_ONLY, Harness, LOOPBACK_REDIRECT, MARKUP_CLIENT_ID,
        PUBLIC, Reply, harness,
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

    /// Ten failed sign-ins from `ip`, which spend its per-IP budget.
    async fn spend_budget(h: &Harness, page: &Reply, ip: &str, tag: &str) {
        for n in 0..10 {
            let reply = h
                .post_form(
                    page,
                    ip,
                    &format!("{tag}{n}@icloud.com"),
                    "wrong-wrong",
                    None,
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
        }
    }

    /// Whether the server is told to trust `X-Forwarded-For`.
    #[derive(Clone, Copy)]
    enum Trust {
        Proxy,
        Nobody,
    }

    /// A harness behind a proxy at 10.0.0.1, built the way `ibridge serve --hosted` builds it.
    async fn proxied(trusts_proxy: Trust) -> Harness {
        let config = crate::config::HostedConfig::resolve(
            crate::config::HostedOptions {
                addr: "127.0.0.1:0".parse().expect("address"),
                public_url: "https://ibridge.example".to_owned(),
                data_dir: "/data".into(),
                multi_tenant: true,
                behind_proxy: matches!(trusts_proxy, Trust::Proxy),
            },
            |_| None,
        )
        .expect("config");
        let mcp =
            axum::Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
        let evict: super::super::Evict = std::sync::Arc::new(|_| {});
        let store = crate::store::Store::memory().await.expect("store");
        let mut h =
            super::super::test_support::harness_configured(config.oauth, store, evict, mcp).await;
        h.proxy = Some("10.0.0.1".parse().expect("proxy address"));
        h
    }

    #[tokio::test]
    async fn two_clients_behind_proxy_get_separate_budgets() {
        let h = proxied(Trust::Proxy).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), "198.51.100.1")
            .await;
        spend_budget(&h, &page, "198.51.100.1", "first").await;
        let limited = h
            .post_form(&page, "198.51.100.1", "x@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            limited.status,
            StatusCode::TOO_MANY_REQUESTS,
            "client one is spent"
        );
        let other = h
            .post_form(&page, "198.51.100.2", "other@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            other.status,
            StatusCode::SEE_OTHER,
            "client two, behind the same proxy, has its own budget"
        );
    }

    #[tokio::test]
    async fn without_behind_proxy_forwarded_for_is_ignored() {
        let h = proxied(Trust::Nobody).await;
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), "198.51.100.1")
            .await;
        spend_budget(&h, &page, "198.51.100.1", "first").await;
        // A direct client cannot pick a fresh budget by sending its own header.
        let spoofed = h
            .post_form(&page, "198.51.100.2", "other@icloud.com", ASP_ALL, None)
            .await;
        assert_eq!(
            spoofed.status,
            StatusCode::TOO_MANY_REQUESTS,
            "the proxy's address is the peer, so the header buys nothing"
        );
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

    const OWNER: &str = "__Host-ibridge_pending=owner-cookie-value";
    const EXPIRED_TEXT: &str = "This page expired";

    fn stored_params() -> super::Params {
        let query = Harness::authorize_path(&[], &[]);
        let query = query.split_once('?').expect("a query").1;
        serde_json::from_value(
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, value)| {
                    (
                        name.into_owned(),
                        serde_json::Value::String(value.into_owned()),
                    )
                })
                .collect::<serde_json::Map<_, _>>()
                .into(),
        )
        .expect("params")
    }

    #[tokio::test]
    async fn authorize_resume_renders_stored_request() {
        let (h, shared) = crate::oauth::test_support::harness_with_shared().await;
        let id = shared
            .pending_authorize
            .put(
                stored_params(),
                "owner-cookie-value",
                std::time::Instant::now(),
            )
            .expect("stored");
        let reply = h
            .get_path(&format!("/authorize/resume?pending={id}"), IP, Some(OWNER))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        assert!(
            reply.text.contains("Claude Test"),
            "the stored client is shown"
        );
        assert_eq!(
            reply.input("code_challenge"),
            crate::oauth::test_support::CHALLENGE,
            "the page carries the stored request"
        );
        assert!(
            reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|value| value
                    .to_str()
                    .is_ok_and(|text| text.starts_with("__Host-ibridge_csrf="))),
            "it sets the form's CSRF cookie like /authorize does"
        );
        let again = h
            .get_path(&format!("/authorize/resume?pending={id}"), IP, Some(OWNER))
            .await;
        assert_eq!(
            again.status,
            StatusCode::OK,
            "resuming twice works until the request expires"
        );
    }

    #[tokio::test]
    async fn authorize_resume_refuses_another_owner() {
        let (h, shared) = crate::oauth::test_support::harness_with_shared().await;
        let id = shared
            .pending_authorize
            .put(
                stored_params(),
                "owner-cookie-value",
                std::time::Instant::now(),
            )
            .expect("stored");
        for cookie in [
            Some("__Host-ibridge_pending=someone-else"),
            Some("__Host-ibridge_pending="),
            None,
        ] {
            let reply = h
                .get_path(&format!("/authorize/resume?pending={id}"), IP, cookie)
                .await;
            assert_eq!(
                reply.status,
                StatusCode::BAD_REQUEST,
                "{cookie:?}: {}",
                reply.text
            );
            assert!(
                reply.text.contains(EXPIRED_TEXT),
                "{cookie:?}: {}",
                reply.text
            );
            assert!(
                !reply.text.contains("Claude Test"),
                "nothing of the request leaks"
            );
        }
    }

    #[tokio::test]
    async fn authorize_resume_unknown_or_expired_shows_expired_page() {
        let (h, shared) = crate::oauth::test_support::harness_with_shared().await;
        let two_hours_ago = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_hours(2))
            .expect("the clock has run for two hours");
        let old = shared
            .pending_authorize
            .put(stored_params(), "owner-cookie-value", two_hours_ago)
            .expect("stored");
        for id in [old.as_str(), "unknown-id"] {
            let reply = h
                .get_path(&format!("/authorize/resume?pending={id}"), IP, Some(OWNER))
                .await;
            assert_eq!(
                reply.status,
                StatusCode::BAD_REQUEST,
                "{id}: {}",
                reply.text
            );
            assert!(reply.text.contains(EXPIRED_TEXT), "{id}: {}", reply.text);
        }
    }
}
