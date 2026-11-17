// SPDX-License-Identifier: Apache-2.0

//! `/account`: sign in with a valid app-specific password, then see and manage what is connected.
//!
//! This is the second page that checks a password with iCloud, so it is protected like
//! `/authorize`: one shared sign-in budget, a double-submit CSRF token and `__Host-` cookies.
//! It never opens a seal. Signing in checks the typed password with iCloud, and everything
//! after that is bookkeeping on ciphertext, so a stolen database or a bug here cannot decrypt a thing.
//!
//! A session holds the address that signed in and a CSRF token, in memory. It never holds the
//! password: minting a key asks for the password again, because a key's seal needs it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use askama::Template;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use secrecy::SecretString;
use serde::Deserialize;

use crate::oauth::{Peer, Shared, address_key};
use crate::store::{GrantId, GrantKind, GrantSummary, Scope, StoreError};
use crate::web::{
    GENERIC_FAILURE, cookie_value, csrf_matches, harden, html, message, random_token, set_cookie,
    tokens_match,
};

const SESSION_COOKIE: &str = "__Host-ibridge_session";
const CSRF_COOKIE: &str = "__Host-ibridge_account_csrf";
const SESSION_SECS: u32 = 30 * 60;
const MAX_FORM: usize = 8 * 1024;
const MAX_NAME: usize = 64;
const EXPIRED: &str = "This page expired. Go to the account page and sign in again.";
const TROUBLE: &str = "Something went wrong on our side. Try again in a moment.";

/// Who is signed in to the account page.
#[derive(Debug, Default)]
pub(crate) struct Sessions(Mutex<HashMap<String, Session>>);

#[derive(Debug, Clone)]
struct Session {
    apple_id: AppleId,
    csrf: String,
    until: Instant,
}

impl Sessions {
    /// Starts a session for `apple_id`. Returns its cookie token and its form token.
    fn start(&self, apple_id: AppleId, now: Instant) -> Option<(String, String)> {
        let (token, csrf) = (random_token()?, random_token()?);
        let mut sessions = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        sessions.retain(|_, session| session.until > now);
        sessions.insert(
            token.clone(),
            Session {
                apple_id,
                csrf: csrf.clone(),
                until: now + Duration::from_secs(u64::from(SESSION_SECS)),
            },
        );
        Some((token, csrf))
    }

    fn get(&self, token: &str, now: Instant) -> Option<Session> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .filter(|session| session.until > now)
            .cloned()
    }

    fn end(&self, token: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(token);
    }
}

pub(crate) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/account", get(show))
        .route("/account/login", post(login))
        .route("/account/logout", post(logout))
        .route("/account/revoke", post(revoke))
        .route("/account/keys", post(mint))
        .route("/account/delete", post(delete))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .with_state(Arc::clone(shared))
}

#[derive(Template)]
#[template(path = "account_login.html")]
struct LoginPage<'a> {
    csrf: &'a str,
    apple_id: &'a str,
    error: Option<&'a str>,
}

struct GrantRow {
    id: String,
    label: String,
    access: &'static str,
    created: String,
    revoked: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage<'a> {
    apple_id: &'a str,
    csrf: &'a str,
    grants: Vec<GrantRow>,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "account_key.html")]
struct KeyPage<'a> {
    name: &'a str,
    key: &'a str,
}

/// The posted sign-in form. It has no `Debug` so the password cannot reach a log.
#[derive(Deserialize)]
struct Login {
    csrf: String,
    apple_id: String,
    password: String,
}

#[derive(Deserialize)]
struct Revoke {
    csrf: String,
    grant: String,
}

/// The posted key form. It has no `Debug` so the password cannot reach a log.
#[derive(Deserialize)]
struct Mint {
    csrf: String,
    name: String,
    password: String,
    read_only: Option<String>,
}

#[derive(Deserialize)]
struct Delete {
    csrf: String,
    confirm: Option<String>,
}

#[derive(Deserialize)]
struct Token {
    csrf: String,
}

async fn show(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    if let Some((_, session)) = session_of(&shared, &headers) {
        return dashboard(&shared, &session, StatusCode::OK, None).await;
    }
    let Some(token) = random_token() else {
        tracing::error!("random source failed while making a sign-in token");
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            TROUBLE,
        );
    };
    let mut response = login_page(&token, "", None, StatusCode::OK);
    set_cookie(&mut response, CSRF_COOKIE, &token, SESSION_SECS);
    response
}

async fn login(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<Login>,
) -> Response {
    if !csrf_matches(&headers, CSRF_COOKIE, &form.csrf) {
        return message(StatusCode::FORBIDDEN, "This page expired", EXPIRED);
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
    let again = || {
        login_page(
            &form.csrf,
            form.apple_id.trim(),
            Some(GENERIC_FAILURE),
            StatusCode::BAD_REQUEST,
        )
    };
    // ponytail: an address off the allowlist is refused before iCloud is asked, so response
    // time shows which addresses are allowed. Same accepted limit as `/authorize`.
    let Some(apple_id) = apple_id.filter(|id| shared.config.may_sign_in(id)) else {
        return again();
    };
    let credentials = Credentials::new(apple_id.clone(), SecretString::from(form.password));
    if let Err(error) = shared.checker.check(credentials).await {
        if !matches!(error, StoreError::Rejected) {
            tracing::error!(%error, "account sign-in check failed");
        }
        return again();
    }
    let Some((token, _)) = shared.sessions.start(apple_id, Instant::now()) else {
        tracing::error!("random source failed while starting a session");
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            TROUBLE,
        );
    };
    let mut response = to_account();
    set_cookie(&mut response, SESSION_COOKIE, &token, SESSION_SECS);
    set_cookie(&mut response, CSRF_COOKIE, "", 0);
    response
}

async fn logout(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<Token>,
) -> Response {
    let Some((token, _)) = checked_session(&shared, &headers, &form.csrf) else {
        return expired();
    };
    shared.sessions.end(&token);
    let mut response = to_account();
    set_cookie(&mut response, SESSION_COOKIE, "", 0);
    response
}

async fn revoke(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<Revoke>,
) -> Response {
    let Some((_, session)) = checked_session(&shared, &headers, &form.csrf) else {
        return expired();
    };
    // A malformed id, or one that is not this person's, changes nothing and says nothing.
    if let Some(grant) = GrantId::from_hex(&form.grant) {
        match shared.store.revoke_grant_of(&session.apple_id, grant).await {
            Ok(accounts) => accounts.iter().for_each(|account| (shared.evict)(account)),
            Err(error) => {
                tracing::error!(%error, "could not revoke a grant");
                return message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    TROUBLE,
                );
            }
        }
    }
    to_account()
}

async fn mint(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<Mint>,
) -> Response {
    let Some((_, session)) = checked_session(&shared, &headers, &form.csrf) else {
        return expired();
    };
    // Checking the password asks iCloud, so it spends the same budget as signing in.
    if !shared.limits.allow(
        &peer.0,
        Some(&address_key(&session.apple_id)),
        Instant::now(),
    ) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            GENERIC_FAILURE,
        );
    }
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return dashboard(
            &shared,
            &session,
            StatusCode::BAD_REQUEST,
            Some("Give the key a name of up to 64 characters."),
        )
        .await;
    }
    let credentials = Credentials::new(session.apple_id.clone(), SecretString::from(form.password));
    let validated = match shared.checker.check(credentials).await {
        Ok(validated) => validated,
        Err(error) => {
            if !matches!(error, StoreError::Rejected) {
                tracing::error!(%error, "key password check failed");
            }
            return dashboard(
                &shared,
                &session,
                StatusCode::BAD_REQUEST,
                Some(GENERIC_FAILURE),
            )
            .await;
        }
    };
    let scope = if form.read_only.is_some() {
        Scope::Read
    } else {
        Scope::ReadWrite
    };
    match shared
        .store
        .mint_api_key(&validated, name, scope, SystemTime::now())
        .await
    {
        Ok(key) => {
            use secrecy::ExposeSecret as _;
            html(
                StatusCode::OK,
                KeyPage {
                    name,
                    key: key.key.expose_secret(),
                }
                .render(),
            )
        }
        Err(StoreError::SignupsFull) => message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-ups are full",
            "This service is not taking new accounts right now. Try again later.",
        ),
        Err(StoreError::Suspended) => {
            dashboard(
                &shared,
                &session,
                StatusCode::FORBIDDEN,
                Some("This account is suspended, so it cannot make new keys."),
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, "could not mint a key");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            )
        }
    }
}

async fn delete(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<Delete>,
) -> Response {
    let Some((token, session)) = checked_session(&shared, &headers, &form.csrf) else {
        return expired();
    };
    if form.confirm.as_deref() != Some("delete") {
        return dashboard(
            &shared,
            &session,
            StatusCode::BAD_REQUEST,
            Some("Tick the box to confirm that you want everything deleted."),
        )
        .await;
    }
    match shared.store.delete_accounts_of(&session.apple_id).await {
        Ok(accounts) => accounts.iter().for_each(|account| (shared.evict)(account)),
        Err(error) => {
            tracing::error!(%error, "could not delete an account");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
    }
    shared.sessions.end(&token);
    let mut response = message(
        StatusCode::OK,
        "Account deleted",
        "Everything stored for this account is deleted: the encrypted copies of your app-specific password, your connected apps and your API keys. They stop working now. To finish, revoke the app-specific password at Apple (Sign-In and Security, then App-Specific Passwords in your Apple Account), so nothing we held can still be used.",
    );
    set_cookie(&mut response, SESSION_COOKIE, "", 0);
    response
}

/// The signed-in session of this request, with its cookie token.
fn session_of(shared: &Shared, headers: &HeaderMap) -> Option<(String, Session)> {
    let token = cookie_value(headers, SESSION_COOKIE)?;
    let session = shared.sessions.get(token, Instant::now())?;
    Some((token.to_owned(), session))
}

/// The session, when the form's token is the one the session was given.
fn checked_session(
    shared: &Shared,
    headers: &HeaderMap,
    from_form: &str,
) -> Option<(String, Session)> {
    session_of(shared, headers).filter(|(_, session)| tokens_match(&session.csrf, from_form))
}

fn expired() -> Response {
    message(StatusCode::FORBIDDEN, "This page expired", EXPIRED)
}

fn to_account() -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/account"));
    harden(&mut response);
    response
}

fn login_page(csrf: &str, apple_id: &str, error: Option<&str>, status: StatusCode) -> Response {
    html(
        status,
        LoginPage {
            csrf,
            apple_id,
            error,
        }
        .render(),
    )
}

async fn dashboard(
    shared: &Shared,
    session: &Session,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let grants = match shared.store.grants_of(&session.apple_id).await {
        Ok(grants) => grants,
        Err(error) => {
            tracing::error!(%error, "could not list grants");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
    };
    html(
        status,
        AccountPage {
            apple_id: session.apple_id.as_str(),
            csrf: &session.csrf,
            grants: grants.iter().map(row).collect(),
            error,
        }
        .render(),
    )
}

fn row(grant: &GrantSummary) -> GrantRow {
    GrantRow {
        id: grant.id.to_hex(),
        label: match (&grant.kind, &grant.name) {
            (GrantKind::ApiKey, Some(name)) => format!("API key: {name}"),
            (GrantKind::ApiKey, None) => "API key".to_owned(),
            _ => "App sign-in".to_owned(),
        },
        access: match grant.scope {
            Scope::Read => "Read-only",
            _ => "Read and write",
        },
        created: day(grant.created_at),
        revoked: grant.revoked,
    }
}

/// `YYYY-MM-DD` for a Unix time, in UTC.
fn day(unix: i64) -> String {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let days = unix.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, PoisonError};
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use ibridge_auth::Credentials;
    use ibridge_core::AppleId;
    use secrecy::{ExposeSecret, SecretString};

    use crate::oauth::test_support::{ADA, ASP_ALL, Harness, Reply, harness, harness_with};
    use crate::oauth::{Access, Evict};
    use crate::provider::AccountCache;
    use crate::server::mcp_router;
    use crate::store::{ApiKey, IssuedTokens, Scope, Store, StoreError, ValidatedCredentials};
    use crate::test_app::{AcceptAll, FakeBackend, call, config, info};

    const IP: &str = "203.0.113.7";
    const BEA: &str = "bea@icloud.com";
    const SESSION: &str = "__Host-ibridge_session";
    const FORM_CSRF: &str = "__Host-ibridge_account_csrf";

    fn apple(id: &str) -> AppleId {
        AppleId::try_from(id).expect("apple id")
    }

    /// An OAuth grant for `id` with its tokens issued.
    async fn oauth_grant(store: &Store, id: &str, asp: &str) -> IssuedTokens {
        let now = SystemTime::now();
        let code = store
            .seal_under_code(&apple(id), &SecretString::from(asp), Scope::ReadWrite, now)
            .await
            .expect("seal");
        store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .expect("exchange")
    }

    /// An API key for `id`.
    async fn api_key(store: &Store, id: &str, name: &str, scope: Scope) -> ApiKey {
        let credentials = Credentials::new(apple(id), SecretString::from(ASP_ALL));
        let validated = ValidatedCredentials::from_check(credentials, |_: &Credentials| AcceptAll)
            .await
            .expect("accepted");
        store
            .mint_api_key(&validated, name, scope, SystemTime::now())
            .await
            .expect("mint")
    }

    fn hex(id: crate::store::GrantId) -> String {
        format!("{id:?}")
    }

    async fn count(store: &Store, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    /// A signed-in browser: its cookie and the token its forms carry.
    struct Browser {
        cookie: String,
        csrf: String,
    }

    impl Harness {
        async fn get_path(&self, path: &str, ip: &str, cookie: Option<&str>) -> Reply {
            let mut request = Request::get(path);
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            self.send(request.body(Body::empty()).expect("request"), ip)
                .await
        }

        async fn post_path(
            &self,
            path: &str,
            ip: &str,
            cookie: Option<&str>,
            fields: &[(&str, &str)],
        ) -> Reply {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish();
            let mut request = Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            self.send(request.body(Body::from(body)).expect("request"), ip)
                .await
        }

        /// Opens the sign-in form and posts `apple_id` and `password` with its token.
        async fn account_login(&self, ip: &str, apple_id: &str, password: &str) -> Reply {
            let form = self.get_path("/account", ip, None).await;
            let csrf = form.input("csrf");
            self.post_path(
                "/account/login",
                ip,
                Some(&form.cookie_pair()),
                &[
                    ("csrf", &csrf),
                    ("apple_id", apple_id),
                    ("password", password),
                ],
            )
            .await
        }

        /// Signs in as `apple_id` with a good password and opens the dashboard.
        async fn browser(&self, ip: &str, apple_id: &str) -> Browser {
            let login = self.account_login(ip, apple_id, ASP_ALL).await;
            assert_eq!(login.status, StatusCode::SEE_OTHER, "{}", login.text);
            let cookie = set_cookie(&login, SESSION).expect("a session cookie");
            let page = self.get_path("/account", ip, Some(&cookie)).await;
            assert_eq!(page.status, StatusCode::OK, "{}", page.text);
            let csrf = page.input("csrf");
            Browser { cookie, csrf }
        }

        async fn dashboard(&self, browser: &Browser) -> Reply {
            self.get_path("/account", IP, Some(&browser.cookie)).await
        }

        /// Posts `fields` plus the browser's own token to `path`.
        async fn act(&self, browser: &Browser, path: &str, fields: &[(&str, &str)]) -> Reply {
            let mut all = vec![("csrf", browser.csrf.as_str())];
            all.extend_from_slice(fields);
            self.post_path(path, IP, Some(&browser.cookie), &all).await
        }
    }

    /// The `name=value` of the `Set-Cookie` named `name`, for sending back.
    fn set_cookie(reply: &Reply, name: &str) -> Option<String> {
        reply
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(|value| value.split(';').next().unwrap_or_default().to_owned())
            .filter(|pair| !pair.ends_with('='))
    }

    #[tokio::test]
    async fn account_login_requires_valid_asp() {
        let h = harness(Access::MultiTenant).await;
        let anonymous = h.get_path("/account", IP, None).await;
        assert_eq!(anonymous.status, StatusCode::OK);
        assert!(
            anonymous.text.contains(r#"name="apple_id""#) && !anonymous.text.contains(ADA),
            "no session shows the sign-in form: {}",
            anonymous.text
        );

        let wrong = h.account_login(IP, ADA, "wrong-wrong-wrong").await;
        assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", wrong.text);
        assert_eq!(
            wrong.error_text().as_deref(),
            Some(crate::web::GENERIC_FAILURE)
        );
        assert!(
            set_cookie(&wrong, SESSION).is_none(),
            "a wrong password gets no session"
        );
        assert!(
            h.get_path("/account", IP, Some("__Host-ibridge_session=guess"))
                .await
                .text
                .contains(r#"name="apple_id""#),
            "an invented session is the sign-in form"
        );

        let right = h.account_login(IP, ADA, ASP_ALL).await;
        assert_eq!(right.status, StatusCode::SEE_OTHER, "{}", right.text);
        assert_eq!(right.headers[header::LOCATION], "/account");
        let cookie = set_cookie(&right, SESSION).expect("a session cookie");
        let page = h.get_path("/account", IP, Some(&cookie)).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(
            page.text.contains(ADA),
            "the dashboard names the account: {}",
            page.text
        );
        assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            2,
            "both attempts ran the live check"
        );
    }

    #[tokio::test]
    async fn account_login_rate_limited_shared_with_authorize() {
        let h = harness(Access::MultiTenant).await;
        let authorize = h
            .get_authorize(&Harness::authorize_path(&[], &[]), IP)
            .await;

        // Five failures at /authorize spend bob's address budget; /account shares it.
        for n in 0..5 {
            let reply = h
                .post_form(
                    &authorize,
                    &format!("192.0.2.{n}"),
                    "bob@icloud.com",
                    "wrong-wrong",
                    None,
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
        }
        let checks = h.checks.load(Ordering::SeqCst);
        let locked = h
            .account_login("192.0.2.99", "Bob@iCloud.com", ASP_ALL)
            .await;
        assert_eq!(
            locked.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            locked.text
        );
        assert_eq!(
            locked.error_text().as_deref(),
            Some(crate::web::GENERIC_FAILURE)
        );
        assert!(
            set_cookie(&locked, SESSION).is_none(),
            "even a right password gets no session"
        );
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            checks,
            "a limited attempt never reaches iCloud"
        );

        // Ten failures at /account spend one IP's budget; /authorize shares it.
        for n in 0..10 {
            let reply = h
                .account_login(
                    "198.51.100.1",
                    &format!("user{n}@icloud.com"),
                    "wrong-wrong",
                )
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "attempt {n}");
        }
        let limited = h
            .post_form(
                &authorize,
                "198.51.100.1",
                "user99@icloud.com",
                ASP_ALL,
                None,
            )
            .await;
        assert_eq!(
            limited.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            limited.text
        );
        let elsewhere = h
            .account_login("198.51.100.2", "user99@icloud.com", ASP_ALL)
            .await;
        assert_eq!(
            elsewhere.status,
            StatusCode::SEE_OTHER,
            "another IP has its own budget"
        );
    }

    #[tokio::test]
    async fn account_forms_require_csrf() {
        let h = harness(Access::MultiTenant).await;
        let tokens = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let grant = hex(tokens.grant_id);

        // The sign-in form.
        let form = h.get_path("/account", IP, None).await;
        let csrf = form.input("csrf");
        let cookie = form.cookie_pair();
        let fields =
            |csrf: &'static str| [("csrf", csrf), ("apple_id", ADA), ("password", ASP_ALL)];
        for (label, cookie, token) in [
            ("no cookie", None, csrf.as_str()),
            ("wrong form token", Some(cookie.as_str()), "not-the-token"),
            (
                "wrong cookie",
                Some("__Host-ibridge_account_csrf=forged"),
                csrf.as_str(),
            ),
            ("empty tokens", Some("__Host-ibridge_account_csrf="), ""),
        ] {
            let mut body = fields("");
            body[0].1 = token;
            let reply = h.post_path("/account/login", IP, cookie, &body).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert!(
                set_cookie(&reply, SESSION).is_none(),
                "{label} gets no session"
            );
        }
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            0,
            "a forged post never reaches iCloud"
        );
        assert_eq!(FORM_CSRF, "__Host-ibridge_account_csrf");

        // Every form behind the session.
        let browser = h.browser(IP, ADA).await;
        let checks = h.checks.load(Ordering::SeqCst);
        let posts: [(&str, Vec<(&str, &str)>); 4] = [
            ("/account/revoke", vec![("grant", grant.as_str())]),
            (
                "/account/keys",
                vec![("name", "laptop"), ("password", ASP_ALL)],
            ),
            ("/account/delete", vec![("confirm", "delete")]),
            ("/account/logout", vec![]),
        ];
        for (path, extra) in &posts {
            for (label, session, token) in [
                (
                    "wrong token",
                    Some(browser.cookie.as_str()),
                    "not-the-token",
                ),
                ("empty token", Some(browser.cookie.as_str()), ""),
                ("no session", None, browser.csrf.as_str()),
            ] {
                let mut body = vec![("csrf", token)];
                body.extend(extra.iter().copied());
                let reply = h.post_path(path, IP, session, &body).await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path}: {label}");
            }
        }
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            checks,
            "refused forms never reach iCloud"
        );
        assert!(
            h.store
                .open_for_call(tokens.access.expose_secret(), SystemTime::now())
                .await
                .is_ok(),
            "nothing was revoked"
        );
        assert_eq!(
            count(&h.store, "SELECT COUNT(*) FROM accounts").await,
            1,
            "nothing was deleted"
        );
        assert_eq!(
            count(
                &h.store,
                "SELECT COUNT(*) FROM grants WHERE kind = 'api_key'"
            )
            .await,
            0,
            "no key was minted"
        );
        assert_eq!(
            h.dashboard(&browser).await.status,
            StatusCode::OK,
            "the session survived the refused logout"
        );
        assert!(
            h.evicted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn session_cookie_is_host_prefixed() {
        let h = harness(Access::MultiTenant).await;
        let form = h.get_path("/account", IP, None).await;
        let login = h.account_login(IP, ADA, ASP_ALL).await;
        for (label, reply) in [("sign-in form", &form), ("signed in", &login)] {
            let cookies: Vec<&str> = reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            assert!(!cookies.is_empty(), "{label} sets a cookie");
            for set in cookies {
                assert!(
                    set.starts_with("__Host-"),
                    "{label}: the name carries the prefix: {set}"
                );
                for attribute in ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"] {
                    assert!(
                        set.contains(attribute),
                        "{label}: {attribute} is set: {set}"
                    );
                }
                assert!(
                    !set.contains("Domain"),
                    "{label}: a __Host- cookie has no Domain: {set}"
                );
            }
        }
        let session = login
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(SESSION))
            .expect("a session cookie");
        let value = session
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, v)| v);
        assert!(
            value.is_some_and(|value| value.len() >= 43),
            "the token is long: {session}"
        );
    }

    #[tokio::test]
    async fn lists_grants_and_keys() {
        let h = harness(Access::MultiTenant).await;
        let app_grant = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let key = api_key(&h.store, ADA, "laptop script", Scope::Read).await;
        let other = oauth_grant(&h.store, BEA, ASP_ALL).await;
        let other_key = api_key(&h.store, BEA, "bea's key", Scope::Read).await;
        let browser = h.browser(IP, ADA).await;

        let page = h.dashboard(&browser).await;
        assert!(
            page.text.contains(&hex(app_grant.grant_id)),
            "the app sign-in is listed: {}",
            page.text
        );
        assert!(page.text.contains(&hex(key.grant_id)), "the key is listed");
        assert!(
            page.text.contains("laptop script"),
            "the key's name is shown"
        );
        assert!(
            page.text.contains("read-only") || page.text.contains("Read-only"),
            "its scope is shown"
        );
        assert!(
            !page.text.contains(&hex(other.grant_id)),
            "another account's grant is not listed"
        );
        assert!(!page.text.contains(&hex(other_key.grant_id)));
        assert!(!page.text.contains("bea's key"));
        for secret in [
            app_grant.access.expose_secret(),
            app_grant.refresh.expose_secret(),
            key.key.expose_secret(),
            ASP_ALL,
        ] {
            assert!(
                !page.text.contains(secret),
                "the page never carries {secret}"
            );
        }
    }

    #[tokio::test]
    async fn account_page_matches_every_spelling_of_the_address() {
        // The store keeps `Ada@iCloud.com` and `ada@icloud.com` as two accounts; Apple does not.
        let h = harness(Access::MultiTenant).await;
        let upper = oauth_grant(&h.store, "Ada@iCloud.com", ASP_ALL).await;
        let lower = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let browser = h.browser(IP, "ADA@icloud.com").await;

        let page = h.dashboard(&browser).await;
        assert!(
            page.text.contains(&hex(upper.grant_id)) && page.text.contains(&hex(lower.grant_id))
        );
        let reply = h
            .act(&browser, "/account/delete", &[("confirm", "delete")])
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        assert_eq!(
            count(&h.store, "SELECT COUNT(*) FROM accounts").await,
            0,
            "both spellings are gone"
        );
        let evicted = h
            .evicted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(
            evicted.contains(&apple("Ada@iCloud.com")) && evicted.contains(&apple(ADA)),
            "{evicted:?}"
        );
    }

    #[tokio::test]
    async fn revoke_grant() {
        let h = harness(Access::MultiTenant).await;
        let app_grant = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let key = api_key(&h.store, ADA, "laptop", Scope::ReadWrite).await;
        let bea = oauth_grant(&h.store, BEA, ASP_ALL).await;
        let browser = h.browser(IP, ADA).await;
        let now = SystemTime::now();

        let reply = h
            .act(
                &browser,
                "/account/revoke",
                &[("grant", &hex(app_grant.grant_id))],
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert!(
            matches!(
                h.store
                    .open_for_call(app_grant.access.expose_secret(), now)
                    .await,
                Err(StoreError::InvalidGrant)
            ),
            "the client is cut off"
        );
        assert!(
            matches!(
                h.store
                    .refresh(app_grant.refresh.expose_secret(), now)
                    .await,
                Err(StoreError::InvalidGrant)
            ),
            "and cannot refresh"
        );
        assert!(
            h.store
                .open_for_call(key.key.expose_secret(), now)
                .await
                .is_ok(),
            "the key is untouched"
        );
        assert_eq!(
            *h.evicted.lock().unwrap_or_else(PoisonError::into_inner),
            vec![apple(ADA)],
            "pooled sessions are dropped"
        );

        let reply = h
            .act(
                &browser,
                "/account/revoke",
                &[("grant", &hex(key.grant_id))],
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert!(
            matches!(
                h.store.open_for_call(key.key.expose_secret(), now).await,
                Err(StoreError::InvalidGrant)
            ),
            "a key is revoked the same way"
        );

        // Someone else's grant, and nonsense, change nothing.
        for target in [hex(bea.grant_id), "zz".to_owned(), "00".repeat(16)] {
            let reply = h
                .act(&browser, "/account/revoke", &[("grant", &target)])
                .await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER, "{target}");
        }
        assert!(
            h.store
                .open_for_call(bea.access.expose_secret(), now)
                .await
                .is_ok(),
            "bea's grant survives ada's request"
        );
    }

    /// The key printed in `page`.
    fn key_in(page: &str) -> String {
        let start = page.find("ibr_").expect("the page shows a key");
        page[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect()
    }

    #[tokio::test]
    async fn mint_apikey_shown_once() {
        let h = harness(Access::MultiTenant).await;
        let browser = h.browser(IP, ADA).await;
        let now = SystemTime::now();

        let wrong = h
            .act(
                &browser,
                "/account/keys",
                &[("name", "ci"), ("password", "wrong-wrong-wrong")],
            )
            .await;
        assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", wrong.text);
        assert!(!wrong.text.contains("ibr_"));
        assert_eq!(
            count(
                &h.store,
                "SELECT COUNT(*) FROM grants WHERE kind = 'api_key'"
            )
            .await,
            0,
            "a wrong password mints nothing"
        );

        let minted = h
            .act(
                &browser,
                "/account/keys",
                &[("name", "ci bot"), ("password", ASP_ALL)],
            )
            .await;
        assert_eq!(minted.status, StatusCode::OK, "{}", minted.text);
        assert_eq!(
            minted.headers[header::CACHE_CONTROL],
            "no-store",
            "a page with a key is never cached"
        );
        let key = key_in(&minted.text);
        assert_eq!(key.len(), 4 + 43, "256 random bits: {key}");
        let call = h
            .store
            .open_for_call(&key, now)
            .await
            .expect("the key works");
        assert_eq!(call.apple_id.as_str(), ADA);
        assert_eq!(call.scope, Scope::ReadWrite);
        assert_eq!(
            call.secret.expose_secret(),
            ASP_ALL,
            "the typed password is what was sealed"
        );

        let again = h.dashboard(&browser).await;
        assert!(!again.text.contains(&key), "the key is not shown again");
        assert!(!again.text.contains("ibr_"), "no key text at all");
        assert!(again.text.contains("ci bot"), "its name is listed");

        let read_only = h
            .act(
                &browser,
                "/account/keys",
                &[
                    ("name", "reader"),
                    ("password", ASP_ALL),
                    ("read_only", "on"),
                ],
            )
            .await;
        let reader = h
            .store
            .open_for_call(&key_in(&read_only.text), now)
            .await
            .expect("works");
        assert_eq!(reader.scope, Scope::Read, "the box picks read-only");
        assert_ne!(key_in(&read_only.text), key, "keys are fresh");
    }

    #[tokio::test]
    async fn delete_account_removes_all_sealed() {
        let h = harness(Access::MultiTenant).await;
        let app_grant = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let key = api_key(&h.store, ADA, "laptop", Scope::Read).await;
        let bea = oauth_grant(&h.store, BEA, ASP_ALL).await;
        let bea_seals = count(&h.store, "SELECT COUNT(*) FROM seals WHERE grant_id = (SELECT id FROM grants WHERE account_id = (SELECT id FROM accounts WHERE apple_id = 'bea@icloud.com'))").await;
        let browser = h.browser(IP, ADA).await;
        let now = SystemTime::now();

        let unconfirmed = h.act(&browser, "/account/delete", &[]).await;
        assert_eq!(
            unconfirmed.status,
            StatusCode::BAD_REQUEST,
            "{}",
            unconfirmed.text
        );
        assert_eq!(
            count(&h.store, "SELECT COUNT(*) FROM accounts").await,
            2,
            "an unconfirmed delete deletes nothing"
        );

        let done = h
            .act(&browser, "/account/delete", &[("confirm", "delete")])
            .await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.text);
        assert!(
            done.text.contains("revoke") && done.text.contains("Apple"),
            "it tells the user to revoke the password at Apple: {}",
            done.text
        );
        assert_eq!(
            count(
                &h.store,
                "SELECT COUNT(*) FROM accounts WHERE apple_id = 'ada@icloud.com'"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &h.store,
                "SELECT COUNT(*) FROM grants WHERE account_id NOT IN (SELECT id FROM accounts)"
            )
            .await,
            0
        );
        assert_eq!(
            count(&h.store, "SELECT COUNT(*) FROM grants").await,
            1,
            "only bea's grant is left"
        );
        assert_eq!(
            count(&h.store, "SELECT COUNT(*) FROM seals").await,
            bea_seals,
            "every sealed copy of ada's password is gone, bea's stay"
        );
        for token in [
            app_grant.access.expose_secret(),
            app_grant.refresh.expose_secret(),
            key.key.expose_secret(),
        ] {
            assert!(
                matches!(
                    h.store.open_for_call(token, now).await,
                    Err(StoreError::InvalidToken)
                ),
                "{token} no longer opens anything"
            );
        }
        assert!(
            h.store
                .open_for_call(bea.access.expose_secret(), now)
                .await
                .is_ok()
        );
        assert!(
            h.get_path("/account", IP, Some(&browser.cookie))
                .await
                .text
                .contains(r#"name="apple_id""#),
            "the session ended with the account"
        );
        assert_eq!(
            *h.evicted.lock().unwrap_or_else(PoisonError::into_inner),
            vec![apple(ADA)]
        );
    }

    #[tokio::test]
    async fn account_page_works_when_store_open_always_fails() {
        // Every stored ciphertext is garbage, so `open_for_call` fails for every token.
        // The page must never need it: sign-in checks iCloud, and the rest is bookkeeping.
        let h = harness(Access::MultiTenant).await;
        let app_grant = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let key = api_key(&h.store, ADA, "laptop", Scope::ReadWrite).await;
        sqlx::query(
            "UPDATE seals SET ciphertext = x'00', nonce = x'00' WHERE ciphertext IS NOT NULL",
        )
        .execute(h.store.pool())
        .await
        .expect("corrupt");
        let now = SystemTime::now();
        for token in [app_grant.access.expose_secret(), key.key.expose_secret()] {
            assert!(
                h.store.open_for_call(token, now).await.is_err(),
                "the precondition: nothing opens"
            );
        }

        let browser = h.browser(IP, ADA).await;
        let page = h.dashboard(&browser).await;
        assert!(
            page.text.contains(&hex(app_grant.grant_id)) && page.text.contains("laptop"),
            "it lists: {}",
            page.text
        );
        let minted = h
            .act(
                &browser,
                "/account/keys",
                &[("name", "new"), ("password", ASP_ALL)],
            )
            .await;
        assert_eq!(minted.status, StatusCode::OK, "{}", minted.text);
        let revoked = h
            .act(
                &browser,
                "/account/revoke",
                &[("grant", &hex(app_grant.grant_id))],
            )
            .await;
        assert_eq!(revoked.status, StatusCode::SEE_OTHER);
        let revoked = h
            .act(
                &browser,
                "/account/revoke",
                &[("grant", &hex(key.grant_id))],
            )
            .await;
        assert_eq!(revoked.status, StatusCode::SEE_OTHER);
        let deleted = h
            .act(&browser, "/account/delete", &[("confirm", "delete")])
            .await;
        assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
        assert_eq!(count(&h.store, "SELECT COUNT(*) FROM accounts").await, 0);
        assert_eq!(count(&h.store, "SELECT COUNT(*) FROM seals").await, 0);
    }

    #[tokio::test]
    async fn delete_account_drops_pooled_sessions() {
        let store = Store::memory().await.expect("store");
        let cache = Arc::new(AccountCache::new(
            FakeBackend,
            store.clone(),
            "https://ibridge.example/account".to_owned(),
        ));
        let evicting = Arc::clone(&cache);
        let evict: Evict = Arc::new(move |apple_id| evicting.drop_account(apple_id));
        let mcp = mcp_router(Arc::clone(&cache), info(), &config(Access::MultiTenant));
        let h = harness_with(
            "https://ibridge.example",
            Access::MultiTenant,
            store,
            evict,
            mcp,
        )
        .await;
        let tokens = oauth_grant(&h.store, ADA, ASP_ALL).await;
        let access = tokens.access.expose_secret();

        let (status, body) = call(&h.app, access, "mail_search", &serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            cache.len(),
            1,
            "the account's providers are pooled after a call"
        );

        let browser = h.browser(IP, ADA).await;
        let reply = h
            .act(&browser, "/account/delete", &[("confirm", "delete")])
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        assert!(
            cache.is_empty(),
            "deleting the account closes its pooled sessions"
        );
        let (status, _body) = call(&h.app, access, "mail_search", &serde_json::json!({})).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the token no longer works"
        );
    }
}
