// SPDX-License-Identifier: Apache-2.0

//! `/signin/apple` and its callback: Sign in with Apple through Firebase.
//!
//! The routes exist only when the identity settings are present. Apple posts the callback
//! from another site, so the cookie that binds it to the browser is the one cookie here
//! that is `SameSite=None`.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;

use super::account::{Principal, SESSION_COOKIE, SESSION_SECS};
use crate::identity::{BINDER_COOKIE, CallbackForm, Identity, IdentityError, ReturnTo, SignedIn};
use crate::oauth::{Peer, Shared};
use crate::web::{cookie_value, message, see_other, set_cookie, set_cookie_same_site};

const MAX_FORM: usize = 8 * 1024;
/// How long the binder cookie lives: as long as the pending sign-in.
const BINDER_SECS: u32 = 600;
/// The longest pending id a sign-in may carry back to `/authorize/resume`.
const MAX_PENDING_ID: usize = 64;
const TROUBLE: &str = "Something went wrong on our side. Try again in a moment.";

pub(crate) fn routes(shared: &Arc<Shared>) -> Router {
    if shared.identity.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/signin/apple", get(start))
        .route("/signin/apple/callback", post(callback))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .with_state(Arc::clone(shared))
}

/// Where the person was going when they chose to sign in.
#[derive(Deserialize)]
struct Start {
    next: Option<String>,
    pending: Option<String>,
}

async fn start(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    Query(query): Query<Start>,
) -> Response {
    let Some(identity) = shared.identity.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "Wait a minute, then try again.",
        );
    }
    let return_to = match (query.next.as_deref(), query.pending) {
        (Some("authorize"), Some(id)) if plausible_id(&id) => ReturnTo::Authorize(id),
        (Some("authorize"), _) => {
            return message(
                StatusCode::BAD_REQUEST,
                "Cannot sign in",
                "This sign-in link is not complete. Go back to the app and start again.",
            );
        }
        _ => ReturnTo::Account,
    };
    begin(identity, return_to)
}

/// Sends the browser to Apple for a sign-in that ends at `return_to`.
pub(crate) fn begin(identity: &Identity, return_to: ReturnTo) -> Response {
    match identity.begin(return_to, Instant::now()) {
        Ok((apple_url, binder)) => {
            let mut response = see_other(&apple_url);
            set_cookie_same_site(&mut response, BINDER_COOKIE, &binder, BINDER_SECS, "None");
            response
        }
        Err(IdentityError::Busy) => message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-ins",
            "Many people are signing in right now. Wait a minute, then try again.",
        ),
        Err(error) => {
            tracing::error!(%error, "could not start a sign-in");
            message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            )
        }
    }
}

async fn callback(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    headers: HeaderMap,
    Form(form): Form<CallbackForm>,
) -> Response {
    let Some(identity) = shared.identity.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !shared.lookups.allow(&peer.0, Instant::now()) {
        return message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "Wait a minute, then try again.",
        );
    }
    let binder = cookie_value(&headers, BINDER_COOKIE);
    let finished = identity
        .finish(form, binder, Instant::now(), SystemTime::now())
        .await;
    let mut response = match finished {
        // A fresh sign-in that was asked for to delete the account does that, and nothing else.
        Ok(signed) => match signed.return_to {
            ReturnTo::DeleteAccount(user) => super::delete::complete(&shared, user, signed).await,
            _ => signed_in(&shared, signed).await,
        },
        Err(error) => failed(error),
    };
    // The binder has done its one job, whichever way the sign-in went.
    set_cookie_same_site(&mut response, BINDER_COOKIE, "", 0, "None");
    response
}

/// Records the user, starts their session and sends them where they were going.
async fn signed_in(shared: &Shared, signed: SignedIn) -> Response {
    let SignedIn {
        firebase_uid,
        apple_sub,
        email,
        return_to,
        apple_access: _,
        firebase_id_token: _,
    } = signed;
    let user = match shared
        .store
        .upsert_user(&firebase_uid, &apple_sub, email.as_deref())
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(%error, "could not store a signed-in user");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
    };
    let principal = Principal::User(user.id);
    let Some((token, _)) = shared.sessions.start(principal, Instant::now()) else {
        tracing::error!("random source failed while starting a session");
        return message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            TROUBLE,
        );
    };
    tracing::info!(user = %user.id, "signed in with Apple");
    let location = match return_to {
        ReturnTo::Authorize(id) => {
            let id: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
            format!("/authorize/resume?pending={id}")
        }
        ReturnTo::Account | ReturnTo::DeleteAccount(_) => "/account".to_owned(),
    };
    let mut response = see_other(&location);
    set_cookie(&mut response, SESSION_COOKIE, &token, SESSION_SECS);
    response
}

/// The page for a sign-in that did not finish. It says what the person can do, not why it failed.
fn failed(error: IdentityError) -> Response {
    match error {
        IdentityError::TooManySignUps => message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-ups are busy",
            "Too many people signed up just now. Please try again in an hour.",
        ),
        IdentityError::StateRejected => message(
            StatusCode::BAD_REQUEST,
            "This sign-in expired",
            "This sign-in link expired, was already used, or was opened in a different browser. Go back and start the sign-in again.",
        ),
        IdentityError::Unreachable | IdentityError::Unavailable | IdentityError::Busy => {
            tracing::warn!(%error, "a sign-in could not finish");
            message(
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign in with Apple is not available",
                "Apple or our sign-in service could not be reached. Try again in a moment.",
            )
        }
        _ => {
            tracing::warn!(%error, "a sign-in was refused");
            message(
                StatusCode::BAD_REQUEST,
                "Sign-in failed",
                "Apple or our sign-in service did not accept this sign-in. Go back and try again.",
            )
        }
    }
}

/// Whether `id` looks like a pending id this server made: base64url, and not long.
fn plausible_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_PENDING_ID
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, PoisonError};
    use std::time::Duration;

    use axum::http::{StatusCode, header};
    use sha2::{Digest, Sha256};
    use tracing::Level;

    use crate::identity::fakes::{FakeApple, FakeFirebase, identity_config};
    use crate::identity::pending::PendingSignIns;
    use crate::identity::{BINDER_COOKIE, Identity};
    use crate::logging::json_subscriber;
    use crate::oauth::Access;
    use crate::oauth::Shared;
    use crate::oauth::test_support::{
        ADA, Harness, PUBLIC, Reply, harness, harness_identity, harness_with_shared,
    };
    use crate::pages::test_rig::Captured;
    use crate::store::Store;

    const IP: &str = "198.51.100.7";
    const SESSION_COOKIE: &str = "__Host-ibridge_session";

    struct Rig {
        harness: Harness,
        shared: Arc<Shared>,
        apple: FakeApple,
        firebase: FakeFirebase,
    }

    async fn rig_with(pending: Option<PendingSignIns>) -> Rig {
        let apple = FakeApple::start().await;
        let firebase = FakeFirebase::start("ibridge-fyi", "test-api-key").await;
        firebase.issue_at_real_time();
        let config = identity_config("ibridge-fyi");
        let mut identity =
            Identity::with_bases(&config, PUBLIC, apple.base(), firebase.base()).expect("identity");
        if let Some(pending) = pending {
            identity = identity.with_pending(pending);
        }
        let store = Store::memory().await.expect("store");
        let (harness, shared) = harness_identity(identity, store).await;
        Rig {
            harness,
            shared,
            apple,
            firebase,
        }
    }

    async fn rig() -> Rig {
        rig_with(None).await
    }

    /// What a started sign-in handed the browser.
    struct Started {
        state: String,
        nonce_hash: String,
        binder: String,
    }

    fn cookies(reply: &Reply) -> Vec<String> {
        reply
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    fn cookie_named(reply: &Reply, name: &str) -> Option<String> {
        cookies(reply)
            .into_iter()
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
    }

    /// The `Location` header as sent: these redirects stay on this server, so it is a path.
    fn target(reply: &Reply) -> String {
        reply
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("a Location header")
            .to_owned()
    }

    fn pair_of(set_cookie: &str) -> String {
        set_cookie.split(';').next().expect("a pair").to_owned()
    }

    impl Rig {
        async fn start(&self, query: &str) -> (Reply, Started) {
            let reply = self
                .harness
                .get_path(&format!("/signin/apple{query}"), IP, None)
                .await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
            let location = reply.location();
            let param = |name: &str| {
                location
                    .query_pairs()
                    .find(|(key, _)| key == name)
                    .map_or_default(|(_, value)| value.into_owned())
            };
            let binder = cookie_named(&reply, BINDER_COOKIE).expect("a binder cookie");
            let started = Started {
                state: param("state"),
                nonce_hash: param("nonce"),
                binder: pair_of(&binder),
            };
            (reply, started)
        }

        async fn callback(&self, fields: &[(&str, &str)], cookie: Option<&str>) -> Reply {
            self.harness
                .post_path("/signin/apple/callback", IP, cookie, fields)
                .await
        }

        async fn finish(&self, started: &Started, code: &str) -> Reply {
            self.callback(
                &[("code", code), ("state", &started.state)],
                Some(&started.binder),
            )
            .await
        }
    }

    fn assert_refused(reply: &Reply) {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text);
        assert!(
            cookie_named(reply, SESSION_COOKIE).is_none(),
            "a refused callback starts no session"
        );
    }

    #[tokio::test]
    async fn signin_redirects_to_apple_and_sets_binder_cookie() {
        let rig = rig().await;
        let (reply, started) = rig.start("").await;
        let location = reply.location();
        assert_eq!(location.path(), "/auth/authorize");
        let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["response_mode"], "form_post");
        assert_eq!(query["scope"], "email");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "fyi.ibridge.signin");
        assert_eq!(
            query["redirect_uri"],
            format!("{PUBLIC}/signin/apple/callback")
        );
        assert_eq!(started.nonce_hash.len(), 64, "a SHA-256 in hex");
        assert!(started.state.len() >= 32, "an unguessable state");
        let cookie = cookie_named(&reply, BINDER_COOKIE).expect("a binder cookie");
        for attribute in [
            "Secure",
            "HttpOnly",
            "SameSite=None",
            "Path=/",
            "Max-Age=600",
        ] {
            assert!(cookie.contains(attribute), "{attribute} in {cookie}");
        }
        assert!(
            !cookie.contains("Domain"),
            "a __Host- cookie names no domain: {cookie}"
        );
        assert_eq!(
            reply
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let binder_value = started.binder.split_once('=').expect("a pair").1;
        assert!(
            !reply.location().as_str().contains(binder_value),
            "the binder never travels to Apple"
        );
    }

    #[tokio::test]
    async fn callback_with_matching_binder_signs_in_and_starts_user_session() {
        let rig = rig().await;
        let (_, started) = rig.start("").await;
        let reply = rig.finish(&started, "good-code").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert_eq!(target(&reply), "/account");
        let session = cookie_named(&reply, SESSION_COOKIE).expect("a session cookie");
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(session.contains(attribute), "{attribute} in {session}");
        }
        let cleared = cookie_named(&reply, BINDER_COOKIE).expect("the binder is cleared");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");

        let user = rig
            .shared
            .store
            .user_by_email_or_uid(FakeFirebase::UID)
            .await
            .expect("store")
            .expect("the user was created");
        assert_eq!(user.apple_sub, FakeFirebase::APPLE_SUB);
        assert_eq!(user.email.as_deref(), Some(FakeFirebase::EMAIL));
        let page = rig
            .harness
            .get_path("/account", IP, Some(&pair_of(&session)))
            .await;
        assert_eq!(page.status, StatusCode::OK, "the session opens /account");
        assert!(
            page.text.contains("No iCloud address connected yet"),
            "{}",
            page.text
        );

        // Apple saw the hash of the nonce Firebase was given.
        let sent = rig.firebase.sign_ins();
        let post_body = sent[0]["postBody"].as_str().expect("a post body");
        let raw = url::form_urlencoded::parse(post_body.as_bytes())
            .find(|(name, _)| name == "nonce")
            .map(|(_, value)| value.into_owned())
            .expect("a nonce");
        let digest = Sha256::digest(raw.as_bytes());
        let mut hashed = String::new();
        for byte in digest {
            use std::fmt::Write as _;
            write!(hashed, "{byte:02x}").expect("write to a String");
        }
        assert_eq!(hashed, started.nonce_hash);
        let exchanged = rig.apple.token_requests();
        assert_eq!(exchanged[0]["code"], "good-code");
    }

    #[tokio::test]
    async fn callback_returns_to_the_stored_authorize_request() {
        let rig = rig().await;
        let (_, started) = rig.start("?next=authorize&pending=abc123").await;
        let reply = rig.finish(&started, "good-code").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
        assert_eq!(target(&reply), "/authorize/resume?pending=abc123");
    }

    #[tokio::test]
    async fn callback_replayed_state_refused() {
        let rig = rig().await;
        let (_, started) = rig.start("").await;
        let first = rig.finish(&started, "good-code").await;
        assert_eq!(first.status, StatusCode::SEE_OTHER);
        let replay = rig.finish(&started, "good-code").await;
        assert_refused(&replay);
        assert_eq!(rig.apple.token_requests().len(), 1, "Apple was asked once");
    }

    #[tokio::test]
    async fn callback_expired_state_refused() {
        let rig = rig_with(Some(PendingSignIns::new(Duration::ZERO, 10))).await;
        let (_, started) = rig.start("").await;
        let reply = rig.finish(&started, "good-code").await;
        assert_refused(&reply);
        assert!(
            rig.apple.token_requests().is_empty(),
            "Apple is not asked for an expired sign-in"
        );
    }

    #[tokio::test]
    async fn callback_without_or_wrong_binder_refused() {
        let rig = rig().await;
        // Finished in another browser: no binder cookie at all.
        let (_, started) = rig.start("").await;
        let reply = rig
            .callback(&[("code", "good-code"), ("state", &started.state)], None)
            .await;
        assert_refused(&reply);
        // The state was used up by that attempt, so the right browser cannot use it now either.
        let late = rig.finish(&started, "good-code").await;
        assert_refused(&late);

        // A binder from another sign-in.
        let (_, mine) = rig.start("").await;
        let (_, theirs) = rig.start("").await;
        let wrong = rig
            .callback(
                &[("code", "good-code"), ("state", &mine.state)],
                Some(&theirs.binder),
            )
            .await;
        assert_refused(&wrong);
        let forged = rig
            .callback(
                &[("code", "good-code"), ("state", &theirs.state)],
                Some(&format!("{BINDER_COOKIE}=forged")),
            )
            .await;
        assert_refused(&forged);
        assert!(
            rig.apple.token_requests().is_empty(),
            "no refused callback reached Apple"
        );
        assert_eq!(rig.firebase.sign_ins(), Vec::<serde_json::Value>::new());
    }

    #[tokio::test]
    async fn callback_with_unknown_state_or_no_state_refused() {
        let rig = rig().await;
        let (_, started) = rig.start("").await;
        for fields in [
            vec![("code", "good-code"), ("state", "unknown")],
            vec![("code", "good-code")],
            vec![("state", started.state.as_str())],
        ] {
            let reply = rig.callback(&fields, Some(&started.binder)).await;
            assert_refused(&reply);
        }
    }

    #[tokio::test]
    async fn callback_bad_firebase_token_refused() {
        let rig = rig().await;
        rig.firebase
            .edit_claims(|claims| claims["aud"] = serde_json::json!("another-project"));
        let (_, started) = rig.start("").await;
        let reply = rig.finish(&started, "good-code").await;
        assert_refused(&reply);
        assert!(
            rig.shared
                .store
                .user_by_email_or_uid(FakeFirebase::UID)
                .await
                .expect("store")
                .is_none(),
            "a refused token creates no user"
        );
    }

    #[tokio::test]
    async fn callback_apple_refusing_the_code_or_the_person_cancelling_is_refused() {
        let rig = rig().await;
        let (_, started) = rig.start("").await;
        assert_refused(&rig.finish(&started, "bad-code").await);
        let (_, cancelled) = rig.start("").await;
        let reply = rig
            .callback(
                &[
                    ("error", "user_cancelled_authorize"),
                    ("state", &cancelled.state),
                ],
                Some(&cancelled.binder),
            )
            .await;
        assert_refused(&reply);
        assert_eq!(rig.firebase.sign_ins(), Vec::<serde_json::Value>::new());
    }

    #[tokio::test]
    async fn callback_firebase_sign_up_limit_shows_try_again_in_an_hour() {
        let rig = rig().await;
        rig.firebase.fail_sign_in(
            StatusCode::BAD_REQUEST,
            "QUOTA_EXCEEDED : Exceeded quota for creating accounts.",
        );
        let (_, started) = rig.start("").await;
        let reply = rig.finish(&started, "good-code").await;
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            reply.text
        );
        assert!(
            reply.text.contains("try again in an hour"),
            "{}",
            reply.text
        );
        assert!(cookie_named(&reply, SESSION_COOKIE).is_none());
    }

    #[tokio::test]
    async fn signin_get_is_rate_limited_per_address() {
        let rig = rig().await;
        let mut limited = None;
        for attempt in 0..40 {
            let reply = rig.harness.get_path("/signin/apple", IP, None).await;
            if reply.status == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(attempt);
                break;
            }
            assert_eq!(reply.status, StatusCode::SEE_OTHER);
        }
        assert_eq!(limited, Some(30), "the shared lookup budget is 30 a minute");
        let other = rig
            .harness
            .get_path("/signin/apple", "198.51.100.8", None)
            .await;
        assert_eq!(
            other.status,
            StatusCode::SEE_OTHER,
            "another address has its own budget"
        );
    }

    #[tokio::test]
    async fn signin_refuses_new_sign_ins_when_too_many_are_waiting() {
        let rig = rig_with(Some(PendingSignIns::new(Duration::from_mins(10), 2))).await;
        rig.start("").await;
        rig.start("").await;
        let reply = rig.harness.get_path("/signin/apple", IP, None).await;
        assert_eq!(
            reply.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            reply.text
        );
    }

    #[tokio::test]
    async fn signin_routes_absent_when_identity_unset() {
        let harness = harness(Access::MultiTenant).await;
        let start = harness.get_path("/signin/apple", IP, None).await;
        assert_eq!(start.status, StatusCode::NOT_FOUND);
        let callback = harness
            .post_path("/signin/apple/callback", IP, None, &[("state", "x")])
            .await;
        assert_eq!(callback.status, StatusCode::NOT_FOUND);
        let (plain, _) = harness_with_shared().await;
        assert_eq!(
            plain.get_path("/signin/apple", IP, None).await.status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn signin_logs_no_secret() {
        let logs = Captured::default();
        let _guard = tracing::subscriber::set_default(json_subscriber(logs.clone(), Level::TRACE));
        let rig = rig().await;
        let (_, ok) = rig.start("").await;
        let signed_in = rig.finish(&ok, "good-code").await;
        assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
        rig.firebase
            .edit_claims(|claims| claims["aud"] = serde_json::json!("another-project"));
        let (_, bad) = rig.start("").await;
        assert_refused(&rig.finish(&bad, "other-code").await);

        let bytes = logs
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.is_empty(), "the requests were logged at all");
        let binder_value = ok.binder.split_once('=').expect("a pair").1;
        for secret in [
            "good-code",
            "other-code",
            "apple-id-",
            "apple-access-",
            "test-api-key",
            FakeFirebase::EMAIL,
            FakeFirebase::UID,
            FakeFirebase::APPLE_SUB,
            ok.state.as_str(),
            bad.state.as_str(),
            binder_value,
            ADA,
        ] {
            assert!(
                !text.contains(secret),
                "a log line carries {secret:?}:\n{text}"
            );
        }
    }
}
