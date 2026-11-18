// SPDX-License-Identifier: Apache-2.0

//! Deleting an account that signed in with Apple.
//!
//! The person ticks the box on the account page, then signs in with Apple again, so a
//! session someone else left open cannot delete an account. That fresh sign-in hands back
//! what the providers need: Apple's access token to revoke, and a Firebase ID token to
//! delete the Firebase user. Neither is stored.
//!
//! Order matters for a failure half way. The subscription is cancelled first, so nobody is
//! billed for an account that is going. The rows go next, and a failure there stops before
//! anything is revoked, so the person can try again. Apple and Firebase come last: they
//! hold no data of ours, and a failure there is reported, not retried.

use std::time::SystemTime;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::account::session_of;
use super::signin;
use crate::identity::{ReturnTo, SignedIn};
use crate::oauth::Shared;
use crate::store::User;
use crate::web::{message, set_cookie};

const TROUBLE: &str =
    "Something went wrong on our side. Nothing was deleted. Try again in a moment.";

/// Sends the person to Apple for the fresh sign-in that confirms the deletion.
pub(super) fn ask_for_fresh_sign_in(shared: &Shared) -> Response {
    let Some(identity) = shared.identity.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    signin::begin(identity, ReturnTo::DeleteAccount)
}

/// Finishes a deletion from the fresh sign-in's callback.
///
/// Only the person whose session asked for it can finish it: the Apple account that just
/// signed in must be the one the session belongs to.
pub(super) async fn complete(shared: &Shared, headers: &HeaderMap, signed: SignedIn) -> Response {
    let Some((token, session)) = session_of(shared, headers) else {
        return message(
            StatusCode::FORBIDDEN,
            "Sign in again",
            "You were signed out before this finished. Nothing was deleted. Go to your account page and start again.",
        );
    };
    let user = match session.principal.user() {
        Some(id) => match shared.store.user(id).await {
            Ok(user) => user,
            Err(error) => {
                tracing::error!(%error, "could not read the user being deleted");
                return message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    TROUBLE,
                );
            }
        },
        None => None,
    };
    let Some(user) = user.filter(|user| user.firebase_uid == signed.firebase_uid) else {
        return message(
            StatusCode::FORBIDDEN,
            "A different Apple account",
            "You signed in with a different Apple account than the one you are deleting. Nothing was deleted. Go to your account page and start again.",
        );
    };
    let mut failed: Vec<&'static str> = Vec::new();
    if cancel_subscription(shared, &user).await.is_err() {
        failed.push("Stripe");
    }
    match shared.store.delete_user(user.id).await {
        Ok(accounts) => accounts.iter().for_each(|account| (shared.evict)(account)),
        Err(error) => {
            tracing::error!(user = %user.id, %error, "could not delete a user");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
    }
    shared.sessions.end(&token);
    if revoke_apple(shared, &user, &signed).await.is_err() {
        failed.push("Apple");
    }
    if delete_firebase(shared, &user, &signed).await.is_err() {
        failed.push("Google");
    }
    let mut response = message(
        StatusCode::OK,
        "Account deleted",
        &farewell(shared, &user, &failed),
    );
    set_cookie(&mut response, super::account::SESSION_COOKIE, "", 0);
    response
}

/// Ends the user's subscription at once. Nothing to do when they never paid.
async fn cancel_subscription(shared: &Shared, user: &User) -> Result<(), ()> {
    let (Some(billing), Some(subscription)) =
        (shared.billing.as_ref(), user.stripe_subscription.as_deref())
    else {
        return Ok(());
    };
    billing.stripe.cancel_now(subscription).await.map_err(|error| {
        tracing::warn!(user = %user.id, %error, "could not cancel a subscription while deleting an account");
    })
}

async fn revoke_apple(shared: &Shared, user: &User, signed: &SignedIn) -> Result<(), ()> {
    let (Some(identity), Some(access)) = (shared.identity.as_ref(), signed.apple_access.as_ref())
    else {
        return Ok(());
    };
    identity
        .revoke_apple(access, SystemTime::now())
        .await
        .map_err(|error| {
            tracing::warn!(user = %user.id, %error, "could not revoke Apple's grant while deleting an account");
        })
}

async fn delete_firebase(shared: &Shared, user: &User, signed: &SignedIn) -> Result<(), ()> {
    let Some(identity) = shared.identity.as_ref() else {
        return Ok(());
    };
    identity
        .delete_firebase(&signed.firebase_id_token)
        .await
        .map_err(|error| {
            tracing::warn!(user = %user.id, %error, "could not delete a Firebase user while deleting an account");
        })
}

/// What the last page says: what is gone, what is left to do, and what could not be finished.
fn farewell(shared: &Shared, user: &User, failed: &[&str]) -> String {
    let mut parts = vec![String::from(
        "Your account is deleted: your sign-in, your connected apps, your API keys and the encrypted copies of your app-specific password. They stop working now.",
    )];
    if user.account.is_some() {
        parts.push(String::from(
            "To finish, revoke the app-specific password at Apple (Sign-In and Security, then App-Specific Passwords in your Apple Account), so nothing we held can still be used.",
        ));
    }
    if !failed.is_empty() {
        parts.push(format!(
            "We could not finish removing you at {}. Everything on this service is deleted.",
            failed.join(" and ")
        ));
        parts.push(match shared.config.contact_address() {
            Some(contact) => format!("Email {contact} and we will finish it."),
            None => String::from("Ask whoever runs this service to finish it."),
        });
    }
    parts.join(" ")
}
