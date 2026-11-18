// SPDX-License-Identifier: Apache-2.0

//! Deleting an account that signed in with Apple.
//!
//! The person ticks the box on the account page, then signs in with Apple again, so a
//! session someone else left open cannot delete an account. That fresh sign-in hands back
//! what the providers need: Apple's access token to revoke, and a Firebase ID token to
//! delete the Firebase user. Neither is stored.
//!
//! Order matters for a failure half way. Every live subscription on the person's Stripe
//! customer is cancelled first, so nobody is billed for an account that is going. If one
//! that still gives access cannot be cancelled, the deletion stops there. The rows go next, and a failure there stops before
//! anything is revoked, so the person can try again. Apple and Firebase come last: they
//! hold no data of ours, and a failure there is reported, not retried.

use std::time::SystemTime;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::signin;
use crate::billing::grants_access;
use crate::identity::{ReturnTo, SignedIn};
use crate::oauth::Shared;
use crate::store::{User, UserId};
use crate::web::{message, notice, set_cookie};

const TROUBLE: &str =
    "Something went wrong on our side. Nothing was deleted. Try again in a moment.";

/// Sends the person to Apple for the fresh sign-in that confirms the deletion.
pub(super) fn ask_for_fresh_sign_in(shared: &Shared, user: UserId) -> Response {
    let Some(identity) = shared.identity.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    signin::begin(identity, ReturnTo::DeleteAccount(user))
}

/// Finishes a deletion from the fresh sign-in's callback.
///
/// Apple posts the callback from another site, so the browser sends no session cookie. The
/// user comes from the pending sign-in instead, which the session started and the binder
/// cookie ties to this browser. The Apple account that just signed in must be that user's.
pub(super) async fn complete(shared: &Shared, asked: UserId, signed: SignedIn) -> Response {
    let user = match shared.store.user(asked).await {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(%error, "could not read the user being deleted");
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
    };
    let Some(user) = user.filter(|user| user.firebase_uid == signed.firebase_uid) else {
        return message(
            StatusCode::FORBIDDEN,
            "A different Apple account",
            "You signed in with a different Apple account than the one you are deleting. Nothing was deleted. Go to your account page and start again.",
        );
    };
    let mut failed: Vec<&'static str> = Vec::new();
    match cancel_subscriptions(shared, &user).await {
        Cancelled::Done => {}
        // A subscription that still gives access keeps billing, so nothing is deleted
        // until it is cancelled.
        Cancelled::PayingOneFailed => {
            return message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                TROUBLE,
            );
        }
        // Any other status is not billing, so the rest goes on.
        Cancelled::OnlyOthersFailed => failed.push("Stripe"),
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
    shared.sessions.end_all_for(user.id);
    if revoke_apple(shared, &user, &signed).await.is_err() {
        failed.push("Apple");
    }
    if delete_firebase(shared, &user, &signed).await.is_err() {
        failed.push("Google");
    }
    let mut response = notice(
        StatusCode::OK,
        "Account deleted",
        &farewell(shared, &user, &failed),
    );
    set_cookie(&mut response, super::account::SESSION_COOKIE, "", 0);
    response
}

/// How ending the user's subscriptions went.
enum Cancelled {
    /// Every live subscription is ended, or there was none.
    Done,
    /// A subscription that gives access could not be ended, so billing may go on.
    PayingOneFailed,
    /// Only subscriptions that no longer give access could not be ended.
    OnlyOthersFailed,
}

/// Ends every live subscription on the user's Stripe customer at once, and the one on the row.
///
/// The customer may hold more than the row records (a second checkout, one the return route
/// never saw), so Stripe is asked. Ended ones are skipped. Every subscription is tried even
/// after one fails, so a retry has less left. When Stripe cannot list them, the row's own
/// status says whether billing may be going on.
async fn cancel_subscriptions(shared: &Shared, user: &User) -> Cancelled {
    let Some(billing) = shared.billing.as_ref() else {
        return Cancelled::Done;
    };
    // (id, whether it gives access)
    let mut live: Vec<(String, bool)> = Vec::new();
    let mut listing_failed = false;
    if let Some(customer) = user.stripe_customer.as_deref() {
        match billing.stripe.subscriptions_of(customer).await {
            Ok(all) => live.extend(
                all.into_iter()
                    .filter(|sub| !is_ended(&sub.status))
                    .map(|sub| (sub.id, grants_access(&sub.status))),
            ),
            Err(error) => {
                tracing::warn!(user = %user.id, %error, "could not list subscriptions while deleting an account");
                listing_failed = true;
            }
        }
    }
    let row_status = user.status.as_deref();
    if let Some(id) = user.stripe_subscription.as_deref()
        && !row_status.is_some_and(is_ended)
        && !live.iter().any(|(known, _)| known == id)
    {
        live.push((id.to_owned(), row_status.is_some_and(grants_access)));
    }
    let mut result = if listing_failed {
        // Unknown subscriptions may be paying; trust the row for how serious that is.
        if row_status.is_some_and(grants_access) {
            Cancelled::PayingOneFailed
        } else {
            Cancelled::OnlyOthersFailed
        }
    } else {
        Cancelled::Done
    };
    for (id, paying) in live {
        if let Err(error) = billing.stripe.cancel_now(&id).await {
            tracing::warn!(user = %user.id, %error, "could not cancel a subscription while deleting an account");
            if paying {
                result = Cancelled::PayingOneFailed;
            } else if matches!(result, Cancelled::Done) {
                result = Cancelled::OnlyOthersFailed;
            }
        }
    }
    result
}

/// Whether Stripe will never bill this subscription again.
fn is_ended(status: &str) -> bool {
    matches!(status, "canceled" | "incomplete_expired")
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
            list(failed)
        ));
        if failed.contains(&"Stripe") {
            parts.push(String::from(
                "Your subscription may not be cancelled, so billing may continue until it is.",
            ));
        }
        parts.push(match shared.config.contact_address() {
            Some(contact) => format!("Email {contact} and we will finish it."),
            None => String::from("Ask whoever runs this service to finish it."),
        });
    }
    parts.join(" ")
}

/// `Stripe`, `Stripe and Apple`, or `Stripe, Apple and Google`.
fn list(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}
