// SPDX-License-Identifier: Apache-2.0

//! The live sign-in check, injected so tests and self-host builds choose the validators.

use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};

use super::cimd::BoxFuture;
use crate::store::{StoreError, ValidatedCredentials};

/// Checks an address and app-specific password with iCloud.
pub trait SignInCheck: Send + Sync + 'static {
    /// Returns the credentials when some iCloud service accepts them.
    fn check(
        &self,
        credentials: Credentials,
    ) -> BoxFuture<'_, Result<ValidatedCredentials, StoreError>>;
}

/// Builds a check from a function that makes a [`Validator`] for each attempt.
#[derive(Debug)]
pub struct ValidatedBy<F>(F);

/// A [`SignInCheck`] that runs the validator `make` builds from the credentials.
pub fn validated_by<V, F>(make: F) -> ValidatedBy<F>
where
    V: Validator + Send + Sync + 'static,
    F: Fn(&Credentials) -> V + Send + Sync + 'static,
{
    ValidatedBy(make)
}

impl<V, F> SignInCheck for ValidatedBy<F>
where
    V: Validator + Send + Sync + 'static,
    F: Fn(&Credentials) -> V + Send + Sync + 'static,
{
    fn check(
        &self,
        credentials: Credentials,
    ) -> BoxFuture<'_, Result<ValidatedCredentials, StoreError>> {
        Box::pin(ValidatedCredentials::from_check(credentials, &self.0))
    }
}

/// Mail from one validator and calendar and contacts from another, as one report.
///
/// Sign-in succeeds if either side does, so an account without iCloud Mail
/// signs in through `CalDAV`.
#[derive(Debug)]
pub struct Combined<M, D> {
    /// Checks mail (IMAP).
    pub mail: M,
    /// Checks calendar and contacts (`CalDAV` and `CardDAV`).
    pub dav: D,
}

impl<M: Validator + Sync, D: Validator + Sync> Validator for Combined<M, D> {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        let (mail, dav) = tokio::join!(self.mail.validate(), self.dav.validate());
        if mail.is_err() && dav.is_err() {
            return Err(AuthError::Validation);
        }
        let unavailable = |what: &str| ServiceCheck::Failed {
            reason: format!("{what} could not be checked"),
        };
        let (mail, calendar, contacts) = match (mail, dav) {
            (Ok(mail), Ok(dav)) => (mail.mail, dav.calendar, dav.contacts),
            (Ok(mail), Err(_)) => (mail.mail, unavailable("calendar"), unavailable("contacts")),
            (Err(_), Ok(dav)) => (unavailable("mail"), dav.calendar, dav.contacts),
            (Err(_), Err(_)) => return Err(AuthError::Validation),
        };
        Ok(ValidationReport {
            mail,
            calendar,
            contacts,
        })
    }
}
