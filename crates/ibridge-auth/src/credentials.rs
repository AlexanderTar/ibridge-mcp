// SPDX-License-Identifier: Apache-2.0

//! Sign-in validation and the app-specific password.

use ibridge_core::AppleId;
use secrecy::{ExposeSecret, SecretString};

/// An Apple ID and its app-specific password.
///
/// The password is a [`SecretString`]: it is not `Serialize`, and `Debug` prints
/// a redaction instead of the characters.
#[derive(Debug)]
pub struct Credentials {
    /// The primary iCloud address.
    pub apple_id: AppleId,
    secret: SecretString,
}

impl Credentials {
    /// Builds credentials. The password is read back only through [`Self::with_secret`].
    #[must_use]
    pub fn new(apple_id: AppleId, secret: impl Into<SecretString>) -> Self {
        Self {
            apple_id,
            secret: secret.into(),
        }
    }

    /// Passes the password to `read` and ends the borrow before returning.
    pub fn with_secret<T>(&self, read: impl FnOnce(&str) -> T) -> T {
        read(self.secret.expose_secret())
    }
}

/// How a caller proves it may use an iCloud account.
///
/// OAuth stays reserved: this enum is non-exhaustive and has no unused variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthMethod {
    /// An app-specific password for the primary address.
    AppPassword(Credentials),
}

/// Why a service was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Validation could not be run.
    #[error("validation failed")]
    Validation,
    /// A credential source could not supply an Apple ID and password.
    #[error("credentials are unavailable")]
    Unavailable,
}

/// Result of checking one iCloud service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceCheck {
    /// The service accepted the credentials.
    Ok,
    /// The service rejected them or could not be reached.
    Failed {
        /// A safe reason to show the user. Never a secret.
        reason: String,
    },
}

/// Per-service results for one sign-in attempt.
///
/// Sign-in succeeds when [`ValidationReport::any_service_ok`] is true, so an
/// account with only calendars can sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// IMAP login.
    pub mail: ServiceCheck,
    /// `CalDAV` principal lookup.
    pub calendar: ServiceCheck,
    /// `CardDAV` principal lookup.
    pub contacts: ServiceCheck,
}

impl ValidationReport {
    /// Returns true when mail, calendar or contacts accepted the credentials.
    #[must_use]
    pub fn any_service_ok(&self) -> bool {
        matches!(self.mail, ServiceCheck::Ok)
            || matches!(self.calendar, ServiceCheck::Ok)
            || matches!(self.contacts, ServiceCheck::Ok)
    }
}

/// Checks mail, calendar and contacts for a sign-in.
///
/// The implementor holds the credentials. Login and the hosted sign-in page
/// both call this and accept the attempt when any service succeeds.
#[trait_variant::make(Send)]
pub trait Validator {
    /// Runs the checks.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when validation cannot be run at all.
    async fn validate(&self) -> Result<ValidationReport, AuthError>;
}
