// SPDX-License-Identifier: Apache-2.0

//! Sign-in validation.

/// Why a service was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Validation could not be run.
    #[error("validation failed")]
    Validation,
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
