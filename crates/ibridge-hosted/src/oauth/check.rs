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
        // A validator that could not run says nothing about its services: not a refusal.
        let unavailable = |what: &str| ServiceCheck::Unreachable {
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

#[cfg(test)]
mod tests {
    use ibridge_auth::{AuthError, ServiceCheck, ValidationReport, Validator};

    use super::Combined;
    use crate::store::Services;

    /// A validator that answers with a fixed result.
    struct Fixed(Result<ValidationReport, AuthError>);

    impl Validator for Fixed {
        fn validate(&self) -> impl Future<Output = Result<ValidationReport, AuthError>> + Send {
            std::future::ready(self.0.clone())
        }
    }

    fn dav_ok() -> Fixed {
        let failed = |reason: &str| ServiceCheck::Failed {
            reason: reason.to_owned(),
        };
        Fixed(Ok(ValidationReport {
            mail: failed("not checked"),
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Ok,
        }))
    }

    fn mail_report(mail: ServiceCheck) -> Fixed {
        let failed = |reason: &str| ServiceCheck::Failed {
            reason: reason.to_owned(),
        };
        Fixed(Ok(ValidationReport {
            mail,
            calendar: failed("not checked"),
            contacts: failed("not checked"),
        }))
    }

    #[tokio::test]
    async fn transient_failure_at_sign_in_keeps_the_service_on() {
        let combined = Combined {
            mail: Fixed(Err(AuthError::Validation)),
            dav: dav_ok(),
        };
        let services = Services::from_report(&combined.validate().await.expect("dav accepted"));
        assert_eq!(services.mail, None, "an unchecked service is not a refusal");
    }

    #[tokio::test]
    async fn unreachable_mail_at_sign_in_keeps_mail_on() {
        let combined = Combined {
            mail: mail_report(ServiceCheck::Unreachable {
                reason: "iCloud Mail could not be reached".to_owned(),
            }),
            dav: dav_ok(),
        };
        let services = Services::from_report(&combined.validate().await.expect("dav accepted"));
        assert_eq!(
            services.mail, None,
            "an unreachable service is not a refusal"
        );
    }

    #[tokio::test]
    async fn refused_mail_at_sign_in_is_stored_off_with_its_reason() {
        let combined = Combined {
            mail: mail_report(ServiceCheck::Failed {
                reason: "iCloud Mail rejected the password".to_owned(),
            }),
            dav: dav_ok(),
        };
        let services = Services::from_report(&combined.validate().await.expect("dav accepted"));
        assert_eq!(
            services.mail.as_deref(),
            Some("iCloud Mail rejected the password")
        );
    }
}
