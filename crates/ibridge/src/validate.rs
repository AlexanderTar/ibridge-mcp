// SPDX-License-Identifier: Apache-2.0

//! The sign-in check `login` runs: mail from IMAP, calendar and contacts from `CalDAV`.

use ibridge_auth::{AuthError, Credentials, ValidationReport, Validator};

/// Takes the mail result from `mail` and the calendar and contacts results from `dav`.
///
/// A service that fails does not fail the check. `login` succeeds when any one works.
#[derive(Debug)]
pub(crate) struct Combined<A, B> {
    pub(crate) mail: A,
    pub(crate) dav: B,
}

impl<A: Validator + Sync, B: Validator + Sync> Validator for Combined<A, B> {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        let mail = self.mail.validate().await?;
        let dav = self.dav.validate().await?;
        Ok(ValidationReport {
            mail: mail.mail,
            calendar: dav.calendar,
            contacts: dav.contacts,
        })
    }
}

/// Stands in for a check this build does not include. It reports every service failed.
#[cfg(any(not(feature = "mail"), not(feature = "calendar")))]
#[derive(Debug)]
pub(crate) struct Skipped;

#[cfg(any(not(feature = "mail"), not(feature = "calendar")))]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl Validator for Skipped {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        use ibridge_auth::ServiceCheck;

        let off = |name: &str| ServiceCheck::Failed {
            reason: format!("{name} sign-in is not available in this build"),
        };
        Ok(ValidationReport {
            mail: off("mail"),
            calendar: off("calendar"),
            contacts: off("contacts"),
        })
    }
}

/// The mail check of this build.
#[cfg(feature = "mail")]
type MailCheck = crate::mail::ImapValidator;
/// The mail check of this build.
#[cfg(not(feature = "mail"))]
type MailCheck = Skipped;

/// The calendar and contacts check of this build.
#[cfg(feature = "calendar")]
type DavCheck = ibridge_dav::DavValidator<ibridge_dav::DavClient>;
/// The calendar and contacts check of this build.
#[cfg(not(feature = "calendar"))]
type DavCheck = Skipped;

/// The validator `login` runs: IMAP for mail, `CalDAV` and `CardDAV` for the rest.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg_attr(
    not(any(feature = "mail", feature = "calendar")),
    expect(
        clippy::unnecessary_wraps,
        reason = "builds with a service can fail, and every build shares one signature"
    )
)]
pub(crate) fn validator(
    #[cfg_attr(
        not(any(feature = "mail", feature = "calendar")),
        expect(unused_variables, reason = "no service in this build reads them")
    )]
    credentials: &Credentials,
) -> anyhow::Result<Combined<MailCheck, DavCheck>> {
    #[cfg(feature = "mail")]
    let mail = crate::mail::imap_validator(credentials)?;
    #[cfg(not(feature = "mail"))]
    let mail = Skipped;
    #[cfg(feature = "calendar")]
    let dav = ibridge_dav::DavValidator::new(credentials.duplicate())?;
    #[cfg(not(feature = "calendar"))]
    let dav = Skipped;
    Ok(Combined { mail, dav })
}

/// The sign-in check of the hosted server: the same two checks as [`validator`], but
/// sign-in succeeds when either side works, so an account without iCloud Mail signs in
/// through `CalDAV`.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg(feature = "hosted")]
pub(crate) fn hosted_validator(
    credentials: &Credentials,
) -> anyhow::Result<impl Validator + Sync + use<>> {
    let Combined { mail, dav } = validator(credentials)?;
    Ok(ibridge_hosted::Combined { mail, dav })
}
