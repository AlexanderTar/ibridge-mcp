// SPDX-License-Identifier: Apache-2.0

//! Mail backends: the real iCloud session, and the stand-in when mail is off.

use std::sync::Arc;

#[cfg(feature = "mail")]
use ibridge_auth::ServiceCheck;
use ibridge_auth::{AuthError, Credentials, ValidationReport, Validator};
use ibridge_core::{CoreError, Draft, FlagChange, MailSearch, Mailbox, MessageId};
use ibridge_server::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail};

/// Mail backend for a build with mail off. Every call says so.
#[cfg(any(not(feature = "mail"), test))]
#[derive(Debug)]
pub(crate) struct NoMail;

#[cfg(any(not(feature = "mail"), test))]
const OFF: CoreError = CoreError::Unsupported("mail is not enabled in this build");

#[cfg(any(not(feature = "mail"), test))]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl MailApi for NoMail {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        Err(OFF)
    }

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
        Err(OFF)
    }

    async fn get_message(&self, _id: &MessageId, _offset: usize) -> Result<MailBody, CoreError> {
        Err(OFF)
    }

    async fn get_attachment(
        &self,
        _id: &MessageId,
        _part: &str,
        _offset: usize,
    ) -> Result<MailPart, CoreError> {
        Err(OFF)
    }

    async fn create_draft(&self, _draft: &Draft) -> Result<MessageId, CoreError> {
        Err(OFF)
    }

    async fn send(&self, _draft: &Draft) -> Result<SentMail, CoreError> {
        Err(OFF)
    }

    async fn move_message(
        &self,
        _id: &MessageId,
        _destination: &MailDest,
    ) -> Result<(), CoreError> {
        Err(OFF)
    }

    async fn set_flags(&self, _id: &MessageId, _flags: &FlagChange) -> Result<(), CoreError> {
        Err(OFF)
    }
}

/// The mail backend `serve` runs with.
#[cfg(feature = "mail")]
pub(crate) type Backend = SessionMail<ibridge_mail::IcloudConnect>;
/// The mail backend `serve` runs with.
#[cfg(not(feature = "mail"))]
pub(crate) type Backend = NoMail;

/// Builds the mail backend for `credentials`. No connection is opened yet.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg(feature = "mail")]
pub(crate) fn backend(credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    use ibridge_mail::{IcloudConnect, ImapPool, MailSession, SmtpClient};

    let pool = ImapPool::new(duplicate(credentials), IcloudConnect::new()?);
    let smtp = SmtpClient::icloud(duplicate(credentials));
    Ok(Arc::new(SessionMail(MailSession::new(pool, smtp))))
}

/// Builds the stand-in mail backend.
///
/// # Errors
///
/// Never fails.
#[cfg(not(feature = "mail"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the mail build can fail, and both builds share one signature"
)]
pub(crate) fn backend(_credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    Ok(Arc::new(NoMail))
}

/// A second copy of the credentials, for the SMTP client.
#[cfg(feature = "mail")]
fn duplicate(credentials: &Credentials) -> Credentials {
    credentials
        .with_secret(|secret| Credentials::new(credentials.apple_id.clone(), secret.to_owned()))
}

/// Adapts an iCloud mail session to the tool layer.
#[cfg(feature = "mail")]
#[derive(Debug)]
pub(crate) struct SessionMail<C: ibridge_mail::Connect>(ibridge_mail::MailSession<C>);

#[cfg(feature = "mail")]
impl<C: ibridge_mail::Connect + 'static> MailApi for SessionMail<C> {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        self.0.imap().list_mailboxes().await
    }

    async fn search(&self, query: &MailSearch) -> Result<MailHitPage, CoreError> {
        let page = self.0.imap().search(query).await?;
        Ok(MailHitPage {
            messages: page.messages,
            next_cursor: page.next_cursor,
            warnings: page.warnings,
        })
    }

    async fn get_message(&self, id: &MessageId, offset: usize) -> Result<MailBody, CoreError> {
        let fetched = self.0.imap().get_message(id, offset).await?;
        Ok(MailBody {
            message: fetched.message,
            next_offset: fetched.next_offset,
        })
    }

    async fn get_attachment(
        &self,
        id: &MessageId,
        part: &str,
        offset: usize,
    ) -> Result<MailPart, CoreError> {
        let fetched = self.0.imap().get_attachment(id, part, offset).await?;
        Ok(MailPart {
            attachment: fetched.attachment,
            next_offset: fetched.next_offset,
        })
    }

    async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError> {
        self.0.create_draft(draft).await
    }

    async fn send(&self, draft: &Draft) -> Result<SentMail, CoreError> {
        let sent = self.0.send(draft).await?;
        Ok(SentMail { id: sent.id })
    }

    async fn move_message(&self, id: &MessageId, destination: &MailDest) -> Result<(), CoreError> {
        match destination {
            MailDest::Path(path) => self.0.move_to(id, path).await,
            MailDest::Role(role) => self.0.move_to_role(id, *role).await,
            _ => Err(CoreError::Unsupported("that move destination")),
        }
    }

    async fn set_flags(&self, id: &MessageId, flags: &FlagChange) -> Result<(), CoreError> {
        self.0.set_flags(id, flags).await
    }
}

/// Checks the sign-in against what this build can reach.
#[cfg(feature = "mail")]
pub(crate) struct ImapValidator {
    pool: ibridge_mail::ImapPool<ibridge_mail::IcloudConnect>,
}

#[cfg(feature = "mail")]
impl Validator for ImapValidator {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        let mail = match self.pool.capabilities().await {
            Ok(_) => ServiceCheck::Ok,
            Err(CoreError::Auth) => ServiceCheck::Failed {
                reason: "iCloud Mail rejected the address or app-specific password; use your primary iCloud address and an app-specific password".to_owned(),
            },
            Err(CoreError::RateLimited { .. }) => ServiceCheck::Failed {
                reason: "iCloud Mail is limiting sign-ins; wait a few minutes and try again"
                    .to_owned(),
            },
            Err(_) => ServiceCheck::Failed {
                reason: "iCloud Mail could not be reached".to_owned(),
            },
        };
        // ponytail: CalDAV and CardDAV checks arrive with the DAV validator.
        Ok(ValidationReport {
            mail,
            calendar: ServiceCheck::Failed {
                reason: "calendar sign-in is not checked in this release".to_owned(),
            },
            contacts: ServiceCheck::Failed {
                reason: "contacts sign-in is not checked in this release".to_owned(),
            },
        })
    }
}

/// The validator `login` runs.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg(feature = "mail")]
pub(crate) fn validator(credentials: &Credentials) -> anyhow::Result<ImapValidator> {
    Ok(ImapValidator {
        pool: ibridge_mail::ImapPool::new(
            duplicate(credentials),
            ibridge_mail::IcloudConnect::new()?,
        ),
    })
}

/// Validator for a build without mail: nothing can be checked, so login fails.
#[cfg(not(feature = "mail"))]
pub(crate) struct Unavailable;

#[cfg(not(feature = "mail"))]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl Validator for Unavailable {
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

/// The validator `login` runs.
///
/// # Errors
///
/// Never fails.
#[cfg(not(feature = "mail"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the mail build can fail, and both builds share one signature"
)]
pub(crate) fn validator(_credentials: &Credentials) -> anyhow::Result<Unavailable> {
    Ok(Unavailable)
}
