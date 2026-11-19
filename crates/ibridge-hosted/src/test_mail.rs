// SPDX-License-Identifier: Apache-2.0

//! A mail backend for tests that only look at which tools exist.

use ibridge_core::{Attachment, CoreError, Draft, FlagChange, MailSearch, Mailbox, MessageId};
use ibridge_server::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail};

/// Every operation fails as unsupported.
#[derive(Debug)]
pub(crate) struct IdleMail;

const OFF: CoreError = CoreError::Unsupported("idle");

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl MailApi for IdleMail {
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

    async fn get_attachment_bytes(
        &self,
        _id: &MessageId,
        _part: &str,
    ) -> Result<Attachment, CoreError> {
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
