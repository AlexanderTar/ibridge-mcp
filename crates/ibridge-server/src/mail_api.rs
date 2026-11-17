// SPDX-License-Identifier: Apache-2.0

//! Mail operations the tools call. The binary adapts `MailSession` to this.

use ibridge_core::{
    Attachment, CoreError, Draft, FlagChange, MailSearch, Mailbox, MailboxPath, MailboxRole,
    Message, MessageId, MessageSummary,
};

/// One page of search hits, plus how many messages were skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailHitPage {
    /// Hits, newest first.
    pub messages: Vec<MessageSummary>,
    /// Present when another page exists.
    pub next_cursor: Option<String>,
    /// Messages skipped because they did not parse.
    pub warnings: u32,
}

/// A message body window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailBody {
    /// Headers, the body window, and the attachment list.
    pub message: Message,
    /// Set when another window starts at this scalar offset.
    pub next_offset: Option<usize>,
}

/// One attachment window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailPart {
    /// The part that was fetched.
    pub attachment: Attachment,
    /// Set when a text part has another window at this scalar offset.
    pub next_offset: Option<usize>,
}

/// A message SMTP accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    /// Id of the copy in Sent Messages.
    ///
    /// `None` when the message was delivered and the Sent append failed.
    pub id: Option<MessageId>,
}

/// Where a move puts a message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MailDest {
    /// A mailbox path.
    Path(MailboxPath),
    /// A well-known role.
    Role(MailboxRole),
}

/// Mail backend for one account.
#[trait_variant::make(Send)]
pub trait MailApi {
    /// Lists mailboxes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the mailbox list cannot be read.
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError>;

    /// Searches messages.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the search cannot be run.
    async fn search(&self, query: &MailSearch) -> Result<MailHitPage, CoreError>;

    /// Fetches one message. `offset` is a Unicode scalar index into the body.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the message cannot be read.
    async fn get_message(&self, id: &MessageId, offset: usize) -> Result<MailBody, CoreError>;

    /// Fetches one attachment. `offset` is a Unicode scalar index into a text part.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the part cannot be read.
    async fn get_attachment(
        &self,
        id: &MessageId,
        part: &str,
        offset: usize,
    ) -> Result<MailPart, CoreError>;

    /// Fetches every decoded byte of one attachment, for saving to disk.
    ///
    /// A backend that cannot do this keeps the default, which refuses.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the part cannot be read.
    async fn get_attachment_bytes(
        &self,
        _id: &MessageId,
        _part: &str,
    ) -> Result<Attachment, CoreError> {
        async { Err(CoreError::Unsupported("saving attachments")) }
    }

    /// Appends a draft.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the draft cannot be saved.
    async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError>;

    /// Sends a message. `id: None` means SMTP accepted it and the Sent copy failed.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the message cannot be sent.
    async fn send(&self, draft: &Draft) -> Result<SentMail, CoreError>;

    /// Moves a message.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the move cannot be done.
    async fn move_message(&self, id: &MessageId, destination: &MailDest) -> Result<(), CoreError>;

    /// Sets or clears flags.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the flags cannot be stored.
    async fn set_flags(&self, id: &MessageId, flags: &FlagChange) -> Result<(), CoreError>;
}
