// SPDX-License-Identifier: Apache-2.0

//! Mail identifiers.

use std::fmt;
use std::num::NonZeroU32;

use crate::error::{CoreError, ParseError};

/// An IMAP mailbox path, stored as Unicode (not modified UTF-7).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MailboxPath(String);

impl MailboxPath {
    /// Returns the mailbox path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for MailboxPath {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 1024
            || value.contains("://")
            || value.starts_with("//")
            || value.chars().any(char::is_control)
        {
            return Err(ParseError::MailboxPath);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for MailboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An IMAP UID. Zero is never a valid UID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Uid(NonZeroU32);

impl Uid {
    /// Returns the UID as a `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for Uid {
    type Error = ParseError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(value).map(Self).ok_or(ParseError::Uid)
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// An IMAP UIDVALIDITY. Zero is never valid.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct UidValidity(NonZeroU32);

impl UidValidity {
    /// Returns the UIDVALIDITY as a `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for UidValidity {
    type Error = ParseError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(value).map(Self).ok_or(ParseError::Uid)
    }
}

impl fmt::Display for UidValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// A mail id: mailbox path, `UIDVALIDITY` and `UID`.
///
/// The wire form is an opaque base64url token from [`crate::encode`]. It carries no host.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct MessageId {
    /// Mailbox the message lives in.
    pub mailbox: MailboxPath,
    /// `UIDVALIDITY` of that mailbox at the time the id was issued.
    pub validity: UidValidity,
    /// IMAP `UID`.
    pub uid: Uid,
}

/// Which well-known mailbox a path plays, when the server says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MailboxRole {
    /// Inbox.
    Inbox,
    /// Sent messages.
    Sent,
    /// Drafts.
    Drafts,
    /// Trash.
    Trash,
    /// Junk.
    Junk,
    /// Archive.
    Archive,
    /// Notes stored as mail.
    Notes,
    /// A mailbox with no special role.
    Other,
}

/// One mailbox and its counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    /// Mailbox path.
    pub path: MailboxPath,
    /// Special-use role, or [`MailboxRole::Other`].
    pub role: MailboxRole,
    /// Messages in the mailbox.
    pub total: u32,
    /// Messages that are not seen.
    pub unread: u32,
}

/// A search over one mailbox or role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailSearch {
    /// Restrict to this mailbox path.
    pub mailbox: Option<MailboxPath>,
    /// Restrict to this role.
    pub role: Option<MailboxRole>,
    /// From header contains this text.
    pub from: Option<String>,
    /// To header contains this text.
    pub to: Option<String>,
    /// Subject contains this text.
    pub subject: Option<String>,
    /// Body or subject contains this text.
    pub text: Option<String>,
    /// Messages on or after this ISO-8601 date.
    pub since: Option<String>,
    /// Messages before this ISO-8601 date.
    pub before: Option<String>,
    /// When true, only unseen messages.
    pub unread_only: bool,
    /// When true, only flagged messages.
    pub flagged_only: bool,
    /// Page size. Callers cap this at 100.
    pub limit: u32,
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
}

/// One hit from [`MailProvider::search`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSummary {
    /// Opaque message id.
    pub id: MessageId,
    /// From header.
    pub from: String,
    /// Subject.
    pub subject: String,
    /// Date header, as text.
    pub date: String,
    /// The message is unseen.
    pub unread: bool,
    /// The message is flagged.
    pub flagged: bool,
}

/// A page of search hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailPage {
    /// Hits, newest first.
    pub messages: Vec<MessageSummary>,
    /// Present when another page exists.
    pub next_cursor: Option<String>,
}

/// An attachment listed on a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// Part identifier the provider understands.
    pub part: String,
    /// MIME type.
    pub content_type: String,
    /// Size in bytes.
    pub size: u64,
    /// File name, when the message has one.
    pub name: String,
}

/// A fetched message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Opaque message id.
    pub id: MessageId,
    /// From header.
    pub from: String,
    /// To headers.
    pub to: Vec<String>,
    /// Subject.
    pub subject: String,
    /// Date header, as text.
    pub date: String,
    /// Body as text. Untrusted content.
    pub body: String,
    /// Attachments, without their bytes.
    pub attachments: Vec<AttachmentInfo>,
}

/// A fetched attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// The part that was fetched.
    pub info: AttachmentInfo,
    /// Extracted text, for a text-like part.
    pub text: Option<String>,
    /// Raw bytes, only when the part is small enough to return inline.
    pub bytes: Option<Vec<u8>>,
}

/// A draft or a message to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// Recipients.
    pub to: Vec<String>,
    /// Subject.
    pub subject: String,
    /// Body as text.
    pub body: String,
    /// `From` when it is not the account's Apple ID. A custom domain is allowed.
    pub from: Option<String>,
    /// Message this draft replies to.
    pub reply_to: Option<MessageId>,
}

/// Flags to set or clear. `None` leaves a flag unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagChange {
    /// Seen flag.
    pub seen: Option<bool>,
    /// Flagged flag.
    pub flagged: Option<bool>,
}

/// Mail read and write operations.
#[trait_variant::make(Send)]
pub trait MailProvider {
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
    async fn search(&self, query: &MailSearch) -> Result<MailPage, CoreError>;

    /// Fetches one message.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the message cannot be read.
    async fn get_message(&self, id: &MessageId) -> Result<Message, CoreError>;

    /// Fetches one attachment.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the part cannot be read.
    async fn get_attachment(&self, id: &MessageId, part: &str) -> Result<Attachment, CoreError>;

    /// Appends a draft.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the draft cannot be saved.
    async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError>;

    /// Sends a message.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the message cannot be sent.
    async fn send(&self, draft: &Draft) -> Result<MessageId, CoreError>;

    /// Moves a message to another mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the move cannot be done.
    async fn move_to(&self, id: &MessageId, destination: &MailboxPath) -> Result<(), CoreError>;

    /// Sets or clears flags.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the flags cannot be stored.
    async fn set_flags(&self, id: &MessageId, flags: &FlagChange) -> Result<(), CoreError>;
}
