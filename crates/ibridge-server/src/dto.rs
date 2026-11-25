// SPDX-License-Identifier: Apache-2.0

//! Tool arguments and structured results.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_page_limit() -> u32 {
    25
}

/// Arguments for `mail_search`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Mailbox path. Omit to use `role` or the inbox.
    #[serde(default)]
    pub mailbox: Option<String>,
    /// Well-known role: inbox, sent, drafts, trash, junk, archive, notes.
    #[serde(default)]
    pub role: Option<String>,
    /// From header contains this text.
    #[serde(default)]
    pub from: Option<String>,
    /// To header contains this text.
    #[serde(default)]
    pub to: Option<String>,
    /// Subject contains this text.
    #[serde(default)]
    pub subject: Option<String>,
    /// Body or subject contains this text.
    #[serde(default)]
    pub text: Option<String>,
    /// Messages on or after this date.
    #[serde(default)]
    pub since: Option<String>,
    /// Messages before this date.
    #[serde(default)]
    pub before: Option<String>,
    /// When set, only unseen messages.
    #[serde(default)]
    pub unread: Option<bool>,
    /// When set, only flagged messages.
    #[serde(default)]
    pub flagged: Option<bool>,
    /// Page size. Omitted means 25. More than 100 is rejected.
    #[serde(default = "default_page_limit")]
    pub limit: u32,
    /// Cursor from the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Arguments for `mail_send` and `mail_create_draft`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SendParams {
    /// Recipients.
    pub to: Vec<String>,
    /// Subject.
    pub subject: String,
    /// Body as text.
    pub body: String,
    /// From address when it is not the signed-in Apple ID.
    #[serde(default)]
    pub from: Option<String>,
    /// Opaque id of the message this one replies to.
    #[serde(default)]
    pub reply_to_id: Option<String>,
}

/// Arguments for `mail_unsubscribe`.
///
/// The message, and optionally which of its routes to use. The address or link comes from
/// the message's own `List-Unsubscribe` header, never from the caller.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UnsubscribeParams {
    /// Opaque message id from `mail_search` or `mail_get_message`.
    pub id: String,
    /// Which of the message's own routes to use: `one_click` or `mailto`. Omit to let the
    /// server choose, which prefers one-click. A route the message does not offer is an error.
    #[serde(default)]
    pub method: Option<UnsubscribeMethodParam>,
}

/// A route a caller may pick. A web link is never followed, so it is not a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnsubscribeMethodParam {
    /// POST to the sender's https link (RFC 8058).
    OneClick,
    /// Email the address in the sender's own mailto.
    Mailto,
}

/// Arguments for `mail_get_message`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GetMessageParams {
    /// Opaque message id.
    pub id: String,
    /// Unicode scalar offset into the body. Omitted means the start.
    #[serde(default)]
    pub offset: u64,
}

/// Arguments for `mail_get_attachment`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GetAttachmentParams {
    /// Opaque message id.
    pub id: String,
    /// Part identifier from `mail_get_message`.
    pub part: String,
    /// Unicode scalar offset into a text part. Omitted means the start.
    #[serde(default)]
    pub offset: u64,
}

/// Arguments for `mail_save_attachment`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SaveAttachmentParams {
    /// Opaque message id.
    pub id: String,
    /// Part identifier from `mail_get_message`.
    pub part: String,
}

/// Arguments for `mail_move`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct MoveParams {
    /// Opaque message id.
    pub id: String,
    /// Mailbox path. Set this or `role`, not both.
    #[serde(default)]
    pub mailbox: Option<String>,
    /// Role: inbox, archive, trash, junk, sent, drafts, or notes.
    #[serde(default)]
    pub role: Option<String>,
}

/// Arguments for `mail_set_flags`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FlagParams {
    /// Opaque message id.
    pub id: String,
    /// Seen flag. Omit to leave it unchanged.
    #[serde(default)]
    pub seen: Option<bool>,
    /// Flagged flag. Omit to leave it unchanged.
    #[serde(default)]
    pub flagged: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct MailboxOut {
    pub(crate) path: String,
    pub(crate) role: String,
    pub(crate) total: u32,
    pub(crate) unread: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct MailboxListOut {
    pub(crate) mailboxes: Vec<MailboxOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SearchHitOut {
    pub(crate) id: String,
    pub(crate) from: String,
    pub(crate) subject: String,
    pub(crate) date: String,
    pub(crate) unread: bool,
    pub(crate) flagged: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SearchOut {
    pub(crate) messages: Vec<SearchHitOut>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) warnings: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct AttachmentInfoOut {
    pub(crate) part: String,
    pub(crate) content_type: String,
    pub(crate) size: u64,
    pub(crate) name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct MessageOut {
    pub(crate) id: String,
    pub(crate) from: String,
    pub(crate) to: Vec<String>,
    pub(crate) subject: String,
    pub(crate) date: String,
    pub(crate) body: String,
    pub(crate) attachments: Vec<AttachmentInfoOut>,
    pub(crate) unsubscribe: UnsubscribeOut,
    pub(crate) next_offset: Option<u64>,
}

/// Whether the sender offers a way to unsubscribe, and which.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct UnsubscribeOut {
    /// True when the sender's headers offer at least one way to unsubscribe.
    pub(crate) available: bool,
    /// What the sender offers, best first: `one_click` (a link that accepts a POST),
    /// `mailto` (an email address) or `link` (a page for a browser).
    pub(crate) methods: Vec<UnsubscribeMethodOut>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnsubscribeMethodOut {
    OneClick,
    Mailto,
    Link,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct AttachmentOut {
    pub(crate) content_type: String,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) text: Option<String>,
    pub(crate) bytes_base64: Option<String>,
    pub(crate) next_offset: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SavedAttachmentOut {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) content_type: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct IdOut {
    pub(crate) id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SendOut {
    pub(crate) id: Option<String>,
    pub(crate) warning: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnsubscribeStatus {
    /// An unsubscribe email was sent.
    Emailed,
    /// The sender's server accepted a one-click unsubscribe request.
    OneClick,
    /// Only a web link is on offer, and nothing was sent.
    LinkOnly,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct UnsubscribedOut {
    pub(crate) status: UnsubscribeStatus,
    /// Id of the copy in Sent Messages, when an email was sent and the copy was saved.
    pub(crate) id: Option<String>,
    /// Set when the email was sent but the Sent copy was not saved.
    pub(crate) warning: Option<String>,
    /// The sender's web links, as the sender wrote them. Empty when an email was sent.
    pub(crate) links: Vec<String>,
    /// What happened and what is left to do.
    pub(crate) note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct MoveOut {
    pub(crate) moved: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct FlagsOut {
    pub(crate) updated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ServiceState {
    On,
    Off,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ServiceOut {
    pub(crate) name: String,
    pub(crate) status: ServiceState,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct AccountStatusOut {
    pub(crate) apple_id: String,
    pub(crate) services: Vec<ServiceOut>,
    pub(crate) version: &'static str,
}
