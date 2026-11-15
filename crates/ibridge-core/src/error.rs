// SPDX-License-Identifier: Apache-2.0

//! Errors from parsing domain newtypes.

/// A domain value failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The address is not a primary `@icloud.com`, `@me.com` or `@mac.com` address.
    #[error(
        "use the primary iCloud address (@icloud.com, @me.com or @mac.com), not a custom domain"
    )]
    AppleId,
    /// The mailbox path is empty or contains a control character.
    #[error("mailbox path is empty or contains a control character")]
    MailboxPath,
    /// An IMAP UID or UIDVALIDITY was zero.
    #[error("uid must be a non-zero IMAP identifier")]
    Uid,
    /// The path is a URL, absolute, or walks out of the collection with `..`.
    #[error("resource path must be relative to the collection, with no URL and no .. segment")]
    ResourcePath,
    /// The `ETag` is empty or contains a control character.
    #[error("etag is empty or contains a control character")]
    ETag,
}
