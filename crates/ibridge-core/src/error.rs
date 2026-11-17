// SPDX-License-Identifier: Apache-2.0

//! Errors from parsing domain values and from provider calls.

use std::time::Duration;

/// A domain value failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The address is not a primary `@icloud.com`, `@me.com` or `@mac.com` address.
    #[error(
        "use the primary iCloud address (@icloud.com, @me.com or @mac.com), not a custom domain"
    )]
    AppleId,
    /// The mailbox path is empty, a URL, or contains a control character.
    #[error("mailbox path is empty, a URL, or contains a control character")]
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

/// An opaque id could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The token is not a versioned, length-prefixed id, or its payload is not allowed.
    #[error("id could not be decoded")]
    Decode,
}

/// Failure from a mail, calendar, reminders or contacts provider.
///
/// [`Display`] never includes protocol detail. Callers must not put a secret in
/// any variant. [`CoreError::protocol_detail`] is the only way to read a protocol
/// string, and it is for diagnostics after the caller has checked it is safe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// The service rejected the credentials.
    #[error("authentication failed")]
    Auth,
    /// The network failed before a protocol result arrived.
    #[error("network error")]
    Network,
    /// A protocol failure. The string is not part of [`Display`].
    #[error("protocol error")]
    Protocol(String),
    /// The mailbox, message or resource does not exist.
    #[error("not found")]
    NotFound,
    /// A conditional write lost a race with another client.
    #[error("conflict")]
    Conflict,
    /// The service refused a change the signed-in account may not make.
    ///
    /// For example a write to a read-only shared calendar. The password was accepted, so
    /// this is not [`CoreError::Auth`].
    #[error("forbidden")]
    Forbidden,
    /// The service asked us to slow down.
    #[error("rate limited")]
    RateLimited {
        /// When the caller may retry. `None` when the server did not say.
        retry_after: Option<Duration>,
    },
    /// The service cannot do this operation.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The host is not on the iCloud allowlist.
    #[error("host not allowed")]
    HostNotAllowed,
    /// A tool or caller passed a value the provider cannot use.
    ///
    /// The string is a safe message for the user, never a secret or raw server text.
    #[error("{0}")]
    InvalidInput(String),
}

impl CoreError {
    /// Protocol detail, when this is [`CoreError::Protocol`].
    ///
    /// This is not included in [`Display`].
    #[must_use]
    pub fn protocol_detail(&self) -> Option<&str> {
        match self {
            Self::Protocol(detail) => Some(detail),
            _ => None,
        }
    }
}
