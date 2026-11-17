// SPDX-License-Identifier: Apache-2.0

//! Failures from the `CalDAV` and `CardDAV` client.
//!
//! [`Display`] never includes a secret or raw server text.

use std::time::Duration;

use ibridge_core::CoreError;

/// A `CalDAV` or `CardDAV` call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DavError {
    /// The service rejected the credentials.
    #[error("authentication failed")]
    Auth,
    /// The network failed before a protocol result arrived.
    #[error("network error")]
    Network,
    /// A protocol failure. The message is not raw server text.
    #[error("protocol error")]
    Protocol,
    /// The resource does not exist.
    #[error("not found")]
    NotFound,
    /// A conditional write lost a race with another client.
    #[error("conflict")]
    Conflict,
    /// The service refused a change the signed-in account may not make.
    ///
    /// The password was accepted, so this is not [`DavError::Auth`].
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
    /// A caller passed a value the client cannot use.
    ///
    /// The string is a safe message for the user, never a secret or raw server text.
    #[error("{0}")]
    InvalidInput(String),
}

impl From<DavError> for CoreError {
    fn from(error: DavError) -> Self {
        match error {
            DavError::Auth => Self::Auth,
            DavError::Network => Self::Network,
            DavError::Protocol => Self::Protocol(String::new()),
            DavError::NotFound => Self::NotFound,
            DavError::Conflict => Self::Conflict,
            DavError::Forbidden => Self::Forbidden,
            DavError::RateLimited { retry_after } => Self::RateLimited { retry_after },
            DavError::Unsupported(reason) => Self::Unsupported(reason),
            DavError::HostNotAllowed => Self::HostNotAllowed,
            DavError::InvalidInput(message) => Self::InvalidInput(message),
        }
    }
}
