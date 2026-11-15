// SPDX-License-Identifier: Apache-2.0

//! Mail identifiers.

use std::fmt;
use std::num::NonZeroU32;

use crate::error::ParseError;

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
