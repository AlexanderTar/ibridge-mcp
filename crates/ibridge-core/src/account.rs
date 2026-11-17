// SPDX-License-Identifier: Apache-2.0

//! Account identifiers.

use std::fmt;

use crate::error::ParseError;

/// A primary iCloud address (`@icloud.com`, `@me.com` or `@mac.com`).
///
/// Held in lowercase: Apple does not tell `Ada@icloud.com` from `ada@icloud.com`, so
/// neither does an account lookup, a cache key or a keychain entry.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AppleId(String);

impl AppleId {
    /// Returns the address in lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for AppleId {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let Some((local, domain)) = value.rsplit_once('@') else {
            return Err(ParseError::AppleId);
        };
        if !valid_local_part(local) {
            return Err(ParseError::AppleId);
        }
        let domain = domain.to_ascii_lowercase();
        if !matches!(domain.as_str(), "icloud.com" | "me.com" | "mac.com") {
            return Err(ParseError::AppleId);
        }
        Ok(Self(format!("{}@{domain}", local.to_ascii_lowercase())))
    }
}

/// ASCII local part: letters, digits and `. _ % + -`, no leading, trailing or doubled dot.
fn valid_local_part(local: &str) -> bool {
    let bytes = local.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if *first == b'.' || *last == b'.' {
        return false;
    }
    let mut prev_dot = false;
    for &byte in bytes {
        let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-');
        if !ok || (byte == b'.' && prev_dot) {
            return false;
        }
        prev_dot = byte == b'.';
    }
    true
}

impl fmt::Display for AppleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
