// SPDX-License-Identifier: Apache-2.0

//! Opaque identifiers and DAV resource paths.

use std::fmt;

use crate::error::ParseError;

/// A DAV resource path relative to the account's discovered collection.
///
/// It is never a URL. The server joins it to the cached iCloud host.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ResourcePath(String);

impl ResourcePath {
    /// Returns the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ResourcePath {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !is_relative_collection_path(value) {
            return Err(ParseError::ResourcePath);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An HTTP `ETag` for a conditional DAV write.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ETag(String);

impl ETag {
    /// Returns the `ETag`, including any `W/` weak prefix and quotes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ETag {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(ParseError::ETag);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for ETag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A collection-relative path: no scheme, no leading slash, no `.` or `..` segment.
///
/// A single trailing slash is kept so a collection path can name a directory.
/// Percent-encoded segments are decoded before the `.` / `..` check.
fn is_relative_collection_path(value: &str) -> bool {
    if value.is_empty()
        || value.contains("://")
        || value.starts_with('/')
        || value.starts_with('\\')
    {
        return false;
    }
    if value.chars().any(|c| c.is_control() || c == '\\') {
        return false;
    }
    let body = value.strip_suffix('/').unwrap_or(value);
    if body.is_empty() || body.ends_with('/') {
        return false;
    }
    body.split('/').all(valid_segment)
}

fn valid_segment(segment: &str) -> bool {
    let Some(decoded) = percent_decode(segment) else {
        return false;
    };
    if decoded.is_empty() || decoded == "." || decoded == ".." {
        return false;
    }
    !decoded
        .chars()
        .any(|c| c == '/' || c == '\\' || c == ':' || c.is_control())
}

fn percent_decode(segment: &str) -> Option<String> {
    if !segment.contains('%') {
        return Some(segment.to_owned());
    }
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = from_hex(*bytes.get(index + 1)?)?;
            let lo = from_hex(*bytes.get(index + 2)?)?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
