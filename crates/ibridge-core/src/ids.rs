// SPDX-License-Identifier: Apache-2.0

//! Opaque identifiers and DAV resource paths.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{IdError, ParseError};
use crate::mail::{MailboxPath, MessageId, Uid, UidValidity};

const VERSION: u8 = 1;
const KIND_MESSAGE: u8 = 1;
const KIND_RESOURCE: u8 = 2;

/// Encodes a [`MessageId`] as an opaque token.
///
/// Version 1 is base64url (no padding) over a length-prefixed body: version,
/// kind, `u16` mailbox length, mailbox bytes, `u32` UIDVALIDITY, `u32` UID, and
/// a CRC-32 of those bytes. A flipped character fails the checksum.
#[must_use]
pub fn encode(id: &MessageId) -> String {
    encode_parts(id.mailbox.as_str(), id.validity.get(), id.uid.get())
}

/// Decodes a token produced by [`encode`].
///
/// # Errors
///
/// Returns [`IdError::Decode`] when the token is malformed, tampered, or carries a URL.
pub fn decode(token: &str) -> Result<MessageId, IdError> {
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| IdError::Decode)?;
    // version + kind + length + validity + uid + checksum, with an empty mailbox.
    if bytes.len() < 16 {
        return Err(IdError::Decode);
    }
    let (body, sum_bytes) = bytes.split_at(bytes.len() - 4);
    let mut sum = [0_u8; 4];
    sum.copy_from_slice(sum_bytes);
    if crc32(body) != u32::from_be_bytes(sum) {
        return Err(IdError::Decode);
    }
    let mut rest = body;
    if take_u8(&mut rest)? != VERSION || take_u8(&mut rest)? != KIND_MESSAGE {
        return Err(IdError::Decode);
    }
    let len = usize::from(take_u16(&mut rest)?);
    if rest.len() != len + 8 {
        return Err(IdError::Decode);
    }
    let (mailbox_bytes, after) = rest.split_at(len);
    let mailbox = std::str::from_utf8(mailbox_bytes).map_err(|_| IdError::Decode)?;
    let mailbox = MailboxPath::try_from(mailbox).map_err(|_| IdError::Decode)?;
    let mut tail = after;
    let validity = UidValidity::try_from(take_u32(&mut tail)?).map_err(|_| IdError::Decode)?;
    let uid = Uid::try_from(take_u32(&mut tail)?).map_err(|_| IdError::Decode)?;
    if !tail.is_empty() {
        return Err(IdError::Decode);
    }
    Ok(MessageId {
        mailbox,
        validity,
        uid,
    })
}

/// Encodes a DAV [`ResourcePath`] as an opaque token. Same framing as
/// [`encode`], with its own kind byte so a message token never decodes as a path.
#[must_use]
pub fn encode_resource(path: &ResourcePath) -> String {
    let bytes = path.as_str().as_bytes();
    // A path is short; a longer one would not have been a useful id anyway.
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    let mut body = Vec::with_capacity(8 + bytes.len());
    body.push(VERSION);
    body.push(KIND_RESOURCE);
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(&bytes[..usize::from(len)]);
    let sum = crc32(&body);
    body.extend_from_slice(&sum.to_be_bytes());
    URL_SAFE_NO_PAD.encode(body)
}

/// Decodes a token produced by [`encode_resource`].
///
/// # Errors
///
/// Returns [`IdError::Decode`] when the token is malformed, tampered, or not a resource token.
pub fn decode_resource(token: &str) -> Result<ResourcePath, IdError> {
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| IdError::Decode)?;
    if bytes.len() < 8 {
        return Err(IdError::Decode);
    }
    let (body, sum_bytes) = bytes.split_at(bytes.len() - 4);
    let mut sum = [0_u8; 4];
    sum.copy_from_slice(sum_bytes);
    if crc32(body) != u32::from_be_bytes(sum) {
        return Err(IdError::Decode);
    }
    let mut rest = body;
    if take_u8(&mut rest)? != VERSION || take_u8(&mut rest)? != KIND_RESOURCE {
        return Err(IdError::Decode);
    }
    let len = usize::from(take_u16(&mut rest)?);
    if rest.len() != len {
        return Err(IdError::Decode);
    }
    let path = std::str::from_utf8(rest).map_err(|_| IdError::Decode)?;
    ResourcePath::try_from(path).map_err(|_| IdError::Decode)
}

/// Builds a token from raw parts, skipping mailbox validation. Tests use this to
/// craft a URL payload.
#[cfg(test)]
#[must_use]
pub(crate) fn encode_raw(mailbox: &str, validity: u32, uid: u32) -> String {
    encode_parts(mailbox, validity, uid)
}

fn encode_parts(mailbox: &str, validity: u32, uid: u32) -> String {
    URL_SAFE_NO_PAD.encode(frame(mailbox, validity, uid))
}

fn frame(mailbox: &str, validity: u32, uid: u32) -> Vec<u8> {
    let mailbox_bytes = mailbox.as_bytes();
    let len = u16::try_from(mailbox_bytes.len()).expect("mailbox name fits in a u16");
    let mut body = Vec::with_capacity(16 + mailbox_bytes.len());
    body.push(VERSION);
    body.push(KIND_MESSAGE);
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(mailbox_bytes);
    body.extend_from_slice(&validity.to_be_bytes());
    body.extend_from_slice(&uid.to_be_bytes());
    let sum = crc32(&body);
    body.extend_from_slice(&sum.to_be_bytes());
    body
}

fn take_u8(rest: &mut &[u8]) -> Result<u8, IdError> {
    let (&first, tail) = rest.split_first().ok_or(IdError::Decode)?;
    *rest = tail;
    Ok(first)
}

fn take_u16(rest: &mut &[u8]) -> Result<u16, IdError> {
    Ok(u16::from_be_bytes(take_array::<2>(rest)?))
}

fn take_u32(rest: &mut &[u8]) -> Result<u32, IdError> {
    Ok(u32::from_be_bytes(take_array::<4>(rest)?))
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], IdError> {
    if rest.len() < N {
        return Err(IdError::Decode);
    }
    let (head, tail) = rest.split_at(N);
    *rest = tail;
    let mut value = [0_u8; N];
    value.copy_from_slice(head);
    Ok(value)
}

/// CRC-32/ISO-HDLC. Detects a flipped token byte; it is not an authenticator.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

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
