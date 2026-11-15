// SPDX-License-Identifier: Apache-2.0

//! Keeps tokens and passwords out of logs.

use std::fmt;

/// Tracing field value that never prints a secret.
#[derive(Clone, Copy)]
pub struct Redacted;

impl fmt::Display for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Redacted {
    /// Value suitable for a tracing field.
    #[must_use]
    pub fn field(&self) -> impl fmt::Display + '_ {
        tracing::field::display(self)
    }
}

const TOKEN_PREFIXES: [&[u8]; 4] = [b"ibc_", b"iba_", b"ibf_", b"ibr_"];
const PARAMS: [&str; 5] = ["access_token", "refresh_token", "password", "token", "code"];

/// Replaces tokens, bearer values and credential parameters.
#[must_use]
pub fn redact(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(len) = bearer_len(bytes, index) {
            out.push_str("authorization: bearer [REDACTED]");
            index += len;
            continue;
        }
        if let Some((name, len)) = param_len(text, index) {
            out.push_str(name);
            out.push_str("=[REDACTED]");
            index += len;
            continue;
        }
        if let Some(len) = token_len(bytes, index) {
            out.push_str("[REDACTED]");
            index += len;
            continue;
        }
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn bearer_len(bytes: &[u8], index: usize) -> Option<usize> {
    let rest = &bytes[index..];
    let header = b"authorization";
    if rest.len() < header.len() || !rest[..header.len()].eq_ignore_ascii_case(header) {
        return None;
    }
    let mut cursor = header.len();
    cursor = skip_ws(rest, cursor);
    if rest.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    cursor = skip_ws(rest, cursor);
    let bearer = b"bearer";
    if rest.len() < cursor + bearer.len()
        || !rest[cursor..cursor + bearer.len()].eq_ignore_ascii_case(bearer)
    {
        return None;
    }
    cursor += bearer.len();
    let after_word = cursor;
    cursor = skip_ws(rest, cursor);
    if cursor == after_word || cursor == rest.len() {
        return None;
    }
    while cursor < rest.len() && !rest[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    Some(cursor)
}

fn param_len(text: &str, index: usize) -> Option<(&'static str, usize)> {
    if !at_boundary(text, index) {
        return None;
    }
    let rest = &text[index..];
    let name = PARAMS.into_iter().find(|name| {
        let rest_bytes = rest.as_bytes();
        rest_bytes.len() > name.len()
            && rest_bytes[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            && rest_bytes[name.len()] == b'='
    })?;
    let mut cursor = name.len() + 1;
    let rest_bytes = rest.as_bytes();
    while cursor < rest_bytes.len()
        && !matches!(
            rest_bytes[cursor],
            b'&' | b'#' | b' ' | b'\n' | b'\r' | b'\t' | b'"' | b'\''
        )
    {
        cursor += 1;
    }
    Some((name, cursor))
}

fn token_len(bytes: &[u8], index: usize) -> Option<usize> {
    let rest = &bytes[index..];
    let prefix = TOKEN_PREFIXES
        .iter()
        .find(|prefix| rest.starts_with(prefix))?;
    if rest.len() == prefix.len() || !is_token_byte(rest[prefix.len()]) {
        return None;
    }
    let mut cursor = prefix.len() + 1;
    while cursor < rest.len() && is_token_byte(rest[cursor]) {
        cursor += 1;
    }
    Some(cursor)
}

fn at_boundary(text: &str, index: usize) -> bool {
    index == 0
        || matches!(
            text.as_bytes()[index - 1],
            b'?' | b'&' | b' ' | b'\n' | b'\r' | b'\t'
        )
}

fn skip_ws(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{Redacted, redact};

    #[test]
    fn redaction_masks_tokens_codes_and_keys() {
        assert_eq!(
            Redacted.to_string(),
            "[REDACTED]",
            "a tracing field must not print the secret"
        );
        assert_eq!(
            format!("{Redacted:?}"),
            "[REDACTED]",
            "debug output must not print the secret"
        );
        assert_eq!(
            format!("{}", Redacted.field()),
            "[REDACTED]",
            "the tracing field value must be redacted"
        );
        let raw = "\
ibridge authorization: bearer iba_BEARERTOKEN end
GET /cb?code=ibc_CODETOKEN&access_token=iba_ACCESSTOKEN&refresh_token=ibf_REFRESHTOKEN HTTP/1.1
password=abcd-efgh-ijkl-mnop&token=ibr_APIKEY
log ibf_LOOSETOKEN end
calendar stays";
        let masked = redact(raw);
        for secret in [
            "iba_BEARERTOKEN",
            "ibc_CODETOKEN",
            "iba_ACCESSTOKEN",
            "ibf_REFRESHTOKEN",
            "ibr_APIKEY",
            "ibf_LOOSETOKEN",
            "abcd-efgh-ijkl-mnop",
        ] {
            assert!(
                !masked.contains(secret),
                "redaction left {secret} in {masked}"
            );
        }
        assert!(
            masked.contains("calendar stays"),
            "unrelated text must remain, got {masked}"
        );
        assert!(
            masked.contains("ibridge"),
            "the product name is not a token, got {masked}"
        );
        assert!(
            masked.contains("[REDACTED]"),
            "secrets must be replaced, got {masked}"
        );
    }
}
