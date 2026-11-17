// SPDX-License-Identifier: Apache-2.0

//! Keeps tokens and passwords out of logs.

use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};

/// Collects a record's fields into a JSON object, each text value passed through [`redact`].
///
/// This is the JSON log's field formatter, for events and spans alike: every value that
/// reaches a log line goes through it.
pub struct RedactingFields<'a>(&'a mut Map<String, Value>);

impl<'a> RedactingFields<'a> {
    /// Records later fields into `fields`.
    #[must_use]
    pub fn new(fields: &'a mut Map<String, Value>) -> Self {
        Self(fields)
    }
}

impl fmt::Debug for RedactingFields<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactingFields")
    }
}

impl Visit for RedactingFields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().to_owned(), Value::String(redact(value)));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value.into());
    }
}

const TOKEN_PREFIXES: [&[u8]; 4] = [b"ibc_", b"iba_", b"ibf_", b"ibr_"];
const PARAMS: [&str; 6] = [
    "access_token",
    "refresh_token",
    "password",
    "token",
    "code",
    "asp",
];

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
        if let Some(len) = param_len(text, index) {
            out.push_str("[REDACTED]");
            index += len;
            continue;
        }
        if let Some(len) = token_len(bytes, index) {
            out.push_str("[REDACTED]");
            index += len;
            continue;
        }
        if let Some(len) = asp_len(bytes, index) {
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

fn param_len(text: &str, index: usize) -> Option<usize> {
    if !name_boundary(text.as_bytes(), index) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut cursor = index;
    let quoted_name = quote_at(bytes, cursor);
    if let Some((_, len)) = quoted_name {
        cursor += len;
    }
    let name_start = cursor;
    while cursor < bytes.len() && is_name_byte(bytes[cursor]) {
        cursor += 1;
    }
    if cursor == name_start || !is_secret_name(&text[name_start..cursor]) {
        return None;
    }
    if let Some((quote, _)) = quoted_name {
        let (closing, len) = quote_at(bytes, cursor)?;
        if closing != quote {
            return None;
        }
        cursor += len;
    }
    cursor = skip_ws(bytes, cursor);
    let sep = *bytes.get(cursor)?;
    if sep != b'=' && sep != b':' {
        return None;
    }
    cursor += 1;
    cursor = skip_ws(bytes, cursor);
    let value_quote = quote_at(bytes, cursor);
    if let Some((_, len)) = value_quote {
        cursor += len;
    }
    let value_start = cursor;
    while cursor < bytes.len() && !value_ends(bytes, cursor, value_quote.map(|(quote, _)| quote)) {
        cursor += 1;
    }
    if cursor == value_start {
        return None;
    }
    if let Some((quote, _)) = value_quote
        && let Some((closing, len)) = quote_at(bytes, cursor)
        && closing == quote
    {
        cursor += len;
    }
    Some(cursor - index)
}

/// A raw quote, or the two-byte `\"` / `\'` a `Debug` string uses.
fn quote_at(bytes: &[u8], index: usize) -> Option<(u8, usize)> {
    if bytes.get(index) == Some(&b'\\') {
        let escaped = *bytes.get(index + 1)?;
        if matches!(escaped, b'"' | b'\'') {
            return Some((escaped, 2));
        }
        return None;
    }
    let byte = *bytes.get(index)?;
    if matches!(byte, b'"' | b'\'') && (index == 0 || bytes[index - 1] != b'\\') {
        return Some((byte, 1));
    }
    None
}

fn is_secret_name(name: &str) -> bool {
    PARAMS.iter().any(|param| name.eq_ignore_ascii_case(param))
        || ends_with_ignore_ascii_case(name, "password")
}

fn ends_with_ignore_ascii_case(text: &str, suffix: &str) -> bool {
    let text = text.as_bytes();
    let suffix = suffix.as_bytes();
    text.len() >= suffix.len() && text[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn value_ends(bytes: &[u8], index: usize, quote: Option<u8>) -> bool {
    match quote {
        Some(quote) => quote_at(bytes, index).is_some_and(|(found, _)| found == quote),
        None => matches!(
            bytes[index],
            b'&' | b'#' | b' ' | b'\n' | b'\r' | b'\t' | b'"' | b'\'' | b',' | b'}'
        ),
    }
}

fn token_len(bytes: &[u8], index: usize) -> Option<usize> {
    if index > 0 && is_token_byte(bytes[index - 1]) {
        return None;
    }
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

fn asp_len(bytes: &[u8], index: usize) -> Option<usize> {
    const GROUP: usize = 4;
    const GROUPS: usize = 4;
    if !name_boundary(bytes, index) {
        return None;
    }
    let rest = &bytes[index..];
    let len = GROUPS * GROUP + (GROUPS - 1);
    if rest.len() < len {
        return None;
    }
    for group in 0..GROUPS {
        let start = group * (GROUP + 1);
        if group > 0 && rest[start - 1] != b'-' {
            return None;
        }
        if !rest[start..start + GROUP]
            .iter()
            .all(u8::is_ascii_alphanumeric)
        {
            return None;
        }
    }
    if rest.len() > len && (is_name_byte(rest[len]) || rest[len] == b'-') {
        return None;
    }
    Some(len)
}

fn name_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_name_byte(bytes[index - 1])
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
    use std::sync::{Arc, Mutex};

    use serde_json::{Map, Value};
    use tracing::Subscriber;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata};

    use super::{RedactingFields, redact};

    #[test]
    fn redaction_masks_tokens_codes_and_keys() {
        let raw = "\
ibridge authorization: bearer iba_BEARERTOKEN end
GET /cb?code=ibc_CODETOKEN&access_token=iba_ACCESSTOKEN&refresh_token=ibf_REFRESHTOKEN HTTP/1.1
password=abcd-efgh-ijkl-mnop&token=ibr_APIKEY
app_password=appw-appw-appw-appw&asp=aspa-aspa-aspa-aspa
{\"password\":\"json-json-json-json\",\"app_password\":\"jasp-jasp-jasp-jasp\"}
bare bare-bare-bare-bare end
log ibf_LOOSETOKEN end
libc_start stays
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
            "appw-appw-appw-appw",
            "aspa-aspa-aspa-aspa",
            "json-json-json-json",
            "jasp-jasp-jasp-jasp",
            "bare-bare-bare-bare",
        ] {
            assert!(
                !masked.contains(secret),
                "redaction left {secret} in {masked}"
            );
        }
        assert!(
            masked.contains("libc_start"),
            "a prefix inside a word is not a token, got {masked}"
        );
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

    struct Capture {
        buf: Arc<Mutex<Map<String, Value>>>,
    }

    impl Subscriber for Capture {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = self.buf.lock().expect("redaction buffer");
            event.record(&mut RedactingFields::new(&mut fields));
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn tracing_field_formatter_redacts_values() {
        let buf = Arc::new(Mutex::new(Map::new()));
        let capture = Capture {
            buf: Arc::clone(&buf),
        };
        tracing::subscriber::with_default(capture, || {
            tracing::info!(
                note = "libc_start",
                credential = "iba_SECRETVALUE",
                form = "asp=aspa-aspa-aspa-aspa",
                "opened"
            );
        });
        let text = Value::Object(buf.lock().expect("redaction buffer").clone()).to_string();
        assert!(
            !text.contains("iba_SECRETVALUE"),
            "the tracing field must not contain the token, got {text}"
        );
        assert!(
            !text.contains("aspa-aspa-aspa-aspa"),
            "the tracing field must not contain the password, got {text}"
        );
        assert!(
            text.contains("libc_start"),
            "a word that merely contains a prefix must stay, got {text}"
        );
        assert!(
            text.contains("[REDACTED]"),
            "the field value must be scrubbed, got {text}"
        );
    }

    #[test]
    fn tracing_debug_field_redacts_string_json() {
        let buf = Arc::new(Mutex::new(Map::new()));
        let capture = Capture {
            buf: Arc::clone(&buf),
        };
        let body = r#"{"password":"hunter2"}"#.to_string();
        tracing::subscriber::with_default(capture, || {
            tracing::info!(body = ?body, note = "libc_start", "posted");
        });
        let text = Value::Object(buf.lock().expect("redaction buffer").clone()).to_string();
        assert!(
            !text.contains("hunter2"),
            "a String logged with Debug must not keep the password, got {text}"
        );
        assert!(
            text.contains("libc_start"),
            "a non-secret field must stay, got {text}"
        );
        assert!(
            text.contains("[REDACTED]"),
            "the debug-formatted password must be scrubbed, got {text}"
        );
    }
}
