// SPDX-License-Identifier: Apache-2.0

//! The one reader of `207 Multi-Status` bodies, and the URL path helpers that go
//! with it. Calendar, contacts and sync all read their responses through it.

use std::fmt::Write as _;

use crate::error::DavError;

/// One `response` of a multistatus body.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// The resource's href as the server wrote it.
    pub href: String,
    /// `getetag`, from a property the server answered with 200.
    pub etag: Option<String>,
    /// `calendar-data`.
    pub calendar_data: Option<String>,
    /// `displayname`.
    pub display_name: Option<String>,
    /// `resourcetype` holds `calendar`.
    pub is_calendar: bool,
    /// `supported-calendar-component-set`; `None` when the server did not list it.
    pub components: Option<Vec<String>>,
    /// The response itself carries a `404` status: the resource is gone.
    pub not_found: bool,
}

const NS_DAV: &str = "DAV:";
const NS_CALDAV: &str = "urn:ietf:params:xml:ns:caldav";

/// Reads every `response` of a multistatus `body`.
///
/// # Errors
///
/// Returns [`DavError::Protocol`] when `body` is not XML.
pub fn parse(body: &[u8]) -> Result<Vec<Entry>, DavError> {
    let text = std::str::from_utf8(body).map_err(|_| DavError::Protocol)?;
    let doc = roxmltree::Document::parse(text).map_err(|_| DavError::Protocol)?;
    let mut entries = Vec::new();
    for response in doc
        .descendants()
        .filter(|node| is(node, NS_DAV, "response"))
    {
        let Some(href) = child_text(response, NS_DAV, "href") else {
            continue;
        };
        let mut entry = Entry {
            href,
            not_found: child_text(response, NS_DAV, "status").is_some_and(|s| s.contains(" 404")),
            ..Entry::default()
        };
        for propstat in response
            .children()
            .filter(|node| is(node, NS_DAV, "propstat"))
        {
            let ok = child_text(propstat, NS_DAV, "status").is_some_and(|s| s.contains(" 200"));
            if !ok {
                continue;
            }
            let Some(prop) = propstat.children().find(|node| is(node, NS_DAV, "prop")) else {
                continue;
            };
            read_prop(prop, &mut entry);
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn read_prop(prop: roxmltree::Node<'_, '_>, entry: &mut Entry) {
    for node in prop.children().filter(roxmltree::Node::is_element) {
        let tag = node.tag_name();
        match (tag.namespace(), tag.name()) {
            (Some(NS_DAV), "getetag") => {
                entry.etag = node
                    .text()
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty());
            }
            (Some(NS_DAV), "displayname") => {
                entry.display_name = node.text().map(|t| t.trim().to_owned());
            }
            (Some(NS_DAV), "resourcetype") => {
                entry.is_calendar = node
                    .children()
                    .any(|child| is(&child, NS_CALDAV, "calendar"));
            }
            (Some(NS_CALDAV), "calendar-data") => {
                entry.calendar_data = Some(node.text().unwrap_or_default().to_owned());
            }
            (Some(NS_CALDAV), "supported-calendar-component-set") => {
                entry.components = Some(
                    node.children()
                        .filter(|child| is(child, NS_CALDAV, "comp"))
                        .filter_map(|child| child.attribute("name").map(str::to_owned))
                        .collect(),
                );
            }
            _ => {}
        }
    }
}

fn is(node: &roxmltree::Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

fn child_text(node: roxmltree::Node<'_, '_>, namespace: &str, name: &str) -> Option<String> {
    node.children()
        .find(|child| is(child, namespace, name))
        .and_then(|child| child.text())
        .map(|text| text.trim().to_owned())
}

/// Percent-decodes `text`. `None` when an escape is malformed or the bytes are not UTF-8.
#[must_use]
pub fn decode_path(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let pair = text.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encodes a path, keeping `/` and the characters iCloud leaves bare.
#[must_use]
pub fn encode_path(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~@:!$&'()*+,;=/".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode_path, encode_path, parse};

    const BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
    <D:href>/1/calendars/work/</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>Work</D:displayname>
        <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>
        <C:supported-calendar-component-set><C:comp name="VEVENT"/></C:supported-calendar-component-set>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
    <D:propstat>
      <D:prop><D:getetag/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/1/calendars/work/a.ics</D:href>
    <D:propstat>
      <D:prop><D:getetag>"e1"</D:getetag><C:calendar-data>BEGIN:VCALENDAR</C:calendar-data></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/1/calendars/work/gone.ics</D:href>
    <D:status>HTTP/1.1 404 Not Found</D:status>
  </D:response>
</D:multistatus>"#;

    #[test]
    fn parse_reads_collections_items_and_gone_resources() {
        let entries = parse(BODY.as_bytes()).expect("parse");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].href, "/1/calendars/work/");
        assert_eq!(entries[0].display_name.as_deref(), Some("Work"));
        assert!(entries[0].is_calendar);
        assert_eq!(entries[0].components, Some(vec!["VEVENT".to_owned()]));
        assert_eq!(entries[0].etag, None, "a 404 property is not a value");
        assert_eq!(entries[1].etag.as_deref(), Some("\"e1\""));
        assert_eq!(entries[1].calendar_data.as_deref(), Some("BEGIN:VCALENDAR"));
        assert!(!entries[1].not_found);
        assert!(entries[2].not_found);
    }

    #[test]
    fn parse_rejects_text_that_is_not_xml() {
        assert!(parse(b"not xml").is_err());
    }

    #[test]
    fn path_helpers_round_trip() {
        assert_eq!(encode_path("work/a b#1.ics"), "work/a%20b%231.ics");
        assert_eq!(encode_path("ada@icloud.com/x"), "ada@icloud.com/x");
        assert_eq!(
            decode_path("work/a%20b%231.ics").as_deref(),
            Some("work/a b#1.ics")
        );
        assert_eq!(decode_path("bad%zz"), None);
    }
}
