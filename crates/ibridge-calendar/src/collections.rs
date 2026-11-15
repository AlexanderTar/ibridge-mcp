// SPDX-License-Identifier: Apache-2.0

//! The calendar home and its collections.

use std::fmt::Write as _;

use http::{Request, StatusCode};
use ibridge_core::{CoreError, ResourcePath};
use ibridge_dav::Exchange;

use crate::CalDavProvider;

const NS_DAV: &str = "DAV:";
const NS_CALDAV: &str = "urn:ietf:params:xml:ns:caldav";

/// The account's calendar home: absolute URL and its path.
#[derive(Clone, Debug)]
pub(crate) struct Home {
    url: String,
    path: String,
}

impl Home {
    /// Absolute URL of the resource at `path`, which is relative to the home
    /// and not percent-encoded.
    pub(crate) fn url_of(&self, path: &str) -> String {
        format!("{}/{}", self.url.trim_end_matches('/'), encode(path))
    }

    /// The decoded path of `href` relative to the home, or `None` outside the
    /// home. Servers differ in what they percent-encode (`@` for one), so the
    /// comparison is on decoded text.
    pub(crate) fn relative(&self, href: &str) -> Option<String> {
        let href_path = href.find("://").map_or(href, |scheme_end| {
            let rest = &href[scheme_end + 3..];
            rest.find('/').map_or("", |slash| &rest[slash..])
        });
        let href_path = decode(href_path)?;
        let home_path = decode(&self.path)?;
        let rest = href_path.strip_prefix(home_path.trim_end_matches('/'))?;
        let rest = rest.strip_prefix('/')?;
        (!rest.is_empty()).then(|| rest.to_owned())
    }
}

/// One collection under the calendar home.
#[derive(Clone, Debug)]
pub(crate) struct Collection {
    pub(crate) path: ResourcePath,
    pub(crate) name: String,
    pub(crate) holds_events: bool,
    pub(crate) holds_tasks: bool,
}

/// One response of a multistatus body.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) href: String,
    pub(crate) etag: Option<String>,
    pub(crate) calendar_data: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) is_calendar: bool,
    /// `None` when the server did not list supported components.
    pub(crate) components: Option<Vec<String>>,
}

impl CalDavProvider {
    pub(crate) async fn home(&self) -> Result<Home, CoreError> {
        let home = self.client.calendar_home().await?;
        let uri: http::Uri = home.url.parse().map_err(|_| protocol())?;
        Ok(Home {
            path: uri.path().to_owned(),
            url: home.url,
        })
    }

    pub(crate) async fn collections(&self, home: &Home) -> Result<Vec<Collection>, CoreError> {
        const BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <D:propfind xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:prop>\
            <D:displayname/><D:resourcetype/><C:supported-calendar-component-set/>\
            </D:prop></D:propfind>";
        let request = Request::builder()
            .method("PROPFIND")
            .uri(home.url.as_str())
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(BODY.to_owned())
            .map_err(|_| protocol())?;
        let exchange = self.client.request(request).await?;
        let entries = multistatus(&exchange)?;
        let mut collections = Vec::new();
        for entry in entries.into_iter().filter(|entry| entry.is_calendar) {
            let Some(relative) = home.relative(&entry.href) else {
                continue;
            };
            let Ok(path) = ResourcePath::try_from(relative.as_str()) else {
                continue;
            };
            let (holds_events, holds_tasks) = match &entry.components {
                Some(names) => (
                    names.iter().any(|name| name.eq_ignore_ascii_case("VEVENT")),
                    names.iter().any(|name| name.eq_ignore_ascii_case("VTODO")),
                ),
                None => (true, true),
            };
            collections.push(Collection {
                name: entry
                    .display_name
                    .unwrap_or_else(|| relative.trim_end_matches('/').to_owned()),
                path,
                holds_events,
                holds_tasks,
            });
        }
        Ok(collections)
    }
}

fn decode(text: &str) -> Option<String> {
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

fn encode(text: &str) -> String {
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

impl CalDavProvider {
    /// Runs a `calendar-query` report on `collection` and returns its responses.
    pub(crate) async fn query(
        &self,
        home: &Home,
        collection: &Collection,
        body: String,
    ) -> Result<Vec<Entry>, CoreError> {
        let request = Request::builder()
            .method("REPORT")
            .uri(home.url_of(collection.path.as_str()))
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body)
            .map_err(|_| protocol())?;
        let exchange = self.client.request(request).await?;
        multistatus(&exchange)
    }
}

pub(crate) fn protocol() -> CoreError {
    CoreError::Protocol(String::new())
}

/// Maps a failed status to the error the caller should see.
pub(crate) fn status_error(status: StatusCode) -> CoreError {
    match status {
        StatusCode::NOT_FOUND | StatusCode::GONE => CoreError::NotFound,
        StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => CoreError::Conflict,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => CoreError::Auth,
        _ => protocol(),
    }
}

/// Parses a 207 multistatus body into its responses.
pub(crate) fn multistatus(exchange: &Exchange) -> Result<Vec<Entry>, CoreError> {
    if exchange.status.as_u16() != 207 {
        return Err(status_error(exchange.status));
    }
    let text = std::str::from_utf8(&exchange.body).map_err(|_| protocol())?;
    let doc = roxmltree::Document::parse(text).map_err(|_| protocol())?;
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
            etag: None,
            calendar_data: None,
            display_name: None,
            is_calendar: false,
            components: None,
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
            (Some(NS_DAV), "getetag") => entry.etag = node.text().map(|t| t.trim().to_owned()),
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
