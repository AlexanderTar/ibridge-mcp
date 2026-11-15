// SPDX-License-Identifier: Apache-2.0

//! The calendar home and its collections.

use http::{Request, StatusCode};
use ibridge_core::{CoreError, ResourcePath};
use ibridge_dav::Exchange;
use ibridge_dav::multistatus::{self, Entry, decode_path, encode_path};

use crate::CalDavProvider;

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
        format!("{}/{}", self.url.trim_end_matches('/'), encode_path(path))
    }

    /// The decoded path of `href` relative to the home, or `None` outside the
    /// home. Servers differ in what they percent-encode (`@` for one), so the
    /// comparison is on decoded text.
    pub(crate) fn relative(&self, href: &str) -> Option<String> {
        let href_path = href.find("://").map_or(href, |scheme_end| {
            let rest = &href[scheme_end + 3..];
            rest.find('/').map_or("", |slash| &rest[slash..])
        });
        let href_path = decode_path(href_path)?;
        let home_path = decode_path(&self.path)?;
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

/// Reads a 207 multistatus response into its entries.
pub(crate) fn multistatus(exchange: &Exchange) -> Result<Vec<Entry>, CoreError> {
    if exchange.status.as_u16() != 207 {
        return Err(status_error(exchange.status));
    }
    multistatus::parse(&exchange.body).map_err(|_| protocol())
}
