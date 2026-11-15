// SPDX-License-Identifier: Apache-2.0

//! Collection sync and conditional writes.

use http::{StatusCode, Uri};
use ibridge_auth::Credentials;
use ibridge_core::ETag;
use libdav::dav::{Propfind, PutResource, SyncCollection, SyncCollectionParseError};
use libdav::names::{GETETAG, VALID_SYNC_TOKEN};
use libdav::requests::DavRequest;
use libdav::{Depth, PropertyName};

use crate::client::{Exchange, Transport, execute};
use crate::error::DavError;
use crate::multistatus;

const GETCTAG: PropertyName<'static, 'static> =
    PropertyName::new(libdav::names::CALENDAR_SERVER, "getctag");

/// One resource a sync report says was created or changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedItem {
    /// Server href of the resource.
    pub href: String,
    /// `ETag` from the report.
    pub etag: ETag,
}

/// Changes since a sync token, or a full etag scan when the token is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Token to send on the next sync.
    ///
    /// `None` after a full etag scan. That value is not a sync token: the caller
    /// diffs [`Self::changed`] and starts a fresh sync.
    pub token: Option<String>,
    /// Resources created or changed.
    pub changed: Vec<SyncedItem>,
    /// Hrefs removed since the previous token.
    pub deleted: Vec<String>,
    /// Items skipped because they had no usable etag.
    pub warnings: u32,
}

/// Sync `collection_url`. `limit` is ignored: iCloud does not honour `DAV:limit`.
///
/// # Errors
///
/// Returns [`DavError::Protocol`] when the report cannot be read, and
/// [`DavError::Network`] when the transport fails.
pub(crate) async fn sync_collection(
    transport: &impl Transport,
    credentials: &Credentials,
    collection_url: &str,
    token: Option<&str>,
    limit: Option<u32>,
) -> Result<SyncReport, DavError> {
    // ponytail: DAV:limit is not sent. iCloud ignores it, so a caller-supplied
    // limit would drop nothing on the server and must not drop items here either.
    let _ = limit;
    let (base, path) = split_url(collection_url)?;
    let owned_token = token.map(str::to_owned);
    let request = SyncCollection::new(&path);
    let request = match owned_token.as_deref() {
        Some(token) => request.with_sync_token(token),
        None => request,
    };
    let http_request = request
        .prepare_request(base)
        .map_err(|_| DavError::Protocol)?;
    let exchange = execute(transport, credentials, http_request).await?;
    if exchange.status.is_success() {
        return report_from_body(&exchange.body);
    }
    let parts = parts_of(&exchange)?;
    match request.parse_response(&parts, &exchange.body) {
        Err(SyncCollectionParseError::PreconditionFailed(precondition)) => {
            if PropertyName::from(precondition) == VALID_SYNC_TOKEN {
                etag_scan(transport, credentials, collection_url).await
            } else {
                Err(DavError::Protocol)
            }
        }
        _ => Err(DavError::Protocol),
    }
}

/// Create a resource. Sends `If-None-Match: *`.
///
/// # Errors
///
/// Returns [`DavError::Conflict`] when the server answers 412.
pub(crate) async fn put_new(
    transport: &impl Transport,
    credentials: &Credentials,
    resource_url: &str,
    body: &str,
    content_type: &str,
) -> Result<ETag, DavError> {
    let (base, path) = split_url(resource_url)?;
    let request = PutResource::new(&path).create(body, content_type);
    let http_request = request
        .prepare_request(base)
        .map_err(|_| DavError::Protocol)?;
    finish_put(transport, credentials, http_request, &request).await
}

/// Replace a resource. Sends `If-Match` with `etag`.
///
/// # Errors
///
/// Returns [`DavError::Conflict`] when the server answers 412.
pub(crate) async fn put_if_match(
    transport: &impl Transport,
    credentials: &Credentials,
    resource_url: &str,
    body: &str,
    content_type: &str,
    etag: &ETag,
) -> Result<ETag, DavError> {
    let (base, path) = split_url(resource_url)?;
    let request = PutResource::new(&path).update(body, content_type, etag.as_str());
    let http_request = request
        .prepare_request(base)
        .map_err(|_| DavError::Protocol)?;
    finish_put(transport, credentials, http_request, &request).await
}

/// Delete a resource. Sends `If-Match` with `etag`.
///
/// # Errors
///
/// Returns [`DavError::Conflict`] when the server answers 412 and
/// [`DavError::NotFound`] when it answers 404.
pub(crate) async fn delete_if_match(
    transport: &impl Transport,
    credentials: &Credentials,
    resource_url: &str,
    etag: &ETag,
) -> Result<(), DavError> {
    let (base, path) = split_url(resource_url)?;
    let request = libdav::dav::Delete::new(&path).with_etag(etag.as_str());
    let http_request = request
        .prepare_request(base)
        .map_err(|_| DavError::Protocol)?;
    let exchange = execute(transport, credentials, http_request).await?;
    match exchange.status {
        status if status.is_success() => Ok(()),
        StatusCode::PRECONDITION_FAILED => Err(DavError::Conflict),
        StatusCode::NOT_FOUND => Err(DavError::NotFound),
        _ => Err(DavError::Protocol),
    }
}

async fn finish_put(
    transport: &impl Transport,
    credentials: &Credentials,
    http_request: http::Request<String>,
    request: &impl DavRequest<
        Response = libdav::dav::PutResourceResponse,
        ParseError = libdav::dav::PutResourceParseError,
    >,
) -> Result<ETag, DavError> {
    let exchange = execute(transport, credentials, http_request).await?;
    let parts = parts_of(&exchange)?;
    match request.parse_response(&parts, &exchange.body) {
        Ok(response) => response
            .etag
            .as_deref()
            .ok_or(DavError::Protocol)
            .and_then(|etag| ETag::try_from(etag).map_err(|_| DavError::Protocol)),
        Err(libdav::dav::PutResourceParseError::BadStatusCode(status))
            if status == StatusCode::PRECONDITION_FAILED =>
        {
            Err(DavError::Conflict)
        }
        Err(_) => Err(DavError::Protocol),
    }
}

fn report_from_body(body: &[u8]) -> Result<SyncReport, DavError> {
    let text = std::str::from_utf8(body).map_err(|_| DavError::Protocol)?;
    let doc = roxmltree::Document::parse(text).map_err(|_| DavError::Protocol)?;
    let token = doc
        .descendants()
        .find(|node| node.tag_name().name() == "sync-token")
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(DavError::Protocol)?;
    let mut changed = Vec::new();
    let mut deleted = Vec::new();
    let mut warnings = 0_u32;
    for entry in multistatus::parse(body)? {
        if entry.href.is_empty() {
            warnings += 1;
        } else if entry.not_found {
            deleted.push(entry.href);
        } else {
            match entry.etag.as_deref().map(ETag::try_from) {
                Some(Ok(etag)) => changed.push(SyncedItem {
                    href: entry.href,
                    etag,
                }),
                _ => warnings += 1,
            }
        }
    }
    Ok(SyncReport {
        token: Some(token),
        changed,
        deleted,
        warnings,
    })
}

async fn etag_scan(
    transport: &impl Transport,
    credentials: &Credentials,
    collection_url: &str,
) -> Result<SyncReport, DavError> {
    let (base, path) = split_url(collection_url)?;
    let request = Propfind::new(&path)
        .with_properties(&[&GETETAG, &GETCTAG])
        .with_depth(Depth::One);
    let http_request = request
        .prepare_request(base)
        .map_err(|_| DavError::Protocol)?;
    let exchange = execute(transport, credentials, http_request).await?;
    if !exchange.status.is_success() {
        return Err(DavError::Protocol);
    }
    scan_report(&exchange.body, &path)
}

fn scan_report(body: &[u8], collection_path: &str) -> Result<SyncReport, DavError> {
    let mut changed = Vec::new();
    let mut warnings = 0_u32;
    for entry in multistatus::parse(body)? {
        if entry.href.is_empty() || same_path(&entry.href, collection_path) {
            continue;
        }
        match entry.etag.as_deref().map(ETag::try_from) {
            Some(Ok(etag)) => changed.push(SyncedItem {
                href: entry.href,
                etag,
            }),
            _ => warnings += 1,
        }
    }
    Ok(SyncReport {
        token: None,
        changed,
        deleted: Vec::new(),
        warnings,
    })
}

fn same_path(left: &str, right: &str) -> bool {
    left.trim_end_matches('/') == right.trim_end_matches('/')
}

fn split_url(url: &str) -> Result<(Uri, String), DavError> {
    let uri: Uri = url.parse().map_err(|_| DavError::Protocol)?;
    let scheme = uri.scheme_str().ok_or(DavError::Protocol)?;
    let authority = uri.authority().ok_or(DavError::Protocol)?;
    let path = uri.path();
    if path.is_empty() {
        return Err(DavError::Protocol);
    }
    let origin = format!("{scheme}://{authority}/")
        .parse()
        .map_err(|_| DavError::Protocol)?;
    Ok((origin, path.to_owned()))
}

fn parts_of(exchange: &Exchange) -> Result<http::response::Parts, DavError> {
    let mut response = http::Response::builder()
        .status(exchange.status)
        .body(())
        .map_err(|_| DavError::Protocol)?;
    *response.headers_mut() = exchange.headers.clone();
    Ok(response.into_parts().0)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use ibridge_core::ETag;

    use super::{put_if_match, put_new, sync_collection};
    use crate::error::DavError;
    use crate::test_support::{Script, credentials};

    const COLLECTION: &str = "https://caldav.icloud.com/184573921/calendars/";
    const EVENT: &str = "https://caldav.icloud.com/184573921/calendars/a.ics";

    fn xml(status: u16, body: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(body.to_owned())))
            .expect("response")
    }

    fn sync_body() -> String {
        r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/184573921/calendars/a.ics</href>
    <propstat>
      <prop><getetag>"e1"</getetag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <response>
    <href>/184573921/calendars/b.ics</href>
    <propstat>
      <prop><getetag>"e2"</getetag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <sync-token>http://example.com/ns/sync/1234</sync-token>
</multistatus>"#
            .to_owned()
    }

    #[tokio::test]
    async fn sync_collection_ignores_limit() {
        let script = Script::new(|request| {
            assert!(
                !request.body().to_ascii_lowercase().contains("limit"),
                "iCloud ignores DAV:limit, so the report must not send one"
            );
            xml(207, &sync_body())
        });
        let report = sync_collection(&script, &credentials(), COLLECTION, None, Some(1))
            .await
            .expect("sync returns every item the server sent");
        assert_eq!(
            report.changed.len(),
            2,
            "a limit of 1 must not drop the second item"
        );
        assert_eq!(report.changed[0].href, "/184573921/calendars/a.ics");
        assert_eq!(report.changed[0].etag.as_str(), "\"e1\"");
        assert_eq!(report.changed[1].etag.as_str(), "\"e2\"");
        assert_eq!(
            report.token.as_deref(),
            Some("http://example.com/ns/sync/1234")
        );
        let seen = script.requests();
        assert!(
            seen.iter()
                .any(|logged| logged.body.contains("sync-collection")),
            "sync uses a sync-collection report, saw {seen:?}"
        );
    }

    #[tokio::test]
    async fn fallback_to_ctag_etag_scan_on_invalid_token() {
        let script = Script::new(|request| {
            let body = request.body();
            if body.contains("sync-collection") {
                return xml(
                    403,
                    r#"<?xml version="1.0" encoding="utf-8"?>
<error xmlns="DAV:">
  <valid-sync-token/>
</error>"#,
                );
            }
            if body.contains("getctag") {
                return xml(
                    207,
                    r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:" xmlns:CS="http://calendarserver.org/ns/">
  <response>
    <href>/184573921/calendars/</href>
    <propstat>
      <prop><CS:getctag>"ctag-9"</CS:getctag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <response>
    <href>/184573921/calendars/a.ics</href>
    <propstat>
      <prop><getetag>"e1"</getetag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
</multistatus>"#,
                );
            }
            xml(404, "")
        });
        let report = sync_collection(
            &script,
            &credentials(),
            COLLECTION,
            Some("stale-token"),
            None,
        )
        .await
        .expect("a stale token falls back to a ctag and etag scan");
        let seen = script.requests();
        assert!(
            seen[0].body.contains("sync-collection") && seen[0].body.contains("stale-token"),
            "the stale token is tried first, saw {seen:?}"
        );
        assert!(
            seen.iter()
                .any(|logged| logged.body.contains("getctag") && logged.body.contains("getetag")),
            "fallback asks for getctag and getetag, saw {seen:?}"
        );
        assert!(
            report.token.is_none(),
            "a getctag must not be handed back as a sync token, got {:?}",
            report.token
        );
        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.changed[0].href, "/184573921/calendars/a.ics");
        assert_eq!(report.changed[0].etag.as_str(), "\"e1\"");
    }

    #[tokio::test]
    async fn put_with_if_match() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(204)
                .header("etag", "\"next\"")
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let etag = ETag::try_from("\"abc\"").expect("etag");
        let written = put_if_match(
            &script,
            &credentials(),
            EVENT,
            "BEGIN:VCALENDAR",
            "text/calendar",
            &etag,
        )
        .await
        .expect("conditional update");
        assert_eq!(written.as_str(), "\"next\"");
        let seen = script.requests();
        assert_eq!(seen.len(), 1, "one PUT, saw {seen:?}");
        assert_eq!(seen[0].if_match.as_deref(), Some("\"abc\""));
        assert_eq!(seen[0].if_none_match, None);
        assert_eq!(seen[0].body, "BEGIN:VCALENDAR");
        assert_eq!(seen[0].uri.path(), "/184573921/calendars/a.ics");
    }

    #[tokio::test]
    async fn put_new_with_if_none_match() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(201)
                .header("etag", "\"created\"")
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let written = put_new(
            &script,
            &credentials(),
            EVENT,
            "BEGIN:VCALENDAR",
            "text/calendar",
        )
        .await
        .expect("create");
        assert_eq!(written.as_str(), "\"created\"");
        let seen = script.requests();
        assert_eq!(seen[0].if_none_match.as_deref(), Some("*"));
        assert_eq!(seen[0].if_match, None);
        assert_eq!(seen[0].body, "BEGIN:VCALENDAR");
    }

    #[tokio::test]
    async fn conflict_on_412() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(412)
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let etag = ETag::try_from("\"abc\"").expect("etag");
        let error = put_if_match(
            &script,
            &credentials(),
            EVENT,
            "BEGIN:VCALENDAR",
            "text/calendar",
            &etag,
        )
        .await
        .expect_err("412 is a lost update");
        assert_eq!(error, DavError::Conflict);
    }

    #[tokio::test]
    async fn delete_if_match_sends_header() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(204)
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let client = crate::DavClient::from_script(script.clone(), credentials());
        let etag = ETag::try_from("\"abc\"").expect("etag");
        client
            .delete_if_match(EVENT, &etag)
            .await
            .expect("conditional delete");
        let seen = script.requests();
        assert_eq!(seen.len(), 1, "one DELETE, saw {seen:?}");
        assert_eq!(seen[0].if_match.as_deref(), Some("\"abc\""));
        assert_eq!(seen[0].uri.path(), "/184573921/calendars/a.ics");
    }

    #[tokio::test]
    async fn delete_conflict_on_412() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(412)
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let client = crate::DavClient::from_script(script, credentials());
        let etag = ETag::try_from("\"abc\"").expect("etag");
        let error = client
            .delete_if_match(EVENT, &etag)
            .await
            .expect_err("412 is a lost delete");
        assert_eq!(error, DavError::Conflict);
    }

    #[tokio::test]
    async fn delete_missing_is_not_found() {
        let script = Script::new(|_request| {
            Response::builder()
                .status(404)
                .body(Full::new(Bytes::new()))
                .expect("response")
        });
        let client = crate::DavClient::from_script(script, credentials());
        let etag = ETag::try_from("\"abc\"").expect("etag");
        let error = client
            .delete_if_match(EVENT, &etag)
            .await
            .expect_err("404 means the resource is already gone");
        assert_eq!(error, DavError::NotFound);
    }

    #[tokio::test]
    async fn sync_reports_deleted_href() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/184573921/calendars/a.ics</href>
    <propstat>
      <prop><getetag>"e1"</getetag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <response>
    <href>/184573921/calendars/gone.ics</href>
    <status>HTTP/1.1 404 Not Found</status>
  </response>
  <sync-token>http://example.com/ns/sync/9</sync-token>
</multistatus>"#;
        let script = Script::new(|_| xml(207, body));
        let report = sync_collection(&script, &credentials(), COLLECTION, Some("prev"), None)
            .await
            .expect("a 404 member is a deletion, not a protocol error");
        assert_eq!(report.deleted, vec!["/184573921/calendars/gone.ics"]);
        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.changed[0].href, "/184573921/calendars/a.ics");
    }

    #[tokio::test]
    async fn sync_skips_item_without_etag() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<multistatus xmlns="DAV:">
  <response>
    <href>/184573921/calendars/a.ics</href>
    <propstat>
      <prop><getetag>"e1"</getetag></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <response>
    <href>/184573921/calendars/bad.ics</href>
    <propstat>
      <prop></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
  <sync-token>http://example.com/ns/sync/9</sync-token>
</multistatus>"#;
        let script = Script::new(|_| xml(207, body));
        let report = sync_collection(&script, &credentials(), COLLECTION, None, None)
            .await
            .expect("one item without an etag must not fail the sync");
        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.changed[0].href, "/184573921/calendars/a.ics");
        assert!(
            report.warnings >= 1,
            "the skipped item is counted, got {}",
            report.warnings
        );
    }

    #[tokio::test]
    async fn status_401_and_bare_403_are_auth() {
        for status in [401_u16, 403] {
            let script = Script::new(move |_| xml(status, ""));
            let error = sync_collection(&script, &credentials(), COLLECTION, None, None)
                .await
                .expect_err("a rejected password is not a protocol error");
            assert_eq!(error, DavError::Auth, "sync status {status}");

            let script = Script::new(move |_| xml(status, ""));
            let error = put_new(
                &script,
                &credentials(),
                EVENT,
                "BEGIN:VCALENDAR",
                "text/calendar",
            )
            .await
            .expect_err("a rejected password is not a protocol error");
            assert_eq!(error, DavError::Auth, "put status {status}");
        }

        let script = Script::new(|request| {
            if request.body().contains("sync-collection") {
                return xml(
                    403,
                    r#"<?xml version="1.0" encoding="utf-8"?>
<error xmlns="DAV:">
  <valid-sync-token/>
</error>"#,
                );
            }
            xml(401, "")
        });
        let error = sync_collection(
            &script,
            &credentials(),
            COLLECTION,
            Some("stale-token"),
            None,
        )
        .await
        .expect_err("a 401 during the etag scan is still auth");
        assert_eq!(error, DavError::Auth);
    }
}
