// SPDX-License-Identifier: Apache-2.0

//! Radicale covers discover, put, get and delete against a real server.

use bytes::Bytes;
use http::{Request, StatusCode};

use crate::DavClient;
use crate::test_support::credentials;

#[tokio::test]
async fn radicale_discover_put_get_delete() {
    let server = ibridge_testkit::containers::radicale()
        .start()
        .await
        .expect("radicale starts");
    let client = DavClient::new(credentials()).expect("client");
    let base = server.base_url();

    let principal = client
        .request(propfind(
            &format!("{base}.well-known/caldav"),
            "current-user-principal",
        ))
        .await
        .expect("discover principal");
    assert!(
        principal.status.is_success(),
        "well-known discovery status {} body {}",
        principal.status,
        body_text(&principal.body)
    );
    let principal_href =
        href_named(&principal.body, "current-user-principal").unwrap_or_else(|| {
            panic!(
                "current-user-principal href missing from {}",
                body_text(&principal.body)
            )
        });
    let principal_url = join_url(base, &principal_href);

    let home = client
        .request(propfind(&principal_url, "C:calendar-home-set"))
        .await
        .expect("discover calendar home");
    assert!(
        home.status.is_success(),
        "calendar home status {}",
        home.status
    );
    let home_href = href_named(&home.body, "calendar-home-set").expect("calendar-home-set href");
    let collection = format!("{}events/", join_url(base, &home_href));

    let created = client
        .request(mkcol(&collection))
        .await
        .expect("create calendar");
    assert!(
        created.status.is_success(),
        "mkcol status {} body {}",
        created.status,
        body_text(&created.body)
    );

    let event = format!("{collection}item.ics");
    let etag = client
        .put_new(&event, EVENT, "text/calendar")
        .await
        .expect("put event");

    let fetched = client
        .request(method("GET", &event))
        .await
        .expect("get event");
    assert_eq!(fetched.status, StatusCode::OK);
    assert!(
        body_text(&fetched.body).contains("UID:radicale-put-get-delete"),
        "get returned {}",
        body_text(&fetched.body)
    );

    let deleted = client
        .request(
            method_header("DELETE", &event, "If-Match", etag.as_str())
                .body(String::new())
                .expect("delete"),
        )
        .await
        .expect("delete event");
    assert!(
        deleted.status.is_success(),
        "delete status {}",
        deleted.status
    );

    let gone = client
        .request(method("GET", &event))
        .await
        .expect("get after delete");
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

const EVENT: &str = "\
BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//ibridge//test//EN\r\n\
BEGIN:VEVENT\r\n\
UID:radicale-put-get-delete\r\n\
DTSTAMP:20261115T120000Z\r\n\
DTSTART:20261116T120000Z\r\n\
DTEND:20261116T130000Z\r\n\
SUMMARY:Bridge\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

fn propfind(url: &str, property: &str) -> Request<String> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
<prop><{property}/></prop></propfind>"
    );
    method_header("PROPFIND", url, "Depth", "0")
        .header("Content-Type", "application/xml; charset=utf-8")
        .body(body)
        .expect("propfind")
}

fn mkcol(url: &str) -> Request<String> {
    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<mkcol xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
<set><prop><resourcetype><collection/><C:calendar/></resourcetype></prop></set>\
</mkcol>";
    method_header(
        "MKCOL",
        url,
        "Content-Type",
        "application/xml; charset=utf-8",
    )
    .body(body.to_owned())
    .expect("mkcol")
}

fn method(name: &str, url: &str) -> Request<String> {
    Request::builder()
        .method(name)
        .uri(url)
        .body(String::new())
        .expect("request")
}

fn method_header(
    name: &str,
    url: &str,
    header: &'static str,
    value: &str,
) -> http::request::Builder {
    Request::builder()
        .method(name)
        .uri(url)
        .header(header, value)
}

fn href_named(body: &Bytes, property: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let node = doc
        .descendants()
        .find(|node| node.tag_name().name() == property)?;
    let href = node
        .descendants()
        .find(|child| child.tag_name().name() == "href")?
        .text()?
        .trim();
    if href.is_empty() {
        None
    } else {
        Some(href.to_owned())
    }
}

fn join_url(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return with_slash(href);
    }
    let origin = base.trim_end_matches('/');
    if href.starts_with('/') {
        let uri: http::Uri = origin.parse().expect("base url");
        let scheme = uri.scheme_str().expect("scheme");
        let authority = uri.authority().expect("authority");
        return with_slash(&format!("{scheme}://{authority}{href}"));
    }
    with_slash(&format!("{origin}/{href}"))
}

fn with_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_owned()
    } else {
        format!("{url}/")
    }
}

fn body_text(body: &Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}
