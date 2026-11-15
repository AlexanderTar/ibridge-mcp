// SPDX-License-Identifier: Apache-2.0

//! Radicale covers discover, put, get and delete against a real server.

use http::{Request, StatusCode};

use crate::DavClient;
use crate::test_support::credentials;

#[tokio::test]
async fn radicale_discover_put_get_delete() {
    let server = ibridge_testkit::containers::radicale()
        .start()
        .await
        .expect("radicale starts");
    let client = DavClient::for_test_server(credentials(), server.base_url()).expect("test client");
    let home = client.calendar_home().await.expect("discover caldav");
    let collection = format!("{}/events/", home.url.trim_end_matches('/'));

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

    client
        .delete_if_match(&event, &etag)
        .await
        .expect("delete event");

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

fn mkcol(url: &str) -> Request<String> {
    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<mkcol xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
<set><prop><resourcetype><collection/><C:calendar/></resourcetype></prop></set>\
</mkcol>";
    Request::builder()
        .method("MKCOL")
        .uri(url)
        .header("Content-Type", "application/xml; charset=utf-8")
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

fn body_text(body: &bytes::Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}
