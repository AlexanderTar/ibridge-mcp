// SPDX-License-Identifier: Apache-2.0

//! Radicale covers the event lifecycle against a real server.

use http::Request;
use ibridge_auth::Credentials;
use ibridge_core::{
    AppleId, CalendarProvider, CoreError, ETag, EventDraft, EventQuery, ResourcePath, UpdateScope,
};
use ibridge_dav::DavClient;

use crate::CalDavProvider;

const SERIES: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//ibridge//test//EN\r\n\
    BEGIN:VEVENT\r\nUID:radicale-series\r\nDTSTAMP:20261101T000000Z\r\n\
    DTSTART:20261116T090000Z\r\nDTEND:20261116T100000Z\r\n\
    RRULE:FREQ=DAILY;COUNT=4\r\nEXDATE:20261118T090000Z\r\nSUMMARY:Standup\r\n\
    BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Soon\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n\
    END:VEVENT\r\nEND:VCALENDAR\r\n";

fn credentials() -> Credentials {
    Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    )
}

fn draft(summary: &str, start: &str, end: &str) -> EventDraft {
    EventDraft {
        summary: summary.to_owned(),
        description: "Notes".to_owned(),
        start: start.to_owned(),
        end: end.to_owned(),
        time_zone: None,
    }
}

fn query() -> EventQuery {
    EventQuery {
        calendars: Vec::new(),
        start: "2026-11-15T00:00:00Z".to_owned(),
        end: "2026-11-30T00:00:00Z".to_owned(),
    }
}

struct Fixture {
    /// Keeps the container running.
    _server: ibridge_testkit::containers::RunningRadicale,
    raw: DavClient,
    provider: CalDavProvider,
    /// URL of the `events/` collection.
    collection: String,
}

async fn fixture() -> Fixture {
    let server = ibridge_testkit::containers::radicale()
        .start()
        .await
        .expect("radicale starts");
    let raw = DavClient::for_test_server(credentials(), server.base_url()).expect("raw client");
    let home = raw.calendar_home().await.expect("discover");
    let collection = format!("{}/events/", home.url.trim_end_matches('/'));
    let mkcol = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        <mkcol xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><set><prop>\
        <resourcetype><collection/><C:calendar/></resourcetype>\
        <C:supported-calendar-component-set><C:comp name=\"VEVENT\"/></C:supported-calendar-component-set>\
        </prop></set></mkcol>";
    let created = raw
        .request(
            Request::builder()
                .method("MKCOL")
                .uri(&collection)
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(mkcol.to_owned())
                .expect("mkcol"),
        )
        .await
        .expect("create calendar");
    assert!(
        created.status.is_success(),
        "mkcol status {}",
        created.status
    );
    let provider = CalDavProvider::new(
        DavClient::for_test_server(credentials(), server.base_url()).expect("provider client"),
    );
    Fixture {
        _server: server,
        raw,
        provider,
        collection,
    }
}

/// Create, read back, change and delete a single event.
async fn single_event_lifecycle(provider: &CalDavProvider) {
    let calendar = ResourcePath::try_from("events/").expect("collection path");
    let path = provider
        .create_event(&calendar, &draft("Lunch", "2026-11-16T12:00:00Z", ""))
        .await
        .expect("create");
    let listed = provider.list_events(&query()).await.expect("list");
    assert_eq!(listed.events.len(), 1, "{:?}", listed.events);
    let lunch = &listed.events[0];
    assert_eq!(lunch.summary, "Lunch");
    assert_eq!(lunch.end, "2026-11-16T13:00:00Z", "DTEND was written");
    let fetched = provider.get_event(&path).await.expect("get");
    assert_eq!(fetched.etag, lunch.etag);
    let moved = draft("Late lunch", "2026-11-16T13:00:00Z", "2026-11-16T14:00:00Z");
    let new_etag = provider
        .update_event(&path, &fetched.etag, &moved, &UpdateScope::Series)
        .await
        .expect("update");
    assert_ne!(new_etag, fetched.etag);
    let stale = provider
        .update_event(&path, &fetched.etag, &moved, &UpdateScope::Series)
        .await
        .expect_err("the old ETag no longer matches");
    assert_eq!(stale, CoreError::Conflict);
    provider
        .delete_event(&path, &new_etag)
        .await
        .expect("delete");
    let left = provider.list_events(&query()).await.expect("list").events;
    assert_eq!(left, Vec::new(), "the event is gone");
}

/// A series with an EXDATE, one occurrence changed on its own.
async fn recurring_series(fixture: &Fixture) {
    let provider = &fixture.provider;
    fixture
        .raw
        .put_new(
            &format!("{}series.ics", fixture.collection),
            SERIES,
            "text/calendar",
        )
        .await
        .expect("put series");
    let series = ResourcePath::try_from("events/series.ics").expect("path");
    let listed = provider.list_events(&query()).await.expect("list series");
    let starts: Vec<&str> = listed.events.iter().map(|e| e.start.as_str()).collect();
    assert_eq!(
        starts,
        [
            "2026-11-16T09:00:00Z",
            "2026-11-17T09:00:00Z",
            "2026-11-19T09:00:00Z"
        ],
        "four occurrences minus the EXDATE"
    );
    let etag: ETag = listed.events[0].etag.clone();
    provider
        .update_event(
            &series,
            &etag,
            &draft("Moved", "2026-11-17T10:00:00Z", "2026-11-17T11:00:00Z"),
            &UpdateScope::Occurrence {
                recurrence_id: "2026-11-17T09:00:00Z".to_owned(),
            },
        )
        .await
        .expect("update one occurrence");
    let listed = provider.list_events(&query()).await.expect("list again");
    let moved: Vec<(&str, &str)> = listed
        .events
        .iter()
        .map(|e| (e.start.as_str(), e.summary.as_str()))
        .collect();
    assert_eq!(
        moved,
        [
            ("2026-11-16T09:00:00Z", "Standup"),
            ("2026-11-17T10:00:00Z", "Moved"),
            ("2026-11-19T09:00:00Z", "Standup"),
        ]
    );
    assert_eq!(
        listed.events[0].alarms,
        ["-PT10M"],
        "the alarm survived the edit"
    );
}

#[tokio::test]
async fn radicale_event_crud_and_recurrence() {
    let fixture = fixture().await;
    single_event_lifecycle(&fixture.provider).await;
    recurring_series(&fixture).await;
}
