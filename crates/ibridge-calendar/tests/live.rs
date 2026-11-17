// SPDX-License-Identifier: Apache-2.0

//! Live smoke test for calendar and reminders, against the user's own iCloud account.
//!
//! Ignored by default and never run in CI. Run it with
//! `IBRIDGE_LIVE=1 cargo nextest run --run-ignored ignored-only -E 'test(live_calendar)'`.
//! It reads `~/.config/ibridge/test-account.env`, writes one marker event to the
//! calendar named `ibridge-test` and, when a task collection of that name is
//! visible over `CalDAV`, one marker reminder to it. It reads each back and deletes
//! it, by path with no etag when the read-back fails, so nothing is left behind.
//! Nothing outside those two collections is read or written.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Request, StatusCode};
use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_calendar::CalDavProvider;
use ibridge_core::{
    CalendarProvider, CompletedFilter, CoreError, EventDraft, EventQuery, ReminderDraft,
    RemindersProvider,
};
use ibridge_dav::DavClient;

const TEST_NAME: &str = "ibridge-test";

async fn account() -> Credentials {
    assert_eq!(
        std::env::var("IBRIDGE_LIVE").as_deref(),
        Ok("1"),
        "live tests need IBRIDGE_LIVE=1"
    );
    let home = std::env::var_os("HOME").expect("HOME is set");
    let path = PathBuf::from(home).join(".config/ibridge/test-account.env");
    FileSource::new(path)
        .credentials()
        .await
        .expect("the test account file is present, mode 0600 and complete")
}

fn copy(credentials: &Credentials) -> Credentials {
    credentials.with_secret(|secret| Credentials::new(credentials.apple_id.clone(), secret))
}

/// Deletes the resource at `url` with no `If-Match`, so a failed read-back cannot leave the
/// marker behind for want of an etag. A 404 means it is already gone.
async fn delete_regardless(client: &DavClient, url: String) {
    let request = Request::builder()
        .method("DELETE")
        .uri(url)
        .body(String::new())
        .expect("a DELETE request");
    let exchange = client
        .request(request)
        .await
        .expect("send the cleanup DELETE");
    assert!(
        exchange.status.is_success() || exchange.status == StatusCode::NOT_FOUND,
        "the cleanup DELETE removed the marker, got {}",
        exchange.status
    );
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_nanos();
    format!("{nanos:x}")
}

#[tokio::test]
#[ignore = "live: needs IBRIDGE_LIVE=1 and the test account file"]
async fn live_calendar_smoke() {
    let credentials = account().await;
    let cleanup = DavClient::new(copy(&credentials)).expect("DAV client");
    let provider = CalDavProvider::new(DavClient::new(credentials).expect("DAV client"));
    let marker = format!("[ibridge-live] {}", nonce());

    let calendars = provider.list_calendars().await.expect("calendars");
    let calendar = calendars
        .iter()
        .find(|calendar| calendar.name == TEST_NAME && calendar.holds_events)
        .expect("a calendar named ibridge-test");

    // Events: create, list, read, delete. Each step that can fail waits until
    // the delete has run.
    let created = provider
        .create_event(
            &calendar.path,
            &EventDraft {
                summary: format!("{marker} event"),
                description: Some("live smoke marker".to_owned()),
                start: "2026-12-15T10:00:00Z".to_owned(),
                end: "2026-12-15T11:00:00Z".to_owned(),
                time_zone: None,
            },
        )
        .await
        .expect("create the marker event");
    let listed = provider
        .list_events(&EventQuery {
            calendars: vec![calendar.path.clone()],
            start: "2026-12-15T00:00:00Z".to_owned(),
            end: "2026-12-16T00:00:00Z".to_owned(),
        })
        .await;
    let fetched = provider.get_event(&created).await;
    let deleted = match &fetched {
        Ok(event) => provider.delete_event(&created, &event.etag).await,
        Err(_) => Err(CoreError::NotFound),
    };
    if deleted.is_err() {
        let home = cleanup.calendar_home().await.expect("calendar home");
        delete_regardless(&cleanup, home.url_of(created.as_str())).await;
    }
    let after = provider.get_event(&created).await;

    let listed = listed.expect("list the marker event");
    assert!(
        listed
            .events
            .iter()
            .any(|event| event.summary == format!("{marker} event")),
        "the marker event is listed"
    );
    let fetched = fetched.expect("read the marker event");
    assert_eq!(fetched.description, "live smoke marker");
    deleted.expect("delete the marker event with its etag");
    assert!(
        matches!(after, Err(CoreError::NotFound)),
        "the marker event is gone, got {after:?}"
    );

    // Reminders: only when a task collection named ibridge-test is visible over
    // CalDAV. Reminders lists made in the Reminders app are not.
    let Some(list) = calendars
        .iter()
        .find(|calendar| calendar.name == TEST_NAME && calendar.holds_tasks)
    else {
        eprintln!("reminders skipped: no task collection named ibridge-test over CalDAV");
        return;
    };
    let path = provider
        .create(
            &list.path,
            &ReminderDraft {
                title: format!("{marker} reminder"),
                notes: "live smoke marker".to_owned(),
                due: Some("2026-12-15T09:00:00Z".to_owned()),
                priority: Some(5),
                completed: false,
            },
        )
        .await
        .expect("create the marker reminder");
    let page = provider.list(Some(&list.path), CompletedFilter::All).await;
    let got = provider.get(&path).await;
    let removed = match &got {
        Ok(reminder) => RemindersProvider::delete(&provider, &path, &reminder.etag).await,
        Err(_) => Err(CoreError::NotFound),
    };
    if removed.is_err() {
        let home = cleanup.calendar_home().await.expect("calendar home");
        delete_regardless(&cleanup, home.url_of(path.as_str())).await;
    }
    let after = provider.get(&path).await;

    let page = page.expect("list the marker reminder");
    assert!(
        page.reminders
            .iter()
            .any(|reminder| reminder.title == format!("{marker} reminder")),
        "the marker reminder is listed"
    );
    assert_eq!(got.expect("read the marker reminder").priority, Some(5));
    removed.expect("delete the marker reminder with its etag");
    assert!(
        matches!(after, Err(CoreError::NotFound)),
        "the marker reminder is gone, got {after:?}"
    );
}
