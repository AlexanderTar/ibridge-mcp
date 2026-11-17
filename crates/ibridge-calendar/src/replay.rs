// SPDX-License-Identifier: Apache-2.0

//! Replays the `CalDAV` responses recorded from real iCloud.

use ibridge_auth::Credentials;
use ibridge_core::{AppleId, CalendarProvider, CompletedFilter, EventQuery, RemindersProvider};
use ibridge_dav::DavClient;
use ibridge_testkit::fixtures::ReplayCalDav;

use crate::CalDavProvider;

#[tokio::test]
async fn fixture_icloud_caldav_discovery_and_sync() {
    let replay = ReplayCalDav::start().await;
    let credentials = Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    );
    let client = DavClient::for_test_server(credentials, &replay.base_url()).expect("test client");
    let provider = CalDavProvider::new(client);

    let calendars = provider.list_calendars().await.expect("recorded home");
    let test_calendars: Vec<_> = calendars
        .iter()
        .filter(|calendar| calendar.name == "ibridge-test")
        .collect();
    assert_eq!(test_calendars.len(), 2, "got {calendars:?}");
    assert!(
        test_calendars
            .iter()
            .any(|calendar| calendar.holds_events && !calendar.holds_tasks),
        "an events-only calendar, got {calendars:?}"
    );
    assert!(
        test_calendars
            .iter()
            .any(|calendar| calendar.holds_tasks && !calendar.holds_events),
        "a tasks-only list, got {calendars:?}"
    );
    assert!(
        calendars
            .iter()
            .all(|calendar| !calendar.path.as_str().contains("inbox")
                && !calendar.path.as_str().contains("outbox")
                && !calendar.path.as_str().contains("notification")),
        "scheduling and notification collections are not calendars, got {calendars:?}"
    );

    let events = provider
        .list_events(&EventQuery {
            calendars: Vec::new(),
            start: "2026-11-01T00:00:00Z".to_owned(),
            end: "2027-01-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("recorded report");
    assert_eq!(events.events.len(), 1, "got {events:?}");
    let event = &events.events[0];
    assert!(
        event.summary.starts_with("[ibridge-fixture] ") && event.summary.ends_with(" event"),
        "got {}",
        event.summary
    );
    assert_eq!(event.description, "recorded by ibridge xtask");
    assert!(
        event.start.starts_with("2026-12-01T10:00"),
        "got {}",
        event.start
    );
    assert!(!event.all_day && !event.recurring);
    let fetched = provider.get_event(&event.path).await.expect("recorded GET");
    assert_eq!(fetched.uid, event.uid);

    let page = provider
        .list(None, CompletedFilter::All)
        .await
        .expect("recorded todo report");
    assert_eq!(page.reminders.len(), 1, "got {page:?}");
    let reminder = &page.reminders[0];
    assert!(
        reminder.title.starts_with("[ibridge-fixture] "),
        "got {}",
        reminder.title
    );
    assert_eq!(reminder.priority, Some(5));
    assert!(!reminder.completed);
    assert!(
        reminder
            .due
            .as_deref()
            .is_some_and(|due| due.starts_with("2026-12-02T09:00")),
        "got {:?}",
        reminder.due
    );
    let got = provider
        .get(&reminder.path)
        .await
        .expect("recorded todo GET");
    assert_eq!(got.title, reminder.title);
}
