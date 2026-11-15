// SPDX-License-Identifier: Apache-2.0

//! Records scrubbed `CalDAV` fixtures from the account's `ibridge-test` calendar and list.
//!
//! The recorder writes only to the collections named `ibridge-test`, and only
//! deletes what it created in the same run.

use std::fs;
use std::io;
use std::path::Path;

use http::{Method, Request};
use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_calendar::CalDavProvider;
use ibridge_core::{
    Calendar, CalendarProvider, ReminderDraft, ReminderList, RemindersProvider, ResourcePath,
};
use ibridge_core::{ETag, EventDraft};
use ibridge_dav::{DavClient, DavError};

use crate::record_fixtures::{MARKER, RecordError};
use crate::scrub::{Identity, Scrubber};

/// Name of the calendar and of the reminders list the recorder may use.
pub(crate) const TEST_NAME: &str = "ibridge-test";

const PROPFIND_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <D:propfind xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:prop>\
    <D:displayname/><D:resourcetype/><C:supported-calendar-component-set/>\
    </D:prop></D:propfind>";

/// What the recorder created, so that it deletes exactly that.
struct Created {
    path: ResourcePath,
    kind: &'static str,
}

/// Sends marker items to the test calendar and list, records the replies,
/// scrubs them into `out_dir`, and deletes the items again.
///
/// Nothing outside the two `ibridge-test` collections is written or deleted.
/// Items that were already there stay.
pub(crate) async fn run_calendar(
    account: &Path,
    make_client: impl Fn(&Credentials) -> Result<DavClient, DavError>,
    out_dir: &Path,
    nonce: &str,
    log: &mut impl io::Write,
) -> Result<(), RecordError> {
    let credentials = load(account).await?;
    let provider = CalDavProvider::new(make_client(&credentials).map_err(dav)?);
    let raw = make_client(&credentials).map_err(dav)?;
    let (calendar, list) = find_test_collections(&provider).await?;
    let marker = format!("{MARKER} {nonce}");

    let mut created = Vec::new();
    let recorded = record(
        &provider,
        &raw,
        &calendar,
        &list,
        &marker,
        &credentials,
        out_dir,
        &mut created,
    )
    .await;
    let cleaned = clean_up(&raw, &created, &marker).await;
    let files = recorded?;
    let deleted = cleaned?;
    writeln!(
        log,
        "recorded {files} fixtures, deleted {deleted} marker items from ibridge-test"
    )?;
    Ok(())
}

/// Reports the `ibridge-test` calendar and list without writing anything.
pub(crate) async fn check_calendar(
    account: &Path,
    make_client: impl Fn(&Credentials) -> Result<DavClient, DavError>,
    log: &mut impl io::Write,
) -> Result<(), RecordError> {
    let credentials = load(account).await?;
    let provider = CalDavProvider::new(make_client(&credentials).map_err(dav)?);
    let (calendar, list) = find_test_collections(&provider).await?;
    writeln!(log, "calendar {TEST_NAME} at {} (events)", calendar.path)?;
    writeln!(log, "list {TEST_NAME} at {} (reminders)", list.path)?;
    Ok(())
}

async fn load(account: &Path) -> Result<Credentials, RecordError> {
    FileSource::new(account)
        .credentials()
        .await
        .map_err(|_| RecordError::Account)
}

fn dav(_error: DavError) -> RecordError {
    RecordError::Dav("the request could not be completed")
}

fn core(_error: ibridge_core::CoreError) -> RecordError {
    RecordError::Dav("the calendar call failed")
}

/// The event calendar and the reminders list called `ibridge-test`.
async fn find_test_collections(
    provider: &CalDavProvider,
) -> Result<(Calendar, ReminderList), RecordError> {
    let calendars = provider.list_calendars().await.map_err(core)?;
    let calendar = calendars
        .iter()
        .find(|c| c.name == TEST_NAME && c.holds_events)
        .cloned()
        .ok_or(RecordError::MissingCollection("calendar"))?;
    let list = calendars
        .iter()
        .find(|c| c.name == TEST_NAME && c.holds_tasks)
        .map(|c| ReminderList {
            path: c.path.clone(),
            name: c.name.clone(),
        })
        .ok_or(RecordError::MissingCollection("list"))?;
    Ok((calendar, list))
}

#[expect(
    clippy::too_many_arguments,
    reason = "one recording pass needs the clients, both collections and the output"
)]
async fn record(
    provider: &CalDavProvider,
    raw: &DavClient,
    calendar: &Calendar,
    list: &ReminderList,
    marker: &str,
    credentials: &Credentials,
    out_dir: &Path,
    created: &mut Vec<Created>,
) -> Result<usize, RecordError> {
    let home = raw.calendar_home().await.map_err(dav)?;
    let mut scrubber = Scrubber::new(Identity {
        apple_id: credentials.apple_id.as_str().to_owned(),
        dsid: None,
        names: Vec::new(),
    });
    let mut fixtures: Vec<(&str, String)> = Vec::new();
    let listing = send(raw, "PROPFIND", &home.url, Some("1"), PROPFIND_BODY).await?;
    fixtures.push(("propfind-home.xml", listing));

    let event = provider
        .create_event(
            &calendar.path,
            &EventDraft {
                summary: format!("{marker} event"),
                description: "recorded by ibridge xtask".to_owned(),
                start: "2026-12-01T10:00:00Z".to_owned(),
                end: "2026-12-01T11:00:00Z".to_owned(),
                time_zone: None,
            },
        )
        .await
        .map_err(core)?;
    created.push(Created {
        path: event.clone(),
        kind: "event",
    });
    let todo = provider
        .create(
            &list.path,
            &ReminderDraft {
                title: format!("{marker} reminder"),
                notes: "recorded by ibridge xtask".to_owned(),
                due: Some("2026-12-02T09:00:00Z".to_owned()),
                priority: Some(5),
                completed: false,
            },
        )
        .await
        .map_err(core)?;
    created.push(Created {
        path: todo.clone(),
        kind: "reminder",
    });

    let events_url = format!("{}/{}", home.url.trim_end_matches('/'), calendar.path);
    let todos_url = format!("{}/{}", home.url.trim_end_matches('/'), list.path);
    fixtures.push((
        "report-events.xml",
        send(
            raw,
            "REPORT",
            &events_url,
            Some("1"),
            &query(
                "VEVENT",
                "<C:time-range start=\"20261101T000000Z\" end=\"20270101T000000Z\"/>",
            ),
        )
        .await?,
    ));
    fixtures.push((
        "report-todos.xml",
        send(raw, "REPORT", &todos_url, Some("1"), &query("VTODO", "")).await?,
    ));
    fixtures.push((
        "event.ics",
        send(
            raw,
            "GET",
            &format!("{}/{event}", home.url.trim_end_matches('/')),
            None,
            "",
        )
        .await?,
    ));
    fixtures.push((
        "todo.ics",
        send(
            raw,
            "GET",
            &format!("{}/{todo}", home.url.trim_end_matches('/')),
            None,
            "",
        )
        .await?,
    ));

    fs::create_dir_all(out_dir)?;
    let count = fixtures.len();
    for (name, body) in fixtures {
        fs::write(out_dir.join(name), scrubber.scrub(&body))?;
    }
    Ok(count)
}

fn query(component: &str, range: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
         <D:prop><D:getetag/><C:calendar-data/></D:prop>\
         <C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"{component}\">{range}\
         </C:comp-filter></C:comp-filter></C:filter></C:calendar-query>"
    )
}

/// Sends one request and returns the response body as text.
async fn send(
    client: &DavClient,
    method: &str,
    url: &str,
    depth: Option<&str>,
    body: &str,
) -> Result<String, RecordError> {
    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).map_err(|_| RecordError::Dav("method"))?)
        .uri(url);
    if let Some(depth) = depth {
        builder = builder.header("Depth", depth);
    }
    if !body.is_empty() {
        builder = builder.header("Content-Type", "application/xml; charset=utf-8");
    }
    let request = builder
        .body(body.to_owned())
        .map_err(|_| RecordError::Dav("request"))?;
    let exchange = client.request(request).await.map_err(dav)?;
    if !exchange.status.is_success() {
        return Err(RecordError::Dav("the server refused a request"));
    }
    Ok(String::from_utf8_lossy(&exchange.body).into_owned())
}

/// Deletes what this run created. An item is deleted only when it still
/// carries this run's marker, with the `ETag` read just before the delete.
async fn clean_up(
    raw: &DavClient,
    created: &[Created],
    marker: &str,
) -> Result<usize, RecordError> {
    let home = raw.calendar_home().await.map_err(dav)?;
    let mut deleted = 0;
    let mut failed = None;
    for item in created {
        let url = format!("{}/{}", home.url.trim_end_matches('/'), item.path);
        match delete_marked(raw, &url, marker).await {
            Ok(()) => deleted += 1,
            Err(error) => failed = Some((error, item.kind)),
        }
    }
    match failed {
        None => Ok(deleted),
        Some((error, _kind)) => Err(error),
    }
}

async fn delete_marked(raw: &DavClient, url: &str, marker: &str) -> Result<(), RecordError> {
    let request = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(String::new())
        .map_err(|_| RecordError::Dav("request"))?;
    let exchange = raw.request(request).await.map_err(dav)?;
    if !exchange.status.is_success() {
        return Err(RecordError::Dav("a marker item could not be read back"));
    }
    if !String::from_utf8_lossy(&exchange.body).contains(marker) {
        return Err(RecordError::Dav(
            "an item without the marker was not deleted",
        ));
    }
    let etag = exchange
        .headers
        .get(http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| ETag::try_from(value).ok())
        .ok_or(RecordError::Dav("a marker item has no ETag"))?;
    raw.delete_if_match(url, &etag).await.map_err(dav)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use ibridge_auth::Credentials;
    use ibridge_dav::{DavClient, DavError};
    use ibridge_testkit::dav_mock::FakeCalDav;

    use super::{check_calendar, run_calendar};
    use crate::record_fixtures::RecordError;

    const ACCOUNT: &str =
        "IBRIDGE_TEST_APPLE_ID=ada@icloud.com\nIBRIDGE_TEST_APP_PASSWORD=never-print-me\n";
    const REAL_EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//real//app//EN\r\n\
        BEGIN:VEVENT\r\nUID:real-1\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261116T090000Z\r\n\
        DTEND:20261116T100000Z\r\nSUMMARY:Dentist\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    const LEFTOVER: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//other//app//EN\r\n\
        BEGIN:VEVENT\r\nUID:keep-1\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261117T090000Z\r\n\
        DTEND:20261117T100000Z\r\nSUMMARY:Not ours\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    async fn account_with_test_collections() -> FakeCalDav {
        let fake = FakeCalDav::start().await;
        fake.add_collection("work", "Work", &["VEVENT"]);
        fake.put("work", "real.ics", REAL_EVENT);
        fake.add_collection("ibridge-test", "ibridge-test", &["VEVENT"]);
        fake.put("ibridge-test", "keep.ics", LEFTOVER);
        fake.add_collection("ibridge-test-list", "ibridge-test", &["VTODO"]);
        fake
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ibridge-cal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn account_file(dir: &std::path::Path) -> PathBuf {
        let path = dir.join("test-account.env");
        fs::write(&path, ACCOUNT).expect("write account file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        path
    }

    fn client_for(base: String) -> impl Fn(&Credentials) -> Result<DavClient, DavError> {
        move |credentials| {
            let copy = credentials.with_secret(|secret| {
                Credentials::new(credentials.apple_id.clone(), secret.to_owned())
            });
            DavClient::for_test_server(copy, &base)
        }
    }

    #[tokio::test]
    async fn calendar_recorder_only_touches_ibridge_test() {
        let fake = account_with_test_collections().await;
        let dir = scratch("only");
        let account = account_file(&dir);
        let mut log = Vec::new();
        run_calendar(
            &account,
            client_for(fake.base_url()),
            &dir.join("out"),
            "n0nce",
            &mut log,
        )
        .await
        .expect("the recorder runs");
        let touched_other = |path: &str| path.starts_with("/ada/calendars/work");
        for request in fake.requests() {
            assert!(
                !touched_other(&request.path),
                "{} {} reached a calendar that is not ibridge-test",
                request.method,
                request.path
            );
            if matches!(
                request.method.as_str(),
                "PUT" | "DELETE" | "MKCOL" | "PROPPATCH"
            ) {
                assert!(
                    request.path.starts_with("/ada/calendars/ibridge-test"),
                    "{} {} wrote outside the test collections",
                    request.method,
                    request.path
                );
            }
        }
        assert_eq!(
            fake.files("work"),
            ["real.ics"],
            "the real calendar is untouched"
        );
        let log = String::from_utf8(log).expect("log text");
        assert!(
            !log.contains("never-print-me"),
            "the log never has the password: {log}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn calendar_recorder_cleans_up() {
        let fake = account_with_test_collections().await;
        let dir = scratch("clean");
        let account = account_file(&dir);
        let out = dir.join("out");
        let mut log = Vec::new();
        run_calendar(
            &account,
            client_for(fake.base_url()),
            &out,
            "n0nce",
            &mut log,
        )
        .await
        .expect("the recorder runs");
        assert_eq!(
            fake.files("ibridge-test"),
            ["keep.ics"],
            "the recorder deleted what it created and nothing else"
        );
        assert_eq!(
            fake.files("ibridge-test-list"),
            Vec::<String>::new(),
            "the reminder it created is gone"
        );
        for file in [
            "propfind-home.xml",
            "report-events.xml",
            "report-todos.xml",
            "event.ics",
            "todo.ics",
        ] {
            let text = fs::read_to_string(out.join(file))
                .unwrap_or_else(|error| panic!("{file} was not recorded: {error}"));
            assert!(
                !text.contains("ada@icloud.com") && !text.contains("never-print-me"),
                "{file} is scrubbed: {text}"
            );
        }
        let event = fs::read_to_string(out.join("event.ics")).expect("event fixture");
        assert!(
            event.contains("[ibridge-fixture] n0nce"),
            "the marker is recorded: {event}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn calendar_recorder_check_lists_test_collections() {
        let fake = account_with_test_collections().await;
        let dir = scratch("check");
        let account = account_file(&dir);
        let mut log = Vec::new();
        check_calendar(&account, client_for(fake.base_url()), &mut log)
            .await
            .expect("both test collections exist");
        let log = String::from_utf8(log).expect("log text");
        assert!(log.contains("calendar ibridge-test"), "{log}");
        assert!(log.contains("list ibridge-test"), "{log}");
        for request in fake.requests() {
            assert!(
                !matches!(
                    request.method.as_str(),
                    "PUT" | "DELETE" | "MKCOL" | "PROPPATCH"
                ),
                "--check wrote with {} {}",
                request.method,
                request.path
            );
        }

        let bare = FakeCalDav::start().await;
        bare.add_collection("work", "Work", &["VEVENT"]);
        bare.add_collection("ibridge-test", "ibridge-test", &["VEVENT"]);
        let mut log = Vec::new();
        let error = check_calendar(&account, client_for(bare.base_url()), &mut log)
            .await
            .expect_err("the list is missing");
        assert!(
            matches!(error, RecordError::MissingCollection("list")),
            "{error}"
        );
        assert!(error.to_string().contains("ibridge-test"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }
}
