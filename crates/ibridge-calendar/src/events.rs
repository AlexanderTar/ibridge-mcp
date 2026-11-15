// SPDX-License-Identifier: Apache-2.0

//! Event reads and writes.

use std::fmt::Write as _;

use calcard::icalendar::{ICalendar, ICalendarProperty};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use http::{Method, Request};
use ibridge_core::{
    Calendar, CalendarProvider, CoreError, ETag, Event, EventDraft, EventList, EventQuery,
    ResourcePath, UpdateScope,
};

use crate::CalDavProvider;
use crate::collections::{Collection, Home, multistatus, protocol, status_error};
use crate::ical::{self, Granularity};
use crate::recurrence::{self, Occurrence, Window, format_instant, zone_name};

#[expect(
    clippy::unused_async_trait_impl,
    reason = "list_calendars arrives with the reminders unit"
)]
impl CalendarProvider for CalDavProvider {
    async fn list_calendars(&self) -> Result<Vec<Calendar>, CoreError> {
        Err(CoreError::Unsupported("list_calendars"))
    }

    async fn list_events(&self, query: &EventQuery) -> Result<EventList, CoreError> {
        let window = Window {
            start: parse_instant(&query.start)?,
            end: parse_instant(&query.end)?,
        };
        if window.end <= window.start {
            return Err(CoreError::InvalidInput(
                "the end of the range must be after its start".to_owned(),
            ));
        }
        let home = self.home().await?;
        let collections = self.collections(&home).await?;
        let chosen = choose_collections(&collections, &query.calendars)?;
        let mut list = EventList {
            events: Vec::new(),
            warnings: 0,
        };
        for collection in chosen {
            self.read_collection(&home, collection, window, &mut list)
                .await?;
        }
        list.events.sort_by(|a, b| a.start.cmp(&b.start));
        Ok(list)
    }

    async fn get_event(&self, path: &ResourcePath) -> Result<Event, CoreError> {
        let fetched = self.fetch(path).await?;
        let ical = ical::parse(&fetched.text).ok_or_else(protocol)?;
        let occurrences = recurrence::expand(&ical, None).occurrences;
        let first = occurrences.first().ok_or_else(protocol)?;
        Ok(to_event(&ical, first, path.clone(), fetched.etag))
    }

    async fn create_event(
        &self,
        calendar: &ResourcePath,
        draft: &EventDraft,
    ) -> Result<ResourcePath, CoreError> {
        let home = self.home().await?;
        let collections = self.collections(&home).await?;
        let key = calendar.as_str().trim_end_matches('/');
        let collection = collections
            .iter()
            .find(|c| c.path.as_str().trim_end_matches('/') == key)
            .ok_or(CoreError::NotFound)?;
        if !collection.holds_events {
            return Err(CoreError::InvalidInput(
                "this calendar holds reminders only; pick a calendar that holds events".to_owned(),
            ));
        }
        let uid = new_uid()?;
        let text = ical::new_event_text(&uid, Utc::now(), draft)?;
        let path =
            ResourcePath::try_from(format!("{key}/{uid}.ics").as_str()).map_err(|_| protocol())?;
        self.client
            .put_new(&home.url_of(path.as_str()), &text, ICS_TYPE)
            .await?;
        Ok(path)
    }

    async fn update_event(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &EventDraft,
        scope: &UpdateScope,
    ) -> Result<ETag, CoreError> {
        let current = self.fetch(path).await?;
        if &current.etag != etag {
            return Err(CoreError::Conflict);
        }
        let text = ical::update_event_text(&current.text, draft, scope)?;
        let home = self.home().await?;
        Ok(self
            .client
            .put_if_match(&home.url_of(path.as_str()), &text, ICS_TYPE, etag)
            .await?)
    }

    async fn delete_event(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError> {
        let home = self.home().await?;
        Ok(self
            .client
            .delete_if_match(&home.url_of(path.as_str()), etag)
            .await?)
    }
}

/// A resource as the server holds it.
struct Fetched {
    etag: ETag,
    text: String,
}

const ICS_TYPE: &str = "text/calendar; charset=utf-8";

/// A random identifier that is safe in a file name.
fn new_uid() -> Result<String, CoreError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| protocol())?;
    let mut uid = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(uid, "{byte:02x}");
    }
    Ok(uid)
}

impl CalDavProvider {
    /// Reads one resource with its `ETag`.
    async fn fetch(&self, path: &ResourcePath) -> Result<Fetched, CoreError> {
        let home = self.home().await?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(home.url_of(path.as_str()))
            .body(String::new())
            .map_err(|_| protocol())?;
        let exchange = self.client.request(request).await?;
        if !exchange.status.is_success() {
            return Err(status_error(exchange.status));
        }
        let etag = exchange
            .headers
            .get(http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ETag::try_from(value).ok())
            .ok_or_else(protocol)?;
        let text = String::from_utf8(exchange.body.to_vec()).map_err(|_| protocol())?;
        Ok(Fetched { etag, text })
    }

    /// Runs one `calendar-query` and adds the expanded events to `list`.
    async fn read_collection(
        &self,
        home: &Home,
        collection: &Collection,
        window: Window,
        list: &mut EventList,
    ) -> Result<(), CoreError> {
        let request = Request::builder()
            .method("REPORT")
            .uri(home.url_of(collection.path.as_str()))
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(time_range_query(window))
            .map_err(|_| protocol())?;
        let exchange = self.client.request(request).await?;
        for entry in multistatus(&exchange)? {
            let (Some(text), Some(etag)) = (entry.calendar_data.as_deref(), entry.etag.as_deref())
            else {
                continue;
            };
            let parsed = (
                home.relative(&entry.href)
                    .and_then(|relative| ResourcePath::try_from(relative.as_str()).ok()),
                ETag::try_from(etag).ok(),
                ical::parse(text),
            );
            let (Some(path), Some(etag), Some(ical)) = parsed else {
                list.warnings += 1;
                continue;
            };
            let expansion = recurrence::expand(&ical, Some(window));
            if expansion.had_errors {
                list.warnings += 1;
            }
            list.events.extend(
                expansion
                    .occurrences
                    .iter()
                    .map(|occurrence| to_event(&ical, occurrence, path.clone(), etag.clone())),
            );
        }
        Ok(())
    }
}

fn choose_collections<'a>(
    all: &'a [Collection],
    wanted: &[ResourcePath],
) -> Result<Vec<&'a Collection>, CoreError> {
    if wanted.is_empty() {
        return Ok(all.iter().filter(|c| c.holds_events).collect());
    }
    wanted
        .iter()
        .map(|path| {
            let key = path.as_str().trim_end_matches('/');
            all.iter()
                .find(|c| c.path.as_str().trim_end_matches('/') == key && c.holds_events)
                .ok_or(CoreError::NotFound)
        })
        .collect()
}

fn time_range_query(window: Window) -> String {
    let format = "%Y%m%dT%H%M%SZ";
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
         <D:prop><D:getetag/><C:calendar-data/></D:prop>\
         <C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\">\
         <C:time-range start=\"{}\" end=\"{}\"/>\
         </C:comp-filter></C:comp-filter></C:filter></C:calendar-query>",
        window.start.format(format),
        window.end.format(format)
    )
}

/// Parses an ISO-8601 timestamp, or a bare date or local time read as UTC.
fn parse_instant(text: &str) -> Result<DateTime<Utc>, CoreError> {
    let text = text.trim();
    if let Ok(moment) = DateTime::parse_from_rfc3339(text) {
        return Ok(moment.with_timezone(&Utc));
    }
    if let Ok(moment) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Ok(moment.and_utc());
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d")
        && let Some(midnight) = date.and_hms_opt(0, 0, 0)
    {
        return Ok(midnight.and_utc());
    }
    Err(CoreError::InvalidInput(format!(
        "'{text}' is not an ISO-8601 date or timestamp"
    )))
}

/// Builds the public event for one occurrence.
fn to_event(ical: &ICalendar, occurrence: &Occurrence, path: ResourcePath, etag: ETag) -> Event {
    let component = &ical.components[occurrence.component];
    let granularity = ical::granularity(component);
    let recurring = ical::is_recurring(component);
    Event {
        path,
        etag,
        uid: ical::text(component, &ICalendarProperty::Uid).unwrap_or_default(),
        summary: ical::text(component, &ICalendarProperty::Summary).unwrap_or_default(),
        description: ical::text(component, &ICalendarProperty::Description).unwrap_or_default(),
        start: format_instant(&occurrence.start, granularity),
        end: format_instant(&occurrence.end, granularity),
        time_zone: zone_name(&occurrence.start),
        all_day: granularity == Granularity::Date,
        recurring,
        recurrence_id: recurring.then(|| format_instant(&occurrence.start, granularity)),
        attendees: ical::attendees(component),
        alarms: ical::alarms(ical, component),
    }
}

#[cfg(test)]
mod tests {
    use ibridge_auth::Credentials;
    use ibridge_core::{
        AppleId, CalendarProvider, CoreError, ETag, EventDraft, EventQuery, ResourcePath,
        UpdateScope,
    };
    use ibridge_dav::DavClient;
    use ibridge_testkit::dav_mock::FakeCalDav;

    use crate::CalDavProvider;

    async fn setup() -> (FakeCalDav, CalDavProvider) {
        let fake = FakeCalDav::start().await;
        fake.add_collection("work", "Work", &["VEVENT"]);
        let credentials = Credentials::new(
            AppleId::try_from("ada@icloud.com").expect("primary address"),
            "test-secret",
        );
        let client =
            DavClient::for_test_server(credentials, &fake.base_url()).expect("test client");
        (fake, CalDavProvider::new(client))
    }

    fn vcalendar(body: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//ibridge//test//EN\r\n{}\r\nEND:VCALENDAR\r\n",
            body.replace('\n', "\r\n")
        )
    }

    fn query(start: &str, end: &str) -> EventQuery {
        EventQuery {
            calendars: Vec::new(),
            start: start.to_owned(),
            end: end.to_owned(),
        }
    }

    #[tokio::test]
    async fn list_events_expands_rrule_with_exdate() {
        let (fake, provider) = setup().await;
        fake.put(
            "work",
            "daily.ics",
            &vcalendar(
                "BEGIN:VEVENT\nUID:daily-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART:20261116T090000Z\nDTEND:20261116T100000Z\n\
                 RRULE:FREQ=DAILY;COUNT=5\nEXDATE:20261118T090000Z\nSUMMARY:Standup\nEND:VEVENT",
            ),
        );
        let list = provider
            .list_events(&query("2026-11-16T00:00:00Z", "2026-11-21T00:00:00Z"))
            .await
            .expect("list events");
        let starts: Vec<&str> = list.events.iter().map(|e| e.start.as_str()).collect();
        assert_eq!(
            starts,
            [
                "2026-11-16T09:00:00Z",
                "2026-11-17T09:00:00Z",
                "2026-11-19T09:00:00Z",
                "2026-11-20T09:00:00Z"
            ],
            "the 18th is excluded by EXDATE"
        );
        assert_eq!(list.events[0].end, "2026-11-16T10:00:00Z");
        assert_eq!(list.events[0].summary, "Standup");
        assert!(list.events[0].recurring);
        assert_eq!(
            list.events[1].recurrence_id.as_deref(),
            Some("2026-11-17T09:00:00Z")
        );
        assert_eq!(list.warnings, 0);
    }

    #[tokio::test]
    async fn list_events_tz_to_iana() {
        let (fake, provider) = setup().await;
        fake.put(
            "work",
            "berlin.ics",
            &vcalendar(
                "BEGIN:VEVENT\nUID:berlin-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART;TZID=Europe/Berlin:20261116T090000\n\
                 DTEND;TZID=Europe/Berlin:20261116T100000\nSUMMARY:Berlin\nEND:VEVENT",
            ),
        );
        fake.put(
            "work",
            "tokyo.ics",
            &vcalendar(
                "BEGIN:VTIMEZONE\nTZID:Custom-Tokyo\nX-LIC-LOCATION:Asia/Tokyo\n\
                 BEGIN:STANDARD\nDTSTART:19700101T000000\nTZOFFSETFROM:+0900\nTZOFFSETTO:+0900\nEND:STANDARD\n\
                 END:VTIMEZONE\n\
                 BEGIN:VEVENT\nUID:tokyo-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART;TZID=Custom-Tokyo:20261117T090000\n\
                 DTEND;TZID=Custom-Tokyo:20261117T100000\nSUMMARY:Tokyo\nEND:VEVENT",
            ),
        );
        let list = provider
            .list_events(&query("2026-11-16T00:00:00Z", "2026-11-19T00:00:00Z"))
            .await
            .expect("list events");
        let berlin = list
            .events
            .iter()
            .find(|e| e.uid == "berlin-1")
            .expect("berlin");
        assert_eq!(berlin.start, "2026-11-16T09:00:00+01:00");
        assert_eq!(berlin.time_zone.as_deref(), Some("Europe/Berlin"));
        let tokyo = list
            .events
            .iter()
            .find(|e| e.uid == "tokyo-1")
            .expect("tokyo");
        assert_eq!(tokyo.start, "2026-11-17T09:00:00+09:00");
        assert_eq!(
            tokyo.time_zone.as_deref(),
            Some("Asia/Tokyo"),
            "a custom TZID resolves to the IANA zone named in the VTIMEZONE"
        );
    }

    #[tokio::test]
    async fn list_events_skips_bad_item_with_warning() {
        let (fake, provider) = setup().await;
        fake.put("work", "broken.ics", "this is not an icalendar object");
        fake.put(
            "work",
            "good.ics",
            &vcalendar(
                "BEGIN:VEVENT\nUID:good-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART:20261116T090000Z\nDTEND:20261116T100000Z\nSUMMARY:Fine\nEND:VEVENT",
            ),
        );
        let list = provider
            .list_events(&query("2026-11-16T00:00:00Z", "2026-11-17T00:00:00Z"))
            .await
            .expect("one bad item does not fail the list");
        assert_eq!(list.events.len(), 1, "only the good event is listed");
        assert_eq!(list.events[0].summary, "Fine");
        assert_eq!(list.warnings, 1, "the bad item is counted");
    }

    #[tokio::test]
    async fn no_uid_calendar_query() {
        let (fake, provider) = setup().await;
        fake.put(
            "work",
            "one.ics",
            &vcalendar(
                "BEGIN:VEVENT\nUID:one-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART:20261116T090000Z\nDTEND:20261116T100000Z\nSUMMARY:One\nEND:VEVENT",
            ),
        );
        let list = provider
            .list_events(&query("2026-11-16T00:00:00Z", "2026-11-17T00:00:00Z"))
            .await
            .expect("list events");
        provider
            .get_event(&list.events[0].path)
            .await
            .expect("get by path");
        let reports: Vec<_> = fake
            .requests()
            .into_iter()
            .filter(|request| request.method == "REPORT")
            .collect();
        assert!(!reports.is_empty(), "listing sends a calendar-query");
        for report in &reports {
            assert!(report.body.contains("calendar-query"), "{}", report.body);
            assert!(
                report.body.contains("start=\"20261116T000000Z\""),
                "time-range is sent, got {}",
                report.body
            );
            assert!(
                !report.body.to_ascii_uppercase().contains("NAME=\"UID\""),
                "iCloud mishandles a UID filter, got {}",
                report.body
            );
        }
        let _ = ResourcePath::try_from("work/one.ics").expect("path shape");
    }

    const ALARM_EVENT: &str = "BEGIN:VEVENT\nUID:alarm-1\nDTSTAMP:20261101T000000Z\n\
        DTSTART:20261116T090000Z\nDTEND:20261116T100000Z\nSUMMARY:Review\n\
        ORGANIZER;CN=Ada:mailto:ada@icloud.com\n\
        ATTENDEE;CN=Grace;PARTSTAT=ACCEPTED:mailto:grace@icloud.com\n\
        X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC\n\
        BEGIN:VALARM\nACTION:DISPLAY\nDESCRIPTION:Reminder\nTRIGGER:-PT15M\nEND:VALARM\n\
        END:VEVENT";

    fn draft(summary: &str, start: &str, end: &str) -> EventDraft {
        EventDraft {
            summary: summary.to_owned(),
            description: String::new(),
            start: start.to_owned(),
            end: end.to_owned(),
            time_zone: None,
        }
    }

    fn work() -> ResourcePath {
        ResourcePath::try_from("work/").expect("collection path")
    }

    #[tokio::test]
    async fn create_always_writes_dtend() {
        let (fake, provider) = setup().await;
        let utc = provider
            .create_event(&work(), &draft("Lunch", "2026-11-16T12:00:00Z", ""))
            .await
            .expect("create without an end");
        let file = utc
            .as_str()
            .strip_prefix("work/")
            .expect("under the collection");
        let body = fake.body("work", file).expect("stored");
        assert!(
            body.contains("DTEND:20261116T130000Z"),
            "default end is an hour later: {body}"
        );
        assert!(body.contains("DTSTART:20261116T120000Z"), "{body}");
        assert!(body.contains("SUMMARY:Lunch"), "{body}");
        let put = fake
            .requests()
            .into_iter()
            .find(|request| request.method == "PUT")
            .expect("one PUT");
        assert_eq!(
            put.if_none_match.as_deref(),
            Some("*"),
            "create never overwrites"
        );

        let zoned = EventDraft {
            time_zone: Some("Europe/Berlin".to_owned()),
            ..draft("Berlin", "2026-11-16T09:00:00", "2026-11-16T10:30:00")
        };
        let path = provider
            .create_event(&work(), &zoned)
            .await
            .expect("create zoned");
        let body = fake
            .body("work", path.as_str().strip_prefix("work/").expect("prefix"))
            .expect("stored");
        assert!(
            body.contains("DTSTART;TZID=Europe/Berlin:20261116T090000"),
            "{body}"
        );
        assert!(
            body.contains("DTEND;TZID=Europe/Berlin:20261116T103000"),
            "{body}"
        );

        let day = provider
            .create_event(&work(), &draft("Offsite", "2026-11-20", ""))
            .await
            .expect("create all-day");
        let body = fake
            .body("work", day.as_str().strip_prefix("work/").expect("prefix"))
            .expect("stored");
        assert!(body.contains("DTSTART;VALUE=DATE:20261120"), "{body}");
        assert!(body.contains("DTEND;VALUE=DATE:20261121"), "{body}");
    }

    #[tokio::test]
    async fn update_requires_etag() {
        let (fake, provider) = setup().await;
        let etag = fake.put("work", "a.ics", &vcalendar(ALARM_EVENT));
        let path = ResourcePath::try_from("work/a.ics").expect("path");
        let stale = ETag::try_from("\"stale\"").expect("etag");
        let error = provider
            .update_event(
                &path,
                &stale,
                &draft("Changed", "2026-11-16T11:00:00Z", "2026-11-16T12:00:00Z"),
                &UpdateScope::Series,
            )
            .await
            .expect_err("a stale ETag is a conflict");
        assert_eq!(error, CoreError::Conflict);
        assert!(
            fake.body("work", "a.ics")
                .expect("stored")
                .contains("SUMMARY:Review"),
            "the stored event is untouched"
        );
        let fresh = ETag::try_from(etag.as_str()).expect("etag");
        provider
            .update_event(
                &path,
                &fresh,
                &draft("Changed", "2026-11-16T11:00:00Z", "2026-11-16T12:00:00Z"),
                &UpdateScope::Series,
            )
            .await
            .expect("matching ETag updates");
        let put = fake
            .requests()
            .into_iter()
            .rev()
            .find(|request| request.method == "PUT")
            .expect("a PUT was sent");
        assert_eq!(put.if_match.as_deref(), Some(etag.as_str()));
        assert!(
            fake.body("work", "a.ics")
                .expect("stored")
                .contains("SUMMARY:Changed")
        );
    }

    #[tokio::test]
    async fn update_single_occurrence_adds_recurrence_id() {
        let (fake, provider) = setup().await;
        let etag = fake.put(
            "work",
            "daily.ics",
            &vcalendar(
                "BEGIN:VEVENT\nUID:daily-1\nDTSTAMP:20261101T000000Z\n\
                 DTSTART:20261116T090000Z\nDTEND:20261116T100000Z\n\
                 RRULE:FREQ=DAILY;COUNT=3\nSUMMARY:Standup\nEND:VEVENT",
            ),
        );
        let path = ResourcePath::try_from("work/daily.ics").expect("path");
        provider
            .update_event(
                &path,
                &ETag::try_from(etag.as_str()).expect("etag"),
                &draft("Moved", "2026-11-17T10:00:00Z", "2026-11-17T11:00:00Z"),
                &UpdateScope::Occurrence {
                    recurrence_id: "2026-11-17T09:00:00Z".to_owned(),
                },
            )
            .await
            .expect("update one occurrence");
        let body = fake.body("work", "daily.ics").expect("stored");
        assert!(body.contains("RECURRENCE-ID:20261117T090000Z"), "{body}");
        assert!(
            body.contains("RRULE:FREQ=DAILY;COUNT=3"),
            "the series is kept: {body}"
        );
        assert!(
            body.contains("SUMMARY:Standup"),
            "the series name is kept: {body}"
        );
        let list = provider
            .list_events(&query("2026-11-16T00:00:00Z", "2026-11-20T00:00:00Z"))
            .await
            .expect("list");
        let summaries: Vec<(&str, &str)> = list
            .events
            .iter()
            .map(|e| (e.start.as_str(), e.summary.as_str()))
            .collect();
        assert_eq!(
            summaries,
            [
                ("2026-11-16T09:00:00Z", "Standup"),
                ("2026-11-17T10:00:00Z", "Moved"),
                ("2026-11-18T09:00:00Z", "Standup"),
            ]
        );
    }

    #[tokio::test]
    async fn delete_with_etag() {
        let (fake, provider) = setup().await;
        let etag = fake.put("work", "a.ics", &vcalendar(ALARM_EVENT));
        let path = ResourcePath::try_from("work/a.ics").expect("path");
        let error = provider
            .delete_event(&path, &ETag::try_from("\"stale\"").expect("etag"))
            .await
            .expect_err("stale ETag");
        assert_eq!(error, CoreError::Conflict);
        assert_eq!(fake.files("work"), ["a.ics"], "nothing was deleted");
        provider
            .delete_event(&path, &ETag::try_from(etag.as_str()).expect("etag"))
            .await
            .expect("matching ETag deletes");
        assert_eq!(fake.files("work"), Vec::<String>::new());
        let delete = fake
            .requests()
            .into_iter()
            .rev()
            .find(|request| request.method == "DELETE")
            .expect("a DELETE was sent");
        assert_eq!(delete.if_match.as_deref(), Some(etag.as_str()));
    }

    #[tokio::test]
    async fn update_event_preserves_alarms_and_x_props() {
        let (fake, provider) = setup().await;
        let etag = fake.put("work", "a.ics", &vcalendar(ALARM_EVENT));
        let path = ResourcePath::try_from("work/a.ics").expect("path");
        provider
            .update_event(
                &path,
                &ETag::try_from(etag.as_str()).expect("etag"),
                &draft("Changed", "2026-11-16T11:00:00Z", "2026-11-16T12:00:00Z"),
                &UpdateScope::Series,
            )
            .await
            .expect("update");
        let body = fake.body("work", "a.ics").expect("stored");
        for kept in [
            "BEGIN:VALARM",
            "TRIGGER:-PT15M",
            "X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC",
            "PARTSTAT=ACCEPTED",
            "mailto:grace@icloud.com",
            "ORGANIZER",
        ] {
            assert!(body.contains(kept), "lost {kept} in {body}");
        }
        assert!(body.contains("DTSTART:20261116T110000Z"), "{body}");
    }
}
