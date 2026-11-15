// SPDX-License-Identifier: Apache-2.0

//! Event reads and writes.

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
    reason = "list_calendars and the writes arrive in the next units"
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
        let text = std::str::from_utf8(&exchange.body).map_err(|_| protocol())?;
        let ical = ical::parse(text).ok_or_else(protocol)?;
        let occurrences = recurrence::expand(&ical, None).occurrences;
        let first = occurrences.first().ok_or_else(protocol)?;
        Ok(to_event(&ical, first, path.clone(), etag))
    }

    async fn create_event(
        &self,
        _calendar: &ResourcePath,
        _draft: &EventDraft,
    ) -> Result<ResourcePath, CoreError> {
        Err(CoreError::Unsupported("create_event"))
    }

    async fn update_event(
        &self,
        _path: &ResourcePath,
        _etag: &ETag,
        _draft: &EventDraft,
        _scope: &UpdateScope,
    ) -> Result<ETag, CoreError> {
        Err(CoreError::Unsupported("update_event"))
    }

    async fn delete_event(&self, _path: &ResourcePath, _etag: &ETag) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("delete_event"))
    }
}

impl CalDavProvider {
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
    use ibridge_core::{AppleId, CalendarProvider, EventQuery, ResourcePath};
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
}
