// SPDX-License-Identifier: Apache-2.0

//! Reading properties from parsed iCalendar objects.

use calcard::common::PartialDateTime;
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
    ICalendarProperty, ICalendarStatus, ICalendarValue, ICalendarValueType,
};
use chrono::{
    DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc,
};
use ibridge_core::{CoreError, EventDraft, ReminderDraft, UpdateScope};

/// Parses an iCalendar object. `None` when the text is not one.
pub(crate) fn parse(text: &str) -> Option<ICalendar> {
    ICalendar::parse(text).ok()
}

/// First text value of `property`.
pub(crate) fn text(component: &ICalendarComponent, property: &ICalendarProperty) -> Option<String> {
    component
        .property(property)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_text)
        .map(str::to_owned)
}

/// What an event's start and end carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Granularity {
    /// A calendar date, for an all-day event.
    Date,
    /// A time of day.
    Time,
}

/// `Date` when `DTSTART` is a date with no time.
pub(crate) fn granularity(component: &ICalendarComponent) -> Granularity {
    let date_only = component
        .property(&ICalendarProperty::Dtstart)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_partial_date_time)
        .is_some_and(|moment| !moment.has_time());
    if date_only {
        Granularity::Date
    } else {
        Granularity::Time
    }
}

/// `DTSTART` is written in UTC (a trailing `Z`).
pub(crate) fn starts_in_utc(component: &ICalendarComponent) -> bool {
    component
        .property(&ICalendarProperty::Dtstart)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_partial_date_time)
        .is_some_and(|moment| {
            moment.has_zone() && moment.tz_hour == Some(0) && moment.tz_minute.unwrap_or(0) == 0
        })
}

/// The event has a repeat rule, extra dates or is an override of a series.
pub(crate) fn is_recurring(component: &ICalendarComponent) -> bool {
    component.is_recurrent_or_override()
}

/// Attendee addresses without the `mailto:` scheme.
pub(crate) fn attendees(component: &ICalendarComponent) -> Vec<String> {
    component
        .properties(&ICalendarProperty::Attendee)
        .filter_map(|entry| entry.calendar_address().map(str::to_owned))
        .collect()
}

/// Alarm triggers of the component's `VALARM` children.
pub(crate) fn alarms(ical: &ICalendar, component: &ICalendarComponent) -> Vec<String> {
    component
        .component_ids
        .iter()
        .filter_map(|id| ical.components.get(usize::try_from(*id).ok()?))
        .filter(|child| child.component_type == ICalendarComponentType::VAlarm)
        .filter_map(|alarm| {
            alarm
                .property(&ICalendarProperty::Trigger)
                .and_then(|entry| entry.values.first())
                .and_then(|value| value.clone().into_text())
                .map(std::borrow::Cow::into_owned)
        })
        .collect()
}

/// A start or end as the draft gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum When {
    /// A calendar date, for an all-day event.
    Date(NaiveDate),
    /// A time of day in UTC.
    Utc(NaiveDateTime),
    /// A local time in a named IANA zone.
    Zoned(NaiveDateTime, String),
    /// A local time with no zone.
    Floating(NaiveDateTime),
}

impl When {
    fn naive(&self) -> NaiveDateTime {
        match self {
            Self::Date(date) => date.and_time(NaiveTime::MIN),
            Self::Utc(naive) | Self::Zoned(naive, _) | Self::Floating(naive) => *naive,
        }
    }

    fn is_date(&self) -> bool {
        matches!(self, Self::Date(_))
    }

    /// The same kind of moment, `delta` later.
    fn plus(&self, delta: Duration) -> Self {
        match self {
            Self::Date(date) => Self::Date(*date + delta),
            Self::Utc(naive) => Self::Utc(*naive + delta),
            Self::Zoned(naive, zone) => Self::Zoned(*naive + delta, zone.clone()),
            Self::Floating(naive) => Self::Floating(*naive + delta),
        }
    }

    /// The iCalendar property that carries this moment.
    fn entry(&self, property: ICalendarProperty) -> ICalendarEntry {
        let entry = ICalendarEntry::new(property);
        match self {
            Self::Date(date) => entry
                .with_param(ICalendarParameter::value(ICalendarValueType::Date))
                .with_value(ICalendarValue::PartialDateTime(Box::new(partial(
                    date.and_time(NaiveTime::MIN),
                    Part::Date,
                )))),
            Self::Utc(naive) => entry.with_value(ICalendarValue::PartialDateTime(Box::new(
                partial(*naive, Part::UtcTime),
            ))),
            Self::Zoned(naive, zone) => entry
                .with_param(ICalendarParameter::tzid(zone.clone()))
                .with_value(ICalendarValue::PartialDateTime(Box::new(partial(
                    *naive,
                    Part::LocalTime,
                )))),
            Self::Floating(naive) => entry.with_value(ICalendarValue::PartialDateTime(Box::new(
                partial(*naive, Part::LocalTime),
            ))),
        }
    }
}

#[derive(Clone, Copy)]
enum Part {
    Date,
    LocalTime,
    UtcTime,
}

fn partial(naive: NaiveDateTime, part: Part) -> PartialDateTime {
    let mut moment = PartialDateTime {
        year: u16::try_from(naive.year()).ok(),
        month: u8::try_from(naive.month()).ok(),
        day: u8::try_from(naive.day()).ok(),
        ..PartialDateTime::default()
    };
    if !matches!(part, Part::Date) {
        moment.hour = u8::try_from(naive.hour()).ok();
        moment.minute = u8::try_from(naive.minute()).ok();
        moment.second = u8::try_from(naive.second()).ok();
    }
    if matches!(part, Part::UtcTime) {
        moment.tz_hour = Some(0);
        moment.tz_minute = Some(0);
    }
    moment
}

fn invalid(message: &str) -> CoreError {
    CoreError::InvalidInput(message.to_owned())
}

/// Reads `text` as a date, or a time in `zone` (UTC when there is none).
///
/// A timestamp with an offset is the same instant converted into `zone`.
fn parse_when(text: &str, zone: Option<&str>) -> Result<When, CoreError> {
    let text = text.trim();
    let zone: Option<chrono_tz::Tz> = zone
        .map(|name| {
            name.parse()
                .map_err(|_| CoreError::InvalidInput(format!("'{name}' is not an IANA time zone")))
        })
        .transpose()?;
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Ok(When::Date(date));
    }
    if let Ok(instant) = DateTime::parse_from_rfc3339(text) {
        return Ok(match zone {
            Some(zone) => When::Zoned(
                instant.with_timezone(&zone).naive_local(),
                zone.name().to_owned(),
            ),
            None => When::Utc(instant.naive_utc()),
        });
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Ok(match zone {
            Some(zone) => When::Zoned(naive, zone.name().to_owned()),
            None => When::Utc(naive),
        });
    }
    Err(CoreError::InvalidInput(format!(
        "'{text}' is not an ISO-8601 date or timestamp"
    )))
}

/// Start and end for a draft. A missing end is an hour later, or a day later
/// for a date: iCloud needs `DTEND`, so it is always written.
fn draft_times(draft: &EventDraft) -> Result<(When, When), CoreError> {
    let zone = draft.time_zone.as_deref();
    let start = parse_when(&draft.start, zone)?;
    let end = if draft.end.trim().is_empty() {
        start.plus(if start.is_date() {
            Duration::days(1)
        } else {
            Duration::hours(1)
        })
    } else {
        parse_when(&draft.end, zone)?
    };
    if start.is_date() != end.is_date() {
        return Err(invalid("start and end must both be dates or both be times"));
    }
    if end.naive() <= start.naive() {
        return Err(invalid("the end must be after the start"));
    }
    Ok((start, end))
}

fn text_entry(property: ICalendarProperty, value: &str) -> ICalendarEntry {
    ICalendarEntry::new(property).with_value(ICalendarValue::Text(value.to_owned()))
}

/// New `VCALENDAR` text for one event. Always writes `DTEND`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] when a time or zone cannot be read, or
/// the end is not after the start.
pub(crate) fn new_event_text(
    uid: &str,
    now: DateTime<Utc>,
    draft: &EventDraft,
) -> Result<String, CoreError> {
    let (start, end) = draft_times(draft)?;
    let mut root = ICalendarComponent::new(ICalendarComponentType::VCalendar);
    root.entries
        .push(text_entry(ICalendarProperty::Version, "2.0"));
    root.entries.push(text_entry(
        ICalendarProperty::Prodid,
        "-//ibridge//calendar//EN",
    ));
    root.component_ids.push(1);
    let mut event = ICalendarComponent::new(ICalendarComponentType::VEvent);
    event.add_uid(uid);
    event.add_dtstamp(partial(now.naive_utc(), Part::UtcTime));
    event.entries.push(start.entry(ICalendarProperty::Dtstart));
    event.entries.push(end.entry(ICalendarProperty::Dtend));
    event
        .entries
        .push(text_entry(ICalendarProperty::Summary, &draft.summary));
    if let Some(description) = draft.description.as_deref().filter(|text| !text.is_empty()) {
        event
            .entries
            .push(text_entry(ICalendarProperty::Description, description));
    }
    let mut ical = ICalendar {
        components: vec![root, event],
    };
    ical.add_missing_timezones();
    Ok(ical.to_string())
}

/// Applies `draft` to the event in `text` and returns the new text.
///
/// Only the summary, description, start and end change, plus `DTSTAMP` and, when
/// the time moves, `SEQUENCE`. Every other property, alarm and attendee is left
/// as it was.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] when a time or zone cannot be read and
/// [`CoreError::Protocol`] when `text` holds no event.
pub(crate) fn update_event_text(
    text: &str,
    draft: &EventDraft,
    scope: &UpdateScope,
    now: DateTime<Utc>,
) -> Result<String, CoreError> {
    let mut ical = parse(text).ok_or_else(|| CoreError::Protocol(String::new()))?;
    let master = ical
        .components
        .iter()
        .position(|component| {
            component.component_type == ICalendarComponentType::VEvent
                && !component.has_property(&ICalendarProperty::RecurrenceId)
        })
        .ok_or_else(|| CoreError::Protocol(String::new()))?;
    let target = match scope {
        UpdateScope::Series => master,
        UpdateScope::Occurrence { recurrence_id } => {
            occurrence_component(&mut ical, master, recurrence_id)?
        }
        _ => return Err(CoreError::Unsupported("update scope")),
    };
    let component = &mut ical.components[target];
    let times = update_times(component, draft)?;
    let before = moments(component);
    apply(component, draft, times.as_ref());
    mark_changed(component, &before, now);
    ical.add_missing_timezones();
    Ok(ical.to_string())
}

/// The properties that place a component in time.
fn moments(component: &ICalendarComponent) -> Vec<ICalendarEntry> {
    component
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.name,
                ICalendarProperty::Dtstart
                    | ICalendarProperty::Dtend
                    | ICalendarProperty::Duration
                    | ICalendarProperty::Due
            )
        })
        .cloned()
        .collect()
}

/// Stamps `component` as changed at `now`. A changed time also raises
/// `SEQUENCE`, which is how attendees' clients order updates (RFC 5545 3.8.7.4).
fn mark_changed(component: &mut ICalendarComponent, before: &[ICalendarEntry], now: DateTime<Utc>) {
    component
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Dtstamp);
    component.add_dtstamp(partial(now.naive_utc(), Part::UtcTime));
    if before == moments(component) {
        return;
    }
    let current = component
        .property(&ICalendarProperty::Sequence)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::Integer(number) => Some(*number),
            _ => None,
        })
        .unwrap_or(0);
    component
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Sequence);
    component.entries.push(
        ICalendarEntry::new(ICalendarProperty::Sequence)
            .with_value(ICalendarValue::Integer(current + 1)),
    );
}

/// The start and end an update writes, or `None` when it names neither and the
/// event keeps its own. A bare local time is read in the zone the event is in.
fn update_times(
    component: &ICalendarComponent,
    draft: &EventDraft,
) -> Result<Option<(When, When)>, CoreError> {
    match (draft.start.trim().is_empty(), draft.end.trim().is_empty()) {
        (true, true) => return Ok(None),
        (false, false) => {}
        _ => return Err(invalid("give both a start and an end, or neither")),
    }
    let own_zone = component
        .property(&ICalendarProperty::Dtstart)
        .and_then(ICalendarEntry::tz_id)
        .filter(|name| name.parse::<chrono_tz::Tz>().is_ok());
    let draft = EventDraft {
        time_zone: draft
            .time_zone
            .clone()
            .or_else(|| own_zone.map(str::to_owned)),
        ..draft.clone()
    };
    draft_times(&draft).map(Some)
}

fn apply(component: &mut ICalendarComponent, draft: &EventDraft, times: Option<&(When, When)>) {
    if !draft.summary.is_empty() {
        set_text(component, &ICalendarProperty::Summary, Some(&draft.summary));
    }
    if let Some(description) = &draft.description {
        let description = Some(description.as_str()).filter(|text| !text.is_empty());
        set_text(component, &ICalendarProperty::Description, description);
    }
    let Some((start, end)) = times else {
        return;
    };
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Dtstart | ICalendarProperty::Dtend | ICalendarProperty::Duration
        )
    });
    component
        .entries
        .push(start.entry(ICalendarProperty::Dtstart));
    component.entries.push(end.entry(ICalendarProperty::Dtend));
}

/// Replaces the first value of `property` and keeps its parameters. `None`
/// removes the property.
fn set_text(component: &mut ICalendarComponent, property: &ICalendarProperty, value: Option<&str>) {
    let Some(value) = value else {
        component.entries.retain(|entry| &entry.name != property);
        return;
    };
    match component.property_mut(property) {
        Some(entry) => entry.values = vec![ICalendarValue::Text(value.to_owned())],
        None => component.entries.push(text_entry(property.clone(), value)),
    }
}

/// Index of the component that overrides the occurrence at `recurrence_id`,
/// created from the master when the series has none yet.
fn occurrence_component(
    ical: &mut ICalendar,
    master: usize,
    recurrence_id: &str,
) -> Result<usize, CoreError> {
    let id_entry = recurrence_entry(&ical.components[master], recurrence_id)?;
    let existing = ical.components.iter().position(|component| {
        component.component_type == ICalendarComponentType::VEvent
            && component
                .property(&ICalendarProperty::RecurrenceId)
                .is_some_and(|entry| entry.values == id_entry.values)
    });
    if let Some(existing) = existing {
        return Ok(existing);
    }
    let template = ical.components[master].clone();
    let mut copy = ICalendarComponent::new(ICalendarComponentType::VEvent);
    copy.entries = template
        .entries
        .into_iter()
        .filter(|entry| {
            !matches!(
                entry.name,
                ICalendarProperty::Rrule
                    | ICalendarProperty::Exrule
                    | ICalendarProperty::Rdate
                    | ICalendarProperty::Exdate
                    | ICalendarProperty::RecurrenceId
            )
        })
        .collect();
    copy.entries.push(id_entry);
    for alarm in template.component_ids {
        let Some(alarm) = usize::try_from(alarm)
            .ok()
            .and_then(|index| ical.components.get(index))
            .cloned()
        else {
            continue;
        };
        copy.component_ids.push(next_id(ical.components.len()));
        ical.components.push(alarm);
    }
    let index = ical.components.len();
    ical.components.push(copy);
    ical.components[0].component_ids.push(next_id(index));
    Ok(index)
}

fn next_id(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

/// The `RECURRENCE-ID` entry for `text`, written in the master's own form
/// (date, UTC or zone) so that it matches the series' `DTSTART`.
fn recurrence_entry(master: &ICalendarComponent, text: &str) -> Result<ICalendarEntry, CoreError> {
    let dtstart = master
        .property(&ICalendarProperty::Dtstart)
        .ok_or_else(|| CoreError::Protocol(String::new()))?;
    if let Some(zone) = dtstart.tz_id() {
        return Ok(zoned_text(text, zone)?.entry(ICalendarProperty::RecurrenceId));
    }
    let moment = dtstart
        .values
        .first()
        .and_then(ICalendarValue::as_partial_date_time);
    let when = match moment {
        Some(moment) if !moment.has_time() => match parse_when(text, None)? {
            When::Utc(naive) | When::Zoned(naive, _) | When::Floating(naive) => {
                When::Date(naive.date())
            }
            date @ When::Date(_) => date,
        },
        Some(moment) if moment.has_zone() => parse_when(text, None)?,
        _ => floating_text(text)?,
    };
    Ok(when.entry(ICalendarProperty::RecurrenceId))
}

/// Local time named by the series' own `TZID`, which may not be an IANA name.
fn zoned_text(text: &str, zone: &str) -> Result<When, CoreError> {
    let local = match DateTime::parse_from_rfc3339(text.trim()) {
        Ok(instant) => match zone.parse::<chrono_tz::Tz>() {
            Ok(iana) => instant.with_timezone(&iana).naive_local(),
            Err(_) => instant.naive_local(),
        },
        Err(_) => floating_text(text)?.naive(),
    };
    Ok(When::Zoned(local, zone.to_owned()))
}

fn floating_text(text: &str) -> Result<When, CoreError> {
    let text = text.trim();
    DateTime::parse_from_rfc3339(text)
        .map(|instant| instant.naive_local())
        .or_else(|_| NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S"))
        .map(When::Floating)
        .map_err(|_| CoreError::InvalidInput(format!("'{text}' is not an ISO-8601 timestamp")))
}

/// What the reminders API shows of a `VTODO`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TodoFields {
    pub(crate) title: String,
    pub(crate) notes: String,
    pub(crate) due: Option<String>,
    pub(crate) priority: Option<u8>,
    pub(crate) completed: bool,
}

/// The first `VTODO` of `ical`, or `None` when it holds no reminder.
pub(crate) fn read_todo(ical: &ICalendar) -> Option<TodoFields> {
    let todo = ical
        .components
        .iter()
        .find(|component| component.component_type == ICalendarComponentType::VTodo)?;
    let priority = todo
        .property(&ICalendarProperty::Priority)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::Integer(number) => u8::try_from(*number).ok(),
            _ => None,
        });
    Some(TodoFields {
        title: text(todo, &ICalendarProperty::Summary).unwrap_or_default(),
        notes: text(todo, &ICalendarProperty::Description).unwrap_or_default(),
        due: todo.property(&ICalendarProperty::Due).and_then(due_text),
        priority,
        completed: is_completed(todo),
    })
}

fn is_completed(todo: &ICalendarComponent) -> bool {
    todo.has_property(&ICalendarProperty::Completed)
        || text(todo, &ICalendarProperty::Status)
            .is_some_and(|s| s.eq_ignore_ascii_case("COMPLETED"))
}

/// ISO-8601 text for a `DUE` value: a date, `Z` for UTC, an offset for a
/// named zone and a bare local time for a floating one.
fn due_text(entry: &ICalendarEntry) -> Option<String> {
    let moment = entry.values.first()?.as_partial_date_time()?;
    let date = NaiveDate::from_ymd_opt(
        i32::from(moment.year?),
        u32::from(moment.month?),
        u32::from(moment.day?),
    )?;
    if !moment.has_time() {
        return Some(date.format("%Y-%m-%d").to_string());
    }
    let naive = date.and_hms_opt(
        u32::from(moment.hour?),
        u32::from(moment.minute?),
        u32::from(moment.second.unwrap_or(0)),
    )?;
    if moment.has_zone() {
        return Some(naive.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    let local = naive.format("%Y-%m-%dT%H:%M:%S");
    let zoned = entry
        .tz_id()
        .and_then(|name| name.parse::<chrono_tz::Tz>().ok())
        .and_then(|zone| zone.from_local_datetime(&naive).single());
    Some(match zoned {
        Some(zoned) => zoned.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        None => local.to_string(),
    })
}

/// New `VCALENDAR` text for one reminder.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] when the due date cannot be read or the
/// priority is outside 1 to 9.
pub(crate) fn new_todo_text(
    uid: &str,
    now: DateTime<Utc>,
    draft: &ReminderDraft,
) -> Result<String, CoreError> {
    let mut root = ICalendarComponent::new(ICalendarComponentType::VCalendar);
    root.entries
        .push(text_entry(ICalendarProperty::Version, "2.0"));
    root.entries.push(text_entry(
        ICalendarProperty::Prodid,
        "-//ibridge//calendar//EN",
    ));
    root.component_ids.push(1);
    let mut todo = ICalendarComponent::new(ICalendarComponentType::VTodo);
    todo.add_uid(uid);
    todo.add_dtstamp(partial(now.naive_utc(), Part::UtcTime));
    apply_todo(&mut todo, draft, now)?;
    Ok(ICalendar {
        components: vec![root, todo],
    }
    .to_string())
}

/// Applies `draft` to the reminder in `text` and returns the new text. Other
/// properties are left as they were.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] for an unreadable due date or priority
/// and [`CoreError::Protocol`] when `text` holds no reminder.
pub(crate) fn update_todo_text(
    text: &str,
    draft: &ReminderDraft,
    now: DateTime<Utc>,
) -> Result<String, CoreError> {
    let mut ical = parse(text).ok_or_else(|| CoreError::Protocol(String::new()))?;
    let todo = ical
        .components
        .iter_mut()
        .find(|component| component.component_type == ICalendarComponentType::VTodo)
        .ok_or_else(|| CoreError::Protocol(String::new()))?;
    let before = moments(todo);
    apply_todo(todo, draft, now)?;
    mark_changed(todo, &before, now);
    Ok(ical.to_string())
}

fn apply_todo(
    todo: &mut ICalendarComponent,
    draft: &ReminderDraft,
    now: DateTime<Utc>,
) -> Result<(), CoreError> {
    let due = draft
        .due
        .as_deref()
        .map(|text| parse_when(text, None))
        .transpose()?;
    if draft
        .priority
        .is_some_and(|priority| !(1..=9).contains(&priority))
    {
        return Err(invalid("priority is from 1 (highest) to 9"));
    }
    set_text(todo, &ICalendarProperty::Summary, Some(&draft.title));
    let notes = Some(draft.notes.as_str()).filter(|text| !text.is_empty());
    set_text(todo, &ICalendarProperty::Description, notes);
    todo.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Due | ICalendarProperty::Priority
        )
    });
    if let Some(due) = due {
        todo.entries.push(due.entry(ICalendarProperty::Due));
    }
    if let Some(priority) = draft.priority {
        todo.entries.push(
            ICalendarEntry::new(ICalendarProperty::Priority)
                .with_value(ICalendarValue::Integer(i64::from(priority))),
        );
    }
    let was_completed = is_completed(todo);
    if draft.completed && !was_completed {
        set_status(todo, ICalendarStatus::Completed);
        todo.entries.push(
            ICalendarEntry::new(ICalendarProperty::Completed).with_value(
                ICalendarValue::PartialDateTime(Box::new(partial(now.naive_utc(), Part::UtcTime))),
            ),
        );
        set_percent(todo, Some(100));
    } else if !draft.completed && was_completed {
        set_status(todo, ICalendarStatus::NeedsAction);
        todo.entries
            .retain(|entry| entry.name != ICalendarProperty::Completed);
        set_percent(todo, None);
    } else if !draft.completed && !todo.has_property(&ICalendarProperty::Status) {
        set_status(todo, ICalendarStatus::NeedsAction);
    }
    Ok(())
}

fn set_status(todo: &mut ICalendarComponent, status: ICalendarStatus) {
    todo.entries
        .retain(|entry| entry.name != ICalendarProperty::Status);
    todo.entries.push(
        ICalendarEntry::new(ICalendarProperty::Status).with_value(ICalendarValue::Status(status)),
    );
}

fn set_percent(todo: &mut ICalendarComponent, percent: Option<i64>) {
    todo.entries
        .retain(|entry| entry.name != ICalendarProperty::PercentComplete);
    if let Some(percent) = percent {
        todo.entries.push(
            ICalendarEntry::new(ICalendarProperty::PercentComplete)
                .with_value(ICalendarValue::Integer(percent)),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use ibridge_core::{EventDraft, UpdateScope};
    use proptest::prelude::*;

    use super::{parse, update_event_text};

    const BASE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//other//app//EN\r\n\
        BEGIN:VEVENT\r\nUID:rt-1\r\nDTSTAMP:20261101T000000Z\r\n\
        DTSTART:20261116T090000Z\r\nDTEND:20261116T100000Z\r\nSUMMARY:Before\r\n";

    fn draft(summary: &str) -> EventDraft {
        EventDraft {
            summary: summary.to_owned(),
            description: None,
            start: "2026-11-16T11:00:00Z".to_owned(),
            end: "2026-11-16T12:00:00Z".to_owned(),
            time_zone: None,
        }
    }

    proptest! {
        #[test]
        fn ical_roundtrip_preserves_unknown(
            names in proptest::collection::btree_set("[A-Z]{3,8}", 1..5),
            value in "[A-Za-z0-9 ]{1,24}",
            partstat in prop_oneof![Just("ACCEPTED"), Just("TENTATIVE"), Just("DECLINED")],
        ) {
            let mut text = BASE.to_owned();
            for name in &names {
                write!(text, "X-IBR-{name}:{value}\r\n").expect("write to string");
            }
            write!(
                text,
                "ATTENDEE;CN=Grace;PARTSTAT={partstat}:mailto:grace@icloud.com\r\n\
                 BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n\
                 END:VEVENT\r\nEND:VCALENDAR\r\n"
            )
            .expect("write to string");
            let updated = update_event_text(&text, &draft("After"), &UpdateScope::Series, chrono::Utc::now())
                .expect("update applies");
            let reparsed = parse(&updated).expect("the result is still an iCalendar object");
            let flat = reparsed.to_string();
            for name in &names {
                let line = format!("X-IBR-{name}:{value}");
                prop_assert!(flat.contains(&line), "lost {line} in {flat}");
            }
            prop_assert!(flat.contains("SUMMARY:After"), "{flat}");
            prop_assert!(flat.contains("BEGIN:VALARM") && flat.contains("TRIGGER:-PT15M"), "{flat}");
            prop_assert!(flat.contains("mailto:grace@icloud.com"), "{flat}");
            prop_assert!(flat.contains(&format!("PARTSTAT={partstat}")), "{flat}");
            prop_assert!(flat.contains("DTSTART:20261116T110000Z"), "{flat}");
        }
    }
}
