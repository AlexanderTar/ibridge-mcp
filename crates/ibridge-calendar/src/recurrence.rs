// SPDX-License-Identifier: Apache-2.0

//! Client-side recurrence expansion and time formatting.
//!
//! iCloud's server-side `expand` is unreliable, so the provider asks for the
//! master events that overlap the range and expands them here.

use calcard::common::PartialDateTime;
use calcard::common::timezone::Tz;
use calcard::icalendar::dates::TimeOrDelta;
use calcard::icalendar::{ICalendar, ICalendarComponentType, ICalendarProperty, ICalendarValue};

use crate::ical::Granularity;
use chrono::{DateTime, Datelike, Offset, TimeZone, Timelike, Utc};

/// The most occurrences expanded from one calendar object. calcard counts from
/// the series' `DTSTART`, not from the window, so this has to cover every
/// occurrence between the two: about 22 years of an hourly rule.
// ponytail: a rule that fires more often than hourly for years passes the limit and is
// reported as a warning; the rule is only clipped at the window's end, never windowed.
const EXPANSION_LIMIT: usize = 200_000;

/// The most occurrences expanded when there is no window: enough to find the first.
const FIRST_EXPANSION_LIMIT: usize = 3000;

/// Days added after the window's end when an open-ended rule is clipped, so that
/// the difference between a series' zone and UTC never drops an occurrence.
const CLIP_SLACK_DAYS: i64 = 2;

/// A half-open range `[start, end)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    pub(crate) start: DateTime<Utc>,
    pub(crate) end: DateTime<Utc>,
}

/// One expanded occurrence of a `VEVENT`.
#[derive(Clone, Debug)]
pub(crate) struct Occurrence {
    /// Index of the component that supplies this occurrence's properties.
    pub(crate) component: usize,
    pub(crate) start: DateTime<Tz>,
    pub(crate) end: DateTime<Tz>,
    /// The `RECURRENCE-ID` of an overridden occurrence: the instance it replaces.
    pub(crate) recurrence_id: Option<DateTime<Tz>>,
}

/// Result of expanding one calendar object.
#[derive(Debug, Default)]
pub(crate) struct Expansion {
    pub(crate) occurrences: Vec<Occurrence>,
    /// Some component could not be expanded, or expansion stopped at the limit.
    pub(crate) had_errors: bool,
}

/// Expands every `VEVENT` in `ical` and keeps the occurrences that overlap `window`.
pub(crate) fn expand(ical: &ICalendar, window: Option<Window>) -> Expansion {
    let prepared = for_expansion(ical, window);
    let limit = if window.is_some() {
        EXPANSION_LIMIT
    } else {
        FIRST_EXPANSION_LIMIT
    };
    let expanded = prepared.expand_dates(Tz::Floating, limit);
    let resolver = ical.build_tz_resolver().with_default(Tz::Floating);
    let mut result = Expansion {
        occurrences: Vec::new(),
        // Stopping at the limit may have missed occurrences.
        had_errors: !expanded.errors.is_empty()
            || (expanded.events.len() >= limit && window.is_some()),
    };
    for event in expanded.events {
        let Some(component) = ical.components.get(usize_from(event.comp_id)) else {
            continue;
        };
        if component.component_type != ICalendarComponentType::VEvent {
            continue;
        }
        // calcard expands a recurring event in the zone named by TZID and
        // drops a trailing Z, so a UTC series comes back floating. Put it back.
        let zone = crate::ical::starts_in_utc(component).then_some(Tz::UTC);
        let start = restore_zone(event.start, zone);
        let end = match event.end {
            TimeOrDelta::Time(end) => restore_zone(end, zone),
            TimeOrDelta::Delta(delta) => start + delta,
        };
        if let Some(window) = window
            && !overlaps(&start, &end, window)
        {
            continue;
        }
        result.occurrences.push(Occurrence {
            component: usize_from(event.comp_id),
            start,
            end,
            recurrence_id: recurrence_id(component, &resolver),
        });
    }
    result
        .occurrences
        .sort_by_key(|occurrence| occurrence.start.timestamp());
    result
}

/// A copy of `ical` made ready for calcard: no `SEQUENCE`, and, when there is a
/// window, open-ended rules end just after it.
///
/// calcard only matches an override to its series when both have the same
/// `SEQUENCE`, but a series and its overrides are free to differ (iCloud and
/// this provider's own updates both do that). The clip keeps an open-ended rule
/// from being expanded all the way to the limit.
fn for_expansion(ical: &ICalendar, window: Option<Window>) -> ICalendar {
    let mut prepared = ical.clone();
    for component in &mut prepared.components {
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Sequence);
    }
    if let Some(window) = window {
        clip_open_rules(&mut prepared, window);
    }
    prepared
}

fn clip_open_rules(prepared: &mut ICalendar, window: Window) {
    let until = window.end + chrono::Duration::days(CLIP_SLACK_DAYS);
    for component in &mut prepared.components {
        for entry in &mut component.entries {
            if entry.name != ICalendarProperty::Rrule {
                continue;
            }
            for value in &mut entry.values {
                if let ICalendarValue::RecurrenceRule(rule) = value
                    && rule.until.is_none()
                    && rule.count.is_none()
                {
                    rule.until = Some(PartialDateTime {
                        year: u16::try_from(until.year()).ok(),
                        month: u8::try_from(until.month()).ok(),
                        day: u8::try_from(until.day()).ok(),
                        hour: u8::try_from(until.hour()).ok(),
                        minute: u8::try_from(until.minute()).ok(),
                        second: u8::try_from(until.second()).ok(),
                        tz_hour: Some(0),
                        tz_minute: Some(0),
                        tz_minus: false,
                    });
                }
            }
        }
    }
}

/// The component's own `RECURRENCE-ID`, read in its zone.
fn recurrence_id(
    component: &calcard::icalendar::ICalendarComponent,
    resolver: &calcard::icalendar::timezone::TzResolver<&str>,
) -> Option<DateTime<Tz>> {
    let entry = component.property(&calcard::icalendar::ICalendarProperty::RecurrenceId)?;
    let moment = entry
        .values
        .first()?
        .as_partial_date_time()?
        .to_date_time_with_tz(resolver.resolve_or_default(entry.tz_id()))?;
    Some(moment)
}

fn restore_zone(moment: DateTime<Tz>, zone: Option<Tz>) -> DateTime<Tz> {
    if let Some(zone) = zone
        && moment.timezone().is_floating()
        && let chrono::LocalResult::Single(fixed) = zone.from_local_datetime(&moment.naive_local())
    {
        return fixed;
    }
    moment
}

fn usize_from(id: u32) -> usize {
    usize::try_from(id).unwrap_or(usize::MAX)
}

fn overlaps(start: &DateTime<Tz>, end: &DateTime<Tz>, window: Window) -> bool {
    let (start, end) = (start.timestamp(), end.timestamp());
    let (from, to) = (window.start.timestamp(), window.end.timestamp());
    start < to && (end > from || start >= from)
}

/// ISO-8601 text for `moment`. A date for an all-day event, a floating time
/// without an offset, `Z` for UTC and `+HH:MM` otherwise.
pub(crate) fn format_instant(moment: &DateTime<Tz>, granularity: Granularity) -> String {
    let local = moment.naive_local();
    if granularity == Granularity::Date {
        return local.format("%Y-%m-%d").to_string();
    }
    let base = local.format("%Y-%m-%dT%H:%M:%S").to_string();
    let zone = moment.timezone();
    if zone.is_floating() {
        return base;
    }
    if zone.is_utc() {
        return format!("{base}Z");
    }
    let seconds = moment.offset().fix().local_minus_utc();
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.abs();
    format!(
        "{base}{sign}{:02}:{:02}",
        seconds / 3600,
        seconds % 3600 / 60
    )
}

/// IANA zone name of `moment`, when it has a named zone other than UTC.
pub(crate) fn zone_name(moment: &DateTime<Tz>) -> Option<String> {
    let zone = moment.timezone();
    if zone.is_floating() || zone.is_utc() {
        return None;
    }
    match zone {
        Tz::Tz(named) => Some(named.name().to_owned()),
        _ => None,
    }
}
