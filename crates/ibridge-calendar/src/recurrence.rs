// SPDX-License-Identifier: Apache-2.0

//! Client-side recurrence expansion and time formatting.
//!
//! iCloud's server-side `expand` is unreliable, so the provider asks for the
//! master events that overlap the range and expands them here.

use calcard::common::timezone::Tz;
use calcard::icalendar::dates::TimeOrDelta;
use calcard::icalendar::{ICalendar, ICalendarComponentType};

use crate::ical::Granularity;
use chrono::{DateTime, Offset, TimeZone, Utc};

/// Occurrences produced for one recurring event, and whether any rule failed.
const EXPANSION_LIMIT: usize = 3000;

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
}

/// Result of expanding one calendar object.
#[derive(Debug, Default)]
pub(crate) struct Expansion {
    pub(crate) occurrences: Vec<Occurrence>,
    /// Some component could not be expanded.
    pub(crate) had_errors: bool,
}

/// Expands every `VEVENT` in `ical` and keeps the occurrences that overlap `window`.
pub(crate) fn expand(ical: &ICalendar, window: Option<Window>) -> Expansion {
    let expanded = ical.expand_dates(Tz::Floating, EXPANSION_LIMIT);
    let mut result = Expansion {
        occurrences: Vec::new(),
        had_errors: !expanded.errors.is_empty(),
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
        });
    }
    result
        .occurrences
        .sort_by_key(|occurrence| occurrence.start.timestamp());
    result
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
