// SPDX-License-Identifier: Apache-2.0

//! Reading properties from parsed iCalendar objects.

use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarValue,
};

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
