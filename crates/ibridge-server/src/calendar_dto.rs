// SPDX-License-Identifier: Apache-2.0

//! Calendar and reminders tool arguments and structured results.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_page_limit() -> u32 {
    25
}

/// Arguments for `calendar_list_events`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListEventsParams {
    /// Calendar ids from `calendar_list_calendars`. Omit for every calendar that holds events.
    #[serde(default)]
    pub calendars: Vec<String>,
    /// Start of the range, as an ISO-8601 date or timestamp. Included.
    pub start: String,
    /// End of the range, as an ISO-8601 date or timestamp. Excluded.
    pub end: String,
    /// Page size. Omitted means 25. More than 100 is rejected.
    #[serde(default = "default_page_limit")]
    pub limit: u32,
    /// Cursor from the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Arguments for `calendar_get_event`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GetByIdParams {
    /// Opaque id from a list result.
    pub id: String,
}

/// Arguments for `calendar_create_event`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CreateEventParams {
    /// Calendar id from `calendar_list_calendars`. It must hold events.
    pub calendar: String,
    /// Title of the event.
    pub summary: String,
    /// Notes.
    #[serde(default)]
    pub description: Option<String>,
    /// Start: an ISO-8601 date for an all-day event, otherwise a timestamp.
    pub start: String,
    /// End. Omit for one hour after the start, or one day for an all-day event.
    #[serde(default)]
    pub end: Option<String>,
    /// IANA time zone name, such as Europe/Berlin. Omit for UTC.
    #[serde(default)]
    pub time_zone: Option<String>,
}

/// Arguments for `calendar_update_event`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UpdateEventParams {
    /// Opaque event id.
    pub id: String,
    /// The `etag` from the last read. A different one means the event changed.
    pub etag: String,
    /// New title. Omit to keep it.
    #[serde(default)]
    pub summary: Option<String>,
    /// New notes. Omit to keep them.
    #[serde(default)]
    pub description: Option<String>,
    /// New start. Omit to keep it.
    #[serde(default)]
    pub start: Option<String>,
    /// New end. Omit to keep it.
    #[serde(default)]
    pub end: Option<String>,
    /// IANA time zone for the new times. Omit to keep the event's zone.
    #[serde(default)]
    pub time_zone: Option<String>,
    /// For a repeating event: the `recurrence_id` of one occurrence to change on its own.
    /// Omit to change the whole series. Changing one occurrence needs `start` and `end`.
    #[serde(default)]
    pub occurrence: Option<String>,
}

/// Arguments for the delete tools.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DeleteParams {
    /// Opaque id.
    pub id: String,
    /// The `etag` from the last read.
    pub etag: String,
}

/// Arguments for `reminders_list`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListRemindersParams {
    /// List id from `reminders_list_lists`. Omit for every list.
    #[serde(default)]
    pub list: Option<String>,
    /// Also return completed reminders. Omitted means open reminders only.
    #[serde(default)]
    pub include_completed: Option<bool>,
    /// Page size. Omitted means 25. More than 100 is rejected.
    #[serde(default = "default_page_limit")]
    pub limit: u32,
    /// Cursor from the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Arguments for `reminders_create`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CreateReminderParams {
    /// List id from `reminders_list_lists`.
    pub list: String,
    /// Title.
    pub title: String,
    /// Notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// Due date or timestamp, ISO-8601.
    #[serde(default)]
    pub due: Option<String>,
    /// Priority from 1 (highest) to 9.
    #[serde(default)]
    pub priority: Option<u8>,
}

/// Arguments for `reminders_update`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UpdateReminderParams {
    /// Opaque reminder id.
    pub id: String,
    /// The `etag` from the last read.
    pub etag: String,
    /// New title. Omit to keep it.
    #[serde(default)]
    pub title: Option<String>,
    /// New notes. Omit to keep them.
    #[serde(default)]
    pub notes: Option<String>,
    /// New due date. Omit to keep it; an empty string removes it.
    #[serde(default)]
    pub due: Option<String>,
    /// New priority, 1 to 9. Omit to keep it; 0 removes it.
    #[serde(default)]
    pub priority: Option<u8>,
    /// Mark completed or open. Omit to keep it.
    #[serde(default)]
    pub completed: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct CalendarOut {
    pub(crate) id: String,
    /// Untrusted content.
    pub(crate) name: String,
    /// `events`, `tasks` or `both`.
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct CalendarListOut {
    pub(crate) calendars: Vec<CalendarOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct EventOut {
    pub(crate) id: String,
    pub(crate) etag: String,
    pub(crate) uid: String,
    /// Untrusted content.
    pub(crate) summary: String,
    /// Untrusted content.
    pub(crate) description: String,
    pub(crate) start: String,
    pub(crate) end: String,
    pub(crate) time_zone: Option<String>,
    pub(crate) all_day: bool,
    pub(crate) recurring: bool,
    /// Pass as `occurrence` to change only this occurrence.
    pub(crate) recurrence_id: Option<String>,
    /// Untrusted content.
    pub(crate) attendees: Vec<String>,
    pub(crate) alarms: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct EventListOut {
    pub(crate) events: Vec<EventOut>,
    pub(crate) next_cursor: Option<String>,
    /// Items that could not be read and were skipped.
    pub(crate) warnings: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct WriteOut {
    pub(crate) id: String,
    /// The new `etag`, when the write returned one.
    pub(crate) etag: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct DeleteOut {
    pub(crate) deleted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ReminderListOut {
    pub(crate) id: String,
    /// Untrusted content.
    pub(crate) name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ReminderListsOut {
    pub(crate) lists: Vec<ReminderListOut>,
    /// Says that lists the Reminders app upgraded are not reachable.
    pub(crate) note: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ReminderOut {
    pub(crate) id: String,
    pub(crate) etag: String,
    /// Untrusted content.
    pub(crate) title: String,
    /// Untrusted content.
    pub(crate) notes: String,
    pub(crate) due: Option<String>,
    pub(crate) priority: Option<u8>,
    pub(crate) completed: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct RemindersOut {
    pub(crate) reminders: Vec<ReminderOut>,
    pub(crate) next_cursor: Option<String>,
    /// Items that could not be read and were skipped.
    pub(crate) warnings: u32,
}
