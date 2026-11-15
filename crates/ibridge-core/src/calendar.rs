// SPDX-License-Identifier: Apache-2.0

//! Calendar and reminders values and provider traits.

use crate::error::CoreError;
use crate::ids::{ETag, ResourcePath};

/// A calendar collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Calendar {
    /// Path relative to the account's calendar home.
    pub path: ResourcePath,
    /// Display name.
    pub name: String,
    /// The collection holds events.
    pub holds_events: bool,
    /// The collection holds tasks (reminders).
    pub holds_tasks: bool,
}

/// A time range over one or more calendars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventQuery {
    /// Calendars to read. Empty means every calendar.
    pub calendars: Vec<ResourcePath>,
    /// Inclusive range start, as an ISO-8601 timestamp.
    pub start: String,
    /// Exclusive range end, as an ISO-8601 timestamp.
    pub end: String,
}

/// One event, or one expanded occurrence of a recurring event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Path relative to the calendar home.
    pub path: ResourcePath,
    /// `ETag` for a conditional write.
    pub etag: ETag,
    /// The iCalendar `UID`.
    pub uid: String,
    /// Summary. Untrusted content.
    pub summary: String,
    /// Description. Untrusted content.
    pub description: String,
    /// Start, as an ISO-8601 timestamp.
    pub start: String,
    /// End, as an ISO-8601 timestamp.
    pub end: String,
    /// IANA zone name of the start, when the event has a named zone.
    pub time_zone: Option<String>,
    /// The event covers whole days.
    pub all_day: bool,
    /// The event repeats. Each expanded occurrence carries the same path.
    pub recurring: bool,
    /// Original start of this occurrence, as an ISO-8601 timestamp, for a
    /// recurring event. Pass it back to change only this occurrence.
    pub recurrence_id: Option<String>,
    /// Attendee addresses. Untrusted content.
    pub attendees: Vec<String>,
    /// Alarm triggers, such as `-PT15M`.
    pub alarms: Vec<String>,
}

/// Events from a query, with a count of items that were skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventList {
    /// Occurrences in start order.
    pub events: Vec<Event>,
    /// Items that could not be read and were left out.
    pub warnings: u32,
}

/// Fields written by create and update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDraft {
    /// Summary.
    pub summary: String,
    /// Description.
    pub description: String,
    /// Start, as an ISO-8601 timestamp.
    pub start: String,
    /// End, as an ISO-8601 timestamp. Writers always store this.
    pub end: String,
    /// IANA zone name for `start` and `end`. `None` writes UTC or a date.
    pub time_zone: Option<String>,
}

/// Which part of a recurring event an update changes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateScope {
    /// The whole event, or the whole series.
    Series,
    /// One occurrence, named by its original start.
    Occurrence {
        /// The occurrence's [`Event::recurrence_id`].
        recurrence_id: String,
    },
}

/// Calendar read and write operations.
#[trait_variant::make(Send)]
pub trait CalendarProvider {
    /// Lists calendars.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the calendar home cannot be read.
    async fn list_calendars(&self) -> Result<Vec<Calendar>, CoreError>;

    /// Lists events in a time range.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the query cannot be run.
    async fn list_events(&self, query: &EventQuery) -> Result<EventList, CoreError>;

    /// Fetches one event.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the event cannot be read.
    async fn get_event(&self, path: &ResourcePath) -> Result<Event, CoreError>;

    /// Creates an event.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the event cannot be written.
    async fn create_event(
        &self,
        calendar: &ResourcePath,
        draft: &EventDraft,
    ) -> Result<ResourcePath, CoreError>;

    /// Changes an event when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn update_event(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &EventDraft,
        scope: &UpdateScope,
    ) -> Result<ETag, CoreError>;

    /// Deletes an event when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn delete_event(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError>;
}

/// A reminders list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReminderList {
    /// Path relative to the calendar home.
    pub path: ResourcePath,
    /// Display name.
    pub name: String,
}

/// Shown with the reminder lists: iCloud's `CalDAV` does not expose lists the
/// Reminders app has upgraded, so they are missing from the result.
pub const UPGRADED_LISTS_NOTE: &str = "Only old-style reminder lists are shown. Lists that the Reminders app upgraded to the newer format can't be reached through iCloud's calendar service, so they are missing here and can't be read or changed.";

/// Whether completed reminders are included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompletedFilter {
    /// Open and completed reminders.
    All,
    /// Open reminders only.
    Open,
}

/// One reminder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reminder {
    /// Path relative to the calendar home.
    pub path: ResourcePath,
    /// `ETag` for a conditional write.
    pub etag: ETag,
    /// Title. Untrusted content.
    pub title: String,
    /// Notes. Untrusted content.
    pub notes: String,
    /// Due date, when the reminder has one.
    pub due: Option<String>,
    /// Priority from 1 (highest) to 9, when set.
    pub priority: Option<u8>,
    /// The reminder is completed.
    pub completed: bool,
}

/// Reminders from a query, with a count of items that were skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReminderPage {
    /// The reminders, in the order the lists returned them.
    pub reminders: Vec<Reminder>,
    /// Items that could not be read and were left out.
    pub warnings: u32,
}

/// Fields written by create and update. An update replaces all of them, so a
/// `None` removes the property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReminderDraft {
    /// Title.
    pub title: String,
    /// Notes.
    pub notes: String,
    /// Due date, when the reminder has one.
    pub due: Option<String>,
    /// Priority from 1 (highest) to 9, when set.
    pub priority: Option<u8>,
    /// The reminder is completed.
    pub completed: bool,
}

/// Reminders read and write operations.
#[trait_variant::make(Send)]
pub trait RemindersProvider {
    /// Lists reminder lists.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the lists cannot be read.
    async fn list_lists(&self) -> Result<Vec<ReminderList>, CoreError>;

    /// Lists reminders.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the list cannot be read.
    async fn list(
        &self,
        list: Option<&ResourcePath>,
        completed: CompletedFilter,
    ) -> Result<ReminderPage, CoreError>;

    /// Fetches one reminder.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when the reminder does not exist.
    async fn get(&self, path: &ResourcePath) -> Result<Reminder, CoreError>;

    /// Creates a reminder.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the reminder cannot be written.
    async fn create(
        &self,
        list: &ResourcePath,
        draft: &ReminderDraft,
    ) -> Result<ResourcePath, CoreError>;

    /// Replaces a reminder when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn update(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &ReminderDraft,
    ) -> Result<ETag, CoreError>;

    /// Deletes a reminder when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn delete(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError>;
}
