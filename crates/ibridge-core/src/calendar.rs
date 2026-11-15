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

/// One event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Path relative to the calendar home.
    pub path: ResourcePath,
    /// `ETag` for a conditional write.
    pub etag: ETag,
    /// Summary. Untrusted content.
    pub summary: String,
    /// Description. Untrusted content.
    pub description: String,
    /// Start, as an ISO-8601 timestamp.
    pub start: String,
    /// End, as an ISO-8601 timestamp.
    pub end: String,
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
    async fn list_events(&self, query: &EventQuery) -> Result<Vec<Event>, CoreError>;

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

    /// Replaces an event when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn update_event(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &EventDraft,
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
    /// The reminder is completed.
    pub completed: bool,
}

/// Fields written by create and update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReminderDraft {
    /// Title.
    pub title: String,
    /// Notes.
    pub notes: String,
    /// Due date, when the reminder has one.
    pub due: Option<String>,
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
    ) -> Result<Vec<Reminder>, CoreError>;

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
