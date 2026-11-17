// SPDX-License-Identifier: Apache-2.0

//! Calendar and reminders tools.

use ibridge_core::{
    Calendar, CalendarProvider, CompletedFilter, ContactsProvider, CoreError, ETag, Event,
    EventDraft, EventList, EventQuery, Reminder, ReminderDraft, ReminderList, ReminderPage,
    RemindersProvider, ResourcePath, UPGRADED_LISTS_NOTE, UpdateScope, decode_resource,
    encode_resource,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorData};
use rmcp::tool;
use rmcp::tool_router;

use crate::calendar_dto::{
    CalendarListOut, CalendarOut, CreateEventParams, CreateReminderParams, DeleteOut, DeleteParams,
    EventListOut, EventOut, GetByIdParams, ListEventsParams, ListRemindersParams, ReminderListOut,
    ReminderListsOut, ReminderOut, RemindersOut, UpdateEventParams, UpdateReminderParams, WriteOut,
};
use crate::handler::{IbridgeServer, mapped, page_limit, respond};
use crate::mail_api::MailApi;
use crate::untrusted::wrap_untrusted;

pub(crate) const CALENDAR_TOOLS: &[&str] = &[
    "calendar_create_event",
    "calendar_delete_event",
    "calendar_get_event",
    "calendar_list_calendars",
    "calendar_list_events",
    "calendar_update_event",
    "reminders_create",
    "reminders_delete",
    "reminders_list",
    "reminders_list_lists",
    "reminders_update",
];

pub(crate) const CALENDAR_WRITE_TOOLS: &[&str] = &[
    "calendar_create_event",
    "calendar_delete_event",
    "calendar_update_event",
    "reminders_create",
    "reminders_delete",
    "reminders_update",
];

/// The calendar backend of a server that has none. Its tools stay hidden.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCalendar;

fn off<T>() -> Result<T, CoreError> {
    Err(CoreError::Unsupported("calendar is not enabled"))
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl CalendarProvider for NoCalendar {
    async fn list_calendars(&self) -> Result<Vec<Calendar>, CoreError> {
        off()
    }
    async fn list_events(&self, _query: &EventQuery) -> Result<EventList, CoreError> {
        off()
    }
    async fn get_event(&self, _path: &ResourcePath) -> Result<Event, CoreError> {
        off()
    }
    async fn create_event(
        &self,
        _calendar: &ResourcePath,
        _draft: &EventDraft,
    ) -> Result<ResourcePath, CoreError> {
        off()
    }
    async fn update_event(
        &self,
        _path: &ResourcePath,
        _etag: &ETag,
        _draft: &EventDraft,
        _scope: &UpdateScope,
    ) -> Result<ETag, CoreError> {
        off()
    }
    async fn delete_event(&self, _path: &ResourcePath, _etag: &ETag) -> Result<(), CoreError> {
        off()
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl RemindersProvider for NoCalendar {
    async fn list_lists(&self) -> Result<Vec<ReminderList>, CoreError> {
        off()
    }
    async fn list(
        &self,
        _list: Option<&ResourcePath>,
        _completed: CompletedFilter,
    ) -> Result<ReminderPage, CoreError> {
        off()
    }
    async fn get(&self, _path: &ResourcePath) -> Result<Reminder, CoreError> {
        off()
    }
    async fn create(
        &self,
        _list: &ResourcePath,
        _draft: &ReminderDraft,
    ) -> Result<ResourcePath, CoreError> {
        off()
    }
    async fn update(
        &self,
        _path: &ResourcePath,
        _etag: &ETag,
        _draft: &ReminderDraft,
    ) -> Result<ETag, CoreError> {
        off()
    }
    async fn delete(&self, _path: &ResourcePath, _etag: &ETag) -> Result<(), CoreError> {
        off()
    }
}

macro_rules! try_cal {
    ($call:expr) => {
        match $call {
            Ok(value) => value,
            Err(error) => return mapped(&error),
        }
    };
}

#[tool_router(router = calendar_router, vis = "pub(crate)")]
impl<M, C, K> IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    /// Lists calendars and says whether each holds events, tasks or both.
    ///
    /// # Errors
    ///
    /// Returns an MCP error when the calendars cannot be read.
    #[tool(
        description = "Lists calendars. Each one says whether it holds events, tasks (reminders) or both.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<CalendarListOut>(),
    )]
    pub async fn calendar_list_calendars(&self) -> Result<CallToolResult, ErrorData> {
        let _permit = self.permit().await?;
        let calendars = try_cal!(self.calendar.list_calendars().await);
        let listed: Vec<CalendarOut> = calendars
            .iter()
            .map(|calendar| CalendarOut {
                id: encode_resource(&calendar.path),
                name: wrap_untrusted(&calendar.name),
                kind: match (calendar.holds_events, calendar.holds_tasks) {
                    (true, true) => "both",
                    (false, true) => "tasks",
                    _ => "events",
                },
            })
            .collect();
        let summary = format!("{} calendars", listed.len());
        respond(&CalendarListOut { calendars: listed }, summary)
    }

    /// Lists events in a time range. Repeating events are expanded.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when an id, the range or the page
    /// size is not usable, and an MCP error when the events cannot be read.
    #[tool(
        description = "Lists events in a time range over one or more calendars. Repeating events are expanded into their occurrences.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<EventListOut>(),
    )]
    pub async fn calendar_list_events(
        &self,
        Parameters(params): Parameters<ListEventsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = page_limit(params.limit)?;
        let start_at = cursor_offset(params.cursor.as_deref())?;
        let calendars = params
            .calendars
            .iter()
            .map(|id| require_path(id))
            .collect::<Result<Vec<_>, _>>()?;
        let query = EventQuery {
            calendars,
            start: params.start,
            end: params.end,
        };
        let _permit = self.permit().await?;
        let listed = try_cal!(self.calendar.list_events(&query).await);
        let (events, next_cursor) = page(listed.events, limit, start_at);
        let summary = if listed.warnings == 0 {
            format!("{} events", events.len())
        } else {
            format!("{} events, {} skipped", events.len(), listed.warnings)
        };
        respond(
            &EventListOut {
                events: events.iter().map(event_out).collect(),
                next_cursor,
                warnings: listed.warnings,
            },
            summary,
        )
    }

    /// Fetches one event with its attendees and alarms.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id is not usable, and an
    /// MCP error when the event cannot be read.
    #[tool(
        description = "Fetches one event in full, including attendees and alarms.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<EventOut>(),
    )]
    pub async fn calendar_get_event(
        &self,
        Parameters(params): Parameters<GetByIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = require_path(&params.id)?;
        let _permit = self.permit().await?;
        let event = try_cal!(self.calendar.get_event(&path).await);
        respond(&event_out(&event), "event".to_owned())
    }

    /// Creates an event. `DTEND` is always written.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the calendar id or a time is
    /// not usable, and an MCP error when the event cannot be written.
    #[tool(
        description = "Creates an event. Times are ISO-8601 and the time zone is an IANA name. An end is always stored.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn calendar_create_event(
        &self,
        Parameters(params): Parameters<CreateEventParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let calendar = require_path(&params.calendar)?;
        let draft = EventDraft {
            summary: params.summary,
            description: params.description,
            start: params.start,
            end: params.end.unwrap_or_default(),
            time_zone: params.time_zone,
        };
        let _permit = self.permit().await?;
        let created = try_cal!(self.calendar.create_event(&calendar, &draft).await);
        respond(
            &WriteOut {
                id: encode_resource(&created),
                etag: None,
            },
            "event created".to_owned(),
        )
    }

    /// Changes an event when its `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when an id, `ETag` or time is not
    /// usable, and a tool error when the event changed since it was read.
    #[tool(
        description = "Changes an event. Needs the etag from the last read; a changed event is refused. Applies to the whole series unless an occurrence is named.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn calendar_update_event(
        &self,
        Parameters(params): Parameters<UpdateEventParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        if params.start.is_some() != params.end.is_some() {
            return Err(ErrorData::invalid_params(
                "give both start and end, or neither",
                None,
            ));
        }
        let scope = match params.occurrence {
            Some(recurrence_id) => {
                if params.start.is_none() || params.end.is_none() {
                    return Err(ErrorData::invalid_params(
                        "changing one occurrence needs start and end",
                        None,
                    ));
                }
                UpdateScope::Occurrence { recurrence_id }
            }
            None => UpdateScope::Series,
        };
        let _permit = self.permit().await?;
        // Left-out fields stay empty: the provider keeps what the event has. Copying
        // them from the first occurrence would write that occurrence's values onto
        // the whole series.
        let draft = EventDraft {
            summary: params.summary.unwrap_or_default(),
            description: params.description,
            start: params.start.unwrap_or_default(),
            end: params.end.unwrap_or_default(),
            time_zone: params.time_zone,
        };
        let fresh = try_cal!(
            self.calendar
                .update_event(&path, &etag, &draft, &scope)
                .await
        );
        respond(
            &WriteOut {
                id: params.id,
                etag: Some(fresh.as_str().to_owned()),
            },
            "event updated".to_owned(),
        )
    }

    /// Deletes an event when its `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or `ETag` is not
    /// usable, and a tool error when the event changed since it was read.
    #[tool(
        description = "Deletes an event. Needs the etag from the last read; a changed event is refused.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<DeleteOut>(),
    )]
    pub async fn calendar_delete_event(
        &self,
        Parameters(params): Parameters<DeleteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        let _permit = self.permit().await?;
        try_cal!(self.calendar.delete_event(&path, &etag).await);
        respond(&DeleteOut { deleted: true }, "event deleted".to_owned())
    }

    /// Lists reminder lists, and says that upgraded lists are out of reach.
    ///
    /// # Errors
    ///
    /// Returns an MCP error when the lists cannot be read.
    #[tool(
        description = "Lists reminder lists. Only old-style lists can be reached; the result says so.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<ReminderListsOut>(),
    )]
    pub async fn reminders_list_lists(&self) -> Result<CallToolResult, ErrorData> {
        let _permit = self.permit().await?;
        let lists = try_cal!(self.calendar.list_lists().await);
        let listed: Vec<ReminderListOut> = lists
            .iter()
            .map(|list| ReminderListOut {
                id: encode_resource(&list.path),
                name: wrap_untrusted(&list.name),
            })
            .collect();
        let summary = format!("{} lists. {UPGRADED_LISTS_NOTE}", listed.len());
        respond(
            &ReminderListsOut {
                lists: listed,
                note: UPGRADED_LISTS_NOTE,
            },
            summary,
        )
    }

    /// Lists reminders, open ones unless completed ones are asked for.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the list id or page size is
    /// not usable, and an MCP error when the reminders cannot be read.
    #[tool(
        description = "Lists reminders in one list or all lists. Open reminders only, unless include_completed is set.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<RemindersOut>(),
    )]
    pub async fn reminders_list(
        &self,
        Parameters(params): Parameters<ListRemindersParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = page_limit(params.limit)?;
        let start_at = cursor_offset(params.cursor.as_deref())?;
        let list = params.list.as_deref().map(require_path).transpose()?;
        let filter = if params.include_completed.unwrap_or(false) {
            CompletedFilter::All
        } else {
            CompletedFilter::Open
        };
        let _permit = self.permit().await?;
        let listed = try_cal!(self.calendar.list(list.as_ref(), filter).await);
        let (reminders, next_cursor) = page(listed.reminders, limit, start_at);
        let summary = format!("{} reminders", reminders.len());
        respond(
            &RemindersOut {
                reminders: reminders.iter().map(reminder_out).collect(),
                next_cursor,
                warnings: listed.warnings,
            },
            summary,
        )
    }

    /// Creates a reminder in a task list.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the list id, due date or
    /// priority is not usable, and an MCP error when it cannot be written.
    #[tool(
        description = "Creates a reminder in a reminder list.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn reminders_create(
        &self,
        Parameters(params): Parameters<CreateReminderParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let list = require_path(&params.list)?;
        let draft = ReminderDraft {
            title: params.title,
            notes: params.notes.unwrap_or_default(),
            due: params.due.filter(|due| !due.is_empty()),
            priority: params.priority.filter(|priority| *priority != 0),
            completed: false,
        };
        let _permit = self.permit().await?;
        let created = try_cal!(self.calendar.create(&list, &draft).await);
        respond(
            &WriteOut {
                id: encode_resource(&created),
                etag: None,
            },
            "reminder created".to_owned(),
        )
    }

    /// Changes a reminder when its `ETag` still matches. Completing is an update.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when an id, `ETag`, due date or
    /// priority is not usable, and a tool error when the reminder changed.
    #[tool(
        description = "Changes a reminder, including marking it completed. Needs the etag from the last read; a changed reminder is refused.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn reminders_update(
        &self,
        Parameters(params): Parameters<UpdateReminderParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        let _permit = self.permit().await?;
        let current = try_cal!(self.calendar.get(&path).await);
        let draft = ReminderDraft {
            title: params.title.unwrap_or(current.title),
            notes: params.notes.unwrap_or(current.notes),
            due: match params.due {
                None => current.due,
                Some(due) if due.is_empty() => None,
                Some(due) => Some(due),
            },
            priority: match params.priority {
                None => current.priority,
                Some(0) => None,
                Some(priority) => Some(priority),
            },
            completed: params.completed.unwrap_or(current.completed),
        };
        let fresh = try_cal!(self.calendar.update(&path, &etag, &draft).await);
        respond(
            &WriteOut {
                id: params.id,
                etag: Some(fresh.as_str().to_owned()),
            },
            "reminder updated".to_owned(),
        )
    }

    /// Deletes a reminder when its `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or `ETag` is not
    /// usable, and a tool error when the reminder changed since it was read.
    #[tool(
        description = "Deletes a reminder. Needs the etag from the last read; a changed reminder is refused.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<DeleteOut>(),
    )]
    pub async fn reminders_delete(
        &self,
        Parameters(params): Parameters<DeleteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        let _permit = self.permit().await?;
        try_cal!(self.calendar.delete(&path, &etag).await);
        respond(&DeleteOut { deleted: true }, "reminder deleted".to_owned())
    }
}

pub(crate) fn require_path(id: &str) -> Result<ResourcePath, ErrorData> {
    decode_resource(id).map_err(|_| ErrorData::invalid_params("invalid id", None))
}

pub(crate) fn require_etag(etag: &str) -> Result<ETag, ErrorData> {
    ETag::try_from(etag).map_err(|_| ErrorData::invalid_params("invalid etag", None))
}

fn cursor_offset(cursor: Option<&str>) -> Result<usize, ErrorData> {
    match cursor {
        None => Ok(0),
        Some(text) => text
            .parse()
            .map_err(|_| ErrorData::invalid_params("invalid cursor", None)),
    }
}

/// One page of `items`, and the cursor for the next page when there is one.
pub(crate) fn page<T>(items: Vec<T>, limit: u32, start: usize) -> (Vec<T>, Option<String>) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let end = start.saturating_add(limit);
    let more = items.len() > end;
    let shown = items.into_iter().skip(start).take(limit).collect();
    (shown, more.then(|| end.to_string()))
}

/// The most characters of a description or note a tool returns, like a mail body.
pub(crate) const BODY_LIMIT: usize = 40_000;

/// `text` cut to [`BODY_LIMIT`] characters, with a marker saying how much is missing.
pub(crate) fn capped(text: &str) -> String {
    let Some((end, _)) = text.char_indices().nth(BODY_LIMIT) else {
        return text.to_owned();
    };
    let missing = text[end..].chars().count();
    format!("{}\n[truncated, {missing} more characters]", &text[..end])
}

fn event_out(event: &Event) -> EventOut {
    EventOut {
        id: encode_resource(&event.path),
        etag: event.etag.as_str().to_owned(),
        uid: event.uid.clone(),
        summary: wrap_untrusted(&event.summary),
        description: wrap_untrusted(&capped(&event.description)),
        start: event.start.clone(),
        end: event.end.clone(),
        time_zone: event.time_zone.clone(),
        all_day: event.all_day,
        recurring: event.recurring,
        recurrence_id: event.recurrence_id.clone(),
        attendees: event.attendees.iter().map(|a| wrap_untrusted(a)).collect(),
        alarms: event.alarms.clone(),
    }
}

fn reminder_out(reminder: &Reminder) -> ReminderOut {
    ReminderOut {
        id: encode_resource(&reminder.path),
        etag: reminder.etag.as_str().to_owned(),
        title: wrap_untrusted(&reminder.title),
        notes: wrap_untrusted(&capped(&reminder.notes)),
        due: reminder.due.clone(),
        priority: reminder.priority,
        completed: reminder.completed,
    }
}
