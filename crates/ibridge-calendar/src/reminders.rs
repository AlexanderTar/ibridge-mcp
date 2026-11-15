// SPDX-License-Identifier: Apache-2.0

//! Reminders as `VTODO` resources in task-capable calendars.

use chrono::Utc;
use ibridge_core::{
    CompletedFilter, CoreError, ETag, Reminder, ReminderDraft, ReminderList, ReminderPage,
    RemindersProvider, ResourcePath, UPGRADED_LISTS_NOTE,
};

use crate::CalDavProvider;
use crate::collections::{Collection, Entry, Home, protocol};
use crate::events::{ICS_TYPE, new_uid};
use crate::ical;

impl RemindersProvider for CalDavProvider {
    async fn list_lists(&self) -> Result<Vec<ReminderList>, CoreError> {
        let home = self.home().await?;
        Ok(self
            .collections(&home)
            .await?
            .into_iter()
            .filter(|collection| collection.holds_tasks)
            .map(|collection| ReminderList {
                path: collection.path,
                name: collection.name,
            })
            .collect())
    }

    async fn list(
        &self,
        list: Option<&ResourcePath>,
        completed: CompletedFilter,
    ) -> Result<ReminderPage, CoreError> {
        let home = self.home().await?;
        let collections = self.collections(&home).await?;
        let chosen: Vec<&Collection> = match list {
            Some(path) => vec![task_list(&collections, path)?],
            None => collections.iter().filter(|c| c.holds_tasks).collect(),
        };
        let mut page = ReminderPage {
            reminders: Vec::new(),
            warnings: 0,
        };
        for collection in chosen {
            let entries = self.query(&home, collection, todo_query()).await?;
            for entry in entries {
                match reminder_of(&home, &entry) {
                    Some(reminder) => {
                        if completed == CompletedFilter::All || !reminder.completed {
                            page.reminders.push(reminder);
                        }
                    }
                    None => page.warnings += 1,
                }
            }
        }
        Ok(page)
    }

    async fn get(&self, path: &ResourcePath) -> Result<Reminder, CoreError> {
        let fetched = self.fetch(path).await?;
        let fields = ical::parse(&fetched.text)
            .and_then(|parsed| ical::read_todo(&parsed))
            .ok_or_else(protocol)?;
        Ok(reminder(path.clone(), fetched.etag, fields))
    }

    async fn create(
        &self,
        list: &ResourcePath,
        draft: &ReminderDraft,
    ) -> Result<ResourcePath, CoreError> {
        let home = self.home().await?;
        let collections = self.collections(&home).await?;
        let collection = task_list(&collections, list)?;
        let uid = new_uid()?;
        let text = ical::new_todo_text(&uid, Utc::now(), draft)?;
        let key = collection.path.as_str().trim_end_matches('/');
        let path =
            ResourcePath::try_from(format!("{key}/{uid}.ics").as_str()).map_err(|_| protocol())?;
        self.client
            .put_new(&home.url_of(path.as_str()), &text, ICS_TYPE)
            .await?;
        Ok(path)
    }

    async fn update(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &ReminderDraft,
    ) -> Result<ETag, CoreError> {
        let current = self.fetch(path).await?;
        if &current.etag != etag {
            return Err(CoreError::Conflict);
        }
        let text = ical::update_todo_text(&current.text, draft, Utc::now())?;
        let home = self.home().await?;
        Ok(self
            .client
            .put_if_match(&home.url_of(path.as_str()), &text, ICS_TYPE, etag)
            .await?)
    }

    async fn delete(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError> {
        let home = self.home().await?;
        Ok(self
            .client
            .delete_if_match(&home.url_of(path.as_str()), etag)
            .await?)
    }
}

/// The task-capable collection at `path`. Anything else, including a list the
/// server does not show at all, is explained with the upgraded-lists note.
fn task_list<'a>(
    collections: &'a [Collection],
    path: &ResourcePath,
) -> Result<&'a Collection, CoreError> {
    let key = path.as_str().trim_end_matches('/');
    collections
        .iter()
        .find(|c| c.path.as_str().trim_end_matches('/') == key && c.holds_tasks)
        .ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "'{key}' is not a reminder list. {UPGRADED_LISTS_NOTE}"
            ))
        })
}

fn todo_query() -> String {
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
     <C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
     <D:prop><D:getetag/><C:calendar-data/></D:prop>\
     <C:filter><C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VTODO\"/>\
     </C:comp-filter></C:filter></C:calendar-query>"
        .to_owned()
}

fn reminder_of(home: &Home, entry: &Entry) -> Option<Reminder> {
    let path = ResourcePath::try_from(home.relative(&entry.href)?.as_str()).ok()?;
    let etag = ETag::try_from(entry.etag.as_deref()?).ok()?;
    let fields = ical::read_todo(&ical::parse(entry.calendar_data.as_deref()?)?)?;
    Some(reminder(path, etag, fields))
}

fn reminder(path: ResourcePath, etag: ETag, fields: ical::TodoFields) -> Reminder {
    Reminder {
        path,
        etag,
        title: fields.title,
        notes: fields.notes,
        due: fields.due,
        priority: fields.priority,
        completed: fields.completed,
    }
}

#[cfg(test)]
mod tests {
    use ibridge_core::{
        CalendarProvider, CompletedFilter, CoreError, ETag, ReminderDraft, RemindersProvider,
        ResourcePath, UPGRADED_LISTS_NOTE,
    };
    use ibridge_testkit::dav_mock::FakeCalDav;

    use crate::CalDavProvider;
    use crate::test_support::{setup, vcalendar};

    async fn with_lists() -> (FakeCalDav, CalDavProvider) {
        let (fake, provider) = setup().await;
        fake.add_collection("tasks", "Groceries", &["VTODO"]);
        fake.add_collection("shared", "Shared", &["VEVENT", "VTODO"]);
        (fake, provider)
    }

    fn draft(title: &str) -> ReminderDraft {
        ReminderDraft {
            title: title.to_owned(),
            notes: String::new(),
            due: None,
            priority: None,
            completed: false,
        }
    }

    fn path(text: &str) -> ResourcePath {
        ResourcePath::try_from(text).expect("resource path")
    }

    #[tokio::test]
    async fn list_lists_only_vtodo_calendars() {
        let (_fake, provider) = with_lists().await;
        let lists = provider.list_lists().await.expect("list reminder lists");
        let names: Vec<&str> = lists.iter().map(|list| list.name.as_str()).collect();
        assert_eq!(
            names,
            ["Shared", "Groceries"],
            "the event-only calendar is not a list"
        );
    }

    #[tokio::test]
    async fn list_calendars_reports_events_tasks_both() {
        let (_fake, provider) = with_lists().await;
        let calendars = provider.list_calendars().await.expect("list calendars");
        let kinds: Vec<(&str, bool, bool)> = calendars
            .iter()
            .map(|c| (c.name.as_str(), c.holds_events, c.holds_tasks))
            .collect();
        assert_eq!(
            kinds,
            [
                ("Shared", true, true),
                ("Groceries", false, true),
                ("Work", true, false)
            ]
        );
    }

    #[tokio::test]
    async fn create_reminder_only_in_task_calendar() {
        let (fake, provider) = with_lists().await;
        let due = ReminderDraft {
            notes: "2% milk".to_owned(),
            due: Some("2026-11-20T08:00:00Z".to_owned()),
            priority: Some(1),
            ..draft("Buy milk")
        };
        let created = provider
            .create(&path("tasks/"), &due)
            .await
            .expect("create in a task list");
        let file = created
            .as_str()
            .strip_prefix("tasks/")
            .expect("under the list");
        let body = fake.body("tasks", file).expect("stored");
        for expected in [
            "BEGIN:VTODO",
            "SUMMARY:Buy milk",
            "DESCRIPTION:2% milk",
            "DUE:20261120T080000Z",
            "PRIORITY:1",
            "STATUS:NEEDS-ACTION",
        ] {
            assert!(body.contains(expected), "missing {expected} in {body}");
        }
        assert!(!body.contains("BEGIN:VEVENT"), "{body}");

        let error = provider
            .create(&path("work/"), &draft("Wrong place"))
            .await
            .expect_err("an event calendar is not a reminder list");
        assert!(
            matches!(&error, CoreError::InvalidInput(message) if message.contains("upgraded")),
            "the error explains the upgraded lists: {error:?}"
        );
        assert_eq!(
            fake.files("work"),
            Vec::<String>::new(),
            "nothing was written"
        );
    }

    #[tokio::test]
    async fn complete_sets_status_and_completed() {
        let (fake, provider) = with_lists().await;
        let etag = fake.put(
            "tasks",
            "milk.ics",
            &vcalendar(
                "BEGIN:VTODO\nUID:milk-1\nDTSTAMP:20261101T000000Z\nSUMMARY:Buy milk\n\
                 STATUS:NEEDS-ACTION\nX-APPLE-SORT-ORDER:7\nEND:VTODO",
            ),
        );
        let target = path("tasks/milk.ics");
        let done = ReminderDraft {
            completed: true,
            ..draft("Buy milk")
        };
        provider
            .update(
                &target,
                &ETag::try_from(etag.as_str()).expect("etag"),
                &done,
            )
            .await
            .expect("complete the reminder");
        let body = fake.body("tasks", "milk.ics").expect("stored");
        assert!(body.contains("STATUS:COMPLETED"), "{body}");
        assert!(
            body.contains("\r\nCOMPLETED:20"),
            "a completion time is stamped: {body}"
        );
        assert!(
            body.contains("X-APPLE-SORT-ORDER:7"),
            "other properties are kept: {body}"
        );

        let open = provider
            .list(Some(&path("tasks/")), CompletedFilter::Open)
            .await
            .expect("list open");
        assert!(open.reminders.is_empty(), "{:?}", open.reminders);
        let all = provider
            .list(None, CompletedFilter::All)
            .await
            .expect("list all");
        assert_eq!(all.reminders.len(), 1);
        assert!(all.reminders[0].completed);
        let fetched = provider.get(&target).await.expect("get");
        assert_eq!(fetched.title, "Buy milk");

        let current = ETag::try_from(fetched.etag.as_str()).expect("etag");
        provider
            .update(&target, &current, &draft("Buy milk"))
            .await
            .expect("reopen the reminder");
        let body = fake.body("tasks", "milk.ics").expect("stored");
        assert!(body.contains("STATUS:NEEDS-ACTION"), "{body}");
        assert!(
            !body.contains("\r\nCOMPLETED:"),
            "the completion time is removed: {body}"
        );
    }

    #[tokio::test]
    async fn upgraded_lists_note() {
        let (_fake, provider) = with_lists().await;
        let error = provider
            .list(Some(&path("work/")), CompletedFilter::All)
            .await
            .expect_err("an event calendar is not a reminder list");
        assert!(
            matches!(&error, CoreError::InvalidInput(message) if message.contains(UPGRADED_LISTS_NOTE)),
            "a list that is missing or not a task list is explained with the note: {error:?}"
        );
    }
}
