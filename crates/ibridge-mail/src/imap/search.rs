// SPDX-License-Identifier: Apache-2.0

//! Mailbox search.

use async_imap::types::Flag;
use futures::StreamExt;
use ibridge_core::{
    CoreError, MailPage, MailSearch, MailboxPath, MessageId, MessageSummary, Uid, UidValidity,
};

use super::pool::{Connect, ImapPool, map_command};

const DEFAULT_LIMIT: u32 = 25;
const MAX_LIMIT: u32 = 100;

impl<C: Connect> ImapPool<C> {
    /// Searches one mailbox, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the search cannot be run.
    pub async fn search(&self, query: &MailSearch) -> Result<MailPage, CoreError> {
        let path = mailbox_path(self, query).await?;
        let mut lease = self.checkout().await?;
        let searched = search_with(&mut lease, query, &path).await;
        lease.release();
        searched
    }
}

async fn mailbox_path<C: Connect>(
    pool: &ImapPool<C>,
    query: &MailSearch,
) -> Result<MailboxPath, CoreError> {
    if let Some(path) = &query.mailbox {
        return Ok(path.clone());
    }
    if let Some(role) = query.role {
        let mailboxes = pool.list_mailboxes().await?;
        return mailboxes
            .into_iter()
            .find(|mailbox| mailbox.role == role)
            .map(|mailbox| mailbox.path)
            .ok_or(CoreError::NotFound);
    }
    MailboxPath::try_from("INBOX").map_err(|_| CoreError::NotFound)
}

async fn search_with<C: Connect>(
    lease: &mut super::pool::Lease<'_, C>,
    query: &MailSearch,
    path: &MailboxPath,
) -> Result<MailPage, CoreError> {
    let criteria = criteria(query)?;
    let Some(session) = lease.session_mut() else {
        return Err(CoreError::Network);
    };
    let selected = session
        .select(path.as_str())
        .await
        .map_err(|error| map_command(&error))?;
    let validity = selected
        .uid_validity
        .ok_or_else(|| CoreError::Protocol("imap command failed".to_owned()))?;
    let validity = UidValidity::try_from(validity)
        .map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
    let uids = session
        .uid_search(criteria)
        .await
        .map_err(|error| map_command(&error))?;
    if uids.is_empty() {
        return Ok(MailPage {
            messages: Vec::new(),
            next_cursor: None,
        });
    }
    let set = uids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut fetches = session
        .uid_fetch(set, "(UID INTERNALDATE FLAGS ENVELOPE)")
        .await
        .map_err(|error| map_command(&error))?;
    let mut hits = Vec::new();
    while let Some(item) = fetches.next().await {
        let fetch = item.map_err(|error| map_command(&error))?;
        let Some(uid) = fetch.uid else {
            continue;
        };
        let Some(internal) = fetch.internal_date() else {
            continue;
        };
        hits.push(Hit {
            uid,
            day: internal.format("%Y-%m-%d").to_string(),
            from: from_text(&fetch),
            subject: subject_text(&fetch),
            unread: !fetch.flags().any(|flag| matches!(flag, Flag::Seen)),
            flagged: fetch.flags().any(|flag| matches!(flag, Flag::Flagged)),
        });
    }
    drop(fetches);
    hits.sort_by(|left, right| right.day.cmp(&left.day).then(right.uid.cmp(&left.uid)));
    page(path, validity, &hits, query)
}

struct Hit {
    uid: u32,
    day: String,
    from: String,
    subject: String,
    unread: bool,
    flagged: bool,
}

fn page(
    path: &MailboxPath,
    validity: UidValidity,
    hits: &[Hit],
    query: &MailSearch,
) -> Result<MailPage, CoreError> {
    let limit = page_limit(query.limit);
    let start = match &query.cursor {
        None => 0,
        Some(cursor) => {
            let (day, uid) = parse_cursor(cursor)?;
            hits.iter()
                .position(|hit| {
                    hit.day.as_str() < day.as_str() || (hit.day == day && hit.uid < uid)
                })
                .unwrap_or(hits.len())
        }
    };
    let end = start.saturating_add(limit).min(hits.len());
    let mut messages = Vec::with_capacity(end.saturating_sub(start));
    for hit in &hits[start..end] {
        let uid = Uid::try_from(hit.uid)
            .map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
        messages.push(MessageSummary {
            id: MessageId {
                mailbox: path.clone(),
                validity,
                uid,
            },
            from: hit.from.clone(),
            subject: hit.subject.clone(),
            date: hit.day.clone(),
            unread: hit.unread,
            flagged: hit.flagged,
        });
    }
    let next_cursor = if end > start && end < hits.len() {
        Some(format!("{}:{}", hits[end - 1].day, hits[end - 1].uid))
    } else {
        None
    };
    Ok(MailPage {
        messages,
        next_cursor,
    })
}

fn page_limit(limit: u32) -> usize {
    let capped = if limit == 0 {
        DEFAULT_LIMIT
    } else {
        limit.min(MAX_LIMIT)
    };
    usize::try_from(capped).unwrap_or(usize::try_from(MAX_LIMIT).unwrap_or(25))
}

fn parse_cursor(cursor: &str) -> Result<(String, u32), CoreError> {
    let Some((day, uid)) = cursor.rsplit_once(':') else {
        return Err(CoreError::InvalidInput(
            "search cursor is not valid".to_owned(),
        ));
    };
    if day.len() != 10 {
        return Err(CoreError::InvalidInput(
            "search cursor is not valid".to_owned(),
        ));
    }
    let uid = uid
        .parse()
        .map_err(|_| CoreError::InvalidInput("search cursor is not valid".to_owned()))?;
    if uid == 0 {
        return Err(CoreError::InvalidInput(
            "search cursor is not valid".to_owned(),
        ));
    }
    Ok((day.to_owned(), uid))
}

fn criteria(query: &MailSearch) -> Result<String, CoreError> {
    let mut parts = Vec::new();
    if let Some(from) = &query.from {
        parts.push(format!("FROM {}", quote_atom(from)));
    }
    if let Some(to) = &query.to {
        parts.push(format!("TO {}", quote_atom(to)));
    }
    if let Some(subject) = &query.subject {
        parts.push(format!("SUBJECT {}", quote_atom(subject)));
    }
    if let Some(text) = &query.text {
        parts.push(format!("TEXT {}", quote_atom(text)));
    }
    if let Some(since) = &query.since {
        parts.push(format!("SINCE {}", imap_date(since)?));
    }
    if let Some(before) = &query.before {
        parts.push(format!("BEFORE {}", imap_date(before)?));
    }
    if query.unread_only {
        parts.push("UNSEEN".to_owned());
    }
    if query.flagged_only {
        parts.push("FLAGGED".to_owned());
    }
    if parts.is_empty() {
        parts.push("ALL".to_owned());
    }
    Ok(parts.join(" "))
}

fn quote_atom(value: &str) -> String {
    let plain = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
    if plain && !value.is_empty() {
        return value.to_owned();
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn imap_date(iso: &str) -> Result<String, CoreError> {
    let mut parts = iso.split('-');
    let year = parts.next();
    let month = parts.next();
    let day = parts.next();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return Err(CoreError::InvalidInput(
            "search date must be YYYY-MM-DD".to_owned(),
        ));
    };
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return Err(CoreError::InvalidInput(
            "search date must be YYYY-MM-DD".to_owned(),
        ));
    }
    let day_num: u32 = day
        .parse()
        .map_err(|_| CoreError::InvalidInput("search date must be YYYY-MM-DD".to_owned()))?;
    if !(1..=31).contains(&day_num) || year.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(CoreError::InvalidInput(
            "search date must be YYYY-MM-DD".to_owned(),
        ));
    }
    let month_name = match month {
        "01" => "Jan",
        "02" => "Feb",
        "03" => "Mar",
        "04" => "Apr",
        "05" => "May",
        "06" => "Jun",
        "07" => "Jul",
        "08" => "Aug",
        "09" => "Sep",
        "10" => "Oct",
        "11" => "Nov",
        "12" => "Dec",
        _ => {
            return Err(CoreError::InvalidInput(
                "search date must be YYYY-MM-DD".to_owned(),
            ));
        }
    };
    Ok(format!("{day_num}-{month_name}-{year}"))
}

fn from_text(fetch: &async_imap::types::Fetch) -> String {
    let Some(address) = fetch
        .envelope()
        .and_then(|envelope| envelope.from.as_ref())
        .and_then(|addresses| addresses.first())
    else {
        return String::new();
    };
    let mailbox = lossy(address.mailbox.as_deref());
    let host = lossy(address.host.as_deref());
    if host.is_empty() {
        mailbox
    } else {
        format!("{mailbox}@{host}")
    }
}

fn subject_text(fetch: &async_imap::types::Fetch) -> String {
    fetch
        .envelope()
        .and_then(|envelope| envelope.subject.as_ref())
        .map_or(String::new(), |subject| {
            String::from_utf8_lossy(subject).into_owned()
        })
}

fn lossy(value: Option<&[u8]>) -> String {
    value.map_or(String::new(), |bytes| {
        String::from_utf8_lossy(bytes).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use ibridge_core::{MailSearch, MailboxPath};
    use ibridge_testkit::imap_fake::FakeScript;

    use super::super::support::pool;

    fn query() -> MailSearch {
        MailSearch {
            mailbox: None,
            role: None,
            from: None,
            to: None,
            subject: None,
            text: None,
            since: None,
            before: None,
            unread_only: false,
            flagged_only: false,
            limit: 25,
            cursor: None,
        }
    }

    #[tokio::test]
    async fn search_builds_criteria() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (fake, pooled) = pool(FakeScript::default());
        let _page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                from: Some("ada@icloud.com".to_owned()),
                subject: Some("race".to_owned()),
                text: Some("calendar".to_owned()),
                since: Some("2026-11-01".to_owned()),
                before: Some("2026-11-15".to_owned()),
                unread_only: true,
                flagged_only: true,
                ..query()
            })
            .await
            .expect("search");
        let lines = fake.lines();
        let search = lines
            .iter()
            .find(|line| line.contains("SEARCH"))
            .map(String::as_str);
        let search = search.unwrap_or("");
        for needle in [
            "UID SEARCH",
            "FROM",
            "ada@icloud.com",
            "SUBJECT",
            "race",
            "TEXT",
            "calendar",
            "SINCE",
            "1-Nov-2026",
            "BEFORE",
            "15-Nov-2026",
            "UNSEEN",
            "FLAGGED",
        ] {
            assert!(
                search.contains(needle),
                "search criteria must include {needle}, line {search:?}, commands {lines:?}"
            );
        }
        assert!(
            lines.iter().any(|line| line.contains("INBOX")),
            "search selects the requested mailbox, commands {lines:?}"
        );
    }

    #[tokio::test]
    async fn search_paginates_newest_first() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (_fake, pooled) = pool(FakeScript::default());
        let page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox.clone()),
                limit: 2,
                ..query()
            })
            .await
            .expect("first page");
        let uids: Vec<u32> = page
            .messages
            .iter()
            .map(|message| message.id.uid.get())
            .collect();
        assert_eq!(
            uids,
            vec![4, 2],
            "newest day first, and the higher uid first when the day matches"
        );
        let cursor = page
            .next_cursor
            .expect("the older message is on the next page");
        let rest = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                limit: 2,
                cursor: Some(cursor),
                ..query()
            })
            .await
            .expect("second page");
        let rest_uids: Vec<u32> = rest
            .messages
            .iter()
            .map(|message| message.id.uid.get())
            .collect();
        assert_eq!(rest_uids, vec![50], "the oldest message follows the cursor");
        assert!(rest.next_cursor.is_none(), "the last page has no cursor");
    }
}
