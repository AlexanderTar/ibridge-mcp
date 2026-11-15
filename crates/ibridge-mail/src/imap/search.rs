// SPDX-License-Identifier: Apache-2.0

//! Mailbox search.

use std::collections::HashMap;

use async_imap::imap_proto::{AttributeValue, MailboxDatum, Response};
use ibridge_core::{
    CoreError, MailSearch, MailboxPath, MessageId, MessageSummary, Uid, UidValidity,
};

/// One page of search hits. `warnings` counts messages skipped because they did not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchPage {
    /// Hits, newest first.
    pub messages: Vec<MessageSummary>,
    /// Present when another page exists.
    pub next_cursor: Option<String>,
    /// Messages skipped while building this page.
    pub warnings: u32,
}

use super::pool::{Connect, ImapPool, map_command, run_checked};

const DEFAULT_LIMIT: u32 = 25;
const MAX_LIMIT: u32 = 100;

impl<C: Connect> ImapPool<C> {
    /// Searches one mailbox, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the search cannot be run.
    pub async fn search(&self, query: &MailSearch) -> Result<SearchPage, CoreError> {
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
) -> Result<SearchPage, CoreError> {
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
    let mut uids = Vec::new();
    let searched = run_checked(session, &format!("UID SEARCH {criteria}"), |response| {
        if let Response::MailboxData(MailboxDatum::Search(ids)) = response {
            uids.extend(ids.iter().copied());
        }
    })
    .await?;
    let mut warnings = u32::from(searched.unparsed);
    if searched.unparsed || uids.is_empty() {
        return Ok(SearchPage {
            messages: Vec::new(),
            next_cursor: None,
            warnings,
        });
    }
    // ponytail: one UID FETCH for every search hit; chunk the set if a mailbox's search line exceeds the server command limit.
    let mut hits = Vec::new();
    let meta = run_checked(
        session,
        &format!(
            "UID FETCH {} (UID INTERNALDATE FLAGS ENVELOPE)",
            uid_list(&uids)
        ),
        |response| {
            let Response::Fetch(_, attributes) = response else {
                return;
            };
            match hit_from(attributes) {
                Some(hit) => hits.push(hit),
                None => warnings = warnings.saturating_add(skip_warnings(attributes)),
            }
        },
    )
    .await?;
    if meta.unparsed {
        warnings = warnings.saturating_add(1);
    }
    hits.sort_by(|left, right| right.unix.cmp(&left.unix).then(right.uid.cmp(&left.uid)));
    // A line the parser rejected closes the stream, so the bodies cannot be read.
    if meta.unparsed {
        return page(path, validity, &hits, query, warnings, None);
    }
    let (start, end) = window(&hits, query)?;
    if start == end {
        return page(path, validity, &hits, query, warnings, None);
    }
    let page_uids: Vec<u32> = hits[start..end].iter().map(|hit| hit.uid).collect();
    let mut bodies = HashMap::new();
    let bodies_reply = run_checked(
        session,
        &format!("UID FETCH {} (BODY.PEEK[])", uid_list(&page_uids)),
        |response| {
            if let Some((uid, body)) = body_of(response) {
                bodies.insert(uid, body);
            }
        },
    )
    .await?;
    if bodies_reply.unparsed {
        warnings = warnings.saturating_add(1);
    }
    page(path, validity, &hits, query, warnings, Some(&bodies))
}

struct Hit {
    uid: u32,
    unix: i64,
    day: String,
    from: String,
    subject: String,
    unread: bool,
    flagged: bool,
}

fn uid_list(uids: &[u32]) -> String {
    uids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn skip_warnings(attributes: &[AttributeValue<'_>]) -> u32 {
    let has_uid = attributes
        .iter()
        .any(|attribute| matches!(attribute, AttributeValue::Uid(uid) if *uid != 0));
    let has_date = attributes.iter().any(|attribute| {
        matches!(
            attribute,
            AttributeValue::InternalDate(value)
                if unix_from_internal(value).is_some() && calendar_day(value).is_some()
        )
    });
    u32::from(!has_uid) + u32::from(!has_date)
}

fn hit_from(attributes: &[AttributeValue<'_>]) -> Option<Hit> {
    let uid = attributes.iter().find_map(|attribute| match attribute {
        AttributeValue::Uid(uid) if *uid != 0 => Some(*uid),
        _ => None,
    })?;
    let internal = attributes.iter().find_map(|attribute| match attribute {
        AttributeValue::InternalDate(value) => Some(value.as_ref()),
        _ => None,
    })?;
    let unix = unix_from_internal(internal)?;
    let day = calendar_day(internal)?;
    let flags = flag_names(attributes);
    Some(Hit {
        uid,
        unix,
        day,
        from: from_text(attributes),
        subject: subject_text(attributes),
        unread: !flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
        flagged: flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Flagged")),
    })
}

fn body_of(response: &Response<'_>) -> Option<(u32, Vec<u8>)> {
    let Response::Fetch(_, attributes) = response else {
        return None;
    };
    let uid = attributes.iter().find_map(|attribute| match attribute {
        AttributeValue::Uid(uid) => Some(*uid),
        _ => None,
    })?;
    let body = attributes.iter().find_map(|attribute| match attribute {
        AttributeValue::BodySection {
            section: None,
            data: Some(data),
            ..
        }
        | AttributeValue::Rfc822(Some(data)) => Some(data.to_vec()),
        _ => None,
    })?;
    Some((uid, body))
}

fn window(hits: &[Hit], query: &MailSearch) -> Result<(usize, usize), CoreError> {
    let limit = page_limit(query.limit);
    let start = match &query.cursor {
        None => 0,
        Some(cursor) => {
            let (unix, uid) = parse_cursor(cursor)?;
            hits.iter()
                .position(|hit| hit.unix < unix || (hit.unix == unix && hit.uid < uid))
                .unwrap_or(hits.len())
        }
    };
    Ok((start, start.saturating_add(limit).min(hits.len())))
}

fn page(
    path: &MailboxPath,
    validity: UidValidity,
    hits: &[Hit],
    query: &MailSearch,
    mut warnings: u32,
    bodies: Option<&HashMap<u32, Vec<u8>>>,
) -> Result<SearchPage, CoreError> {
    let (start, end) = window(hits, query)?;
    let mut messages = Vec::new();
    for hit in &hits[start..end] {
        if let Some(bodies) = bodies {
            let parsed = bodies
                .get(&hit.uid)
                .is_some_and(|bytes| crate::mime::parses(bytes));
            if !parsed {
                warnings = warnings.saturating_add(1);
                continue;
            }
        }
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
        Some(format!("{}:{}", hits[end - 1].unix, hits[end - 1].uid))
    } else {
        None
    };
    Ok(SearchPage {
        messages,
        next_cursor,
        warnings,
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

fn parse_cursor(cursor: &str) -> Result<(i64, u32), CoreError> {
    let Some((stamp, uid)) = cursor.rsplit_once(':') else {
        return Err(CoreError::InvalidInput(
            "search cursor is not valid".to_owned(),
        ));
    };
    let unix = stamp
        .parse()
        .map_err(|_| CoreError::InvalidInput("search cursor is not valid".to_owned()))?;
    let uid = uid
        .parse()
        .map_err(|_| CoreError::InvalidInput("search cursor is not valid".to_owned()))?;
    if uid == 0 {
        return Err(CoreError::InvalidInput(
            "search cursor is not valid".to_owned(),
        ));
    }
    Ok((unix, uid))
}

fn criteria(query: &MailSearch) -> Result<String, CoreError> {
    let mut parts = Vec::new();
    let mut charset = false;
    if let Some(from) = &query.from {
        let (quoted, non_ascii) = quote_atom(from)?;
        charset |= non_ascii;
        parts.push(format!("FROM {quoted}"));
    }
    if let Some(to) = &query.to {
        let (quoted, non_ascii) = quote_atom(to)?;
        charset |= non_ascii;
        parts.push(format!("TO {quoted}"));
    }
    if let Some(subject) = &query.subject {
        let (quoted, non_ascii) = quote_atom(subject)?;
        charset |= non_ascii;
        parts.push(format!("SUBJECT {quoted}"));
    }
    if let Some(text) = &query.text {
        let (quoted, non_ascii) = quote_atom(text)?;
        charset |= non_ascii;
        parts.push(format!("TEXT {quoted}"));
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
    if charset {
        parts.insert(0, "CHARSET UTF-8".to_owned());
    }
    Ok(parts.join(" "))
}

fn quote_atom(value: &str) -> Result<(String, bool), CoreError> {
    if value.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        return Err(CoreError::InvalidInput(
            "search text cannot contain a line break".to_owned(),
        ));
    }
    if !value.is_ascii() {
        // ponytail: literals are sent in the same write; switch to a continuation handshake if a server refuses to read the literal until it has sent `+`.
        return Ok((format!("{{{}}}\r\n{value}", value.len()), true));
    }
    let plain = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
    if plain {
        return Ok((value.to_owned(), false));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok((format!("\"{escaped}\""), false))
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

fn from_text(attributes: &[AttributeValue<'_>]) -> String {
    let Some(address) = envelope(attributes)
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

fn subject_text(attributes: &[AttributeValue<'_>]) -> String {
    envelope(attributes)
        .and_then(|envelope| envelope.subject.as_ref())
        .map_or(String::new(), |subject| {
            String::from_utf8_lossy(subject).into_owned()
        })
}

fn envelope<'a>(
    attributes: &'a [AttributeValue<'a>],
) -> Option<&'a async_imap::imap_proto::Envelope<'a>> {
    attributes.iter().find_map(|attribute| match attribute {
        AttributeValue::Envelope(envelope) => Some(envelope.as_ref()),
        _ => None,
    })
}

fn flag_names<'a>(attributes: &'a [AttributeValue<'a>]) -> Vec<&'a str> {
    attributes
        .iter()
        .find_map(|attribute| match attribute {
            AttributeValue::Flags(flags) => {
                Some(flags.iter().map(AsRef::as_ref).collect::<Vec<_>>())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn lossy(value: Option<&[u8]>) -> String {
    value.map_or(String::new(), |bytes| {
        String::from_utf8_lossy(bytes).into_owned()
    })
}

fn calendar_day(value: &str) -> Option<String> {
    let (day, month, year) = split_date(value)?;
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn unix_from_internal(value: &str) -> Option<i64> {
    let (day, month, year) = split_date(value)?;
    let mut parts = value.split_whitespace();
    let _date = parts.next()?;
    let time = parts.next()?;
    let zone = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mut clock = time.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let offset = zone_offset(zone)?;
    let days = days_from_civil(year, month, day)?;
    let local = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    local.checked_sub(offset)
}

fn split_date(value: &str) -> Option<(u32, u32, i32)> {
    let date = value.split_whitespace().next()?;
    let mut parts = date.split('-');
    let day: u32 = parts.next()?.trim().parse().ok()?;
    let month = month_index(parts.next()?)?;
    let year: i32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || day == 0 || day > 31 {
        return None;
    }
    Some((day, month, year))
}

fn month_index(name: &str) -> Option<u32> {
    Some(match name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn zone_offset(zone: &str) -> Option<i64> {
    let (sign, rest) = zone.split_at_checked(1)?;
    if rest.len() != 4 {
        return None;
    }
    let hours: i64 = rest[..2].parse().ok()?;
    let minutes: i64 = rest[2..].parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    let seconds = hours * 3_600 + minutes * 60;
    match sign {
        "+" => Some(seconds),
        "-" => Some(-seconds),
        _ => None,
    }
}

/// Days since the Unix epoch for a civil date. Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year.div_euclid(400);
    let year_of_era = u64::try_from(year.checked_sub(era.checked_mul(400)?)?).ok()?;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + u64::from(day_of_year);
    let days = i64::from(era)
        .checked_mul(146_097)?
        .checked_add(i64::try_from(day_of_era).ok()?)?
        .checked_sub(719_468)?;
    Some(days)
}

#[cfg(test)]
mod tests {
    use ibridge_core::{CoreError, MailSearch, MailboxPath};
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

    #[tokio::test]
    async fn search_refuses_a_value_that_breaks_out_of_the_command() {
        let (fake, pooled) = pool(FakeScript::default());
        let injected = "x\r\nA9 UID STORE 1:* +FLAGS (\\Deleted)\r\nA10 EXPUNGE";
        let error = pooled
            .search(&MailSearch {
                mailbox: Some(MailboxPath::try_from("INBOX").expect("inbox")),
                text: Some(injected.to_owned()),
                ..query()
            })
            .await
            .expect_err("a value with a line break is rejected");
        assert!(
            matches!(error, CoreError::InvalidInput(_)),
            "the value is invalid input, got {error:?}"
        );
        assert!(
            !fake.saw("UID STORE") && !fake.saw("EXPUNGE"),
            "the injected command must not be written"
        );
        let nul = pooled
            .search(&MailSearch {
                mailbox: Some(MailboxPath::try_from("INBOX").expect("inbox")),
                subject: Some("a\0b".to_owned()),
                ..query()
            })
            .await
            .expect_err("NUL is rejected");
        assert!(matches!(nul, CoreError::InvalidInput(_)), "got {nul:?}");
    }

    #[tokio::test]
    async fn search_sends_non_ascii_as_utf8_literals() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (fake, pooled) = pool(FakeScript::default());
        let _page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                subject: Some("für".to_owned()),
                ..query()
            })
            .await
            .expect("a non-ASCII subject is searchable");
        let search = fake
            .lines()
            .into_iter()
            .find(|line| line.contains("SEARCH"))
            .expect("a SEARCH command was sent");
        assert!(
            search.contains("CHARSET UTF-8"),
            "non-ASCII search uses CHARSET UTF-8, line {search:?}"
        );
        assert!(
            search.contains("für"),
            "the value is sent as UTF-8, line {search:?}"
        );
    }

    #[tokio::test]
    async fn search_fetches_bodies_for_the_page_only() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (fake, pooled) = pool(FakeScript::default());
        let _page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                limit: 2,
                ..query()
            })
            .await
            .expect("page");
        let lines = fake.lines();
        let metadata = lines
            .iter()
            .find(|line| line.contains("INTERNALDATE") && !line.contains("BODY"));
        assert!(
            metadata.is_some(),
            "ordering fetches metadata, not every body, commands {lines:?}"
        );
        let body = lines
            .iter()
            .find(|line| line.contains("BODY.PEEK"))
            .map_or("", String::as_str);
        assert!(
            !body.contains("50") && !body.contains('7'),
            "bodies are fetched for the page only, line {body:?}"
        );
    }

    #[tokio::test]
    async fn search_orders_by_full_internal_date() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (_fake, pooled) = pool(FakeScript {
            later_clock: true,
            ..FakeScript::default()
        });
        let page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                limit: 2,
                ..query()
            })
            .await
            .expect("page");
        let uids: Vec<u32> = page
            .messages
            .iter()
            .map(|message| message.id.uid.get())
            .collect();
        assert_eq!(
            uids,
            vec![2, 4],
            "the later clock time on the same day comes first"
        );
    }

    #[tokio::test]
    async fn search_counts_a_hit_without_a_date() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (_fake, pooled) = pool(FakeScript {
            missing_date: true,
            ..FakeScript::default()
        });
        let page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                ..query()
            })
            .await
            .expect("a hit without a date does not fail the search");
        let uids: Vec<u32> = page
            .messages
            .iter()
            .map(|message| message.id.uid.get())
            .collect();
        assert!(
            !uids.contains(&9),
            "the undated hit is skipped, got {uids:?}"
        );
        assert!(
            page.warnings >= 2,
            "the undated hit and the unreadable message are both warnings, got {}",
            page.warnings
        );
    }

    #[tokio::test]
    async fn search_counts_an_unparsed_fetch() {
        let inbox = MailboxPath::try_from("INBOX").expect("inbox");
        let (_fake, pooled) = pool(FakeScript {
            corrupt_fetch: true,
            ..FakeScript::default()
        });
        let page = pooled
            .search(&MailSearch {
                mailbox: Some(inbox),
                ..query()
            })
            .await
            .expect("one unparsed FETCH does not fail the search");
        assert!(
            page.warnings >= 1,
            "the unparsed response is a warning, got {}",
            page.warnings
        );
    }
}
