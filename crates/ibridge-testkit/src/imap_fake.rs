// SPDX-License-Identifier: Apache-2.0

//! Scripted IMAP server for contract tests.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, Mutex};

use imap_codec::decode::{CommandDecodeError, Decoder};
use imap_codec::encode::Encoder;
use imap_codec::imap_types::command::{Command, CommandBody};
use imap_codec::imap_types::core::{Atom, LiteralMode, QuotedChar, Tag};
use imap_codec::imap_types::flag::{Flag, FlagNameAttribute, StoreType};
use imap_codec::imap_types::mailbox::Mailbox;
use imap_codec::imap_types::response::{
    Capability, Code, CodeOther, Data, Greeting, Response, Status,
};
use imap_codec::imap_types::sequence::{SeqOrUid, Sequence};
use imap_codec::imap_types::status::StatusDataItem;
use imap_codec::{CommandCodec, GreetingCodec, ResponseCodec};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Which iCloud quirks a [`FakeImap`] injects.
#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one independent server quirk a test turns on"
)]
pub struct FakeScript {
    /// `LOGIN` is rejected.
    pub reject_login: bool,
    /// `LOGIN` with any other password is rejected. `None` accepts every password.
    pub accepts_password: Option<String>,
    /// `LIST` answers `NO [THROTTLED]`.
    pub throttle_list: bool,
    /// `UID SEARCH` answers `NO [THROTTLED]`.
    pub throttle_search: bool,
    /// `UID FETCH` answers `NO [THROTTLED]`.
    pub throttle_fetch: bool,
    /// `LIST` includes a `\\Noselect` row, a `\\NonExistent` row and a path the client must skip.
    pub list_noselect: bool,
    /// `STATUS` for `Notes` answers `NO`.
    pub fail_status: bool,
    /// The first `FETCH` response is not valid IMAP.
    pub corrupt_fetch: bool,
    /// Search results include a hit whose `FETCH` has no `INTERNALDATE`.
    pub missing_date: bool,
    /// The lower inbox UID on 3 Nov has a later clock time.
    pub later_clock: bool,
    /// Inbox UID 8 is a text attachment longer than 40,000 characters.
    pub long_attachment: bool,
    /// `UIDVALIDITY` advertised by `SELECT`. `None` means 1.
    pub uid_validity: Option<u32>,
    /// `UID MOVE` is rejected, so the client must copy, delete, and expunge that uid.
    pub reject_uid_move: bool,
    /// `APPEND` is rejected.
    pub fail_append: bool,
    /// A user folder named `Archive` is listed before the `\Archive` mailbox.
    pub archive_name_shadow: bool,
    /// Inbox UIDs 60 and 61 are fixture-recorder markers: their subjects start with `[ibridge-fixture]`.
    /// `UID SEARCH` still answers every inbox UID, as a loose server could, so a client must filter.
    pub marker_messages: bool,
    /// Per-run token in the marker subjects: `[ibridge-fixture] <nonce> seed one`. `None` means `unset`.
    pub marker_nonce: Option<String>,
    /// Inbox UID 62 is a marker left over from another run: `[ibridge-fixture] stale seed old`.
    /// It needs `marker_messages`.
    pub stale_marker: bool,
    /// Inbox UID 70 offers mailto, an `https` link and one-click. UID 71 offers an `http`
    /// link only. UID 72 has a mailto with `cc`, `bcc` and `to` fields. UID 73 has a mailto
    /// with two recipients and nothing else. UID 74 has a bare mailto. UID 75 has an `https` link and no `List-Unsubscribe-Post`. UID 76 has an
    /// `https` link and a mailto, no `List-Unsubscribe-Post`. UID 77 has an `https` link and `List-Unsubscribe-Post`,
    /// no mailto. UID 78 has a mailto with a subject and a body, nothing else. They are not search hits.
    pub unsubscribe_messages: bool,
}

#[derive(Debug)]
struct Observed {
    connections: usize,
    logins: usize,
    commands: Vec<&'static str>,
    lines: Vec<String>,
    appended: Vec<AppendedMessage>,
    /// Bytes of a command the decoder rejected. Successful `LOGIN` is never stored.
    inbound: Vec<u8>,
    /// Inbox UIDs that carry `\Deleted`. UID 99 starts deleted and is not the message under test.
    inbox_deleted: Vec<u32>,
    /// Flags stored on inbox UID 4. A repeated `+FLAGS` does not insert twice.
    flags_on_four: BTreeSet<String>,
}

/// One message a client appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendedMessage {
    /// Mailbox name from the `APPEND` command.
    pub mailbox: String,
    /// Flag atoms from the command, such as `\Draft`.
    pub flags: String,
    /// Literal bytes, without the IMAP framing.
    pub bytes: Vec<u8>,
}

/// A scripted IMAP server on an in-memory duplex.
///
/// The greeting advertises `IMAP4REV1` and `AUTH=PLAIN` only. After `LOGIN`,
/// `CAPABILITY` adds `SPECIAL-USE` and `UIDPLUS`. `MOVE` and `IDLE` are never
/// advertised. `LIST` returns the iCloud special-use set, unless
/// [`FakeScript::throttle_list`] is set. `INBOX` holds three readable
/// messages and one that does not parse.
#[derive(Clone, Debug)]
pub struct FakeImap {
    script: FakeScript,
    observed: Arc<Mutex<Observed>>,
}

impl FakeImap {
    /// Starts a server. Connections begin when [`Self::connect`] is called.
    #[must_use]
    pub fn spawn(script: FakeScript) -> Self {
        Self {
            script,
            observed: Arc::new(Mutex::new(Observed {
                connections: 0,
                logins: 0,
                commands: Vec::new(),
                lines: Vec::new(),
                appended: Vec::new(),
                inbound: Vec::new(),
                inbox_deleted: vec![99],
                flags_on_four: BTreeSet::new(),
            })),
        }
    }

    /// How many duplex connections have been opened.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.observed().connections
    }

    /// How many `LOGIN` commands have arrived, including rejected ones.
    #[must_use]
    pub fn login_count(&self) -> usize {
        self.observed().logins
    }

    /// Command names in arrival order. Arguments, including passwords, are not stored.
    #[must_use]
    pub fn commands(&self) -> Vec<&'static str> {
        self.observed().commands.clone()
    }

    /// Command lines in arrival order. `LOGIN` is stored as the name only, so the password is not kept.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.observed().lines.clone()
    }

    /// Messages stored by `APPEND`, in arrival order.
    #[must_use]
    pub fn appended(&self) -> Vec<AppendedMessage> {
        self.observed().appended.clone()
    }

    /// Inbox UIDs that still carry `\Deleted`.
    #[must_use]
    pub fn deleted_uids(&self, mailbox: &str) -> Vec<u32> {
        if mailbox == "INBOX" {
            self.observed().inbox_deleted.clone()
        } else {
            Vec::new()
        }
    }

    /// Whether inbox UID 4 carries `flag`. One when it is in the flag set.
    #[must_use]
    pub fn flag_count(&self, mailbox: &str, uid: u32, flag: &str) -> usize {
        if mailbox == "INBOX" && uid == 4 {
            usize::from(self.observed().flags_on_four.contains(flag))
        } else {
            0
        }
    }

    /// Whether a successfully parsed command, or a command the decoder rejected, contains `needle`.
    #[must_use]
    pub fn saw(&self, needle: &str) -> bool {
        let observed = self.observed();
        observed.lines.iter().any(|line| line.contains(needle))
            || String::from_utf8_lossy(&observed.inbound).contains(needle)
    }

    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().expect("observed lock")
    }

    /// Opens one client half of a duplex and serves IMAP on the other half.
    #[must_use]
    pub fn connect(&self) -> DuplexStream {
        // One FETCH of the inbox is about 110 KiB. The buffer has to hold it
        // while the client is still sending the command.
        let (client, server) = tokio::io::duplex(512 * 1024);
        let script = self.script.clone();
        let observed = Arc::clone(&self.observed);
        tokio::spawn(async move {
            let _ = serve(server, script, observed).await;
        });
        client
    }
}

async fn serve(
    mut stream: DuplexStream,
    script: FakeScript,
    observed: Arc<Mutex<Observed>>,
) -> io::Result<()> {
    {
        let mut observed = observed.lock().expect("observed lock");
        observed.connections += 1;
    }
    stream.write_all(&greeting()).await?;
    stream.flush().await?;

    let commands = CommandCodec::new();
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    let mut selected = String::new();
    let mut next_uid = 1_u32;
    let mut literal_acked = false;
    loop {
        let reply = match commands.decode(&buf) {
            Ok((rest, command)) => {
                literal_acked = false;
                let consumed = buf.len() - rest.len();
                if consumed == 0 {
                    break;
                }
                let raw = String::from_utf8_lossy(&buf[..consumed]).into_owned();
                let reply = command_reply(
                    &command,
                    &raw,
                    &script,
                    &mut selected,
                    &mut next_uid,
                    &observed,
                );
                buf.drain(..consumed);
                Some(reply)
            }
            Err(CommandDecodeError::Incomplete) => None,
            Err(CommandDecodeError::LiteralFound { mode, .. }) => {
                if mode == LiteralMode::Sync && !literal_acked {
                    stream.write_all(b"+ go\r\n").await?;
                    stream.flush().await?;
                    literal_acked = true;
                }
                None
            }
            Err(_) => {
                let line_end = buf.windows(2).position(|window| window == b"\r\n");
                let expunged = line_end.and_then(|end| {
                    let line = String::from_utf8_lossy(&buf[..end]).into_owned();
                    uid_expunge(&line).map(|(tag, uid)| (end, tag, uid, line))
                });
                if let Some((end, tag, uid, line)) = expunged {
                    {
                        let mut observed = observed.lock().expect("observed lock");
                        observed.commands.push("EXPUNGE");
                        observed.lines.push(line);
                        observed.inbox_deleted.retain(|kept| *kept != uid);
                    }
                    buf.drain(..end + 2);
                    Some(format!("{tag} OK expunged\r\n").into_bytes())
                } else {
                    let mut observed = observed.lock().expect("observed lock");
                    observed.inbound.extend_from_slice(&buf);
                    break;
                }
            }
        };
        if let Some(reply) = reply {
            stream.write_all(&reply).await?;
            stream.flush().await?;
            continue;
        }
        let read = stream.read(&mut tmp).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..read]);
    }
    Ok(())
}

fn command_reply(
    command: &Command<'_>,
    raw: &str,
    script: &FakeScript,
    selected: &mut String,
    next_uid: &mut u32,
    observed: &Arc<Mutex<Observed>>,
) -> Vec<u8> {
    if let CommandBody::Select { mailbox } = &command.body {
        *selected = mailbox_name(mailbox);
    }
    let stored = appended_from(command, next_uid);
    let appended_uid = stored.as_ref().map(|(uid, _)| *uid);
    let fail_append = script.fail_append && matches!(command.body, CommandBody::Append { .. });
    {
        let mut observed = observed.lock().expect("observed lock");
        observed.commands.push(command.name());
        observed.lines.push(recorded_line(command, raw));
        if matches!(command.body, CommandBody::Login { .. }) {
            observed.logins += 1;
        }
        if let Some((_, message)) = stored
            && !fail_append
        {
            observed.appended.push(message);
        }
        apply_mailbox(command, &mut observed);
    }
    if fail_append {
        tagged(Status::no(Some(command.tag.clone()), None, "append failed").expect("no text"))
    } else {
        appended_uid.map_or_else(
            || encode_reply(command, script, selected),
            |uid| append_ok(&command.tag, script.uid_validity.unwrap_or(1), uid),
        )
    }
}

fn appended_from(command: &Command<'_>, next_uid: &mut u32) -> Option<(u32, AppendedMessage)> {
    let CommandBody::Append {
        mailbox,
        flags,
        message,
        ..
    } = &command.body
    else {
        return None;
    };
    let uid = *next_uid;
    *next_uid = next_uid.saturating_add(1);
    let flags = flags
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    Some((
        uid,
        AppendedMessage {
            mailbox: mailbox_name(mailbox),
            flags,
            bytes: message.as_ref().to_vec(),
        },
    ))
}

fn append_ok(tag: &Tag<'_>, validity: u32, uid: u32) -> Vec<u8> {
    format!(
        "{} OK [APPENDUID {validity} {uid}] appended\r\n",
        tag.inner()
    )
    .into_bytes()
}

fn apply_mailbox(command: &Command<'_>, observed: &mut Observed) {
    match &command.body {
        CommandBody::Store {
            sequence_set,
            kind,
            flags,
            uid: true,
            ..
        } => {
            let Some(uid) = single_uid(sequence_set) else {
                return;
            };
            if uid == 4 {
                apply_flag_set(&mut observed.flags_on_four, *kind, flags);
            }
            if matches!(kind, StoreType::Add)
                && flags.iter().any(|flag| matches!(flag, Flag::Deleted))
                && !observed.inbox_deleted.contains(&uid)
            {
                observed.inbox_deleted.push(uid);
            }
        }
        CommandBody::Expunge => observed.inbox_deleted.clear(),
        _ => {}
    }
}

fn apply_flag_set(set: &mut BTreeSet<String>, kind: StoreType, flags: &[Flag<'_>]) {
    let names = flags.iter().map(ToString::to_string);
    match kind {
        StoreType::Add => set.extend(names),
        StoreType::Remove => {
            for name in names {
                set.remove(&name);
            }
        }
        StoreType::Replace => {
            set.clear();
            set.extend(names);
        }
    }
}

fn single_uid(set: &imap_codec::imap_types::sequence::SequenceSet) -> Option<u32> {
    let Sequence::Single(SeqOrUid::Value(uid)) = set.0.as_ref().first()? else {
        return None;
    };
    Some(uid.get())
}

fn uid_expunge(line: &str) -> Option<(String, u32)> {
    let mut parts = line.split_whitespace();
    let tag = parts.next()?;
    let uid_word = parts.next()?;
    let verb = parts.next()?;
    if !uid_word.eq_ignore_ascii_case("UID") || !verb.eq_ignore_ascii_case("EXPUNGE") {
        return None;
    }
    let uid = parts.next()?.parse().ok()?;
    Some((tag.to_owned(), uid))
}

fn recorded_line(command: &Command<'_>, raw: &str) -> String {
    if matches!(command.body, CommandBody::Login { .. }) {
        return "LOGIN".to_owned();
    }
    raw.trim_end_matches(['\r', '\n']).to_owned()
}

fn mailbox_name(mailbox: &Mailbox<'_>) -> String {
    match mailbox {
        Mailbox::Inbox => "INBOX".to_owned(),
        Mailbox::Other(other) => String::from_utf8_lossy(other.as_ref()).into_owned(),
    }
}

fn greeting() -> Vec<u8> {
    let code = Code::capability(names(&["IMAP4REV1", "AUTH=PLAIN"])).expect("greeting caps");
    let greeting = Greeting::ok(Some(code), "ready").expect("greeting");
    GreetingCodec::new().encode(&greeting).dump()
}

fn encode_reply(command: &Command<'_>, script: &FakeScript, selected: &str) -> Vec<u8> {
    let tag = &command.tag;
    match &command.body {
        CommandBody::Login { password, .. }
            if script
                .accepts_password
                .as_ref()
                .is_some_and(|expected| password.declassify().as_ref() != expected.as_bytes()) =>
        {
            tagged(Status::no(Some(tag.clone()), None, "server-said-no").expect("no text"))
        }
        CommandBody::Login { .. } if script.reject_login => {
            tagged(Status::no(Some(tag.clone()), None, "server-said-no").expect("no text"))
        }
        CommandBody::Capability => {
            let mut bytes = untagged(
                Data::capability(names(&[
                    "IMAP4REV1",
                    "AUTH=PLAIN",
                    "SPECIAL-USE",
                    "UIDPLUS",
                ]))
                .expect("session caps"),
            );
            bytes.extend(tagged_ok(tag));
            bytes
        }
        CommandBody::List { .. } if script.throttle_list => throttled(tag),
        CommandBody::List { .. } => list_reply(tag, script),
        CommandBody::Status { mailbox, .. }
            if script.fail_status && mailbox_name(mailbox) == "Notes" =>
        {
            tagged(Status::no(Some(tag.clone()), None, "no status").expect("status text"))
        }
        CommandBody::Status { mailbox, .. } => status_reply(tag, mailbox),
        CommandBody::Select { .. } => select_reply(tag, selected, script),
        CommandBody::Search { .. } if script.throttle_search => throttled(tag),
        CommandBody::Search { .. } if selected == "INBOX" => search_reply(tag, &inbox_uids(script)),
        CommandBody::Search { .. } => search_reply(tag, &[]),
        CommandBody::Fetch { .. } if script.throttle_fetch => throttled(tag),
        CommandBody::Fetch { .. } if selected == "INBOX" => fetch_inbox(tag, script),
        CommandBody::Move { uid: true, .. } if script.reject_uid_move => {
            tagged(Status::no(Some(tag.clone()), None, "no move").expect("no text"))
        }
        CommandBody::Login { .. }
        | CommandBody::Noop
        | CommandBody::Move { .. }
        | CommandBody::Copy { .. }
        | CommandBody::Store { .. }
        | CommandBody::Expunge => tagged_ok(tag),
        _ => tagged(Status::bad(Some(tag.clone()), None, "unknown").expect("bad text")),
    }
}

fn names(names: &[&'static str]) -> Vec<Capability<'static>> {
    names
        .iter()
        .copied()
        .map(|name| Capability::try_from(name).expect("capability name is valid"))
        .collect()
}

const MAILBOXES: &[(&str, Option<&str>, u32, u32)] = &[
    ("INBOX", None, 3, 1),
    ("Sent Messages", Some("Sent"), 4, 2),
    ("Deleted Messages", Some("Trash"), 0, 0),
    ("Junk", Some("Junk"), 0, 0),
    ("Drafts", Some("Drafts"), 0, 0),
    ("Archive", Some("Archive"), 0, 0),
    ("Notes", None, 0, 0),
];

fn list_reply(tag: &Tag<'_>, script: &FakeScript) -> Vec<u8> {
    let mut bytes = Vec::new();
    if script.archive_name_shadow {
        bytes.extend(untagged(list_data("Archive", None)));
    }
    for (name, attribute, _, _) in MAILBOXES {
        let name = if script.archive_name_shadow && *name == "Archive" {
            "Archived Messages"
        } else {
            *name
        };
        bytes.extend(untagged(list_data(name, *attribute)));
    }
    if script.list_noselect {
        bytes.extend(untagged(list_data("All Mail", Some("Noselect"))));
        bytes.extend(untagged(list_data("Ghost", Some("NonExistent"))));
        bytes.extend(untagged(list_data("http://evil", None)));
    }
    bytes.extend(tagged_ok(tag));
    bytes
}

fn list_data(name: &'static str, attribute: Option<&'static str>) -> Data<'static> {
    let items = attribute.map_or(Vec::new(), |attribute| {
        vec![FlagNameAttribute::from(
            Atom::try_from(attribute).expect("attribute is an atom"),
        )]
    });
    Data::List {
        items,
        delimiter: Some(QuotedChar::try_from('/').expect("slash is a quoted char")),
        mailbox: Mailbox::try_from(name).expect("mailbox name"),
    }
}

fn status_reply(tag: &Tag<'_>, mailbox: &Mailbox<'_>) -> Vec<u8> {
    let name = mailbox_name(mailbox);
    let (total, unread) = MAILBOXES
        .iter()
        .find(|(known, _, _, _)| *known == name)
        .map_or((0, 0), |(_, _, total, unread)| (*total, *unread));
    let mut bytes = untagged(Data::Status {
        mailbox: mailbox.clone(),
        items: Cow::Owned(vec![
            StatusDataItem::Messages(total),
            StatusDataItem::Unseen(unread),
        ]),
    });
    bytes.extend(tagged_ok(tag));
    bytes
}

fn select_reply(tag: &Tag<'_>, selected: &str, script: &FakeScript) -> Vec<u8> {
    let total = MAILBOXES
        .iter()
        .find(|(name, _, _, _)| *name == selected)
        .map_or(0, |(_, _, total, _)| *total);
    let validity = script.uid_validity.unwrap_or(1);
    let mut bytes = format!(
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* {total} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY {validity}] uid\r\n* OK [UIDNEXT 51] uid\r\n"
    )
    .into_bytes();
    bytes.extend(tagged_ok(tag));
    bytes
}

fn inbox_uids(script: &FakeScript) -> Vec<u32> {
    let mut uids = vec![4, 2, 50, 7];
    if script.missing_date {
        uids.push(9);
    }
    if script.marker_messages {
        uids.extend([60, 61]);
        if script.stale_marker {
            uids.push(62);
        }
    }
    uids
}

fn throttled(tag: &Tag<'_>) -> Vec<u8> {
    tagged(
        Status::no(
            Some(tag.clone()),
            Some(Code::Other(CodeOther::unvalidated(b"THROTTLED".as_slice()))),
            "THROTTLED",
        )
        .expect("throttle text"),
    )
}

fn search_reply(tag: &Tag<'_>, uids: &[u32]) -> Vec<u8> {
    let numbers = uids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let mut bytes = format!("* SEARCH {numbers}\r\n").into_bytes();
    bytes.extend(tagged_ok(tag));
    bytes
}

fn fetch_inbox(tag: &Tag<'_>, script: &FakeScript) -> Vec<u8> {
    let mut bytes = Vec::new();
    if script.corrupt_fetch {
        bytes.extend(b"* 1 FETCH !!!\r\n");
    }
    let mut long = vec![b'x'; 40_000];
    long.extend(b"0123456789");
    let older_clock = if script.later_clock {
        "18:00:00"
    } else {
        "00:00:00"
    };
    let older_head = format!(
        r#"INTERNALDATE "03-Nov-2026 {older_clock} +0000" FLAGS (\Seen) ENVELOPE (NIL "older-same-day" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL)"#
    );
    let mut messages = vec![
        (
            4,
            r#"INTERNALDATE "03-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "newer" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL)"#
                .to_owned(),
            headed(
                "text/html; charset=utf-8",
                "Message-ID: <parent@example.com>\r\nReferences: <root@example.com>\r\n",
                b"<p>Hello <b>there</b></p>",
            ),
        ),
        (
            2,
            older_head,
            single_part("text/plain; charset=utf-8", &long),
        ),
        (
            50,
            r#"INTERNALDATE "01-Nov-2026 00:00:00 +0000" FLAGS (\Seen \Flagged) ENVELOPE (NIL "oldest" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL)"#
                .to_owned(),
            note_and_blob(),
        ),
        (
            7,
            r#"INTERNALDATE "01-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "bad" NIL NIL NIL NIL NIL NIL NIL NIL)"#
                .to_owned(),
            b"not-a-message".to_vec(),
        ),
    ];
    if script.missing_date {
        messages.push((
            9,
            r#"FLAGS () ENVELOPE (NIL "nodate" NIL NIL NIL NIL NIL NIL NIL NIL)"#.to_owned(),
            single_part("text/plain; charset=utf-8", b"dated"),
        ));
    }
    if script.long_attachment {
        messages.push((
            8,
            r#"INTERNALDATE "02-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "long" NIL NIL NIL NIL NIL NIL NIL NIL)"#
                .to_owned(),
            long_note(),
        ));
    }
    if script.marker_messages {
        let nonce = script.marker_nonce.as_deref().unwrap_or("unset");
        messages.extend([
            marker_message(60, nonce, "one"),
            marker_message(61, nonce, "two"),
        ]);
        if script.stale_marker {
            messages.push(marker_message(62, "stale", "old"));
        }
    }
    if script.unsubscribe_messages {
        messages.extend([
            list_message(
                70,
                "<mailto:unsub@example.com?subject=unsubscribe&body=remove%20me>, <https://example.com/u?id=1>\r\n\
                 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
            ),
            list_message(71, "<http://example.com/u?id=2>\r\n"),
            list_message(
                72,
                "<mailto:a@example.com?cc=evil1@example.net&bcc=evil2@example.net&to=evil3@example.net&subject=hi>\r\n",
            ),
            list_message(73, "<mailto:a@example.com,b@example.com>\r\n"),
            list_message(74, "<mailto:bare@example.com>\r\n"),
            list_message(75, "<https://example.com/u?id=3>\r\n"),
            list_message(
                76,
                "<https://example.com/u?id=4>, <mailto:m@example.com>\r\n",
            ),
            list_message(
                78,
                "<mailto:unsub@example.com?subject=unsubscribe&body=remove%20me>\r\n",
            ),
            list_message(
                77,
                "<https://example.com/u?id=5>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
            ),
        ]);
    }
    for (seq, (uid, head, body)) in messages.into_iter().enumerate() {
        let seq = u32::try_from(seq.saturating_add(1)).unwrap_or(1);
        push_fetch(&mut bytes, seq, uid, &head, &body);
    }
    bytes.extend(tagged_ok(tag));
    bytes
}

fn list_message(uid: u32, list_unsubscribe: &str) -> (u32, String, Vec<u8>) {
    let head = r#"INTERNALDATE "05-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "newsletter" (("News" NIL "news" "example.com")) NIL NIL NIL NIL NIL NIL NIL)"#;
    let raw = format!(
        "Message-ID: <list-{uid}@example.com>\r\n\
         From: News <news@example.com>\r\n\
         To: ada@icloud.com\r\n\
         Subject: newsletter\r\n\
         List-Unsubscribe: {list_unsubscribe}\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This week's news"
    );
    (uid, head.to_owned(), raw.into_bytes())
}

fn marker_message(uid: u32, nonce: &str, word: &str) -> (u32, String, Vec<u8>) {
    let subject = format!("[ibridge-fixture] {nonce} seed {word}");
    let head = format!(
        r#"INTERNALDATE "04-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "{subject}" (("Ada Lovelace" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL)"#
    );
    let raw = format!(
        "Message-ID: <marker-{word}@mail.icloud.com>\r\n\
         From: \"Ada Lovelace\" <ada@icloud.com>\r\n\
         To: ada@icloud.com\r\n\
         Subject: {subject}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         marker body {word}"
    );
    (uid, head, raw.into_bytes())
}

fn long_note() -> Vec<u8> {
    let mut bytes = b"MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"b\"\r\n\
        \r\n\
        --b\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        Content-Disposition: attachment; filename=\"long.txt\"\r\n\
        \r\n"
        .to_vec();
    bytes.extend(std::iter::repeat_n(b'a', 40_010));
    bytes.extend(b"\r\n--b--");
    bytes
}

fn push_fetch(out: &mut Vec<u8>, seq: u32, uid: u32, head: &str, body: &[u8]) {
    let prefix = format!(
        "* {seq} FETCH (UID {uid} {head} BODY[] {{{}}}\r\n",
        body.len()
    );
    out.extend(prefix.as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b")\r\n");
}

fn single_part(content_type: &str, body: &[u8]) -> Vec<u8> {
    headed(content_type, "", body)
}

fn headed(content_type: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{headers}Content-Type: {content_type}\r\n\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn note_and_blob() -> Vec<u8> {
    let mut bytes = b"MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"b\"\r\n\
        \r\n\
        --b\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        Content-Disposition: attachment; filename=\"note.txt\"\r\n\
        \r\n\
        note\r\n\
        --b\r\n\
        Content-Type: application/octet-stream\r\n\
        Content-Disposition: attachment; filename=\"blob.bin\"\r\n\
        \r\n"
        .to_vec();
    bytes.extend(std::iter::repeat_n(1_u8, 65_537));
    bytes.extend(b"\r\n--b--");
    bytes
}

fn tagged_ok(tag: &Tag<'_>) -> Vec<u8> {
    tagged(Status::ok(Some(tag.clone()), None, "ok").expect("ok text"))
}

fn tagged(status: Status<'_>) -> Vec<u8> {
    ResponseCodec::new()
        .encode(&Response::Status(status))
        .dump()
}

fn untagged(data: Data<'_>) -> Vec<u8> {
    ResponseCodec::new().encode(&Response::Data(data)).dump()
}

#[cfg(test)]
mod tests {
    use async_imap::types::NameAttribute;
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    use super::{FakeImap, FakeScript};

    #[tokio::test]
    async fn fake_answers_login_and_list() {
        let fake = FakeImap::spawn(FakeScript::default());
        let mut stream = fake.connect();
        let mut greeting = [0_u8; 512];
        let read = stream
            .read(&mut greeting)
            .await
            .expect("greeting should arrive");
        assert!(read > 0, "the server must send a greeting");
        let greeting = String::from_utf8_lossy(&greeting[..read]);
        let upper = greeting.to_ascii_uppercase();
        assert!(
            !upper.contains("MOVE") && !upper.contains("IDLE"),
            "greeting must not advertise MOVE or IDLE, got {greeting}"
        );

        let client = async_imap::Client::new(stream);
        let mut session = client
            .login("ada@icloud.com", "test-secret")
            .await
            .map_err(|(error, _)| error)
            .expect("login should succeed");

        let caps = session.capabilities().await.expect("capability");
        assert!(
            caps.has_str("SPECIAL-USE"),
            "post-login capability must differ from the greeting and include SPECIAL-USE"
        );
        assert!(
            !caps.has_str("MOVE") && !caps.has_str("IDLE"),
            "MOVE and IDLE stay unadvertised"
        );

        let mut listed = session
            .list(Some(""), Some("*"))
            .await
            .expect("list should succeed");
        let mut saw_sent = false;
        while let Some(name) = listed.next().await {
            let name = name.expect("list row");
            if name.name() == "Sent Messages" && name.attributes().contains(&NameAttribute::Sent) {
                saw_sent = true;
            }
        }
        assert!(saw_sent, "LIST must return Sent Messages with \\Sent");

        let throttled = FakeImap::spawn(FakeScript {
            throttle_list: true,
            ..FakeScript::default()
        });
        let stream = throttled.connect();
        // Drain the greeting so LOGIN is the next exchange.
        let mut stream = stream;
        let mut buf = [0_u8; 512];
        let _ = stream.read(&mut buf).await;
        let client = async_imap::Client::new(stream);
        let mut session = client
            .login("ada@icloud.com", "test-secret")
            .await
            .map_err(|(error, _)| error)
            .expect("login still succeeds when list is throttled");
        // `Session::list` drops the tagged completion, so a `NO` never
        // appears on that stream. This is the call that returns it.
        let error = session
            .run_command_and_check_ok("LIST \"\" *")
            .await
            .expect_err("a throttled LIST must fail");
        let rendered = error.to_string();
        assert!(
            rendered.to_ascii_uppercase().contains("THROTTLED"),
            "NO [THROTTLED] must be visible to the client, got {rendered}"
        );
    }
}
