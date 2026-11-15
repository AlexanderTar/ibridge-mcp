// SPDX-License-Identifier: Apache-2.0

//! Scripted IMAP server for contract tests.

use std::borrow::Cow;
use std::io;
use std::sync::{Arc, Mutex};

use imap_codec::decode::{CommandDecodeError, Decoder};
use imap_codec::encode::Encoder;
use imap_codec::imap_types::command::{Command, CommandBody};
use imap_codec::imap_types::core::{Atom, QuotedChar, Tag};
use imap_codec::imap_types::flag::FlagNameAttribute;
use imap_codec::imap_types::mailbox::Mailbox;
use imap_codec::imap_types::response::{
    Capability, Code, CodeOther, Data, Greeting, Response, Status,
};
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
}

#[derive(Debug)]
struct Observed {
    connections: usize,
    logins: usize,
    commands: Vec<&'static str>,
    lines: Vec<String>,
    /// Bytes of a command the decoder rejected. Successful `LOGIN` is never stored.
    inbound: Vec<u8>,
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
                inbound: Vec::new(),
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
    loop {
        let reply = match commands.decode(&buf) {
            Ok((rest, command)) => {
                let consumed = buf.len() - rest.len();
                if consumed == 0 {
                    break;
                }
                let raw = String::from_utf8_lossy(&buf[..consumed]).into_owned();
                if let CommandBody::Select { mailbox } = &command.body {
                    selected = mailbox_name(mailbox);
                }
                {
                    let mut observed = observed.lock().expect("observed lock");
                    observed.commands.push(command.name());
                    observed.lines.push(recorded_line(&command, &raw));
                    if matches!(command.body, CommandBody::Login { .. }) {
                        observed.logins += 1;
                    }
                }
                let reply = encode_reply(&command, &script, &selected);
                buf.drain(..consumed);
                Some(reply)
            }
            Err(CommandDecodeError::Incomplete) => None,
            Err(_) => {
                let mut observed = observed.lock().expect("observed lock");
                observed.inbound.extend_from_slice(&buf);
                break;
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
        CommandBody::Login { .. } if script.reject_login => {
            tagged(Status::no(Some(tag.clone()), None, "server-said-no").expect("no text"))
        }
        CommandBody::Login { .. } | CommandBody::Noop => tagged_ok(tag),
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
    for (name, attribute, _, _) in MAILBOXES {
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
            single_part("text/html; charset=utf-8", b"<p>Hello <b>there</b></p>"),
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
    for (seq, (uid, head, body)) in messages.into_iter().enumerate() {
        let seq = u32::try_from(seq.saturating_add(1)).unwrap_or(1);
        push_fetch(&mut bytes, seq, uid, &head, &body);
    }
    bytes.extend(tagged_ok(tag));
    bytes
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
    let mut bytes = format!("Content-Type: {content_type}\r\n\r\n").into_bytes();
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
