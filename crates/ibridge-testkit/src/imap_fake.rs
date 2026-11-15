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
pub struct FakeScript {
    /// `LOGIN` is rejected.
    pub reject_login: bool,
    /// `LIST` answers `NO [THROTTLED]`.
    pub throttle_list: bool,
}

#[derive(Debug)]
struct Observed {
    connections: usize,
    logins: usize,
    commands: Vec<&'static str>,
    lines: Vec<String>,
}

/// A scripted IMAP server on an in-memory duplex.
///
/// The greeting advertises `IMAP4REV1` and `AUTH=PLAIN` only. After `LOGIN`,
/// `CAPABILITY` adds `SPECIAL-USE` and `UIDPLUS`. `MOVE` and `IDLE` are never
/// advertised. `LIST` returns the iCloud special-use set, unless
/// [`FakeScript::throttle_list`] is set. `INBOX` holds three messages.
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

    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().expect("observed lock")
    }

    /// Opens one client half of a duplex and serves IMAP on the other half.
    #[must_use]
    pub fn connect(&self) -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
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
            Err(_) => break,
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
        CommandBody::List { .. } if script.throttle_list => tagged(
            Status::no(
                Some(tag.clone()),
                Some(Code::Other(CodeOther::unvalidated(b"THROTTLED".as_slice()))),
                "THROTTLED",
            )
            .expect("throttle text"),
        ),
        CommandBody::List { .. } => list_reply(tag),
        CommandBody::Status { mailbox, .. } => status_reply(tag, mailbox),
        CommandBody::Select { .. } => select_reply(tag, selected),
        CommandBody::Search { .. } if selected == "INBOX" => search_reply(tag, &[4, 2, 50]),
        CommandBody::Search { .. } => search_reply(tag, &[]),
        CommandBody::Fetch { .. } if selected == "INBOX" => fetch_inbox(tag),
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

fn list_reply(tag: &Tag<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, attribute, _, _) in MAILBOXES {
        bytes.extend(untagged(list_data(name, *attribute)));
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

fn select_reply(tag: &Tag<'_>, selected: &str) -> Vec<u8> {
    let total = MAILBOXES
        .iter()
        .find(|(name, _, _, _)| *name == selected)
        .map_or(0, |(_, _, total, _)| *total);
    let mut bytes = format!(
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* {total} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] uid\r\n* OK [UIDNEXT 51] uid\r\n"
    )
    .into_bytes();
    bytes.extend(tagged_ok(tag));
    bytes
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

fn fetch_inbox(tag: &Tag<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for line in [
        r#"* 1 FETCH (UID 4 INTERNALDATE "03-Nov-2026 00:00:00 +0000" FLAGS () ENVELOPE (NIL "newer" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL))"#,
        r#"* 2 FETCH (UID 2 INTERNALDATE "03-Nov-2026 00:00:00 +0000" FLAGS (\Seen) ENVELOPE (NIL "older-same-day" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL))"#,
        r#"* 3 FETCH (UID 50 INTERNALDATE "01-Nov-2026 00:00:00 +0000" FLAGS (\Seen \Flagged) ENVELOPE (NIL "oldest" (("Ada" NIL "ada" "icloud.com")) NIL NIL NIL NIL NIL NIL NIL))"#,
    ] {
        bytes.extend(line.as_bytes());
        bytes.extend(b"\r\n");
    }
    bytes.extend(tagged_ok(tag));
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
