// SPDX-License-Identifier: Apache-2.0

//! Records scrubbed mail fixtures from a real account.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_imap::Session;
use async_imap::types::NameAttribute;
use futures::StreamExt;
use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_mail::{Connect, OutgoingMail, SmtpClient};
use mail_parser::MessageParser;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::scrub::{Identity, Scrubber};

/// Subject prefix of every message the recorder seeds. A per-run nonce follows it.
pub(crate) const MARKER: &str = "[ibridge-fixture]";

/// Why a recording failed. Text never carries the password or server replies.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecordError {
    /// The account file is missing, not mode `0600`, or lacks a valid Apple ID and password.
    #[error("the test account file is missing, not mode 0600, or incomplete")]
    Account,
    /// The connection could not be opened or dropped.
    #[error("could not reach the mail server")]
    Connect,
    /// `LOGIN` was refused.
    #[error("the mail server refused the login")]
    Login,
    /// An IMAP command failed.
    #[error("an IMAP command failed: {0}")]
    Imap(&'static str),
    /// A marker mail could not be sent.
    #[error("could not send a marker mail")]
    Send,
    /// The fixture directory could not be written.
    #[error("could not write fixtures: {0}")]
    Write(#[from] std::io::Error),
    /// Fewer marker mails arrived than were sent. The ones that did were recorded and cleaned up.
    #[error("sent {sent} marker mails but only {found} arrived")]
    MarkersMissing { sent: usize, found: usize },
}

/// One marker mail is seeded per word.
const SEEDS: [&str; 2] = ["one", "two"];

/// Sends the marker mails that the recorder then records.
pub(crate) trait MarkerSender {
    /// Sends one plain-text mail to `to`.
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), RecordError>;
}

/// How long to wait for sent mail to reach the inbox.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wait {
    pub(crate) attempts: u32,
    pub(crate) delay: Duration,
}

/// What the recorder wrote and cleaned up.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Recorded {
    /// Fixture files, in the order they were written.
    pub(crate) files: Vec<PathBuf>,
    /// Marker messages moved to Trash.
    pub(crate) trashed: usize,
}

/// Sends marker mails, records the ones that arrive, scrubs them into
/// `out_dir`, and moves them to Trash. Mail without the marker subject is
/// never written, moved or flagged.
pub(crate) async fn record_mail<C: Connect, S: MarkerSender>(
    connector: &C,
    credentials: &Credentials,
    sender: &S,
    out_dir: &Path,
    wait: Wait,
    nonce: &str,
) -> Result<Recorded, RecordError> {
    let address = credentials.apple_id.as_str();
    let prefix = format!("{MARKER} {nonce} seed");
    for word in SEEDS {
        sender
            .send(
                address,
                &format!("{prefix} {word}"),
                &format!("marker body {word}"),
            )
            .await?;
    }
    let mut session = login(connector, credentials).await?;
    let result = record_inbox(&mut session, address, out_dir, wait, &prefix, SEEDS.len()).await;
    let _ = session.logout().await;
    result
}

/// Loads the account file, records mail, and reports what it did on `log`.
/// `log` and the returned error never carry the password.
pub(crate) async fn run_mail<C: Connect, S: MarkerSender>(
    account: &Path,
    connector: &C,
    make_sender: impl FnOnce(&Credentials) -> S,
    out_dir: &Path,
    wait: Wait,
    nonce: &str,
    log: &mut impl io::Write,
) -> Result<(), RecordError> {
    let credentials = FileSource::new(account)
        .credentials()
        .await
        .map_err(|_| RecordError::Account)?;
    let sender = make_sender(&credentials);
    let recorded = record_mail(connector, &credentials, &sender, out_dir, wait, nonce).await?;
    writeln!(
        log,
        "recorded {} fixtures, moved {} markers to Trash",
        recorded.files.len(),
        recorded.trashed
    )?;
    Ok(())
}

/// Sends the marker mails over iCloud SMTP.
#[derive(Debug)]
pub(crate) struct SmtpSender(SmtpClient);

impl SmtpSender {
    /// Builds a sender that signs in with a copy of `credentials`.
    pub(crate) fn new(credentials: &Credentials) -> Self {
        let copy = credentials
            .with_secret(|secret| Credentials::new(credentials.apple_id.clone(), secret));
        Self(SmtpClient::icloud(copy))
    }
}

impl MarkerSender for SmtpSender {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), RecordError> {
        let mail = OutgoingMail {
            from: to.to_owned(),
            to: vec![to.to_owned()],
            subject: subject.to_owned(),
            body: body.to_owned(),
            in_reply_to: None,
            references: Vec::new(),
        };
        self.0.send(&mail).await.map_err(|_| RecordError::Send)
    }
}

async fn record_inbox<S>(
    session: &mut Session<S>,
    address: &str,
    out_dir: &Path,
    wait: Wait,
    prefix: &str,
    sent: usize,
) -> Result<Recorded, RecordError>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    session
        .select("INBOX")
        .await
        .map_err(|_| RecordError::Imap("SELECT"))?;
    let mut markers = Vec::new();
    for attempt in 0..wait.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(wait.delay).await;
        }
        markers = fetch_markers(session, prefix).await?;
        if markers.len() >= sent {
            break;
        }
    }
    let mut recorded = Recorded::default();
    if !markers.is_empty() {
        let mut scrubber = Scrubber::new(Identity {
            apple_id: address.to_owned(),
            dsid: None,
            names: markers
                .iter()
                .flat_map(|marker| display_names(&marker.raw))
                .collect(),
        });
        fs::create_dir_all(out_dir)?;
        for (index, marker) in markers.iter().enumerate() {
            let clean = scrubber.scrub(&String::from_utf8_lossy(&marker.raw));
            let file = out_dir.join(format!("mail-{}.eml", index + 1));
            fs::write(&file, clean)?;
            recorded.files.push(file);
        }
        let trash = trash_path(session).await?;
        for marker in &markers {
            trash_one(session, marker.uid, &trash).await?;
            recorded.trashed += 1;
        }
    }
    if markers.len() < sent {
        return Err(RecordError::MarkersMissing {
            sent,
            found: markers.len(),
        });
    }
    Ok(recorded)
}

struct Marker {
    uid: u32,
    raw: Vec<u8>,
}

/// Searches the inbox by subject, fetches what came back, and keeps only
/// messages whose own `Subject` header starts with this run's `prefix`. The
/// server's search is a hint: a loose one may answer with every message. Markers
/// from an earlier run, or from anyone else, never match.
async fn fetch_markers<S>(
    session: &mut Session<S>,
    prefix: &str,
) -> Result<Vec<Marker>, RecordError>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let found = session
        .uid_search(format!("SUBJECT \"{prefix}\""))
        .await
        .map_err(|_| RecordError::Imap("UID SEARCH"))?;
    if found.is_empty() {
        return Ok(Vec::new());
    }
    let mut uids: Vec<u32> = found.into_iter().collect();
    uids.sort_unstable();
    let set = uids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let fetched = session
        .uid_fetch(set, "BODY.PEEK[]")
        .await
        .map_err(|_| RecordError::Imap("UID FETCH"))?;
    let fetched: Vec<_> = fetched.collect().await;
    let mut markers = Vec::new();
    for fetch in fetched {
        let fetch = fetch.map_err(|_| RecordError::Imap("UID FETCH"))?;
        let (Some(uid), Some(raw)) = (fetch.uid, fetch.body()) else {
            continue;
        };
        if uids.contains(&uid) && is_marker(raw, prefix) {
            markers.push(Marker {
                uid,
                raw: raw.to_vec(),
            });
        }
    }
    markers.sort_by_key(|marker| marker.uid);
    Ok(markers)
}

fn is_marker(raw: &[u8], prefix: &str) -> bool {
    MessageParser::default()
        .parse(raw)
        .and_then(|message| message.subject().map(|subject| subject.starts_with(prefix)))
        .unwrap_or(false)
}

fn display_names(raw: &[u8]) -> Vec<String> {
    let Some(message) = MessageParser::default().parse(raw) else {
        return Vec::new();
    };
    [message.from(), message.to()]
        .into_iter()
        .flatten()
        .flat_map(|list| list.mailboxes())
        .filter_map(|address| address.name().map(str::to_owned))
        .collect()
}

async fn login<C: Connect>(
    connector: &C,
    credentials: &Credentials,
) -> Result<Session<C::Stream>, RecordError> {
    let stream = connector
        .connect()
        .await
        .map_err(|_| RecordError::Connect)?;
    let password = credentials.with_secret(|secret| Zeroizing::new(secret.to_owned()));
    async_imap::Client::new(stream)
        .login(credentials.apple_id.as_str(), (*password).as_str())
        .await
        .map_err(|_| RecordError::Login)
}

/// The `\Trash` mailbox. A name that cannot be quoted safely is refused.
async fn trash_path<S>(session: &mut Session<S>) -> Result<String, RecordError>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    let names = session
        .list(Some(""), Some("*"))
        .await
        .map_err(|_| RecordError::Imap("LIST"))?;
    let names: Vec<_> = names.collect().await;
    let trash = names
        .into_iter()
        .filter_map(Result::ok)
        .find(|name| name.attributes().contains(&NameAttribute::Trash))
        .ok_or(RecordError::Imap("no Trash mailbox"))?;
    let path = trash.name().to_owned();
    if path.contains(['"', '\\', '\r', '\n']) {
        return Err(RecordError::Imap("unsafe Trash name"));
    }
    Ok(path)
}

/// `UID MOVE`, or copy, flag and expunge that one uid when the server has no `MOVE`.
async fn trash_one<S>(session: &mut Session<S>, uid: u32, trash: &str) -> Result<(), RecordError>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send,
{
    if session
        .run_command_and_check_ok(format!("UID MOVE {uid} \"{trash}\""))
        .await
        .is_ok()
    {
        return Ok(());
    }
    for command in [
        format!("UID COPY {uid} \"{trash}\""),
        format!("UID STORE {uid} +FLAGS.SILENT (\\Deleted)"),
        format!("UID EXPUNGE {uid}"),
    ] {
        session
            .run_command_and_check_ok(command)
            .await
            .map_err(|_| RecordError::Imap("move to Trash"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::{Future, ready};
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    use ibridge_auth::Credentials;
    use ibridge_core::AppleId;
    use ibridge_mail::Connect;
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
    use tokio::io::DuplexStream;

    use super::{MARKER, MarkerSender, RecordError, Wait, record_mail, run_mail};

    struct Fake(FakeImap);

    impl Connect for Fake {
        type Stream = DuplexStream;

        fn connect(&self) -> impl Future<Output = io::Result<DuplexStream>> + Send {
            ready(Ok(self.0.connect()))
        }
    }

    #[derive(Default)]
    struct Outbox(Mutex<Vec<(String, String)>>);

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the test outbox only records the mail"
    )]
    impl MarkerSender for Outbox {
        async fn send(&self, to: &str, subject: &str, _body: &str) -> Result<(), RecordError> {
            self.0
                .lock()
                .expect("outbox")
                .push((to.to_owned(), subject.to_owned()));
            Ok(())
        }
    }

    fn credentials() -> Credentials {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        Credentials::new(apple_id, "test-secret")
    }

    const ONCE: Wait = Wait {
        attempts: 1,
        delay: Duration::ZERO,
    };

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ibridge-record-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    const NONCE: &str = "n0nce42";

    fn markers_script() -> FakeScript {
        FakeScript {
            marker_messages: true,
            marker_nonce: Some(NONCE.to_owned()),
            ..FakeScript::default()
        }
    }

    #[tokio::test]
    async fn recorder_filters_to_marker_messages() {
        let fake = FakeImap::spawn(markers_script());
        let out = scratch("filter");
        let outbox = Outbox::default();

        let recorded = record_mail(&Fake(fake), &credentials(), &outbox, &out, ONCE, NONCE)
            .await
            .expect("recording succeeds");

        assert_eq!(
            recorded.files.len(),
            2,
            "only the two marker mails are kept"
        );
        for file in &recorded.files {
            let text = fs::read_to_string(file).expect("fixture file");
            assert!(
                text.contains(&format!("Subject: {MARKER}")),
                "{} is not a marker mail:\n{text}",
                file.display()
            );
            assert!(
                !text.contains("ada@icloud.com")
                    && !text.contains("Ada Lovelace")
                    && !text.contains("marker-"),
                "{} was written unscrubbed:\n{text}",
                file.display()
            );
        }
        let entries = fs::read_dir(&out).expect("out dir").count();
        assert_eq!(entries, 2, "nothing else is written to the fixture dir");
        let sent = outbox.0.lock().expect("outbox").clone();
        assert_eq!(sent.len(), 2, "one marker per expected fixture");
        for (to, subject) in sent {
            assert_eq!(
                to, "ada@icloud.com",
                "markers go to the account's own address"
            );
            assert!(
                subject.starts_with(&format!("{MARKER} {NONCE} ")),
                "{subject} lacks the marker and this run's nonce"
            );
        }
        let _ = fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn recorder_ignores_markers_from_other_runs() {
        let fake = FakeImap::spawn(FakeScript {
            stale_marker: true,
            ..markers_script()
        });
        let out = scratch("stale");

        let recorded = record_mail(
            &Fake(fake.clone()),
            &credentials(),
            &Outbox::default(),
            &out,
            ONCE,
            NONCE,
        )
        .await
        .expect("recording succeeds");

        assert_eq!(recorded.files.len(), 2, "only this run's markers are kept");
        assert_eq!(recorded.trashed, 2);
        for file in &recorded.files {
            let text = fs::read_to_string(file).expect("fixture file");
            assert!(
                text.contains(&format!("{MARKER} {NONCE} seed")) && !text.contains("stale"),
                "{} is not from this run:\n{text}",
                file.display()
            );
        }
        let lines = fake.lines();
        assert!(
            !lines.iter().any(|line| line.contains(" 62 ")),
            "the stale marker must not be moved or flagged, saw {lines:?}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn recorder_moves_markers_to_trash() {
        let fake = FakeImap::spawn(markers_script());
        let out = scratch("trash");

        let recorded = record_mail(
            &Fake(fake.clone()),
            &credentials(),
            &Outbox::default(),
            &out,
            ONCE,
            NONCE,
        )
        .await
        .expect("recording succeeds");

        assert_eq!(recorded.trashed, 2, "both markers are cleaned up");
        let lines = fake.lines();
        for uid in [60, 61] {
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains(&format!("UID MOVE {uid} \"Deleted Messages\""))),
                "marker {uid} should move to Trash, saw {lines:?}"
            );
        }
        for uid in [2, 4, 7, 50] {
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains(&format!("MOVE {uid} "))
                        || line.contains(&format!("STORE {uid} "))),
                "message {uid} is not a marker and must be left alone, saw {lines:?}"
            );
        }
        let _ = fs::remove_dir_all(&out);
    }

    #[tokio::test]
    async fn recorder_trashes_with_copy_and_expunge_when_move_is_rejected() {
        let fake = FakeImap::spawn(FakeScript {
            reject_uid_move: true,
            ..markers_script()
        });
        let out = scratch("copy");

        let recorded = record_mail(
            &Fake(fake.clone()),
            &credentials(),
            &Outbox::default(),
            &out,
            ONCE,
            NONCE,
        )
        .await
        .expect("recording succeeds");

        assert_eq!(recorded.trashed, 2, "markers are still cleaned up");
        let lines = fake.lines();
        for verb in ["UID COPY 60 ", "UID STORE 60 ", "UID EXPUNGE 60"] {
            assert!(
                lines.iter().any(|line| line.contains(verb)),
                "expected {verb}, saw {lines:?}"
            );
        }
        let _ = fs::remove_dir_all(&out);
    }

    const PASSWORD: &str = "hunter2-never-print";

    #[cfg(unix)]
    fn account_file(name: &str, mode: u32, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("ibridge-account-{name}-{}", std::process::id()));
        fs::write(&path, body).expect("write account file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set mode");
        path
    }

    fn account_body(apple_id: &str) -> String {
        format!("IBRIDGE_TEST_APPLE_ID={apple_id}\nIBRIDGE_TEST_APP_PASSWORD={PASSWORD}\n")
    }

    fn visible(error: &RecordError, log: &[u8]) -> String {
        format!("{error} {error:?} {}", String::from_utf8_lossy(log))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recorder_never_prints_password() {
        let out = scratch("secret");
        let good = account_file("good", 0o600, &account_body("ada@icloud.com"));
        let bad_id = account_file("badid", 0o600, &account_body("not-an-apple-id"));
        let mut everything = String::new();

        // A run that works: it must say what it did, without the password.
        let fake = FakeImap::spawn(markers_script());
        let mut log = Vec::new();
        run_mail(
            &good,
            &Fake(fake),
            |_| Outbox::default(),
            &out,
            ONCE,
            NONCE,
            &mut log,
        )
        .await
        .expect("recording succeeds");
        let summary = String::from_utf8_lossy(&log).into_owned();
        assert!(
            summary.contains("2 fixtures") && summary.contains("Trash"),
            "summary: {summary}"
        );
        everything.push_str(&summary);

        // A rejected login.
        let fake = FakeImap::spawn(FakeScript {
            reject_login: true,
            ..markers_script()
        });
        let mut log = Vec::new();
        let error = run_mail(
            &good,
            &Fake(fake),
            |_| Outbox::default(),
            &out,
            ONCE,
            NONCE,
            &mut log,
        )
        .await
        .expect_err("the server refuses the login");
        assert!(matches!(error, RecordError::Login), "got {error:?}");
        everything.push_str(&visible(&error, &log));

        // A file with a bad Apple ID next to the password.
        let fake = FakeImap::spawn(markers_script());
        let mut log = Vec::new();
        let error = run_mail(
            &bad_id,
            &Fake(fake),
            |_| Outbox::default(),
            &out,
            ONCE,
            NONCE,
            &mut log,
        )
        .await
        .expect_err("the Apple ID is invalid");
        assert!(matches!(error, RecordError::Account), "got {error:?}");
        everything.push_str(&visible(&error, &log));

        assert!(
            !everything.contains(PASSWORD),
            "the password was printed:\n{everything}"
        );
        for file in fs::read_dir(&out).expect("out dir") {
            let text = fs::read_to_string(file.expect("entry").path()).expect("fixture");
            assert!(!text.contains(PASSWORD), "the password reached a fixture");
        }
        for path in [good, bad_id] {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir_all(&out);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recorder_refuses_non_0600_account_file() {
        let out = scratch("loose");
        let loose = account_file("loose", 0o644, &account_body("ada@icloud.com"));
        let fake = FakeImap::spawn(markers_script());
        let mut log = Vec::new();

        let error = run_mail(
            &loose,
            &Fake(fake.clone()),
            |_| Outbox::default(),
            &out,
            ONCE,
            NONCE,
            &mut log,
        )
        .await
        .expect_err("a group-readable account file is refused");

        assert!(matches!(error, RecordError::Account), "got {error:?}");
        assert_eq!(
            fake.connection_count(),
            0,
            "the password must not reach a server"
        );
        assert!(!out.exists(), "nothing is recorded");
        assert!(!visible(&error, &log).contains(PASSWORD));
        let _ = fs::remove_file(loose);
    }
}
