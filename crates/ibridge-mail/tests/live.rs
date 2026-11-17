// SPDX-License-Identifier: Apache-2.0

//! Live smoke test for mail, against the user's own iCloud account.
//!
//! Ignored by default and never run in CI. Run it with
//! `IBRIDGE_LIVE=1 cargo nextest run --run-ignored ignored-only -E 'test(live_mail)'`.
//! It reads `~/.config/ibridge/test-account.env`, sends one marker mail to the
//! account's own address, reads it back, and moves it to Trash. Then it expunges every
//! copy of the marker from Inbox, Trash, Sent, Drafts and Junk, so the account is left as
//! it was. Only mail whose subject carries this run's marker is touched.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_core::{MailSearch, MailboxRole};
use ibridge_mail::{Connect, IcloudConnect, ImapPool, MailSession, OutgoingMail, SmtpClient};

async fn account() -> Credentials {
    assert_eq!(
        std::env::var("IBRIDGE_LIVE").as_deref(),
        Ok("1"),
        "live tests need IBRIDGE_LIVE=1"
    );
    let home = std::env::var_os("HOME").expect("HOME is set");
    let path = PathBuf::from(home).join(".config/ibridge/test-account.env");
    FileSource::new(path)
        .credentials()
        .await
        .expect("the test account file is present, mode 0600 and complete")
}

fn copy(credentials: &Credentials) -> Credentials {
    credentials.with_secret(|secret| Credentials::new(credentials.apple_id.clone(), secret))
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_nanos();
    format!("{nanos:x}")
}

/// Permanently deletes every message in `mailboxes` whose subject is `subject`, and returns
/// how many it removed.
///
/// `UID EXPUNGE` takes only the uids this call flagged, so nothing else that is marked
/// `\Deleted` in the account goes with them.
async fn purge(credentials: &Credentials, mailboxes: &[String], subject: &str) -> usize {
    let stream = IcloudConnect::new()
        .expect("TLS roots")
        .connect()
        .await
        .expect("connect for cleanup");
    let password = credentials.with_secret(str::to_owned);
    let mut session = async_imap::Client::new(stream)
        .login(credentials.apple_id.as_str(), password)
        .await
        .map_err(|(error, _)| error)
        .expect("log in for cleanup");
    let mut removed = 0;
    for mailbox in mailboxes {
        session.select(mailbox).await.expect("select for cleanup");
        let uids = session
            .uid_search(format!("SUBJECT \"{subject}\""))
            .await
            .expect("search for cleanup");
        if uids.is_empty() {
            continue;
        }
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        session
            .run_command_and_check_ok(format!("UID STORE {set} +FLAGS.SILENT (\\Deleted)"))
            .await
            .expect("flag the marker for deletion");
        session
            .run_command_and_check_ok(format!("UID EXPUNGE {set}"))
            .await
            .expect("expunge the marker");
        removed += uids.len();
    }
    session.logout().await.expect("log out after cleanup");
    removed
}

#[tokio::test]
#[ignore = "live: needs IBRIDGE_LIVE=1 and the test account file"]
async fn live_mail_smoke() {
    let credentials = account().await;
    let address = credentials.apple_id.as_str().to_owned();
    let sender = SmtpClient::icloud(copy(&credentials));
    let reader = copy(&credentials);
    let session = MailSession::new(
        ImapPool::new(copy(&credentials), IcloudConnect::new().expect("TLS roots")),
        SmtpClient::icloud(credentials),
    );

    let capabilities = session.imap().capabilities().await.expect("capabilities");
    let boxes = session.imap().list_mailboxes().await.expect("mailboxes");
    let has_role = |role| boxes.iter().any(|mailbox| mailbox.role == role);

    let subject = format!("[ibridge-live] {} smoke", nonce());
    sender
        .send(&OutgoingMail {
            from: address.clone(),
            to: vec![address],
            subject: subject.clone(),
            body: "live smoke marker".to_owned(),
            in_reply_to: None,
            references: Vec::new(),
        })
        .await
        .expect("send the marker mail");

    let query = MailSearch {
        mailbox: None,
        role: Some(MailboxRole::Inbox),
        from: None,
        to: None,
        subject: Some(subject.clone()),
        text: None,
        since: None,
        before: None,
        unread_only: false,
        flagged_only: false,
        limit: 5,
        cursor: None,
    };
    let mut found = Vec::new();
    for _ in 0..30 {
        // A failed search is not a reason to skip the cleanup below.
        if let Ok(page) = session.imap().search(&query).await {
            found = page
                .messages
                .into_iter()
                .filter(|message| message.subject == subject)
                .collect();
        }
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Clean up before asserting, so a failure still leaves nothing in the account.
    let mut read = Vec::new();
    let mut moves = Vec::new();
    for message in &found {
        read.push(session.imap().get_message(&message.id, 0).await);
        moves.push(session.move_to_role(&message.id, MailboxRole::Trash).await);
    }
    let sweep: Vec<String> = boxes
        .iter()
        .filter(|mailbox| {
            matches!(
                mailbox.role,
                MailboxRole::Inbox
                    | MailboxRole::Trash
                    | MailboxRole::Sent
                    | MailboxRole::Drafts
                    | MailboxRole::Junk
            )
        })
        .map(|mailbox| mailbox.path.as_str().to_owned())
        .collect();
    // This search runs after the poll, so a message that arrived late is deleted too.
    let mut removed = purge(&reader, &sweep, &subject).await;
    if found.is_empty() {
        // Nothing arrived inside the poll. Give a slow delivery one more chance to land, then
        // delete it, so a late marker is not left behind.
        tokio::time::sleep(Duration::from_secs(20)).await;
        removed += purge(&reader, &sweep, &subject).await;
    }
    eprintln!("cleanup removed {removed} marker message(s)");

    assert!(
        capabilities
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case("UIDPLUS")),
        "got {capabilities:?}"
    );
    assert!(has_role(MailboxRole::Inbox) && has_role(MailboxRole::Trash));
    assert!(has_role(MailboxRole::Sent), "got {boxes:?}");
    assert_eq!(found.len(), 1, "the marker mail arrived once");
    assert!(
        moves.iter().all(Result::is_ok),
        "the marker moved to Trash, got {moves:?}"
    );
    let message = read.remove(0).expect("read the marker mail").message;
    assert_eq!(message.subject, subject);
    assert_eq!(message.body.trim(), "live smoke marker");
}
