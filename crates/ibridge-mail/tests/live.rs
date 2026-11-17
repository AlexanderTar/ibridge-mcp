// SPDX-License-Identifier: Apache-2.0

//! Live smoke test for mail, against the user's own iCloud account.
//!
//! Ignored by default and never run in CI. Run it with
//! `IBRIDGE_LIVE=1 cargo nextest run --run-ignored ignored-only -E 'test(live_mail)'`.
//! It reads `~/.config/ibridge/test-account.env`, sends one marker mail to the
//! account's own address, reads it back, and moves it to Trash. Only mail whose
//! subject carries this run's marker is touched.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_core::{MailSearch, MailboxRole};
use ibridge_mail::{IcloudConnect, ImapPool, MailSession, OutgoingMail, SmtpClient};

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

#[tokio::test]
#[ignore = "live: needs IBRIDGE_LIVE=1 and the test account file"]
async fn live_mail_smoke() {
    let credentials = account().await;
    let address = credentials.apple_id.as_str().to_owned();
    let sender = SmtpClient::icloud(copy(&credentials));
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
        let page = session.imap().search(&query).await.expect("search");
        found = page
            .messages
            .into_iter()
            .filter(|message| message.subject == subject)
            .collect();
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Clean up before asserting, so a failure still leaves nothing in the inbox.
    let mut read = Vec::new();
    for message in &found {
        read.push(session.imap().get_message(&message.id, 0).await);
        session
            .move_to_role(&message.id, MailboxRole::Trash)
            .await
            .expect("move the marker to Trash");
    }

    assert!(
        capabilities
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case("UIDPLUS")),
        "got {capabilities:?}"
    );
    assert!(has_role(MailboxRole::Inbox) && has_role(MailboxRole::Trash));
    assert!(has_role(MailboxRole::Sent), "got {boxes:?}");
    assert_eq!(found.len(), 1, "the marker mail arrived once");
    let message = read.remove(0).expect("read the marker mail").message;
    assert_eq!(message.subject, subject);
    assert_eq!(message.body.trim(), "live smoke marker");
}
