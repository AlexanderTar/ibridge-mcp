// SPDX-License-Identifier: Apache-2.0

//! One account's IMAP pool and SMTP client.

use ibridge_core::{CoreError, Draft, FlagChange, MailboxPath, MailboxRole, MessageId};

use crate::imap::{Connect, ImapPool};
use crate::smtp::{OutgoingMail, SmtpClient};

/// IMAP and SMTP for one account.
#[derive(Debug)]
pub struct MailSession<C: Connect> {
    imap: ImapPool<C>,
    smtp: SmtpClient,
}

impl<C: Connect> MailSession<C> {
    /// Builds a session. The pool and the SMTP client share one account.
    #[must_use]
    pub fn new(imap: ImapPool<C>, smtp: SmtpClient) -> Self {
        Self { imap, smtp }
    }

    /// Sends `draft` and appends the same MIME to Sent Messages.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when SMTP or the Sent append fails.
    pub async fn send(&self, draft: &Draft) -> Result<MessageId, CoreError> {
        let mail = outgoing(self.smtp.login_address(), draft);
        let bytes = self.smtp.transmit(&mail).await?;
        self.imap.append(MailboxRole::Sent, None, &bytes).await
    }

    /// Appends `draft` to Drafts with the `\Draft` flag.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the append fails.
    pub async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError> {
        let mail = outgoing(self.smtp.login_address(), draft);
        let bytes = crate::smtp::build_message(&mail)?;
        self.imap
            .append(MailboxRole::Drafts, Some(r"(\Draft)"), &bytes)
            .await
    }

    /// Moves `id` to `destination`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the move cannot be done.
    pub async fn move_to(
        &self,
        id: &MessageId,
        destination: &MailboxPath,
    ) -> Result<(), CoreError> {
        self.imap.move_uid(id, destination).await
    }

    /// Moves `id` to the mailbox with `role`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the role is missing or the move fails.
    pub async fn move_to_role(&self, id: &MessageId, role: MailboxRole) -> Result<(), CoreError> {
        self.imap.move_to_role(id, role).await
    }

    /// Sets or clears `\Seen` and `\Flagged`. A second identical call leaves the same flags.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the flags cannot be stored.
    pub async fn set_flags(&self, id: &MessageId, flags: &FlagChange) -> Result<(), CoreError> {
        self.imap.store_flags(id, flags).await
    }
}

fn outgoing(from: &str, draft: &Draft) -> OutgoingMail {
    OutgoingMail {
        from: from.to_owned(),
        to: draft.to.clone(),
        subject: draft.subject.clone(),
        body: draft.body.clone(),
        in_reply_to: None,
        references: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use ibridge_auth::Credentials;
    use ibridge_core::{
        AppleId, Draft, FlagChange, MailboxPath, MailboxRole, MessageId, Uid, UidValidity,
    };
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};

    use super::MailSession;
    use crate::imap::ImapPool;
    use crate::smtp::SmtpClient;
    use crate::smtp::tests::SmtpCapture;

    fn credentials() -> Credentials {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        Credentials::new(apple_id, "test-secret")
    }

    fn draft() -> Draft {
        Draft {
            to: vec!["bob@example.com".to_owned()],
            subject: "Picnic".to_owned(),
            body: "Bring napkins.".to_owned(),
            reply_to: None,
        }
    }

    async fn session() -> (FakeImap, SmtpCapture, MailSession<FakeImap>) {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript::default());
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        (fake, capture, MailSession::new(imap, smtp))
    }

    #[tokio::test]
    async fn send_appends_to_sent_messages() {
        let (fake, capture, session) = session().await;
        session.send(&draft()).await.expect("send");
        let copies = fake.appended();
        assert_eq!(copies.len(), 1, "send appends one copy");
        assert_eq!(
            copies[0].mailbox, "Sent Messages",
            "the copy goes to Sent Messages"
        );
        let sent = String::from_utf8_lossy(&copies[0].bytes);
        assert_eq!(
            sent,
            capture.message(),
            "the Sent copy is the same MIME that SMTP sent"
        );
        assert!(
            sent.contains("Bring napkins."),
            "the copy contains the draft body"
        );
    }

    #[tokio::test]
    async fn create_draft_appends_with_draft_flag() {
        let (fake, _capture, session) = session().await;
        session.create_draft(&draft()).await.expect("draft");
        let copies = fake.appended();
        assert_eq!(copies.len(), 1, "a draft is one append");
        assert_eq!(copies[0].mailbox, "Drafts", "drafts are appended to Drafts");
        assert!(
            copies[0].flags.contains("\\Draft"),
            "the append carries the Draft flag, got {}",
            copies[0].flags
        );
    }

    fn message(uid: u32) -> MessageId {
        MessageId {
            mailbox: MailboxPath::try_from("INBOX").expect("inbox"),
            validity: UidValidity::try_from(1).expect("validity"),
            uid: Uid::try_from(uid).expect("uid"),
        }
    }

    fn plain_expunge(line: &str) -> bool {
        let upper = line.to_ascii_uppercase();
        upper.contains("EXPUNGE") && !upper.contains("UID")
    }

    #[tokio::test]
    async fn move_tries_uid_move_without_capability() {
        let (fake, _capture, session) = session().await;
        let archive = MailboxPath::try_from("Archive").expect("archive");
        session.move_to(&message(4), &archive).await.expect("move");
        assert!(
            fake.saw("UID MOVE"),
            "UID MOVE is sent even though the server never advertises MOVE, got {:?}",
            fake.lines()
        );
    }

    #[tokio::test]
    async fn move_falls_back_to_uid_copy_store_uid_expunge() {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            reject_uid_move: true,
            ..FakeScript::default()
        });
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        let session = MailSession::new(imap, smtp);
        let archive = MailboxPath::try_from("Archive").expect("archive");
        session.move_to(&message(4), &archive).await.expect("move");
        let lines = fake.lines();
        assert!(
            lines.iter().any(|line| line.contains("UID COPY")),
            "a rejected UID MOVE is followed by UID COPY, got {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("UID STORE") && line.contains("\\Deleted")),
            "the copy is followed by UID STORE of \\Deleted, got {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("UID EXPUNGE")),
            "the deleted uid is removed with UID EXPUNGE, got {lines:?}"
        );
    }

    #[tokio::test]
    async fn move_fallback_does_not_expunge_other_deleted() {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            reject_uid_move: true,
            ..FakeScript::default()
        });
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        let session = MailSession::new(imap, smtp);
        let archive = MailboxPath::try_from("Archive").expect("archive");
        session.move_to(&message(4), &archive).await.expect("move");
        assert!(
            fake.saw("UID EXPUNGE"),
            "the moved uid is removed with UID EXPUNGE, got {:?}",
            fake.lines()
        );
        assert!(
            !fake.lines().iter().any(|line| plain_expunge(line)),
            "plain EXPUNGE would remove every \\Deleted message, got {:?}",
            fake.lines()
        );
        assert!(
            fake.deleted_uids("INBOX").contains(&99),
            "a \\Deleted message that was not moved stays, got {:?}",
            fake.deleted_uids("INBOX")
        );
    }

    #[tokio::test]
    async fn move_to_role_trash() {
        let (fake, _capture, session) = session().await;
        session
            .move_to_role(&message(4), MailboxRole::Trash)
            .await
            .expect("move to trash");
        assert!(
            fake.lines()
                .iter()
                .any(|line| line.contains("Deleted Messages")),
            "trash is the Deleted Messages mailbox, got {:?}",
            fake.lines()
        );
    }

    #[tokio::test]
    async fn set_flags_idempotent() {
        let (fake, _capture, session) = session().await;
        let flags = FlagChange {
            seen: Some(true),
            flagged: None,
        };
        session.set_flags(&message(4), &flags).await.expect("set");
        session
            .set_flags(&message(4), &flags)
            .await
            .expect("set again");
        let stores: Vec<_> = fake
            .lines()
            .into_iter()
            .filter(|line| line.contains("UID STORE"))
            .collect();
        assert_eq!(stores.len(), 2, "each call stores the flag, got {stores:?}");
        assert!(
            stores.iter().all(|line| line.contains("\\Seen")),
            "both stores set \\Seen, got {stores:?}"
        );
        assert_eq!(
            fake.flag_count("INBOX", 4, "\\Seen"),
            1,
            "a second identical store does not add a second \\Seen"
        );
    }
}
