// SPDX-License-Identifier: Apache-2.0

//! One account's IMAP pool and SMTP client.

use ibridge_core::{CoreError, Draft, FlagChange, MailboxPath, MailboxRole, MessageId};

use crate::imap::{Connect, ImapPool};
use crate::limits::{SendLimits, SendWindow};
use crate::smtp::{OutgoingMail, SmtpClient};

/// A send that SMTP accepted.
#[derive(Debug, PartialEq, Eq)]
pub struct SendOutcome {
    /// Id of the copy in Sent Messages.
    ///
    /// `None` when the message was delivered and the Sent append failed.
    pub id: Option<MessageId>,
}

/// IMAP and SMTP for one account.
#[derive(Debug)]
pub struct MailSession<C: Connect> {
    imap: ImapPool<C>,
    smtp: SmtpClient,
    sends: SendWindow,
}

impl<C: Connect> MailSession<C> {
    /// Builds a session. The pool and the SMTP client share one account.
    ///
    /// Send caps are [`SendLimits::default`]: 50 recipients, 20 sends an hour.
    #[must_use]
    pub fn new(imap: ImapPool<C>, smtp: SmtpClient) -> Self {
        Self::with_limits(imap, smtp, SendLimits::default())
    }

    /// Builds a session with explicit send caps.
    #[must_use]
    pub fn with_limits(imap: ImapPool<C>, smtp: SmtpClient, limits: SendLimits) -> Self {
        Self {
            imap,
            smtp,
            sends: SendWindow::new(limits),
        }
    }

    /// The IMAP pool, for reads.
    #[must_use]
    pub const fn imap(&self) -> &ImapPool<C> {
        &self.imap
    }

    /// Sends `draft` and appends the same MIME to Sent Messages.
    ///
    /// SMTP acceptance is success. A failed Sent append is logged and returned
    /// as [`SendOutcome::id`] `None`, so a retry does not send the message again.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidInput`] when the draft has more recipients
    /// than the cap or the parent message has no `Message-ID`,
    /// [`CoreError::RateLimited`] when this account has already sent its hourly
    /// cap, [`CoreError::NotFound`] when `reply_to` cannot be read, and
    /// [`CoreError`] when SMTP fails. A failed SMTP attempt does not use a slot.
    pub async fn send(&self, draft: &Draft) -> Result<SendOutcome, CoreError> {
        let mail = self.outgoing(draft).await?;
        let reservation = self.sends.admit(draft.to.len())?;
        let bytes = match self.smtp.transmit(&mail).await {
            Ok(bytes) => {
                reservation.commit();
                bytes
            }
            Err(error) => return Err(error),
        };
        match self.imap.append(MailboxRole::Sent, None, &bytes).await {
            Ok(id) => Ok(SendOutcome { id: Some(id) }),
            Err(error) => {
                tracing::warn!(%error, "sent message was not copied to Sent Messages");
                Ok(SendOutcome { id: None })
            }
        }
    }

    /// Appends `draft` to Drafts with the `\Draft` flag.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the parent cannot be read or the append fails.
    pub async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError> {
        let mail = self.outgoing(draft).await?;
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

    async fn outgoing(&self, draft: &Draft) -> Result<OutgoingMail, CoreError> {
        let (in_reply_to, references) = if let Some(parent) = &draft.reply_to {
            let headers = self.imap.reply_headers(parent).await?;
            (Some(headers.in_reply_to), headers.references)
        } else {
            (None, Vec::new())
        };
        let from = match &draft.from {
            Some(from) => from.clone(),
            None => self.smtp.login_address().to_owned(),
        };
        Ok(OutgoingMail {
            from,
            to: draft.to.clone(),
            subject: draft.subject.clone(),
            body: draft.body.clone(),
            in_reply_to,
            references,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ibridge_auth::Credentials;
    use ibridge_core::{
        AppleId, CoreError, Draft, FlagChange, MailboxPath, MailboxRole, MessageId, Uid,
        UidValidity,
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
            from: None,
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

    #[tokio::test]
    async fn send_refuses_over_50_recipients() {
        let (fake, capture, session) = session().await;
        let mut mail = draft();
        mail.to = (0..51).map(|n| format!("r{n}@example.com")).collect();
        let err = session
            .send(&mail)
            .await
            .expect_err("51 recipients are refused");
        assert!(
            matches!(err, CoreError::InvalidInput(_)),
            "too many recipients is invalid input, got {err:?}"
        );
        assert!(
            fake.appended().is_empty(),
            "a refused send is not appended to Sent"
        );
        assert!(
            capture.message().is_empty(),
            "a refused send is not transmitted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn send_refuses_21st_in_hour() {
        let (fake, _capture, session) = session().await;
        for _ in 0..20 {
            session
                .send(&draft())
                .await
                .expect("a send within the hour");
        }
        let err = session
            .send(&draft())
            .await
            .expect_err("the 21st send in an hour is refused");
        assert!(
            matches!(err, CoreError::RateLimited { .. }),
            "the hourly cap is rate limited, got {err:?}"
        );
        assert_eq!(
            fake.appended().len(),
            20,
            "the refused send is not appended"
        );
        tokio::time::sleep(Duration::from_hours(1)).await;
        session
            .send(&draft())
            .await
            .expect("a send is allowed after an hour");
        assert_eq!(fake.appended().len(), 21, "the later send is appended");
    }

    #[tokio::test]
    async fn send_reports_success_when_sent_append_fails() {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            fail_append: true,
            ..FakeScript::default()
        });
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        let session = MailSession::new(imap, smtp);
        let outcome = session.send(&draft()).await.expect(
            "SMTP already delivered the message, so a failed Sent copy is not a failed send",
        );
        assert!(outcome.id.is_none(), "a failed Sent append has no Sent id");
        assert!(
            capture.message().contains("Bring napkins."),
            "the message was transmitted, got {}",
            capture.message()
        );
    }

    #[tokio::test]
    async fn send_reply_sets_headers_from_the_parent() {
        let (fake, capture, session) = session().await;
        let mut mail = draft();
        mail.reply_to = Some(message(4));
        session.send(&mail).await.expect("send");
        let sent = capture.message();
        assert!(
            sent.contains("In-Reply-To:") && sent.contains("<parent@example.com>"),
            "In-Reply-To is the parent's Message-ID, got {sent}"
        );
        assert!(
            sent.contains("References:") && sent.contains("<root@example.com>"),
            "References keeps the parent's references, got {sent}"
        );
        assert!(
            sent.contains("<parent@example.com>"),
            "References includes the parent, got {sent}"
        );
        let copies = fake.appended();
        let copy = String::from_utf8_lossy(&copies[0].bytes);
        assert!(
            copy.contains("<parent@example.com>"),
            "the Sent copy carries the reply headers, got {copy}"
        );
    }

    #[tokio::test]
    async fn create_draft_reply_sets_headers_from_the_parent() {
        let (fake, _capture, session) = session().await;
        let mut mail = draft();
        mail.reply_to = Some(message(4));
        session.create_draft(&mail).await.expect("draft");
        let copies = fake.appended();
        let copy = String::from_utf8_lossy(&copies[0].bytes);
        assert!(
            copy.contains("In-Reply-To:") && copy.contains("<parent@example.com>"),
            "a drafted reply sets In-Reply-To, got {copy}"
        );
        assert!(
            copy.contains("<root@example.com>"),
            "a drafted reply keeps References, got {copy}"
        );
    }

    #[tokio::test]
    async fn send_uses_optional_from() {
        let (_fake, capture, session) = session().await;
        let mut mail = draft();
        mail.from = Some("coach@example.com".to_owned());
        session.send(&mail).await.expect("send");
        assert_eq!(
            capture.username(),
            "ada@icloud.com",
            "login stays the Apple ID"
        );
        assert_eq!(
            capture.mail_from(),
            "coach@example.com",
            "MAIL FROM is the optional from address"
        );
        assert!(
            capture.message().contains("coach@example.com"),
            "the From header is the optional from address, got {}",
            capture.message()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn send_failure_does_not_use_the_hourly_slot() {
        let capture = SmtpCapture::start_failing(1).await;
        let fake = FakeImap::spawn(FakeScript::default());
        let imap = ImapPool::new(credentials(), fake);
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        let session = MailSession::with_limits(
            imap,
            smtp,
            crate::limits::SendLimits {
                max_recipients: 50,
                max_per_hour: 1,
            },
        );
        let err = session
            .send(&draft())
            .await
            .expect_err("the server refuses the first send");
        assert!(
            !matches!(err, CoreError::RateLimited { .. }),
            "the first send fails at SMTP, got {err:?}"
        );
        session
            .send(&draft())
            .await
            .expect("a refused SMTP attempt does not use the hourly slot");
    }

    #[tokio::test]
    async fn move_to_role_prefers_special_use_over_the_same_name() {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            archive_name_shadow: true,
            ..FakeScript::default()
        });
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        let session = MailSession::new(imap, smtp);
        session
            .move_to_role(&message(4), MailboxRole::Archive)
            .await
            .expect("move");
        let moves: Vec<_> = fake
            .lines()
            .into_iter()
            .filter(|line| line.contains("UID MOVE"))
            .collect();
        assert!(
            moves.iter().any(|line| line.contains("Archived Messages")),
            "the \\Archive mailbox wins over a user folder named Archive, got {moves:?}"
        );
    }

    #[tokio::test]
    async fn set_flags_clear_removes_the_flag() {
        let (fake, _capture, session) = session().await;
        let seen = FlagChange {
            seen: Some(true),
            flagged: None,
        };
        session.set_flags(&message(4), &seen).await.expect("set");
        let clear = FlagChange {
            seen: Some(false),
            flagged: None,
        };
        session.set_flags(&message(4), &clear).await.expect("clear");
        assert_eq!(
            fake.flag_count("INBOX", 4, "\\Seen"),
            0,
            "clearing \\Seen removes it"
        );
        session
            .set_flags(&message(4), &seen)
            .await
            .expect("set again");
        assert_eq!(
            fake.flag_count("INBOX", 4, "\\Seen"),
            1,
            "setting \\Seen again leaves one flag"
        );
    }
}
