// SPDX-License-Identifier: Apache-2.0

//! One account's IMAP pool and SMTP client.

use ibridge_core::{CoreError, Draft, MailboxRole, MessageId};

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
    use ibridge_core::{AppleId, Draft};
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
}
