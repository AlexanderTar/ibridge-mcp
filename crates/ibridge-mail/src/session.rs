// SPDX-License-Identifier: Apache-2.0

//! One account's IMAP pool and SMTP client.

use std::sync::Arc;

use ibridge_core::{
    CoreError, Draft, FlagChange, MailboxPath, MailboxRole, MessageId, OneClickFailure,
    Unsubscribe, UnsubscribeMail, UnsubscribeMethod,
};

use crate::imap::{Connect, ImapPool};
use crate::limits::{SendLimits, SendWindow};
#[cfg(test)]
use crate::oneclick::OneClick;
use crate::smtp::{OutgoingMail, SmtpClient};

/// A send that SMTP accepted.
#[derive(Debug, PartialEq, Eq)]
pub struct SendOutcome {
    /// Id of the copy in Sent Messages.
    ///
    /// `None` when the message was delivered and the Sent append failed.
    pub id: Option<MessageId>,
}

/// Subject of an unsubscribe email whose mailto names none.
const UNSUBSCRIBE_SUBJECT: &str = "Unsubscribe";

/// How [`MailSession::unsubscribe`] will act on a message.
enum Route {
    /// POST to the https link; `mailto_offered` is only for the failure message.
    OneClick {
        link: String,
        mailto_offered: bool,
    },
    Mailto(UnsubscribeMail),
    Links(Vec<String>),
    /// The caller asked for a method the message does not offer.
    MethodNotOffered(UnsubscribeMethod),
    None,
}

/// Picks the route for `options`. The only place that decides; a new method goes here.
///
/// `method` is what the caller asked for. It only selects among the routes the header
/// itself offers; the address and link always come from `options`. `None` takes the best
/// route: one-click, then mailto, then links.
fn choose_route(options: Option<Unsubscribe>, method: Option<UnsubscribeMethod>) -> Route {
    let Some(options) = options else {
        return Route::None;
    };
    let one_click = options.one_click_link().map(|link| Route::OneClick {
        link: link.to_owned(),
        mailto_offered: options.mailto.is_some(),
    });
    let mailto = options.mailto.map(Route::Mailto);
    let links = (!options.links.is_empty()).then_some(Route::Links(options.links));
    match method {
        None => one_click.or(mailto).or(links).unwrap_or(Route::None),
        Some(UnsubscribeMethod::OneClick) => {
            one_click.unwrap_or(Route::MethodNotOffered(UnsubscribeMethod::OneClick))
        }
        Some(UnsubscribeMethod::Mailto) => {
            mailto.unwrap_or(Route::MethodNotOffered(UnsubscribeMethod::Mailto))
        }
        Some(UnsubscribeMethod::Link) => {
            links.unwrap_or(Route::MethodNotOffered(UnsubscribeMethod::Link))
        }
        Some(other) => Route::MethodNotOffered(other),
    }
}

/// What [`MailSession::unsubscribe`] did.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsubscribeOutcome {
    /// The sender's unsubscribe address was emailed and SMTP accepted it.
    Emailed(SendOutcome),
    /// The sender's server accepted the one-click POST (RFC 8058).
    OneClicked,
    /// The one-click POST failed. Nothing else was sent, not even the mailto.
    OneClickFailed {
        /// Why, as a class that carries no server text.
        failure: OneClickFailure,
        /// The message also offers an unsubscribe email, which was not sent.
        mailto_offered: bool,
    },
    /// The sender offers only web links, which this session does not follow.
    Links(Vec<String>),
    /// The caller asked for a method that the message does not offer.
    MethodNotOffered(UnsubscribeMethod),
    /// The message has no usable `List-Unsubscribe` header.
    NotOffered,
}

/// IMAP and SMTP for one account.
#[derive(Debug)]
pub struct MailSession<C: Connect> {
    imap: ImapPool<C>,
    smtp: SmtpClient,
    sends: Arc<SendWindow>,
    /// Replaces the shared client in tests.
    #[cfg(test)]
    one_click: Option<OneClick>,
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
        Self::with_window(imap, smtp, Arc::new(SendWindow::new(limits)))
    }

    /// Builds a session on a send window the caller keeps.
    ///
    /// A host that drops and rebuilds sessions passes the same window each time, so the
    /// hourly cap belongs to the account and not to the session.
    #[must_use]
    pub const fn with_window(imap: ImapPool<C>, smtp: SmtpClient, sends: Arc<SendWindow>) -> Self {
        Self {
            imap,
            smtp,
            sends,
            #[cfg(test)]
            one_click: None,
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

    /// Unsubscribes from the sender of `id`, by the best route its headers offer, or by
    /// `method` when the caller picks one.
    ///
    /// A `method` the message does not offer sends nothing and returns
    /// [`UnsubscribeOutcome::MethodNotOffered`]. It never carries an address or link: the
    /// address, subject and body come from the message's own `List-Unsubscribe` header
    /// and from nowhere else. A mailto is sent like any message: it counts against the send
    /// caps, goes out from the account's address, and a copy is saved to Sent Messages (a
    /// failed copy is logged, as for [`MailSession::send`]). When the message offers
    /// RFC 8058 one-click, that wins: an `https` POST with no credentials, and a failure
    /// is reported, never retried by mail. A message that offers only web links returns
    /// them and sends nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when the message cannot be read,
    /// [`CoreError::RateLimited`] when this account has already sent its hourly cap, and
    /// [`CoreError`] when SMTP fails.
    pub async fn unsubscribe(
        &self,
        id: &MessageId,
        method: Option<UnsubscribeMethod>,
    ) -> Result<UnsubscribeOutcome, CoreError> {
        match choose_route(self.imap.unsubscribe_options(id).await?, method) {
            Route::OneClick {
                link,
                mailto_offered,
            } => {
                // Never falls back to the mailto: a failed POST is the user's call.
                Ok(match self.post_one_click(&link).await {
                    Ok(()) => UnsubscribeOutcome::OneClicked,
                    Err(failure) => UnsubscribeOutcome::OneClickFailed {
                        failure,
                        mailto_offered,
                    },
                })
            }
            Route::Mailto(mailto) => {
                let draft = Draft {
                    to: vec![mailto.to],
                    subject: mailto
                        .subject
                        .unwrap_or_else(|| UNSUBSCRIBE_SUBJECT.to_owned()),
                    body: mailto.body.unwrap_or_default(),
                    from: None,
                    reply_to: None,
                };
                self.send(&draft).await.map(UnsubscribeOutcome::Emailed)
            }
            Route::Links(links) => Ok(UnsubscribeOutcome::Links(links)),
            Route::MethodNotOffered(method) => Ok(UnsubscribeOutcome::MethodNotOffered(method)),
            Route::None => Ok(UnsubscribeOutcome::NotOffered),
        }
    }

    async fn post_one_click(&self, link: &str) -> Result<(), OneClickFailure> {
        #[cfg(test)]
        if let Some(client) = &self.one_click {
            return client.post(link).await;
        }
        match crate::oneclick::shared().await {
            Some(client) => client.post(link).await,
            None => Err(OneClickFailure::Unreachable),
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

    use ibridge_core::{OneClickFailure, UnsubscribeMethod};
    use ibridge_testkit::tls_fake::{TlsFake, TlsReply};

    use super::{MailSession, UnsubscribeOutcome};
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

    async fn newsletter_session() -> (FakeImap, SmtpCapture, MailSession<FakeImap>) {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            unsubscribe_messages: true,
            ..FakeScript::default()
        });
        let imap = ImapPool::new(credentials(), fake.clone());
        let smtp = SmtpClient::plain(credentials(), capture.host(), capture.port())
            .expect("loopback host is allowed");
        (fake, capture, MailSession::new(imap, smtp))
    }

    #[tokio::test]
    async fn unsubscribe_emails_the_mailto_and_saves_a_sent_copy() {
        let (fake, capture, session) = newsletter_session().await;
        let outcome = session
            .unsubscribe(&message(78), None)
            .await
            .expect("unsubscribe");
        assert!(
            matches!(&outcome, UnsubscribeOutcome::Emailed(sent) if sent.id.is_some()),
            "a mailto is emailed and the Sent copy is saved, got {outcome:?}"
        );
        assert_eq!(capture.rcpts(), vec!["unsub@example.com".to_owned()]);
        assert_eq!(capture.mail_from(), "ada@icloud.com");
        let sent = capture.message();
        assert!(
            sent.contains("To: <unsub@example.com>")
                && sent.contains("Subject: unsubscribe")
                && sent.contains("remove me"),
            "recipient, subject and body come from the mailto, got {sent}"
        );
        let copies = fake.appended();
        assert_eq!(copies.len(), 1, "one Sent copy");
        assert_eq!(copies[0].mailbox, "Sent Messages");
        assert_eq!(
            String::from_utf8_lossy(&copies[0].bytes),
            sent,
            "the Sent copy is what SMTP sent"
        );
    }

    #[tokio::test]
    async fn unsubscribe_ignores_cc_bcc_and_to_fields_and_defaults_the_subject() {
        let (_fake, capture, session) = newsletter_session().await;
        session
            .unsubscribe(&message(72), None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            capture.rcpts(),
            vec!["a@example.com".to_owned()],
            "only the address in the mailto path is a recipient"
        );
        let sent = capture.message();
        assert!(
            !sent.contains("evil"),
            "cc, bcc and to fields never reach the message, got {sent}"
        );
        assert!(sent.contains("Subject: hi"), "subject kept, got {sent}");

        session
            .unsubscribe(&message(74), None)
            .await
            .expect("bare mailto");
        assert_eq!(capture.rcpts(), vec!["bare@example.com".to_owned()]);
        assert!(
            capture.message().contains("Subject: Unsubscribe"),
            "a mailto with no subject gets one, got {}",
            capture.message()
        );
    }

    #[tokio::test]
    async fn unsubscribe_with_links_only_sends_nothing() {
        let (fake, capture, session) = newsletter_session().await;
        let outcome = session
            .unsubscribe(&message(71), None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            outcome,
            UnsubscribeOutcome::Links(vec!["http://example.com/u?id=2".to_owned()])
        );
        assert!(capture.message().is_empty(), "nothing is transmitted");
        assert!(fake.appended().is_empty(), "nothing is saved to Sent");
    }

    #[tokio::test]
    async fn unsubscribe_without_a_usable_header_sends_nothing() {
        let (fake, capture, session) = newsletter_session().await;
        for uid in [4, 73] {
            let outcome = session
                .unsubscribe(&message(uid), None)
                .await
                .expect("unsubscribe");
            assert_eq!(
                outcome,
                UnsubscribeOutcome::NotOffered,
                "uid {uid} has no usable List-Unsubscribe"
            );
        }
        assert!(capture.message().is_empty(), "nothing is transmitted");
        assert!(fake.appended().is_empty(), "nothing is saved to Sent");
    }

    #[tokio::test(start_paused = true)]
    async fn unsubscribe_counts_against_the_hourly_send_cap() {
        let capture = SmtpCapture::start().await;
        let fake = FakeImap::spawn(FakeScript {
            unsubscribe_messages: true,
            ..FakeScript::default()
        });
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
        session
            .unsubscribe(&message(78), None)
            .await
            .expect("first");
        let err = session
            .unsubscribe(&message(78), None)
            .await
            .expect_err("the cap applies to unsubscribe emails");
        assert!(matches!(err, CoreError::RateLimited { .. }), "got {err:?}");
    }

    /// A session whose one-click client talks to `fake` as if it were `example.com`.
    async fn one_click_session(
        reply: TlsReply,
    ) -> (TlsFake, SmtpCapture, FakeImap, MailSession<FakeImap>) {
        let tls = TlsFake::start("example.com", reply).await;
        let (fake, capture, mut session) = newsletter_session().await;
        session.one_click = Some(crate::oneclick::loopback(tls.root_der(), tls.port()));
        (tls, capture, fake, session)
    }

    fn ok_reply() -> TlsReply {
        TlsReply::Bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
    }

    #[tokio::test]
    async fn unsubscribe_prefers_one_click_over_mailto() {
        let (tls, capture, fake, session) = one_click_session(ok_reply()).await;
        let outcome = session
            .unsubscribe(&message(70), None)
            .await
            .expect("unsubscribe");
        assert_eq!(outcome, UnsubscribeOutcome::OneClicked);
        let requests = tls.requests();
        assert_eq!(requests.len(), 1, "one POST");
        let request = String::from_utf8_lossy(&requests[0]).into_owned();
        assert!(
            request.starts_with("POST /u?id=1 HTTP/1.1\r\n")
                && request.ends_with("\r\n\r\nList-Unsubscribe=One-Click"),
            "the https link from the header gets the RFC 8058 body, got {request:?}"
        );
        assert!(capture.message().is_empty(), "the mailto is not also sent");
        assert!(fake.appended().is_empty(), "nothing is saved to Sent");
    }

    #[tokio::test]
    async fn method_mailto_sends_the_header_mailto_even_when_one_click_is_offered() {
        let (tls, capture, fake, session) = one_click_session(ok_reply()).await;
        let outcome = session
            .unsubscribe(&message(70), Some(UnsubscribeMethod::Mailto))
            .await
            .expect("unsubscribe");
        assert!(
            matches!(&outcome, UnsubscribeOutcome::Emailed(sent) if sent.id.is_some()),
            "the mailto is emailed and the Sent copy is saved, got {outcome:?}"
        );
        assert_eq!(
            capture.rcpts(),
            vec!["unsub@example.com".to_owned()],
            "the recipient is the address in the message's own header"
        );
        assert_eq!(tls.connections(), 0, "no POST was made");
        assert_eq!(fake.appended().len(), 1, "one Sent copy");
    }

    #[tokio::test]
    async fn method_one_click_posts_when_offered() {
        let (tls, capture, _fake, session) = one_click_session(ok_reply()).await;
        let outcome = session
            .unsubscribe(&message(70), Some(UnsubscribeMethod::OneClick))
            .await
            .expect("unsubscribe");
        assert_eq!(outcome, UnsubscribeOutcome::OneClicked);
        assert_eq!(tls.requests().len(), 1, "one POST");
        assert!(capture.message().is_empty(), "no email was sent");
    }

    #[tokio::test]
    async fn a_method_the_message_does_not_offer_sends_nothing() {
        let (tls, capture, fake, session) = one_click_session(ok_reply()).await;
        // 77 offers one-click and no mailto; 78 offers a mailto and no one-click.
        for (uid, method) in [
            (77, UnsubscribeMethod::Mailto),
            (78, UnsubscribeMethod::OneClick),
        ] {
            let outcome = session
                .unsubscribe(&message(uid), Some(method))
                .await
                .expect("unsubscribe");
            assert_eq!(
                outcome,
                UnsubscribeOutcome::MethodNotOffered(method),
                "uid {uid} does not offer {method:?}"
            );
        }
        assert_eq!(tls.connections(), 0, "no POST was made");
        assert!(capture.message().is_empty(), "no email was sent");
        assert!(fake.appended().is_empty(), "nothing is saved to Sent");
    }

    #[tokio::test]
    async fn an_https_link_without_the_post_header_is_never_posted() {
        let (tls, capture, _fake, session) = one_click_session(ok_reply()).await;
        let outcome = session
            .unsubscribe(&message(75), None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            outcome,
            UnsubscribeOutcome::Links(vec!["https://example.com/u?id=3".to_owned()]),
            "the link is returned for the user to open"
        );
        let outcome = session
            .unsubscribe(&message(76), None)
            .await
            .expect("unsubscribe");
        assert!(
            matches!(outcome, UnsubscribeOutcome::Emailed(_)),
            "https plus mailto and no Post header falls to the mailto, got {outcome:?}"
        );
        assert_eq!(capture.rcpts(), vec!["m@example.com".to_owned()]);
        assert_eq!(tls.connections(), 0, "no web request was made");
    }

    #[tokio::test]
    async fn a_failed_one_click_sends_nothing_and_says_the_mailto_exists() {
        let (tls, capture, fake, session) = one_click_session(TlsReply::Bytes(
            b"HTTP/1.1 500 Internal Server Error\r\n\r\nSECRET".to_vec(),
        ))
        .await;
        let outcome = session
            .unsubscribe(&message(70), None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            outcome,
            UnsubscribeOutcome::OneClickFailed {
                failure: OneClickFailure::Rejected,
                mailto_offered: true,
            }
        );
        assert_eq!(tls.requests().len(), 1, "one attempt, no retry");
        assert!(capture.message().is_empty(), "the mailto is not auto-sent");
        assert!(fake.appended().is_empty(), "nothing is saved to Sent");
    }

    #[tokio::test]
    async fn a_failed_one_click_without_a_mailto_says_so() {
        let (_tls, capture, _fake, session) = one_click_session(TlsReply::Bytes(
            b"HTTP/1.1 302 Found\r\nLocation: https://example.net/\r\n\r\n".to_vec(),
        ))
        .await;
        let outcome = session
            .unsubscribe(&message(77), None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            outcome,
            UnsubscribeOutcome::OneClickFailed {
                failure: OneClickFailure::Redirected,
                mailto_offered: false,
            }
        );
        assert_eq!(capture.message(), "", "no email was sent");
    }

    #[tokio::test]
    async fn one_click_does_not_use_up_the_send_cap() {
        let (_tls, _capture, _fake, mut session) = one_click_session(ok_reply()).await;
        session.sends =
            std::sync::Arc::new(crate::limits::SendWindow::new(crate::limits::SendLimits {
                max_recipients: 50,
                max_per_hour: 1,
            }));
        for _ in 0..2 {
            let outcome = session
                .unsubscribe(&message(70), None)
                .await
                .expect("unsubscribe");
            assert_eq!(outcome, UnsubscribeOutcome::OneClicked);
        }
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
