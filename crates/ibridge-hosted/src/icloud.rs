// SPDX-License-Identifier: Apache-2.0

//! The production backend: iCloud mail, calendar, reminders, contacts and send.
//!
//! Nothing built here holds a password. Each account gets an IMAP pool, a SMTP client and
//! two DAV clients that log in with the credentials of the call that needs them (see
//! `ibridge_auth::with_call_credentials`). A call without credentials, or with another
//! account's, fails before anything is sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use ibridge_calendar::CalDavProvider;
use ibridge_contacts::CardDavProvider;
use ibridge_core::{
    AppleId, Attachment, CoreError, Draft, FlagChange, MailSearch, Mailbox, MessageId,
};
use ibridge_dav::{DavClient, DavHttp};
use ibridge_mail::{
    Connect, IcloudConnect, ImapPool, MailSession, SendLimits, SendWindow, SmtpClient,
    UnsubscribeOutcome,
};
use ibridge_server::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail, Unsubscribed};

use crate::provider::{Backend, Providers};

/// Where the DAV clients start discovery.
#[derive(Debug)]
enum DavTarget {
    /// `caldav.icloud.com` and `contacts.icloud.com`.
    Icloud,
    /// Loopback servers for tests: one for `CalDAV`, one for `CardDAV`.
    #[cfg(test)]
    Loopback { caldav: String, carddav: String },
}

/// Where the SMTP clients send.
#[derive(Debug)]
enum SmtpTarget {
    /// `smtp.mail.me.com:587` with STARTTLS.
    Icloud,
    /// A cleartext loopback server, for tests.
    #[cfg(test)]
    Loopback(String, u16),
}

/// Accounts tracked before windows with no send in the last hour are swept out.
const SWEEP_AT: usize = 10_000;

/// One hourly send window per account.
///
/// The windows outlive the account cache's entries. The cache drops an idle entry after five
/// minutes and keeps one per set of services, so a window kept in the entry would let an
/// account send its cap again every five minutes, or once per entry.
#[derive(Debug, Default)]
struct SendWindows(Mutex<HashMap<AppleId, Arc<SendWindow>>>);

impl SendWindows {
    fn for_account(&self, apple_id: &AppleId) -> Arc<SendWindow> {
        let mut windows = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() >= SWEEP_AT {
            windows.retain(|_, window| !window.is_idle());
        }
        Arc::clone(
            windows
                .entry(apple_id.clone())
                .or_insert_with(|| Arc::new(SendWindow::new(SendLimits::default()))),
        )
    }
}

/// Builds each account's providers from per-call credentials.
#[derive(Debug)]
pub struct IcloudBackend<C: Connect + Clone> {
    imap: C,
    http: DavHttp,
    dav: DavTarget,
    smtp: SmtpTarget,
    sends: SendWindows,
}

impl IcloudBackend<IcloudConnect> {
    /// The iCloud hosts.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Network`] when the system has no root certificates to check
    /// iCloud with.
    pub fn icloud() -> Result<Self, CoreError> {
        Ok(Self {
            imap: IcloudConnect::new().map_err(|_| CoreError::Network)?,
            http: DavHttp::new()?,
            dav: DavTarget::Icloud,
            smtp: SmtpTarget::Icloud,
            sends: SendWindows::default(),
        })
    }
}

impl<C: Connect + Clone> IcloudBackend<C> {
    /// Loopback servers instead of iCloud: Radicale for DAV and `GreenMail` for SMTP.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Network`] when the system has no root certificates.
    #[cfg(test)]
    pub(crate) fn loopback(
        imap: C,
        caldav_url: &str,
        carddav_url: &str,
        smtp_host: &str,
        smtp_port: u16,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            imap,
            http: DavHttp::new()?,
            dav: DavTarget::Loopback {
                caldav: caldav_url.to_owned(),
                carddav: carddav_url.to_owned(),
            },
            smtp: SmtpTarget::Loopback(smtp_host.to_owned(), smtp_port),
            sends: SendWindows::default(),
        })
    }

    fn caldav_client(&self, apple_id: &AppleId) -> DavClient {
        match &self.dav {
            DavTarget::Icloud => DavClient::per_call(apple_id.clone(), &self.http),
            #[cfg(test)]
            DavTarget::Loopback { caldav, .. } => self.loopback_client(apple_id, caldav),
        }
    }

    fn carddav_client(&self, apple_id: &AppleId) -> DavClient {
        match &self.dav {
            DavTarget::Icloud => DavClient::per_call(apple_id.clone(), &self.http),
            #[cfg(test)]
            DavTarget::Loopback { carddav, .. } => self.loopback_client(apple_id, carddav),
        }
    }

    /// A test gave a URL that is not loopback, which is the test's bug.
    #[cfg(test)]
    fn loopback_client(&self, apple_id: &AppleId, url: &str) -> DavClient {
        DavClient::per_call_for_test_server(apple_id.clone(), url, &self.http)
            .expect("a loopback DAV url")
    }

    fn smtp_client(&self, apple_id: &AppleId) -> SmtpClient {
        match &self.smtp {
            SmtpTarget::Icloud => SmtpClient::icloud_per_call(apple_id.clone()),
            #[cfg(test)]
            SmtpTarget::Loopback(host, port) => {
                SmtpClient::plain_per_call(apple_id.clone(), host.clone(), *port)
                    .expect("a loopback SMTP host")
            }
        }
    }
}

impl<C: Connect + Clone + 'static> Backend for IcloudBackend<C> {
    type Mail = SessionMail<C>;
    type Calendar = CalDavProvider;
    type Contacts = CardDavProvider;

    fn open(
        &self,
        apple_id: &AppleId,
    ) -> Providers<SessionMail<C>, CalDavProvider, CardDavProvider> {
        let pool = ImapPool::per_call(apple_id.clone(), self.imap.clone());
        let mail = MailSession::with_window(
            pool,
            self.smtp_client(apple_id),
            self.sends.for_account(apple_id),
        );
        Providers {
            mail: Arc::new(SessionMail(mail)),
            calendar: Arc::new(CalDavProvider::new(self.caldav_client(apple_id))),
            contacts: Arc::new(CardDavProvider::new(self.carddav_client(apple_id))),
        }
    }
}

/// Adapts an iCloud mail session to the tool layer.
#[derive(Debug)]
pub struct SessionMail<C: Connect>(MailSession<C>);

impl<C: Connect + 'static> MailApi for SessionMail<C> {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        self.0.imap().list_mailboxes().await
    }

    async fn search(&self, query: &MailSearch) -> Result<MailHitPage, CoreError> {
        let page = self.0.imap().search(query).await?;
        Ok(MailHitPage {
            messages: page.messages,
            next_cursor: page.next_cursor,
            warnings: page.warnings,
        })
    }

    async fn get_message(&self, id: &MessageId, offset: usize) -> Result<MailBody, CoreError> {
        let fetched = self.0.imap().get_message(id, offset).await?;
        Ok(MailBody {
            message: fetched.message,
            next_offset: fetched.next_offset,
        })
    }

    async fn get_attachment(
        &self,
        id: &MessageId,
        part: &str,
        offset: usize,
    ) -> Result<MailPart, CoreError> {
        let fetched = self.0.imap().get_attachment(id, part, offset).await?;
        Ok(MailPart {
            attachment: fetched.attachment,
            next_offset: fetched.next_offset,
        })
    }

    async fn get_attachment_bytes(
        &self,
        id: &MessageId,
        part: &str,
    ) -> Result<Attachment, CoreError> {
        self.0.imap().get_attachment_bytes(id, part).await
    }

    async fn create_draft(&self, draft: &Draft) -> Result<MessageId, CoreError> {
        self.0.create_draft(draft).await
    }

    async fn send(&self, draft: &Draft) -> Result<SentMail, CoreError> {
        let sent = self.0.send(draft).await?;
        Ok(SentMail { id: sent.id })
    }

    async fn unsubscribe(&self, id: &MessageId) -> Result<Unsubscribed, CoreError> {
        Ok(match self.0.unsubscribe(id).await? {
            UnsubscribeOutcome::Emailed(sent) => Unsubscribed::Emailed(SentMail { id: sent.id }),
            UnsubscribeOutcome::OneClicked => Unsubscribed::OneClicked,
            UnsubscribeOutcome::OneClickFailed {
                failure,
                mailto_offered,
            } => Unsubscribed::OneClickFailed {
                failure,
                mailto_offered,
            },
            UnsubscribeOutcome::Links(links) => Unsubscribed::Links(links),
            _ => Unsubscribed::NotOffered,
        })
    }

    async fn move_message(&self, id: &MessageId, destination: &MailDest) -> Result<(), CoreError> {
        match destination {
            MailDest::Path(path) => self.0.move_to(id, path).await,
            MailDest::Role(role) => self.0.move_to_role(id, *role).await,
            _ => Err(CoreError::Unsupported("that move destination")),
        }
    }

    async fn set_flags(&self, id: &MessageId, flags: &FlagChange) -> Result<(), CoreError> {
        self.0.set_flags(id, flags).await
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use ibridge_auth::{Credentials, LoginLog, with_call_credentials};
    use ibridge_core::{
        AppleId, CalendarProvider, ContactQuery, ContactsProvider, CoreError, Draft,
        RemindersProvider,
    };
    use ibridge_mail::Connect;
    use ibridge_server::MailApi;
    use ibridge_testkit::dav_mock::{FakeCalDav, FakeCardDav};
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
    use tokio::net::TcpListener;

    use super::IcloudBackend;
    use crate::provider::Backend;

    const PASSWORD: &str = "abcd-efgh-ijkl-mnop";

    #[derive(Clone, Debug)]
    struct FakeConnect(FakeImap);

    impl Connect for FakeConnect {
        type Stream = DuplexStream;

        fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
            std::future::ready(Ok(self.0.connect()))
        }
    }

    /// A SMTP server that accepts one message and remembers what it logged in with.
    struct Smtp {
        port: u16,
        logins: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Smtp {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("address").port();
            let logins = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&logins);
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    let seen = Arc::clone(&seen);
                    tokio::spawn(async move {
                        let _ = Self::session(socket, seen).await;
                    });
                }
            });
            Self { port, logins }
        }

        async fn session(
            socket: tokio::net::TcpStream,
            seen: Arc<Mutex<Vec<(String, String)>>>,
        ) -> io::Result<()> {
            let mut reader = BufReader::new(socket);
            reader.get_mut().write_all(b"220 localhost\r\n").await?;
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                let reply: &[u8] = if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        b"250 queued\r\n"
                    } else {
                        continue;
                    }
                } else if line.starts_with("EHLO") {
                    b"250-localhost\r\n250 AUTH PLAIN\r\n"
                } else if let Some(initial) = line.trim().strip_prefix("AUTH PLAIN ") {
                    let decoded = base64_decode(initial);
                    let mut parts = decoded.split('\0').skip(1);
                    let user = parts.next().unwrap_or_default().to_owned();
                    let password = parts.next().unwrap_or_default().to_owned();
                    seen.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((user, password));
                    b"235 ok\r\n"
                } else if line.starts_with("DATA") {
                    in_data = true;
                    b"354 go\r\n"
                } else if line.starts_with("QUIT") {
                    reader.get_mut().write_all(b"221 bye\r\n").await?;
                    return Ok(());
                } else {
                    b"250 ok\r\n"
                };
                reader.get_mut().write_all(reply).await?;
            }
        }

        fn logins(&self) -> Vec<(String, String)> {
            self.logins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    fn base64_decode(text: &str) -> String {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text)
            .expect("base64");
        String::from_utf8(bytes).expect("utf-8")
    }

    fn ada() -> AppleId {
        AppleId::try_from("ada@icloud.com").expect("apple id")
    }

    fn credentials_for(apple_id: &str) -> Arc<Credentials> {
        Arc::new(Credentials::new(
            AppleId::try_from(apple_id).expect("apple id"),
            PASSWORD,
        ))
    }

    async fn as_call<T>(credentials: Arc<Credentials>, work: impl Future<Output = T>) -> T {
        with_call_credentials(credentials, Arc::new(LoginLog::new()), work).await
    }

    struct Rig {
        backend: IcloudBackend<FakeConnect>,
        imap: FakeImap,
        calendar: FakeCalDav,
        contacts: FakeCardDav,
        smtp: Smtp,
    }

    async fn rig() -> Rig {
        let imap = FakeImap::spawn(FakeScript::default());
        let calendar = FakeCalDav::start().await;
        calendar.add_collection("home", "Home", &["VEVENT"]);
        calendar.add_collection("tasks", "Tasks", &["VTODO"]);
        let contacts = FakeCardDav::start().await;
        contacts.add_book("main", "Main");
        let smtp = Smtp::start().await;
        let backend = IcloudBackend::loopback(
            FakeConnect(imap.clone()),
            &calendar.base_url(),
            &contacts.base_url(),
            "127.0.0.1",
            smtp.port,
        )
        .expect("backend");
        Rig {
            backend,
            imap,
            calendar,
            contacts,
            smtp,
        }
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

    #[tokio::test]
    async fn hosted_backend_serves_every_service() {
        let rig = rig().await;
        let providers = rig.backend.open(&ada());
        as_call(credentials_for("ada@icloud.com"), async {
            let boxes = providers.mail.list_mailboxes().await.expect("mail lists");
            assert!(
                boxes.iter().any(|mailbox| mailbox.path.as_str() == "INBOX"),
                "mail reaches the fake IMAP, got {boxes:?}"
            );
            let calendars = providers
                .calendar
                .list_calendars()
                .await
                .expect("calendar lists");
            assert!(
                calendars.iter().any(|calendar| calendar.name == "Home"),
                "calendar reaches the fake CalDAV, got {calendars:?}"
            );
            let lists = providers.calendar.list_lists().await.expect("reminders");
            assert!(
                lists.iter().any(|list| list.name == "Tasks"),
                "reminders reach the fake CalDAV task list, got {lists:?}"
            );
            providers
                .contacts
                .search(&ContactQuery {
                    text: "ada".to_owned(),
                    limit: 5,
                    include_groups: false,
                })
                .await
                .expect("contacts search");
            providers.mail.send(&draft()).await.expect("send");
        })
        .await;
        assert!(
            !rig.calendar.requests().is_empty(),
            "calendar sent DAV requests"
        );
        assert_eq!(
            rig.smtp.logins(),
            vec![("ada@icloud.com".to_owned(), PASSWORD.to_owned())],
            "send signed in with the call's password"
        );
        assert!(
            !rig.contacts.requests().is_empty(),
            "contacts sent DAV requests"
        );
    }

    /// Sends `count` mails as `credentials` through `providers`, one call each.
    async fn send_many(
        providers: &crate::provider::Providers<
            super::SessionMail<FakeConnect>,
            ibridge_calendar::CalDavProvider,
            ibridge_contacts::CardDavProvider,
        >,
        credentials: &Arc<Credentials>,
        count: usize,
    ) {
        for _ in 0..count {
            as_call(Arc::clone(credentials), async {
                providers
                    .mail
                    .send(&draft())
                    .await
                    .expect("send is within the cap");
            })
            .await;
        }
    }

    #[tokio::test]
    async fn send_cap_survives_cache_eviction() {
        let rig = rig().await;
        let credentials = credentials_for("ada@icloud.com");
        let before_eviction = rig.backend.open(&ada());
        send_many(&before_eviction, &credentials, 20).await;
        // The cache drops an idle entry and builds a new one with a fresh `open`.
        drop(before_eviction);
        let rebuilt = rig.backend.open(&ada());
        let refused = as_call(Arc::clone(&credentials), async {
            rebuilt.mail.send(&draft()).await
        })
        .await;
        assert!(
            matches!(refused, Err(CoreError::RateLimited { .. })),
            "the 21st send in the hour is refused after the entry was rebuilt, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn send_cap_is_shared_by_every_entry_of_one_account() {
        let rig = rig().await;
        let credentials = credentials_for("ada@icloud.com");
        // Two grants that found different services on get two cache entries, so two opens.
        let first = rig.backend.open(&ada());
        let second = rig.backend.open(&ada());
        send_many(&first, &credentials, 10).await;
        send_many(&second, &credentials, 10).await;
        let refused = as_call(Arc::clone(&credentials), async {
            first.mail.send(&draft()).await
        })
        .await;
        assert!(
            matches!(refused, Err(CoreError::RateLimited { .. })),
            "ten sends through each entry use the one hourly cap, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn send_cap_is_per_account() {
        let rig = rig().await;
        let ada_calls = credentials_for("ada@icloud.com");
        let bob_calls = credentials_for("bob@icloud.com");
        let ada_providers = rig.backend.open(&ada());
        send_many(&ada_providers, &ada_calls, 20).await;
        let bob_providers = rig
            .backend
            .open(&AppleId::try_from("bob@icloud.com").expect("apple id"));
        send_many(&bob_providers, &bob_calls, 1).await;
    }

    #[tokio::test]
    async fn hosted_backend_holds_no_password_between_calls() {
        let rig = rig().await;
        let providers = rig.backend.open(&ada());
        let credentials = credentials_for("ada@icloud.com");
        as_call(Arc::clone(&credentials), async {
            providers.calendar.list_calendars().await.expect("calendar");
            providers.mail.send(&draft()).await.expect("send");
        })
        .await;
        assert_eq!(
            Arc::strong_count(&credentials),
            1,
            "no provider kept the call's credentials"
        );
        let dav_before = rig.calendar.requests().len();
        let smtp_before = rig.smtp.logins().len();
        let imap_before = rig.imap.login_count();

        let calendar = providers.calendar.list_calendars().await;
        assert!(
            matches!(calendar, Err(CoreError::Protocol(_))),
            "a calendar call with no credentials fails, got {calendar:?}"
        );
        let send = providers.mail.send(&draft()).await;
        assert!(send.is_err(), "a send with no credentials fails");
        assert_eq!(rig.calendar.requests().len(), dav_before, "no DAV request");
        assert_eq!(rig.smtp.logins().len(), smtp_before, "no SMTP login");
        assert_eq!(rig.imap.login_count(), imap_before, "no IMAP login");

        let other = as_call(credentials_for("bob@icloud.com"), async {
            providers.calendar.list_calendars().await
        })
        .await;
        assert!(
            matches!(other, Err(CoreError::Protocol(_))),
            "another account's call is refused, got {other:?}"
        );
        assert_eq!(
            rig.calendar.requests().len(),
            dav_before,
            "still no request"
        );
    }
}
