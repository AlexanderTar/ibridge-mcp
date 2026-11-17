// SPDX-License-Identifier: Apache-2.0

//! IMAP session pool. At most two connections per account.

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_imap::error::Error as ImapError;
use async_imap::types::Capability;
use ibridge_auth::Credentials;
use ibridge_core::CoreError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const SESSION_LIMIT: usize = 2;
const IDLE_LIMIT: Duration = Duration::from_mins(5);

/// Opens one IMAP byte stream. The pool speaks the protocol.
pub trait Connect: Send + Sync {
    /// Connected stream. The connector owns TLS when the host is real.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + fmt::Debug;

    /// Opens a stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream cannot be opened.
    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

struct IdleSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug,
{
    session: async_imap::Session<S>,
    capabilities: Vec<String>,
    idle_at: tokio::time::Instant,
}

/// Checked-out session. Dropping it frees a pool slot without reuse.
#[must_use = "release the lease to put the session back"]
pub struct Lease<'a, C: Connect> {
    pool: &'a ImapPool<C>,
    session: Option<IdleSession<C::Stream>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<C: Connect> fmt::Debug for Lease<'_, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("session", &self.session.is_some())
            .field("permit", &self.permit.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: Connect> Lease<'_, C> {
    /// Returns the session to the idle set.
    pub fn release(mut self) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        session.idle_at = tokio::time::Instant::now();
        self.pool.push_idle(session);
    }

    pub(super) fn session_mut(&mut self) -> Option<&mut async_imap::Session<C::Stream>> {
        self.session.as_mut().map(|idle| &mut idle.session)
    }
}

/// Where a new connection gets its password.
enum Login {
    /// The pool owns the credentials.
    Owned(Credentials),
    /// The pool owns none. The call that needs a connection supplies them.
    PerCall(ibridge_core::AppleId),
}

impl Login {
    fn apple_id(&self) -> &ibridge_core::AppleId {
        match self {
            Self::Owned(credentials) => &credentials.apple_id,
            Self::PerCall(apple_id) => apple_id,
        }
    }

    /// The Apple ID and password for one `LOGIN`. The password is wiped when the pair drops.
    fn for_login(&self) -> Result<(ibridge_core::AppleId, Zeroizing<String>), CoreError> {
        let read = |credentials: &Credentials| {
            (
                credentials.apple_id.clone(),
                credentials.with_secret(|secret| Zeroizing::new(secret.to_owned())),
            )
        };
        match self {
            Self::Owned(credentials) => Ok(read(credentials)),
            Self::PerCall(apple_id) => match ibridge_auth::call_credentials(read) {
                Some((id, password)) if id == *apple_id => Ok((id, password)),
                // A call without credentials, or with another account's, is a bug in the caller.
                _ => Err(CoreError::Protocol(
                    "no credentials for this call".to_owned(),
                )),
            },
        }
    }
}

/// Two IMAP sessions for one account, reused after `NOOP` while they are fresh.
pub struct ImapPool<C: Connect> {
    login: Login,
    connector: C,
    slots: Arc<Semaphore>,
    idle: Mutex<Vec<IdleSession<C::Stream>>>,
}

impl<C: Connect> fmt::Debug for ImapPool<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImapPool")
            .field("apple_id", self.login.apple_id())
            .finish_non_exhaustive()
    }
}

impl<C: Connect> ImapPool<C> {
    /// Builds a pool. The password stays inside `credentials` until `LOGIN`.
    #[must_use]
    pub fn new(credentials: Credentials, connector: C) -> Self {
        Self {
            login: Login::Owned(credentials),
            connector,
            slots: Arc::new(Semaphore::new(SESSION_LIMIT)),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Builds a pool for a server that must not keep the password between calls.
    ///
    /// A new connection logs in with the credentials of the call that needs it
    /// (see `ibridge_auth::with_call_credentials`). Sessions that are already open
    /// serve any later call, whatever credentials it carries.
    #[must_use]
    pub fn per_call(apple_id: ibridge_core::AppleId, connector: C) -> Self {
        Self {
            login: Login::PerCall(apple_id),
            connector,
            slots: Arc::new(Semaphore::new(SESSION_LIMIT)),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Logs in, then reads capabilities with a separate `CAPABILITY` command.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Auth`] when `LOGIN` is rejected. That rejection is not retried.
    pub async fn capabilities(&self) -> Result<Vec<String>, CoreError> {
        let lease = self.checkout().await?;
        let Some(capabilities) = lease
            .session
            .as_ref()
            .map(|session| session.capabilities.clone())
        else {
            lease.release();
            return Err(CoreError::Network);
        };
        lease.release();
        Ok(capabilities)
    }

    /// Takes a session, opening one when fewer than two are live.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Auth`] when `LOGIN` is rejected. That rejection is not retried.
    pub async fn checkout(&self) -> Result<Lease<'_, C>, CoreError> {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| CoreError::Network)?;
        let session = match self.reuse().await {
            Some(session) => session,
            None => self.login().await?,
        };
        Ok(Lease {
            pool: self,
            session: Some(session),
            permit: Some(permit),
        })
    }

    async fn reuse(&self) -> Option<IdleSession<C::Stream>> {
        loop {
            let mut session = self.pop_idle()?;
            if session.idle_at.elapsed() > IDLE_LIMIT {
                continue;
            }
            if session.session.noop().await.is_ok() {
                return Some(session);
            }
        }
    }

    async fn login(&self) -> Result<IdleSession<C::Stream>, CoreError> {
        let stream = self
            .connector
            .connect()
            .await
            .map_err(|_| CoreError::Network)?;
        let client = async_imap::Client::new(stream);
        let logged_in = {
            let (apple_id, password) = self.login.for_login()?;
            client.login(apple_id.as_str(), (*password).as_str()).await
        };
        let mut session = match logged_in {
            Ok(session) => {
                ibridge_auth::report_login(ibridge_auth::LoginVerdict::Accepted);
                session
            }
            Err((error, _)) => {
                let mapped = map_login(&error);
                // Throttling and dropped connections say nothing about the password.
                if matches!(mapped, CoreError::Auth) {
                    ibridge_auth::report_login(ibridge_auth::LoginVerdict::Rejected);
                }
                return Err(mapped);
            }
        };
        let capabilities = session
            .capabilities()
            .await
            .map_err(|error| map_command(&error))?;
        Ok(IdleSession {
            capabilities: capabilities.iter().map(capability_name).collect(),
            session,
            idle_at: tokio::time::Instant::now(),
        })
    }

    fn pop_idle(&self) -> Option<IdleSession<C::Stream>> {
        self.idle.lock().expect("idle sessions").pop()
    }

    fn push_idle(&self, session: IdleSession<C::Stream>) {
        self.idle.lock().expect("idle sessions").push(session);
    }
}

fn capability_name(capability: &Capability) -> String {
    match capability {
        Capability::Imap4rev1 => "IMAP4REV1".to_owned(),
        Capability::Auth(mechanism) => format!("AUTH={mechanism}"),
        Capability::Atom(atom) => atom.clone(),
    }
}

fn map_login(error: &ImapError) -> CoreError {
    if throttled(error) {
        CoreError::RateLimited { retry_after: None }
    } else if matches!(error, ImapError::No(_) | ImapError::Bad(_)) {
        CoreError::Auth
    } else {
        map_command(error)
    }
}

pub(super) fn map_command(error: &ImapError) -> CoreError {
    if throttled(error) {
        return CoreError::RateLimited { retry_after: None };
    }
    match error {
        ImapError::Io(_) | ImapError::ConnectionLost => CoreError::Network,
        _ => CoreError::Protocol("imap command failed".to_owned()),
    }
}

/// How a command finished. Untagged replies are handed to the caller as they arrive.
pub(super) struct Checked {
    /// The stream stopped on a line the parser could not read.
    pub(super) unparsed: bool,
}

/// Runs a command and reads through the tagged completion.
///
/// `Session::list` and `Session::uid_fetch` stop before that completion, so a
/// `NO [THROTTLED]` there never becomes an error. `on_item` sees each untagged
/// reply and must copy anything it keeps.
///
/// # Errors
///
/// Returns [`CoreError::RateLimited`] when the tagged status mentions `THROTTLED`,
/// [`CoreError::Network`] when the stream ends, and [`CoreError::Protocol`] for any
/// other failed status. Server text is not copied into the error.
pub(super) async fn run_checked<S>(
    session: &mut async_imap::Session<S>,
    command: &str,
    mut on_item: impl FnMut(&async_imap::imap_proto::Response<'_>),
) -> Result<Checked, CoreError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + fmt::Debug + Send,
{
    let id = session
        .run_command(command)
        .await
        .map_err(|error| map_command(&error))?;
    loop {
        match session.read_response().await {
            Ok(Some(response)) => {
                let finished = match response.parsed() {
                    async_imap::imap_proto::Response::Done {
                        tag,
                        status,
                        outcome,
                    } if tag == &id => Some(done_status(status, outcome)),
                    _ => None,
                };
                if let Some(finished) = finished {
                    finished?;
                    return Ok(Checked { unparsed: false });
                }
                on_item(response.parsed());
            }
            Ok(None) => return Err(CoreError::Network),
            Err(error) => {
                if error.to_string().contains("during parsing") {
                    return Ok(Checked { unparsed: true });
                }
                return Err(CoreError::Network);
            }
        }
    }
}

pub(super) fn done_status(
    status: &async_imap::imap_proto::Status,
    outcome: &async_imap::imap_proto::Outcome<'_>,
) -> Result<(), CoreError> {
    if matches!(status, async_imap::imap_proto::Status::Ok) {
        return Ok(());
    }
    let rendered = format!(
        "{:?} {}",
        outcome.code,
        outcome.information.as_deref().unwrap_or("")
    );
    if rendered.to_ascii_uppercase().contains("THROTTLED") {
        return Err(CoreError::RateLimited { retry_after: None });
    }
    Err(CoreError::Protocol("imap command failed".to_owned()))
}

fn throttled(error: &ImapError) -> bool {
    let text = match error {
        ImapError::No(text) | ImapError::Bad(text) => text.as_str(),
        other => return other.to_string().to_ascii_uppercase().contains("THROTTLED"),
    };
    text.to_ascii_uppercase().contains("THROTTLED")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ibridge_core::{CoreError, MailSearch, MailboxPath, MessageId, Uid, UidValidity};
    use ibridge_testkit::imap_fake::FakeScript;

    use super::super::support::{PASSWORD, pool, replay_pool};

    #[tokio::test]
    async fn pool_requeries_capability_after_login() {
        let (fake, pool) = pool(FakeScript::default());
        let caps = pool.capabilities().await.expect("capabilities");
        assert!(
            caps.iter()
                .any(|cap| cap.eq_ignore_ascii_case("SPECIAL-USE")),
            "post-login capabilities include SPECIAL-USE, got {caps:?}"
        );
        let commands = fake.commands();
        let login_at = commands.iter().position(|command| *command == "LOGIN");
        let capability_at = commands.iter().position(|command| *command == "CAPABILITY");
        assert!(
            matches!((login_at, capability_at), (Some(login), Some(capability)) if login < capability),
            "CAPABILITY is a separate command after LOGIN, commands {commands:?}"
        );
    }

    #[tokio::test]
    async fn fixture_icloud_capability_requery() {
        let greeting = ibridge_testkit::fixtures::read("imap", "capability-greeting.txt");
        let after_login = ibridge_testkit::fixtures::read("imap", "capability-after-login.txt");
        assert!(
            !greeting.contains("UIDPLUS") && after_login.contains("UIDPLUS"),
            "the recording shows iCloud advertising more after LOGIN than in its greeting"
        );
        let caps = replay_pool().capabilities().await.expect("capabilities");
        let has = |name: &str| caps.iter().any(|cap| cap.eq_ignore_ascii_case(name));
        assert!(
            has("UIDPLUS") && has("IDLE") && has("NAMESPACE"),
            "the pool keeps the post-login set, got {caps:?}"
        );
        assert!(
            !has("AUTH=PLAIN"),
            "greeting-only capabilities are replaced, got {caps:?}"
        );
        assert!(
            !has("MOVE") && !has("SPECIAL-USE"),
            "iCloud advertises neither MOVE nor SPECIAL-USE, got {caps:?}"
        );
    }

    #[tokio::test]
    async fn pool_caps_two_connections_per_account() {
        let (fake, pool) = pool(FakeScript::default());
        let first = pool.checkout().await.expect("first session");
        let second = pool.checkout().await.expect("second session");
        assert_eq!(
            fake.connection_count(),
            2,
            "two checkouts open two connections"
        );
        let third = tokio::time::timeout(Duration::from_millis(200), pool.checkout()).await;
        assert!(
            third.is_err(),
            "a third checkout waits instead of opening another connection"
        );
        assert_eq!(fake.connection_count(), 2, "still two connections");
        first.release();
        let _reused = pool.checkout().await.expect("session after a release");
        assert_eq!(
            fake.connection_count(),
            2,
            "releasing a session lets the next checkout reuse it"
        );
        second.release();
    }

    #[tokio::test]
    async fn pool_reuses_after_noop() {
        tokio::time::pause();
        let (fake, pool) = pool(FakeScript::default());
        let lease = pool.checkout().await.expect("session");
        lease.release();
        tokio::time::advance(Duration::from_mins(4)).await;
        let again = pool.checkout().await.expect("reused session");
        assert_eq!(fake.connection_count(), 1, "an idle session is reused");
        assert!(
            fake.commands().contains(&"NOOP"),
            "reuse is checked with NOOP, commands {:?}",
            fake.commands()
        );
        again.release();
        tokio::time::advance(Duration::from_mins(6)).await;
        let _fresh = pool.checkout().await.expect("session after idle expiry");
        assert_eq!(
            fake.connection_count(),
            2,
            "a session idle for more than 5 minutes is replaced"
        );
    }

    #[tokio::test]
    async fn pool_never_retries_auth_failure() {
        let (fake, pool) = pool(FakeScript {
            reject_login: true,
            ..FakeScript::default()
        });
        let error = pool.capabilities().await.expect_err("login is rejected");
        assert!(
            matches!(error, CoreError::Auth),
            "a rejected LOGIN is auth, got {error:?}"
        );
        let rendered = format!("{error} {error:?} {pool:?}");
        assert!(
            !rendered.contains("server-said-no") && !rendered.contains(PASSWORD),
            "auth errors and the pool debug must not carry the server text or the password, got {rendered}"
        );
        assert_eq!(fake.login_count(), 1, "an auth failure sends LOGIN once");
    }

    fn message_id(uid: u32) -> MessageId {
        MessageId {
            mailbox: MailboxPath::try_from("INBOX").expect("inbox"),
            validity: UidValidity::try_from(1).expect("validity"),
            uid: Uid::try_from(uid).expect("uid"),
        }
    }

    fn inbox_query() -> MailSearch {
        MailSearch {
            mailbox: Some(MailboxPath::try_from("INBOX").expect("inbox")),
            role: None,
            from: None,
            to: None,
            subject: None,
            text: None,
            since: None,
            before: None,
            unread_only: false,
            flagged_only: false,
            limit: 25,
            cursor: None,
        }
    }

    #[tokio::test]
    async fn throttled_maps_to_rate_limited() {
        let (_fake, listed) = pool(FakeScript {
            throttle_list: true,
            ..FakeScript::default()
        });
        let list_error = listed
            .list_mailboxes()
            .await
            .expect_err("LIST is throttled");
        assert!(
            matches!(list_error, CoreError::RateLimited { retry_after: None }),
            "a throttled LIST is rate limited, got {list_error:?}"
        );

        let (_fake, searched) = pool(FakeScript {
            throttle_search: true,
            ..FakeScript::default()
        });
        let search_error = searched
            .search(&inbox_query())
            .await
            .expect_err("SEARCH is throttled");
        assert!(
            matches!(search_error, CoreError::RateLimited { retry_after: None }),
            "a throttled UID SEARCH is rate limited, got {search_error:?}"
        );

        let (_fake, fetched) = pool(FakeScript {
            throttle_fetch: true,
            ..FakeScript::default()
        });
        let fetch_error = fetched
            .search(&inbox_query())
            .await
            .expect_err("FETCH during search is throttled");
        assert!(
            matches!(fetch_error, CoreError::RateLimited { retry_after: None }),
            "a throttled UID FETCH is rate limited, got {fetch_error:?}"
        );
        let message_error = fetched
            .get_message(&message_id(4), 0)
            .await
            .expect_err("FETCH of one message is throttled");
        assert!(
            matches!(message_error, CoreError::RateLimited { retry_after: None }),
            "get_message maps a throttled FETCH to rate limited, got {message_error:?}"
        );
    }
}
