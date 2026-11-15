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

    async fn list(&mut self) -> Result<(), CoreError> {
        let Some(session) = self.session.as_mut() else {
            return Err(CoreError::Network);
        };
        session
            .session
            .run_command_and_check_ok("LIST \"\" *")
            .await
            .map_err(|error| map_command(&error))
    }
}

/// Two IMAP sessions for one account, reused after `NOOP` while they are fresh.
pub struct ImapPool<C: Connect> {
    credentials: Credentials,
    connector: C,
    slots: Arc<Semaphore>,
    idle: Mutex<Vec<IdleSession<C::Stream>>>,
}

impl<C: Connect> fmt::Debug for ImapPool<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImapPool")
            .field("apple_id", &self.credentials.apple_id)
            .finish_non_exhaustive()
    }
}

impl<C: Connect> ImapPool<C> {
    /// Builds a pool. The password stays inside `credentials` until `LOGIN`.
    #[must_use]
    pub fn new(credentials: Credentials, connector: C) -> Self {
        Self {
            credentials,
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

    /// Runs `LIST` on a pooled session.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RateLimited`] when the server answers `NO [THROTTLED]`.
    pub async fn list(&self) -> Result<(), CoreError> {
        let mut lease = self.checkout().await?;
        let listed = lease.list().await;
        lease.release();
        listed
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
            let password = self
                .credentials
                .with_secret(|secret| Zeroizing::new(secret.to_owned()));
            client
                .login(self.credentials.apple_id.as_str(), (*password).as_str())
                .await
        };
        let mut session = match logged_in {
            Ok(session) => session,
            Err((error, _)) => return Err(map_login(&error)),
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

fn map_command(error: &ImapError) -> CoreError {
    if throttled(error) {
        return CoreError::RateLimited { retry_after: None };
    }
    match error {
        ImapError::Io(_) | ImapError::ConnectionLost => CoreError::Network,
        _ => CoreError::Protocol("imap command failed".to_owned()),
    }
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
    use std::future::{Future, ready};
    use std::time::Duration;

    use ibridge_auth::Credentials;
    use ibridge_core::{AppleId, CoreError};
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
    use tokio::io::DuplexStream;

    use super::{Connect, ImapPool};

    const PASSWORD: &str = "test-secret";

    fn credentials() -> Credentials {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        Credentials::new(apple_id, PASSWORD)
    }

    fn pool(script: FakeScript) -> (FakeImap, ImapPool<FakeImap>) {
        let fake = FakeImap::spawn(script);
        let pool = ImapPool::new(credentials(), fake.clone());
        (fake, pool)
    }

    impl Connect for FakeImap {
        type Stream = DuplexStream;

        fn connect(&self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send {
            let stream = FakeImap::connect(self);
            ready(Ok(stream))
        }
    }

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

    #[tokio::test]
    async fn throttled_maps_to_rate_limited() {
        let (_fake, pool) = pool(FakeScript {
            throttle_list: true,
            ..FakeScript::default()
        });
        let error = pool.list().await.expect_err("LIST is throttled");
        assert!(
            matches!(error, CoreError::RateLimited { retry_after: None }),
            "NO [THROTTLED] is rate limited with no retry delay, got {error:?}"
        );
    }
}
