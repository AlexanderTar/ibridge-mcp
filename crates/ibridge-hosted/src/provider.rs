// SPDX-License-Identifier: Apache-2.0

//! One set of providers per account, shared by every grant of that account.
//!
//! The cache holds what is safe to keep between calls: pooled IMAP sessions, the
//! per-account limit of four calls at once, and the tool servers built on them. It never
//! holds a password. A call's password lives in the call's credentials scope and
//! reaches a provider only through `ibridge_auth::call_credentials`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ibridge_auth::with_call_credentials;
use ibridge_core::{AppleId, CalendarProvider, ContactsProvider, RemindersProvider};
use ibridge_server::{AccountSnapshot, IbridgeServer, MailApi, ServiceStatus};
use rmcp::RoleServer;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, ListToolsResult, PaginatedRequestParams,
    ServerConfig,
};
use rmcp::service::RequestContext;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::middleware::CallAuth;
use crate::oauth::address_key;
use crate::server::{ScopedServers, ServerSource, call_auth};

/// Tool calls one account may have in flight at once.
const CALLS_PER_ACCOUNT: usize = 4;
/// How long an account's providers stay cached with no calls.
const IDLE: Duration = Duration::from_mins(5);

/// The providers for one account.
#[derive(Debug)]
pub struct Providers<M, C, K> {
    /// Mail.
    pub mail: Arc<M>,
    /// Calendar and reminders.
    pub calendar: Arc<C>,
    /// Contacts.
    pub contacts: Arc<K>,
}

/// Builds an account's providers.
pub trait Backend: Send + Sync + 'static {
    /// Mail backend.
    type Mail: MailApi + Send + Sync + 'static;
    /// Calendar and reminders backend.
    type Calendar: CalendarProvider + RemindersProvider + Send + Sync + 'static;
    /// Contacts backend.
    type Contacts: ContactsProvider + Send + Sync + 'static;

    /// Builds the providers for `apple_id`. They hold no password: a provider that
    /// needs one reads the current call's through `ibridge_auth::call_credentials`.
    fn open(&self, apple_id: &AppleId) -> Providers<Self::Mail, Self::Calendar, Self::Contacts>;
}

/// The tool server an account's cache entry hands out.
pub type AccountServer<B> = Account<
    IbridgeServer<<B as Backend>::Mail, <B as Backend>::Calendar, <B as Backend>::Contacts>,
>;

struct Gate {
    permits: Semaphore,
    last_used: Mutex<Instant>,
}

impl Gate {
    fn new() -> Self {
        Self {
            permits: Semaphore::new(CALLS_PER_ACCOUNT),
            last_used: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    /// No call is running and none has run for `idle`.
    fn expired(&self, idle: Duration) -> bool {
        self.permits.available_permits() == CALLS_PER_ACCOUNT
            && self
                .last_used
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .elapsed()
                > idle
    }
}

struct Entry<S> {
    servers: Arc<ScopedServers<S>>,
    gate: Arc<Gate>,
}

/// A tool server that runs at most four calls at once for its account.
#[derive(Debug)]
pub struct Account<S> {
    inner: S,
    gate: Arc<Gate>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Gate").finish_non_exhaustive()
    }
}

impl<S: ServerHandler> ServerHandler for Account<S> {
    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.inner.list_tools(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let credentials = Arc::clone(call_auth(&context)?.credentials());
        let _permit = self
            .gate
            .permits
            .acquire()
            .await
            .map_err(|_| ErrorData::internal_error("internal error", None))?;
        // The password is visible to the providers for this call, and to nothing after it.
        let result =
            with_call_credentials(credentials, self.inner.call_tool(request, context)).await;
        self.gate.touch();
        result
    }
}

impl<B: Backend> std::fmt::Debug for AccountCache<B> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountCache")
            .field("accounts", &self.len())
            .finish_non_exhaustive()
    }
}

/// Providers for every account with recent calls, keyed by Apple ID.
pub struct AccountCache<B: Backend> {
    backend: B,
    idle: Duration,
    entries: Mutex<HashMap<String, Entry<AccountServer<B>>>>,
}

impl<B: Backend> AccountCache<B> {
    /// A cache that drops an account's providers after five idle minutes.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self::with_idle(backend, IDLE)
    }

    /// A cache that drops an account's providers after `idle` with no calls.
    #[must_use]
    pub fn with_idle(backend: B, idle: Duration) -> Self {
        Self {
            backend,
            idle,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How many accounts are cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no account is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets an account and closes its pooled sessions.
    ///
    /// Call this when a grant is revoked and when an account is deleted or suspended.
    pub fn drop_account(&self, apple_id: &AppleId) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&address_key(apple_id));
    }

    fn build(&self, apple_id: &AppleId) -> Entry<AccountServer<B>> {
        let providers = self.backend.open(apple_id);
        let account = AccountSnapshot {
            apple_id: apple_id.clone(),
            mail: ServiceStatus::On,
            calendar: ServiceStatus::On,
            contacts: ServiceStatus::On,
        };
        let gate = Arc::new(Gate::new());
        let server = |read_write: bool| {
            let base = if read_write {
                IbridgeServer::read_write(account.clone(), Arc::clone(&providers.mail))
            } else {
                IbridgeServer::read_only(account.clone(), Arc::clone(&providers.mail))
            };
            Account {
                inner: base
                    .with_calendar(Arc::clone(&providers.calendar))
                    .with_contacts(Arc::clone(&providers.contacts)),
                gate: Arc::clone(&gate),
            }
        };
        Entry {
            servers: Arc::new(ScopedServers {
                read_only: server(false),
                read_write: server(true),
            }),
            gate,
        }
    }
}

impl<B: Backend> ServerSource for AccountCache<B> {
    type Server = AccountServer<B>;

    fn servers(&self, call: &CallAuth) -> Arc<ScopedServers<Self::Server>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // Idle accounts go when any account is next called. ponytail: sockets of an account
        // nobody calls again stay open until then; a sweeper task would close them on time.
        entries.retain(|_, entry| !entry.gate.expired(self.idle));
        let entry = entries
            .entry(address_key(call.apple_id()))
            .or_insert_with(|| self.build(call.apple_id()));
        entry.gate.touch();
        Arc::clone(&entry.servers)
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, ready};
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::{Duration, SystemTime};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::header;
    use ibridge_core::{AppleId, CoreError, MailSearch, Mailbox, MessageId};
    use ibridge_mail::{Connect, ImapPool};
    use ibridge_server::{
        MailApi, MailBody, MailDest, MailHitPage, MailPart, NoCalendar, NoContacts, SentMail,
    };
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
    use secrecy::{ExposeSecret as _, SecretString};
    use serde_json::{Value, json};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::sync::Semaphore;
    use tower::ServiceExt as _;

    use super::{AccountCache, Backend, Providers};
    use crate::middleware::protect;
    use crate::oauth::{Access, OAuthConfig};
    use crate::server::mcp_router;
    use crate::store::{Scope, Store};

    const METADATA: &str = "https://ibridge.example/.well-known/oauth-protected-resource/mcp";

    /// A fake IMAP connection that counts how many are open.
    #[derive(Debug)]
    struct Tracked {
        inner: DuplexStream,
        live: Arc<AtomicUsize>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl AsyncRead for Tracked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Tracked {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct TrackedConnect {
        fake: FakeImap,
        live: Arc<AtomicUsize>,
    }

    impl Connect for TrackedConnect {
        type Stream = Tracked;

        fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
            self.live.fetch_add(1, Ordering::SeqCst);
            ready(Ok(Tracked {
                inner: self.fake.connect(),
                live: Arc::clone(&self.live),
            }))
        }
    }

    /// Counts calls inside the mail backend, and can hold them there.
    struct Hold {
        gate: Semaphore,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    /// Mail over a per-call-credential IMAP pool. Only `list_mailboxes` is real.
    struct ImapMail {
        pool: ImapPool<TrackedConnect>,
        hold: Option<Arc<Hold>>,
    }

    const OFF: CoreError = CoreError::Unsupported("idle");

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the unused operations answer without waiting"
    )]
    impl MailApi for ImapMail {
        async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
            if let Some(hold) = &self.hold {
                let now = hold.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                hold.peak.fetch_max(now, Ordering::SeqCst);
                hold.gate.acquire().await.expect("gate open").forget();
                hold.in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            self.pool.list_mailboxes().await
        }

        async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
            Err(OFF)
        }

        async fn get_message(
            &self,
            _id: &MessageId,
            _offset: usize,
        ) -> Result<MailBody, CoreError> {
            Err(OFF)
        }

        async fn get_attachment(
            &self,
            _id: &MessageId,
            _part: &str,
            _offset: usize,
        ) -> Result<MailPart, CoreError> {
            Err(OFF)
        }

        async fn create_draft(&self, _draft: &ibridge_core::Draft) -> Result<MessageId, CoreError> {
            Err(OFF)
        }

        async fn send(&self, _draft: &ibridge_core::Draft) -> Result<SentMail, CoreError> {
            Err(OFF)
        }

        async fn move_message(
            &self,
            _id: &MessageId,
            _destination: &MailDest,
        ) -> Result<(), CoreError> {
            Err(OFF)
        }

        async fn set_flags(
            &self,
            _id: &MessageId,
            _flags: &ibridge_core::FlagChange,
        ) -> Result<(), CoreError> {
            Err(OFF)
        }
    }

    struct TestBackend {
        fake: FakeImap,
        live: Arc<AtomicUsize>,
        hold: Option<Arc<Hold>>,
    }

    impl Backend for TestBackend {
        type Mail = ImapMail;
        type Calendar = NoCalendar;
        type Contacts = NoContacts;

        fn open(&self, apple_id: &AppleId) -> Providers<ImapMail, NoCalendar, NoContacts> {
            let connector = TrackedConnect {
                fake: self.fake.clone(),
                live: Arc::clone(&self.live),
            };
            Providers {
                mail: Arc::new(ImapMail {
                    pool: ImapPool::per_call(apple_id.clone(), connector),
                    hold: self.hold.clone(),
                }),
                calendar: Arc::new(NoCalendar),
                contacts: Arc::new(NoContacts),
            }
        }
    }

    struct Rig {
        store: Store,
        fake: FakeImap,
        live: Arc<AtomicUsize>,
        cache: Arc<AccountCache<TestBackend>>,
        app: Router,
    }

    async fn rig(script: FakeScript, hold: Option<Arc<Hold>>, idle: Duration) -> Rig {
        let store = Store::memory().await.expect("store");
        let fake = FakeImap::spawn(script);
        let live = Arc::new(AtomicUsize::new(0));
        let backend = TestBackend {
            fake: fake.clone(),
            live: Arc::clone(&live),
            hold,
        };
        let cache = Arc::new(AccountCache::with_idle(backend, idle));
        let config =
            OAuthConfig::new("https://ibridge.example", Access::MultiTenant).expect("public url");
        let info = ibridge_server::IbridgeServer::read_only(
            ibridge_server::AccountSnapshot {
                apple_id: AppleId::try_from("ada@icloud.com").expect("apple id"),
                mail: ibridge_server::ServiceStatus::On,
                calendar: ibridge_server::ServiceStatus::On,
                contacts: ibridge_server::ServiceStatus::On,
            },
            Arc::new(crate::test_mail::IdleMail),
        );
        let info = rmcp::ServerHandler::get_info(&info);
        let app = protect(
            mcp_router(Arc::clone(&cache), info, &config),
            store.clone(),
            METADATA.to_owned(),
        );
        Rig {
            store,
            fake,
            live,
            cache,
            app,
        }
    }

    /// An access token for `apple_id` whose sealed password is `asp`.
    async fn token(store: &Store, apple_id: &str, asp: &str, scope: Scope) -> String {
        let now = SystemTime::now();
        let apple = AppleId::try_from(apple_id).expect("apple id");
        let code = store
            .seal_under_code(&apple, &SecretString::from(asp), scope, now)
            .await
            .expect("seal");
        let issued = store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .expect("exchange");
        issued.access.expose_secret().to_owned()
    }

    /// Calls `mail_list_mailboxes` and returns the JSON-RPC message.
    async fn list_mailboxes(app: &Router, bearer: &str) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "mail_list_mailboxes",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        });
        let request = Request::post("/mcp")
            .header(header::HOST, "ibridge.example")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "mail_list_mailboxes")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("response");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("a JSON reply, got {bytes:?}: {error}"))
    }

    fn succeeded(message: &Value) -> bool {
        message.get("error").is_none() && message["result"]["isError"] != json!(true)
    }

    #[tokio::test]
    async fn hosted_reuses_pooled_imap_session() {
        let rig = rig(FakeScript::default(), None, Duration::from_mins(5)).await;
        let first = token(&rig.store, "ada@icloud.com", "pw-1", Scope::ReadWrite).await;
        let second = token(&rig.store, "ada@icloud.com", "pw-1", Scope::Read).await;

        let one = list_mailboxes(&rig.app, &first).await;
        let two = list_mailboxes(&rig.app, &second).await;

        assert!(succeeded(&one), "first call: {one}");
        assert!(succeeded(&two), "second call, another grant: {two}");
        assert_eq!(
            rig.fake.connection_count(),
            1,
            "both grants of one account share a pooled IMAP connection"
        );
        assert_eq!(rig.fake.login_count(), 1, "the second call does not log in");
    }

    #[tokio::test]
    async fn new_connection_uses_call_credential() {
        let script = FakeScript {
            accepts_password: Some("pw-current".to_owned()),
            ..FakeScript::default()
        };
        let rig = rig(script, None, Duration::from_mins(5)).await;
        let stale = token(&rig.store, "ada@icloud.com", "pw-stale", Scope::ReadWrite).await;
        let current = token(&rig.store, "ada@icloud.com", "pw-current", Scope::ReadWrite).await;

        let refused = list_mailboxes(&rig.app, &stale).await;
        assert!(
            !succeeded(&refused),
            "a new connection logs in with the call's own password, which this server refuses: {refused}"
        );
        assert_eq!(rig.fake.login_count(), 1, "one LOGIN so far");

        let accepted = list_mailboxes(&rig.app, &current).await;
        assert!(
            succeeded(&accepted),
            "a new connection logs in with the password this call carries: {accepted}"
        );
        assert_eq!(
            rig.fake.login_count(),
            2,
            "the second call opened a connection"
        );

        let pooled = list_mailboxes(&rig.app, &stale).await;
        assert!(
            succeeded(&pooled),
            "a pooled session needs no password, so even the stale grant is served: {pooled}"
        );
        assert_eq!(
            rig.fake.login_count(),
            2,
            "no LOGIN when a pooled session serves the call"
        );
    }

    #[tokio::test]
    async fn per_account_semaphore_caps_4_hosted() {
        let hold = Arc::new(Hold {
            gate: Semaphore::new(0),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let rig = rig(
            FakeScript::default(),
            Some(Arc::clone(&hold)),
            Duration::from_mins(5),
        )
        .await;
        // Two servers (read-only and read-write) serve one account: they share one limit.
        let read_only = token(&rig.store, "ada@icloud.com", "pw-1", Scope::Read).await;
        let read_write = token(&rig.store, "ada@icloud.com", "pw-1", Scope::ReadWrite).await;

        let mut calls = Vec::new();
        for index in 0..8 {
            let app = rig.app.clone();
            let bearer = if index % 2 == 0 {
                &read_only
            } else {
                &read_write
            }
            .clone();
            calls.push(tokio::spawn(
                async move { list_mailboxes(&app, &bearer).await },
            ));
        }
        for _ in 0..200 {
            if hold.in_flight.load(Ordering::SeqCst) >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            hold.in_flight.load(Ordering::SeqCst),
            4,
            "four calls run, the rest wait"
        );
        hold.gate.add_permits(8);
        for call in calls {
            let message = call.await.expect("call task");
            assert!(
                succeeded(&message),
                "every waiting call is served: {message}"
            );
        }
        assert_eq!(
            hold.peak.load(Ordering::SeqCst),
            4,
            "never more than four at once for one account"
        );
    }

    #[tokio::test]
    async fn cache_evicts_idle_accounts() {
        let rig = rig(FakeScript::default(), None, Duration::from_millis(200)).await;
        let ada = token(&rig.store, "ada@icloud.com", "pw-1", Scope::Read).await;
        let bea = token(&rig.store, "bea@icloud.com", "pw-2", Scope::Read).await;

        assert!(succeeded(&list_mailboxes(&rig.app, &ada).await));
        assert_eq!(
            rig.live.load(Ordering::SeqCst),
            1,
            "ada has a pooled session"
        );
        assert_eq!(rig.cache.len(), 1);

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(succeeded(&list_mailboxes(&rig.app, &bea).await));

        assert_eq!(
            rig.cache.len(),
            1,
            "ada sat idle past the limit and was dropped; only bea is cached"
        );
        assert_eq!(
            rig.live.load(Ordering::SeqCst),
            1,
            "ada's session was closed; only bea's is open"
        );
    }

    #[tokio::test]
    async fn revoked_grant_drops_pooled_sessions() {
        let rig = rig(FakeScript::default(), None, Duration::from_mins(5)).await;
        let ada = token(&rig.store, "ada@icloud.com", "pw-1", Scope::Read).await;
        assert!(succeeded(&list_mailboxes(&rig.app, &ada).await));
        assert_eq!(rig.live.load(Ordering::SeqCst), 1, "a session is pooled");

        rig.cache
            .drop_account(&AppleId::try_from("ada@icloud.com").expect("apple id"));

        assert_eq!(
            rig.live.load(Ordering::SeqCst),
            0,
            "the pooled session closed"
        );
        assert!(rig.cache.is_empty(), "the account is forgotten");
        assert!(succeeded(&list_mailboxes(&rig.app, &ada).await));
        assert_eq!(
            rig.fake.connection_count(),
            2,
            "the next call opens a fresh connection"
        );
    }
}
