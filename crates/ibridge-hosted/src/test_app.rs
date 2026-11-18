// SPDX-License-Identifier: Apache-2.0

//! A hosted router over a fake mail backend, and helpers to call it.

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
use ibridge_core::{
    AppleId, CoreError, Draft, FlagChange, MailSearch, Mailbox, MailboxPath, MessageId,
    MessageSummary, Uid, UidValidity,
};
use ibridge_server::{
    AccountSnapshot, IbridgeServer, MailApi, MailBody, MailDest, MailHitPage, MailPart, NoCalendar,
    NoContacts, SentMail, ServiceStatus,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::limits::Guards;
use crate::oauth::{Access, OAuthConfig, validated_by};
use crate::provider::{Backend, Providers};
use crate::store::{Scope, Store};

/// The subject of the one message the fake mailbox holds. No log may contain it.
pub(crate) const SECRET_SUBJECT: &str = "Quarterly layoffs plan";
/// A search for this text never finishes, so a test can watch the timeout fire.
pub(crate) const HANG: &str = "hang";
pub(crate) const HOST: &str = "ibridge.example";
pub(crate) const PUBLIC_URL: &str = "https://ibridge.example";

#[derive(Debug)]
pub(crate) struct FakeMail;

const OFF: CoreError = CoreError::Unsupported("fake");

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the fake answers without waiting"
)]
impl MailApi for FakeMail {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        Ok(Vec::new())
    }

    async fn search(&self, query: &MailSearch) -> Result<MailHitPage, CoreError> {
        if query.text.as_deref() == Some(HANG) {
            std::future::pending::<()>().await;
        }
        let id = MessageId {
            mailbox: MailboxPath::try_from("INBOX").expect("path"),
            validity: UidValidity::try_from(1).expect("validity"),
            uid: Uid::try_from(1).expect("uid"),
        };
        Ok(MailHitPage {
            messages: vec![MessageSummary {
                id,
                from: "boss@example.com".to_owned(),
                subject: SECRET_SUBJECT.to_owned(),
                date: "Mon, 16 Nov 2026 09:00:00 +0000".to_owned(),
                unread: true,
                flagged: false,
            }],
            next_cursor: None,
            warnings: 0,
        })
    }

    async fn get_message(&self, _id: &MessageId, _offset: usize) -> Result<MailBody, CoreError> {
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

    async fn create_draft(&self, _draft: &Draft) -> Result<MessageId, CoreError> {
        Err(OFF)
    }

    async fn send(&self, _draft: &Draft) -> Result<SentMail, CoreError> {
        Err(OFF)
    }

    async fn move_message(
        &self,
        _id: &MessageId,
        _destination: &MailDest,
    ) -> Result<(), CoreError> {
        Err(OFF)
    }

    async fn set_flags(&self, _id: &MessageId, _flags: &FlagChange) -> Result<(), CoreError> {
        Err(OFF)
    }
}

#[derive(Debug)]
pub(crate) struct FakeBackend;

impl Backend for FakeBackend {
    type Mail = FakeMail;
    type Calendar = NoCalendar;
    type Contacts = NoContacts;

    fn open(&self, _apple_id: &AppleId) -> Providers<FakeMail, NoCalendar, NoContacts> {
        Providers {
            mail: Arc::new(FakeMail),
            calendar: Arc::new(NoCalendar),
            contacts: Arc::new(NoContacts),
        }
    }
}

/// A sign-in check that accepts every password.
pub(crate) struct AcceptAll;

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the fake answers without waiting"
)]
impl Validator for AcceptAll {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        Ok(ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Ok,
        })
    }
}

/// A sign-in check that reports what it was given.
struct Reports(ValidationReport);

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the fake answers without waiting"
)]
impl Validator for Reports {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        Ok(self.0.clone())
    }
}

/// An access token for a password whose sign-in check reported `report`.
pub(crate) async fn token_after_check(
    store: &Store,
    apple_id: &str,
    asp: &str,
    scope: Scope,
    report: ValidationReport,
) -> String {
    let now = SystemTime::now();
    let credentials = Credentials::new(
        AppleId::try_from(apple_id).expect("apple id"),
        asp.to_owned(),
    );
    let validated =
        crate::store::ValidatedCredentials::from_check(credentials, |_| Reports(report))
            .await
            .expect("some service accepts the password");
    let code = store
        .seal_validated_under_code(&validated, scope, now, None)
        .await
        .expect("seal");
    let issued = store
        .exchange_code(code.code.expose_secret(), now)
        .await
        .expect("exchange");
    issued.access.expose_secret().to_owned()
}

pub(crate) fn config(access: Access) -> OAuthConfig {
    OAuthConfig::new(PUBLIC_URL, access).expect("public url")
}

/// What `initialize` reports.
pub(crate) fn info() -> rmcp::model::ServerConfig {
    let server = IbridgeServer::read_only(
        AccountSnapshot {
            apple_id: AppleId::try_from("ada@icloud.com").expect("apple id"),
            mail: ServiceStatus::On,
            calendar: ServiceStatus::On,
            contacts: ServiceStatus::On,
        },
        Arc::new(FakeMail),
    );
    rmcp::ServerHandler::get_info(&server)
}

/// The hosted router over `store`, open to anyone, with the default limits.
pub(crate) async fn app_over(store: &Store) -> Router {
    app_with(store, &Guards::default()).await
}

/// The hosted router over `store`, open to anyone.
pub(crate) async fn app_with(store: &Store, guards: &Guards) -> Router {
    crate::app::app(
        config(Access::MultiTenant),
        store.clone(),
        FakeBackend,
        validated_by(|_: &Credentials| AcceptAll),
        info(),
        guards,
    )
    .await
    .expect("app")
}

/// An access token for `apple_id` whose sealed password is `asp`.
pub(crate) async fn token(store: &Store, apple_id: &str, asp: &str, scope: Scope) -> String {
    let now = SystemTime::now();
    let apple = AppleId::try_from(apple_id).expect("apple id");
    let code = store
        .seal_under_code(&apple, &SecretString::from(asp), scope, now, None)
        .await
        .expect("seal");
    let issued = store
        .exchange_code(code.code.expose_secret(), now)
        .await
        .expect("exchange");
    issued.access.expose_secret().to_owned()
}

/// A JSON-RPC request to `/mcp` in the stateless 2026-07-28 form.
pub(crate) fn rpc_request(
    bearer: &str,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> Request<Body> {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut request = Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(name) = name {
        request = request.header("mcp-name", name);
    }
    request.body(Body::from(body.to_string())).expect("request")
}

/// A `tools/call` request to `/mcp`.
pub(crate) fn tool_request(bearer: &str, name: &str, arguments: &Value) -> Request<Body> {
    rpc_request(
        bearer,
        "tools/call",
        Some(name),
        json!({"name": name, "arguments": arguments}),
    )
}

/// One response, read to the end.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) text: String,
}

/// Sends `request` through `app`.
pub(crate) async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    Reply {
        status,
        headers,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Calls a tool and returns the HTTP status and body text.
pub(crate) async fn call(
    app: &Router,
    bearer: &str,
    name: &str,
    arguments: &Value,
) -> (StatusCode, String) {
    let reply = send(app, tool_request(bearer, name, arguments)).await;
    (reply.status, reply.text)
}
