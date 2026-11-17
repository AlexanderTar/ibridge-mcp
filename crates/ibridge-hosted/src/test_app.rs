// SPDX-License-Identifier: Apache-2.0

//! A hosted router over a fake mail backend, and helpers to call it.

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
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

use crate::oauth::{Access, OAuthConfig, validated_by};
use crate::provider::{Backend, Providers};
use crate::store::{Scope, Store};

/// The subject of the one message the fake mailbox holds. No log may contain it.
pub(crate) const SECRET_SUBJECT: &str = "Quarterly layoffs plan";
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

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
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

/// The hosted router over `store`, open to anyone.
pub(crate) async fn app_over(store: &Store) -> Router {
    crate::app::app(
        config(Access::MultiTenant),
        store.clone(),
        FakeBackend,
        validated_by(|_: &Credentials| AcceptAll),
        info(),
    )
    .await
    .expect("app")
}

/// An access token for `apple_id` whose sealed password is `asp`.
pub(crate) async fn token(store: &Store, apple_id: &str, asp: &str, scope: Scope) -> String {
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

/// A `tools/call` request to `/mcp`.
pub(crate) fn tool_request(bearer: &str, name: &str, arguments: &Value) -> Request<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// Calls a tool and returns the HTTP status and body text.
pub(crate) async fn call(
    app: &Router,
    bearer: &str,
    name: &str,
    arguments: &Value,
) -> (axum::http::StatusCode, String) {
    let response = app
        .clone()
        .oneshot(tool_request(bearer, name, arguments))
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}
