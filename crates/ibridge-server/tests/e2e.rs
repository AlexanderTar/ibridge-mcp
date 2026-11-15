// SPDX-License-Identifier: Apache-2.0

//! End to end over rmcp: a real client talks to the server through an
//! in-memory transport. The mail backend is a scripted fake.

use std::sync::{Arc, Mutex};

use ibridge_core::{
    AppleId, CoreError, Draft, FlagChange, MailSearch, Mailbox, Message, MessageId, MessageSummary,
    Uid, UidValidity, encode,
};
use ibridge_server::{
    AccountSnapshot, IbridgeServer, MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail,
    ServiceStatus,
};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};

fn message_id() -> MessageId {
    MessageId {
        mailbox: ibridge_core::MailboxPath::try_from("INBOX").expect("inbox path"),
        validity: UidValidity::try_from(7).expect("validity"),
        uid: Uid::try_from(42).expect("uid"),
    }
}

/// Backend with one message in the inbox. Sends are recorded.
#[derive(Default)]
struct Scripted {
    sent: Mutex<Vec<Draft>>,
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the scripted backend answers without waiting"
)]
impl MailApi for Scripted {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        Ok(Vec::new())
    }

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
        Ok(MailHitPage {
            messages: vec![MessageSummary {
                id: message_id(),
                from: "bob@example.com".to_owned(),
                subject: "Picnic".to_owned(),
                date: "2026-11-01".to_owned(),
                unread: true,
                flagged: false,
            }],
            next_cursor: None,
            warnings: 0,
        })
    }

    async fn get_message(&self, id: &MessageId, _offset: usize) -> Result<MailBody, CoreError> {
        if *id != message_id() {
            return Err(CoreError::NotFound);
        }
        Ok(MailBody {
            message: Message {
                id: id.clone(),
                from: "bob@example.com".to_owned(),
                to: vec!["ada@icloud.com".to_owned()],
                subject: "Picnic".to_owned(),
                date: "2026-11-01".to_owned(),
                body: "Bring napkins.".to_owned(),
                attachments: Vec::new(),
            },
            next_offset: None,
        })
    }

    async fn get_attachment(
        &self,
        _id: &MessageId,
        _part: &str,
        _offset: usize,
    ) -> Result<MailPart, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn create_draft(&self, _draft: &Draft) -> Result<MessageId, CoreError> {
        Ok(message_id())
    }

    async fn send(&self, draft: &Draft) -> Result<SentMail, CoreError> {
        self.sent.lock().expect("sent lock").push(Draft {
            to: draft.to.clone(),
            subject: draft.subject.clone(),
            body: draft.body.clone(),
            from: draft.from.clone(),
            reply_to: draft.reply_to.clone(),
        });
        Ok(SentMail { id: None })
    }

    async fn move_message(
        &self,
        _id: &MessageId,
        _destination: &MailDest,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn set_flags(&self, _id: &MessageId, _flags: &FlagChange) -> Result<(), CoreError> {
        Ok(())
    }
}

fn account() -> AccountSnapshot {
    AccountSnapshot {
        apple_id: AppleId::try_from("ada@icloud.com").expect("apple id"),
        mail: ServiceStatus::On,
        calendar: ServiceStatus::On,
        contacts: ServiceStatus::On,
    }
}

/// Connects a client to `server` over a duplex pipe.
async fn connect(server: IbridgeServer<Scripted>) -> RunningService<RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let running = server.serve(server_io).await.expect("server starts");
        let _quit = running.waiting().await;
    });
    ().serve(client_io).await.expect("client starts")
}

fn arguments(value: &serde_json::Value) -> rmcp::model::JsonObject {
    value.as_object().expect("an object").clone()
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = Some(arguments(&args));
    client.call_tool(params).await.expect("tool call")
}

#[tokio::test]
async fn e2e_search_then_get() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;

    let found = call(&client, "mail_search", serde_json::json!({})).await;
    let structured = found.structured_content.expect("search structured content");
    let id = structured["messages"][0]["id"]
        .as_str()
        .expect("the hit carries an id")
        .to_owned();
    assert_eq!(id, encode(&message_id()), "the id is the opaque token");

    let fetched = call(&client, "mail_get_message", serde_json::json!({ "id": id })).await;
    assert_eq!(fetched.is_error, Some(false), "get succeeds: {fetched:?}");
    let message = fetched
        .structured_content
        .expect("message structured content");
    let body = message["body"].as_str().expect("body text");
    assert!(
        body.contains("Bring napkins.") && body.contains("untrusted"),
        "the body arrives wrapped as untrusted, got {body}"
    );
}

#[tokio::test]
async fn e2e_send_requires_destructive_annotation() {
    let mail = Arc::new(Scripted::default());
    let client = connect(IbridgeServer::read_write(account(), Arc::clone(&mail))).await;

    let tools = client.list_all_tools().await.expect("list tools");
    let send = tools
        .iter()
        .find(|tool| tool.name == "mail_send")
        .expect("mail_send is listed");
    let annotations = send.annotations.as_ref().expect("mail_send annotations");
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(true));

    let delivered = call(
        &client,
        "mail_send",
        serde_json::json!({ "to": ["bob@example.com"], "subject": "Hi", "body": "Hello" }),
    )
    .await;
    let out = delivered
        .structured_content
        .expect("send structured content");
    assert!(
        out["warning"]
            .as_str()
            .is_some_and(|text| text.contains("Sent Messages")),
        "a failed Sent copy is a warning on a successful send, got {out}"
    );
    assert_eq!(
        mail.sent.lock().expect("sent lock").len(),
        1,
        "the backend sent once"
    );

    let read_only = connect(IbridgeServer::read_only(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let names: Vec<_> = read_only
        .list_all_tools()
        .await
        .expect("list tools")
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect();
    assert!(
        !names.iter().any(|name| name == "mail_send")
            && names.iter().any(|name| name == "mail_search"),
        "a read-only server hides writes over the wire, got {names:?}"
    );
}
