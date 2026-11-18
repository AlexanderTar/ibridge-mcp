// SPDX-License-Identifier: Apache-2.0

//! End to end over rmcp: a real client talks to the server through an
//! in-memory transport. The mail backend is a scripted fake.

use std::sync::{Arc, Mutex};

use ibridge_core::{
    AppleId, Attachment, AttachmentInfo, CoreError, Draft, FlagChange, MailSearch, Mailbox,
    Message, MessageId, MessageSummary, Uid, UidValidity, encode,
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

    async fn get_attachment_bytes(
        &self,
        id: &MessageId,
        part: &str,
    ) -> Result<Attachment, CoreError> {
        if *id != message_id() || part != "2" {
            return Err(CoreError::NotFound);
        }
        Ok(Attachment {
            info: AttachmentInfo {
                part: "2".to_owned(),
                content_type: "text/plain".to_owned(),
                size: 16,
                // A hostile name: a path that climbs out of the download folder.
                name: "../../evil name.txt".to_owned(),
            },
            text: None,
            bytes: Some(b"hello attachment".to_vec()),
        })
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

async fn tool_names(client: &RunningService<RoleClient, ()>) -> Vec<String> {
    client
        .list_all_tools()
        .await
        .expect("list tools")
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect()
}

#[tokio::test]
async fn save_attachment_only_in_local_modes() {
    let downloads = tempfile::tempdir().expect("download folder");
    let listed = |names: &[String]| names.iter().any(|name| name == "mail_save_attachment");

    let hosted_like = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    assert!(
        !listed(&tool_names(&hosted_like).await),
        "a server with no download folder never offers the tool"
    );
    let mut params = CallToolRequestParams::new("mail_save_attachment");
    params.arguments = Some(arguments(
        &serde_json::json!({ "id": encode(&message_id()), "part": "2" }),
    ));
    hosted_like
        .call_tool(params)
        .await
        .expect_err("and a direct call is refused");

    let local = connect(
        IbridgeServer::read_write(account(), Arc::new(Scripted::default()))
            .with_downloads(downloads.path().to_path_buf()),
    )
    .await;
    let tools = local.list_all_tools().await.expect("list tools");
    let save = tools
        .iter()
        .find(|tool| tool.name == "mail_save_attachment")
        .expect("a local server offers mail_save_attachment");
    let annotations = save.annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(false), "it writes a file");
    assert_eq!(
        annotations.destructive_hint,
        Some(true),
        "so clients ask first"
    );

    let read_only = connect(
        IbridgeServer::read_only(account(), Arc::new(Scripted::default()))
            .with_downloads(downloads.path().to_path_buf()),
    )
    .await;
    assert!(
        !listed(&tool_names(&read_only).await),
        "--read-only hides it: saving a file is a write"
    );
}

#[tokio::test]
async fn save_attachment_writes_to_download_dir() {
    let root = tempfile::tempdir().expect("temp root");
    let downloads = root.path().join("not").join("made").join("yet");
    let client = connect(
        IbridgeServer::read_write(account(), Arc::new(Scripted::default()))
            .with_downloads(downloads.clone()),
    )
    .await;
    let id = encode(&message_id());

    let saved = call(
        &client,
        "mail_save_attachment",
        serde_json::json!({ "id": id, "part": "2" }),
    )
    .await;
    assert_eq!(saved.is_error, Some(false), "save succeeds: {saved:?}");
    let out = saved.structured_content.expect("structured content");
    let path = std::path::PathBuf::from(out["path"].as_str().expect("a path"));
    assert_eq!(
        path.parent(),
        Some(downloads.as_path()),
        "the file lands directly in the download folder, got {path:?}"
    );
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("evil name.txt"),
        "a name that climbs out of the folder is cut down to its last part"
    );
    assert_eq!(
        std::fs::read(&path).expect("the file exists"),
        b"hello attachment",
        "every byte is written"
    );
    assert_eq!(out["size"], 16);

    let again = call(
        &client,
        "mail_save_attachment",
        serde_json::json!({ "id": id, "part": "2" }),
    )
    .await;
    let second = std::path::PathBuf::from(
        again.structured_content.expect("structured content")["path"]
            .as_str()
            .expect("a path"),
    );
    assert_ne!(second, path, "a second save never overwrites the first");
    assert_eq!(
        second.file_name().and_then(|name| name.to_str()),
        Some("evil name (1).txt")
    );
    assert_eq!(
        std::fs::read(&path).expect("the first file is intact"),
        b"hello attachment"
    );
    assert!(
        !root.path().join("evil name.txt").exists(),
        "nothing was written above the download folder"
    );

    let missing = call(
        &client,
        "mail_save_attachment",
        serde_json::json!({ "id": id, "part": "9" }),
    )
    .await;
    assert_eq!(
        missing.is_error,
        Some(true),
        "an unknown part is a tool error"
    );
}

#[tokio::test]
async fn e2e_initialize_reports_ibridge_and_crate_version() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;

    let info = client.peer_info().expect("initialize completed");
    let server = info.server_info.as_ref().expect("server info");
    assert_eq!(server.name, "ibridge", "server name");
    assert_eq!(
        server.version,
        env!("CARGO_PKG_VERSION"),
        "server version is the crate version"
    );
}

/// The model-visible text of a result: every text block, in order.
fn text_blocks(result: &CallToolResult) -> Vec<String> {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

/// Claude reads the text content, not `structuredContent`: it must name the sender, the subject
/// and the body, and end with the same JSON the structured content holds.
#[tokio::test]
async fn mail_text_content_carries_the_sender_subject_and_body() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let found = call(&client, "mail_search", serde_json::json!({})).await;
    let found_text = text_blocks(&found).join("\n");
    for wanted in ["bob@example.com", "Picnic"] {
        assert!(
            found_text.contains(wanted),
            "{wanted} in search: {found_text}"
        );
    }
    let id = encode(&message_id());
    let fetched = call(&client, "mail_get_message", serde_json::json!({ "id": id })).await;
    let fetched_text = text_blocks(&fetched).join("\n");
    for wanted in ["bob@example.com", "Picnic", "Bring napkins."] {
        assert!(
            fetched_text.contains(wanted),
            "{wanted} in message: {fetched_text}"
        );
    }
    for result in [&found, &fetched] {
        let blocks = text_blocks(result);
        let json: serde_json::Value =
            serde_json::from_str(blocks.last().expect("a text block")).expect("the JSON block");
        assert_eq!(Some(&json), result.structured_content.as_ref());
    }
}
