// SPDX-License-Identifier: Apache-2.0

//! End to end over rmcp: a real client talks to the server through an
//! in-memory transport. The mail backend is a scripted fake.

use std::sync::{Arc, Mutex};

use ibridge_core::{
    AppleId, Attachment, AttachmentInfo, CoreError, Draft, FlagChange, MailSearch, Mailbox,
    Message, MessageId, MessageSummary, OneClickFailure, Uid, UidValidity, Unsubscribe,
    UnsubscribeMail, UnsubscribeMethod, encode,
};
use ibridge_server::{
    AccountSnapshot, IbridgeServer, MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail,
    ServiceStatus, Unsubscribed,
};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};

/// The one message with an unsubscribe header: one-click, mailto and a link.
fn unsubscribe_for(id: &MessageId) -> Option<Unsubscribe> {
    (id.uid.get() == 42).then(|| Unsubscribe {
        mailto: Some(UnsubscribeMail {
            to: "unsub@example.com".to_owned(),
            subject: Some("unsubscribe".to_owned()),
            body: None,
        }),
        links: vec!["https://example.com/u".to_owned()],
        one_click: true,
    })
}

/// A second message with no unsubscribe header.
fn other_message_id() -> MessageId {
    MessageId {
        uid: Uid::try_from(43).expect("uid"),
        ..message_id()
    }
}

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
    unsubscribed: Mutex<Vec<MessageId>>,
    unsubscribe_methods: Mutex<Vec<Option<UnsubscribeMethod>>>,
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
        if *id != message_id() && *id != other_message_id() {
            return Err(CoreError::NotFound);
        }
        Ok(MailBody {
            message: Message {
                id: id.clone(),
                from: "Bob\u{202E}\u{E0049} <bob@example.com>".to_owned(),
                to: vec!["Ada\u{200B} <ada@icloud.com>".to_owned()],
                subject: "Pic\u{FEFF}nic\u{202E}".to_owned(),
                date: "2026-11-01".to_owned(),
                body: "Bring\u{200B} napkins.\u{E0049}\u{E0067}\u{2066}".to_owned(),
                attachments: Vec::new(),
                unsubscribe: unsubscribe_for(id),
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

    async fn unsubscribe(
        &self,
        id: &MessageId,
        method: Option<UnsubscribeMethod>,
    ) -> Result<Unsubscribed, CoreError> {
        self.unsubscribe_methods
            .lock()
            .expect("methods lock")
            .push(method);
        self.unsubscribed
            .lock()
            .expect("unsubscribed lock")
            .push(id.clone());
        match id.uid.get() {
            42 => Ok(Unsubscribed::Emailed(SentMail {
                id: Some(message_id()),
            })),
            43 => Ok(Unsubscribed::NotOffered),
            44 => Ok(Unsubscribed::Links(vec![
                "https://example.com/u?id=9\u{200B}\u{E0049}".to_owned(),
            ])),
            45 => Ok(Unsubscribed::Emailed(SentMail { id: None })),
            46 => Ok(Unsubscribed::OneClicked),
            47 => Ok(Unsubscribed::OneClickFailed {
                failure: OneClickFailure::Rejected,
                mailto_offered: true,
            }),
            48 => Ok(Unsubscribed::OneClickFailed {
                failure: OneClickFailure::Blocked,
                mailto_offered: false,
            }),
            49 => Ok(Unsubscribed::MethodNotOffered(UnsubscribeMethod::Mailto)),
            _ => Err(CoreError::NotFound),
        }
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
    assert_eq!(
        message["body"].as_str(),
        Some("Bring napkins."),
        "the body arrives as plain text with hidden characters stripped"
    );
    assert_eq!(
        message["subject"].as_str(),
        Some("Picnic"),
        "the subject arrives as plain text with hidden characters stripped"
    );
    assert_eq!(
        message["from"].as_str(),
        Some("Bob <bob@example.com>"),
        "the sender's display name has hidden characters stripped"
    );
    assert_eq!(
        message["to"][0].as_str(),
        Some("Ada <ada@icloud.com>"),
        "recipient display names have hidden characters stripped"
    );
    assert!(
        !message.to_string().contains("untrusted"),
        "no untrusted marker, got {message}"
    );
}

#[tokio::test]
async fn e2e_get_message_reports_how_to_unsubscribe() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let offered = call(
        &client,
        "mail_get_message",
        serde_json::json!({ "id": encode(&message_id()) }),
    )
    .await;
    let message = offered.structured_content.expect("structured content");
    assert_eq!(
        message["unsubscribe"],
        serde_json::json!({ "available": true, "methods": ["one_click", "mailto", "link"] }),
        "a message with the header lists its methods best first, got {message}"
    );
    assert!(
        !message.to_string().contains("unsub@example.com"),
        "the sender's address is not shown, got {message}"
    );
    let plain = call(
        &client,
        "mail_get_message",
        serde_json::json!({ "id": encode(&other_message_id()) }),
    )
    .await;
    let message = plain.structured_content.expect("structured content");
    assert_eq!(
        message["unsubscribe"],
        serde_json::json!({ "available": false, "methods": [] }),
        "a message without the header says so, got {message}"
    );
}

fn id_with_uid(uid: u32) -> String {
    encode(&MessageId {
        uid: Uid::try_from(uid).expect("uid"),
        ..message_id()
    })
}

#[tokio::test]
async fn e2e_unsubscribe_reports_the_email_it_sent() {
    let mail = Arc::new(Scripted::default());
    let client = connect(IbridgeServer::read_write(account(), Arc::clone(&mail))).await;
    let result = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(42), "to": "attacker@example.net" }),
    )
    .await;
    assert_eq!(
        result.is_error,
        Some(false),
        "unsubscribe works: {result:?}"
    );
    let out = result.structured_content.expect("structured content");
    assert_eq!(out["status"], "emailed", "got {out}");
    assert_eq!(out["id"].as_str(), Some(id_with_uid(42).as_str()));
    assert_eq!(out["warning"], serde_json::Value::Null);
    assert_eq!(out["links"], serde_json::json!([]));
    assert_eq!(
        *mail.unsubscribed.lock().expect("lock"),
        vec![MessageId {
            uid: Uid::try_from(42).expect("uid"),
            ..message_id()
        }],
        "the backend is asked about the message id and nothing else"
    );
    let warned = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(45) }),
    )
    .await;
    let out = warned.structured_content.expect("structured content");
    assert_eq!(out["status"], "emailed");
    assert_eq!(out["id"], serde_json::Value::Null);
    assert_eq!(
        out["warning"].as_str(),
        Some("sent, but the copy was not saved to Sent Messages"),
        "a failed Sent copy is a warning on a sent email, got {out}"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_says_when_the_message_offers_nothing() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let result = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(43) }),
    )
    .await;
    assert_eq!(result.is_error, Some(true), "a tool error, got {result:?}");
    let text = text_blocks(&result).join(" ");
    assert!(
        text.contains("does not offer") && text.contains("unsubscribe"),
        "the error says unsubscribe isn't offered, got {text:?}"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_link_only_returns_the_link_and_sends_nothing() {
    let mail = Arc::new(Scripted::default());
    let client = connect(IbridgeServer::read_write(account(), Arc::clone(&mail))).await;
    let result = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(44) }),
    )
    .await;
    assert_eq!(result.is_error, Some(false), "not an error: {result:?}");
    let out = result.structured_content.expect("structured content");
    assert_eq!(out["status"], "link_only", "got {out}");
    assert_eq!(
        out["links"],
        serde_json::json!(["https://example.com/u?id=9"]),
        "the link comes back with hidden characters stripped"
    );
    assert!(
        out["note"].as_str().is_some_and(|note| {
            note.contains("does not support one-click") && note.contains("open it in a browser")
        }),
        "the note says why nothing was posted and what to do, got {out}"
    );
    assert!(
        mail.sent.lock().expect("sent lock").is_empty(),
        "nothing was sent"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_reports_an_accepted_one_click_post() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let result = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(46) }),
    )
    .await;
    assert_eq!(result.is_error, Some(false), "not an error: {result:?}");
    let out = result.structured_content.expect("structured content");
    assert_eq!(out["status"], "one_click", "got {out}");
    assert_eq!(out["id"], serde_json::Value::Null);
    assert_eq!(out["links"], serde_json::json!([]));
    assert!(
        out["note"]
            .as_str()
            .is_some_and(|note| note.contains("accepted") && note.contains("one-click")),
        "the note says the sender accepted the request, got {out}"
    );
}

#[tokio::test]
async fn e2e_a_failed_one_click_is_a_tool_error_that_names_the_class_and_the_mailto() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let refused = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(47) }),
    )
    .await;
    assert_eq!(
        refused.is_error,
        Some(true),
        "a tool error, got {refused:?}"
    );
    let text = text_blocks(&refused).join(" ");
    assert!(
        text.contains("refused the request")
            && text.contains("unsubscribe email")
            && text.contains("not sent"),
        "names the class, says the mailto exists and was not sent, got {text:?}"
    );
    let blocked = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(48) }),
    )
    .await;
    assert_eq!(
        blocked.is_error,
        Some(true),
        "a tool error, got {blocked:?}"
    );
    let text = text_blocks(&blocked).join(" ");
    assert!(
        text.contains("private or local network") && !text.contains("unsubscribe email"),
        "names the class and offers no mailto when there is none, got {text:?}"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_passes_the_chosen_method_to_the_backend() {
    let mail = Arc::new(Scripted::default());
    let client = connect(IbridgeServer::read_write(account(), Arc::clone(&mail))).await;
    for params in [
        serde_json::json!({ "id": id_with_uid(42) }),
        serde_json::json!({ "id": id_with_uid(42), "method": "mailto" }),
        serde_json::json!({ "id": id_with_uid(42), "method": "one_click" }),
    ] {
        let result = call(&client, "mail_unsubscribe", params).await;
        assert_eq!(result.is_error, Some(false), "works: {result:?}");
    }
    assert_eq!(
        *mail.unsubscribe_methods.lock().expect("lock"),
        vec![
            None,
            Some(UnsubscribeMethod::Mailto),
            Some(UnsubscribeMethod::OneClick)
        ],
        "an omitted method stays omitted, so the backend keeps its own preference"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_refuses_a_method_it_does_not_know() {
    let mail = Arc::new(Scripted::default());
    let client = connect(IbridgeServer::read_write(account(), Arc::clone(&mail))).await;
    for method in ["link", "https://evil.example/u", "attacker@example.net"] {
        let result = call(
            &client,
            "mail_unsubscribe",
            serde_json::json!({ "id": id_with_uid(42), "method": method }),
        )
        .await;
        assert_eq!(
            result.is_error,
            Some(true),
            "{method:?} is refused, got {result:?}"
        );
    }
    assert!(
        mail.unsubscribed.lock().expect("lock").is_empty(),
        "the backend is never asked"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_says_when_the_message_lacks_the_chosen_method() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let result = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(49), "method": "mailto" }),
    )
    .await;
    assert_eq!(result.is_error, Some(true), "a tool error, got {result:?}");
    let text = text_blocks(&result).join(" ");
    assert!(
        text.contains("does not offer an unsubscribe email") && text.contains("nothing was sent"),
        "the error names the method and says nothing was sent, got {text:?}"
    );
}

#[tokio::test]
async fn e2e_a_failed_one_click_tells_the_model_how_to_use_the_mailto() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let refused = call(
        &client,
        "mail_unsubscribe",
        serde_json::json!({ "id": id_with_uid(47) }),
    )
    .await;
    let text = text_blocks(&refused).join(" ");
    assert!(
        text.contains("\"method\": \"mailto\""),
        "the error names the argument that sends the mailto, got {text:?}"
    );
}

#[tokio::test]
async fn e2e_unsubscribe_is_hidden_and_refused_when_read_only() {
    let client = connect(IbridgeServer::read_only(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    assert!(
        !tool_names(&client)
            .await
            .iter()
            .any(|name| name == "mail_unsubscribe"),
        "read-only servers do not list mail_unsubscribe"
    );
    let mut params = CallToolRequestParams::new("mail_unsubscribe");
    params.arguments = Some(arguments(&serde_json::json!({ "id": id_with_uid(42) })));
    let refused = client.call_tool(params).await;
    assert!(
        refused.is_err_and(|error| error.to_string().contains("tool not found")),
        "a direct call is refused as an unknown tool"
    );
}

#[tokio::test]
async fn mail_read_tools_say_where_the_text_comes_from() {
    let client = connect(IbridgeServer::read_write(
        account(),
        Arc::new(Scripted::default()),
    ))
    .await;
    let tools = client.list_all_tools().await.expect("list tools");
    for (name, sentence) in [
        ("mail_search", "Subjects are as the sender wrote them."),
        (
            "mail_get_message",
            "The subject and body are as the sender wrote them.",
        ),
        (
            "mail_get_attachment",
            "The file name and text are as the sender wrote them.",
        ),
    ] {
        let tool = tools.iter().find(|tool| tool.name == name).expect(name);
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains(sentence),
            "{name} names the source of the text, got {description:?}"
        );
    }
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
