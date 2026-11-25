// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ibridge_core::{AppleId, CoreError, Draft, FlagChange, MailSearch, Mailbox, MessageId};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::Tool;

use crate::account::{AccountSnapshot, ServiceStatus};
use crate::dto::{SearchParams, SendParams, UnsubscribeParams};
use crate::handler::IbridgeServer;
use crate::mail_api::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail};

const READS: &[&str] = &[
    "account_status",
    "mail_get_attachment",
    "mail_get_message",
    "mail_list_mailboxes",
    "mail_search",
];

const WRITES: &[&str] = &[
    "mail_create_draft",
    "mail_move",
    "mail_send",
    "mail_set_flags",
    "mail_unsubscribe",
];

fn account() -> AccountSnapshot {
    AccountSnapshot {
        apple_id: AppleId::try_from("ada@icloud.com").expect("apple id"),
        mail: ServiceStatus::On,
        calendar: ServiceStatus::Off {
            reason: "calendar login failed".to_owned(),
        },
        contacts: ServiceStatus::On,
    }
}

fn names_of(tools: Vec<Tool>) -> Vec<String> {
    tools
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect()
}

fn require<'a>(tools: &'a [Tool], name: &str) -> &'a Tool {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn unsupported<T>() -> Result<T, CoreError> {
    Err(CoreError::Unsupported("idle"))
}

macro_rules! idle_mail {
    () => {
        async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
            unsupported()
        }
        async fn get_message(
            &self,
            _id: &MessageId,
            _offset: usize,
        ) -> Result<MailBody, CoreError> {
            unsupported()
        }
        async fn get_attachment(
            &self,
            _id: &MessageId,
            _part: &str,
            _offset: usize,
        ) -> Result<MailPart, CoreError> {
            unsupported()
        }
        async fn create_draft(&self, _draft: &Draft) -> Result<MessageId, CoreError> {
            unsupported()
        }
        async fn send(&self, _draft: &Draft) -> Result<SentMail, CoreError> {
            unsupported()
        }
        async fn move_message(
            &self,
            _id: &MessageId,
            _destination: &MailDest,
        ) -> Result<(), CoreError> {
            unsupported()
        }
        async fn set_flags(&self, _id: &MessageId, _flags: &FlagChange) -> Result<(), CoreError> {
            unsupported()
        }
    };
}

struct Idle;

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the idle backend returns without waiting"
)]
impl MailApi for Idle {
    idle_mail!();

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
        Ok(MailHitPage {
            messages: Vec::new(),
            next_cursor: None,
            warnings: 0,
        })
    }
}

struct GateProbe {
    current: AtomicUsize,
    peak: AtomicUsize,
    release: tokio::sync::watch::Receiver<bool>,
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "unused mail methods return without waiting; search waits on the gate"
)]
impl MailApi for GateProbe {
    idle_mail!();

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let mut release = self.release.clone();
        while !*release.borrow() {
            if release.changed().await.is_err() {
                break;
            }
        }
        self.current.fetch_sub(1, Ordering::SeqCst);
        Ok(MailHitPage {
            messages: Vec::new(),
            next_cursor: None,
            warnings: 0,
        })
    }
}

#[test]
fn tools_list_snapshot() {
    let server = IbridgeServer::read_write(account(), Arc::new(Idle));
    let tools = server.tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    for name in READS.iter().chain(WRITES) {
        assert!(names.contains(name), "missing {name} in {names:?}");
    }
    for tool in &tools {
        assert!(
            tool.description
                .as_ref()
                .is_some_and(|text| !text.is_empty()),
            "{} has no description",
            tool.name
        );
        assert!(
            tool.output_schema.is_some(),
            "{} has no output schema",
            tool.name
        );
        assert!(
            tool.annotations.is_some(),
            "{} has no annotations",
            tool.name
        );
    }
    insta::assert_json_snapshot!(tools);
}

#[test]
fn every_mail_tool_has_a_title() {
    let tools = IbridgeServer::read_write(account(), Arc::new(Idle))
        .with_downloads(std::path::PathBuf::from("downloads"))
        .tools();
    assert!(
        tools.iter().any(|tool| tool.name == "mail_save_attachment"),
        "the download tool is part of this check"
    );
    for tool in &tools {
        assert!(
            tool.title.as_ref().is_some_and(|text| !text.is_empty()),
            "{} has no title",
            tool.name
        );
    }
}

#[test]
fn every_write_tool_is_destructive() {
    let tools = IbridgeServer::read_write(account(), Arc::new(Idle)).tools();
    for name in WRITES {
        let annotations = require(&tools, name)
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{name} has no annotations"));
        assert_eq!(annotations.read_only_hint, Some(false), "{name}");
        assert_eq!(annotations.destructive_hint, Some(true), "{name}");
    }
    let unsubscribe = require(&tools, "mail_unsubscribe")
        .annotations
        .as_ref()
        .expect("mail_unsubscribe annotations");
    assert_eq!(
        unsubscribe.idempotent_hint,
        Some(false),
        "a second unsubscribe sends a second email"
    );
    assert_eq!(unsubscribe.open_world_hint, Some(true));
    let flags = require(&tools, "mail_set_flags")
        .annotations
        .as_ref()
        .expect("mail_set_flags annotations");
    assert_eq!(flags.idempotent_hint, Some(true));
    for name in READS {
        let annotations = require(&tools, name)
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{name} has no annotations"));
        assert_eq!(annotations.read_only_hint, Some(true), "{name}");
        assert_eq!(
            annotations.destructive_hint,
            Some(false),
            "{name} must set destructive_hint false, not leave the default"
        );
    }
    let status = require(&tools, "account_status")
        .annotations
        .as_ref()
        .expect("account_status annotations");
    assert_eq!(status.open_world_hint, Some(false));
}

#[tokio::test]
async fn read_only_mode_hides_writes() {
    let writable = IbridgeServer::read_write(account(), Arc::new(Idle));
    let read_only = IbridgeServer::read_only(account(), Arc::new(Idle));
    let shown = names_of(writable.tools());
    for name in READS.iter().chain(WRITES) {
        assert!(
            shown.iter().any(|got| got == name),
            "read-write list missing {name}"
        );
    }
    let hidden = names_of(read_only.tools());
    for name in READS {
        assert!(
            hidden.iter().any(|got| got == name),
            "read-only list missing {name}"
        );
    }
    for name in WRITES {
        assert!(
            !hidden.iter().any(|got| got == name),
            "read-only list still shows {name}"
        );
    }
    let error = read_only
        .mail_send(Parameters(SendParams::default()))
        .await
        .expect_err("read-only send is rejected");
    let rendered = error.to_string();
    assert!(
        rendered.contains("tool not found"),
        "read-only send should report tool not found, got {rendered}"
    );
    let error = read_only
        .mail_unsubscribe(Parameters(UnsubscribeParams::default()))
        .await
        .expect_err("read-only unsubscribe is rejected");
    assert!(
        error.to_string().contains("tool not found"),
        "read-only unsubscribe should report tool not found, got {error}"
    );
}

#[tokio::test]
async fn account_status_reports_disabled_service_reason() {
    let server = IbridgeServer::read_write(account(), Arc::new(Idle));
    let result = server.account_status().await.expect("account status");
    assert_eq!(result.is_error, Some(false));
    let text: String = result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect();
    assert!(text.contains("ada@icloud.com"), "{text}");
    assert!(text.contains("calendar login failed"), "{text}");
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
}

#[tokio::test]
async fn per_account_semaphore_caps_4() {
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let mail = Arc::new(GateProbe {
        current: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        release: release_rx,
    });
    let server = IbridgeServer::read_write(account(), Arc::clone(&mail));
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let server = server.clone();
        tasks.push(tokio::spawn(async move {
            server
                .mail_search(Parameters(SearchParams {
                    limit: 25,
                    ..SearchParams::default()
                }))
                .await
        }));
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while mail.current.load(Ordering::SeqCst) < 4 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fewer than 4 calls entered the backend"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let peak = mail.peak.load(Ordering::SeqCst);
    let _sent = release_tx.send(true);
    for task in tasks {
        task.await.expect("search task").expect("search result");
    }
    assert_eq!(peak, 4, "a fifth call ran beside the first four");
}
