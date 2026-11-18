// SPDX-License-Identifier: Apache-2.0

//! Fakes for running the hosted server without iCloud: IMAP answered by [`FakeImap`],
//! and a sign-in check that accepts every password.
//!
//! This is for tests of this crate and of the tools that drive a hosted server, such as
//! `cargo xtask live-hosted-check`. It is not part of a production build.

use std::io;
use std::sync::Arc;

use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
use ibridge_core::{
    AppleId, Attachment, CoreError, Draft, FlagChange, MailSearch, Mailbox, MessageId,
};
use ibridge_mail::{Connect, ImapPool};
use ibridge_server::{
    AccountSnapshot, IbridgeServer, MailApi, MailBody, MailDest, MailHitPage, MailPart, NoCalendar,
    NoContacts, SentMail, ServiceStatus,
};
use ibridge_testkit::imap_fake::FakeImap;
use rmcp::model::ServerConfig;
use tokio::io::DuplexStream;

pub use crate::identity::fakes::{FAKE_NOW_SECS, FakeApple, FakeFirebase, identity_config};
use crate::oauth::{SignInCheck, validated_by};
use crate::provider::{Backend, Providers};

/// Opens a stream to a [`FakeImap`].
#[derive(Debug)]
pub struct FakeConnect(FakeImap);

impl Connect for FakeConnect {
    type Stream = DuplexStream;

    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        std::future::ready(Ok(self.0.connect()))
    }
}

/// Mail over a per-call-credential IMAP pool. Only `list_mailboxes` is wired.
#[derive(Debug)]
pub struct ImapMail {
    pool: ImapPool<FakeConnect>,
}

const OFF: CoreError = CoreError::Unsupported("the fake backend wires list_mailboxes only");

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the unwired operations answer without waiting"
)]
impl MailApi for ImapMail {
    async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        self.pool.list_mailboxes().await
    }

    async fn search(&self, _query: &MailSearch) -> Result<MailHitPage, CoreError> {
        Err(OFF)
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

    async fn get_attachment_bytes(
        &self,
        _id: &MessageId,
        _part: &str,
    ) -> Result<Attachment, CoreError> {
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

/// A backend whose every account reads mail from one [`FakeImap`].
#[derive(Debug)]
pub struct FakeImapBackend(pub FakeImap);

impl Backend for FakeImapBackend {
    type Mail = ImapMail;
    type Calendar = NoCalendar;
    type Contacts = NoContacts;

    fn open(&self, apple_id: &AppleId) -> Providers<ImapMail, NoCalendar, NoContacts> {
        Providers {
            mail: Arc::new(ImapMail {
                pool: ImapPool::per_call(apple_id.clone(), FakeConnect(self.0.clone())),
            }),
            calendar: Arc::new(NoCalendar),
            contacts: Arc::new(NoContacts),
        }
    }
}

struct AcceptAll;

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

/// A sign-in check that accepts every address and password.
#[must_use]
pub fn accept_all() -> impl SignInCheck {
    validated_by(|_: &Credentials| AcceptAll)
}

/// What `initialize` reports for the fake server.
///
/// # Panics
///
/// Never in practice: the placeholder address is valid.
#[must_use]
pub fn info() -> ServerConfig {
    let server = IbridgeServer::read_only(
        AccountSnapshot {
            apple_id: AppleId::try_from("placeholder@icloud.com").expect("a valid address"),
            mail: ServiceStatus::On,
            calendar: ServiceStatus::On,
            contacts: ServiceStatus::On,
        },
        Arc::new(ImapMail {
            pool: ImapPool::per_call(
                AppleId::try_from("placeholder@icloud.com").expect("a valid address"),
                FakeConnect(FakeImap::spawn(
                    ibridge_testkit::imap_fake::FakeScript::default(),
                )),
            ),
        }),
    );
    rmcp::ServerHandler::get_info(&server)
}
