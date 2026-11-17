// SPDX-License-Identifier: Apache-2.0

//! Shared pool fixtures.

use std::future::{Future, ready};

use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use ibridge_testkit::fixtures::ReplayImap;
use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
use tokio::io::DuplexStream;

use super::pool::{Connect, ImapPool};

pub(super) const PASSWORD: &str = "test-secret";

fn credentials() -> Credentials {
    let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
    Credentials::new(apple_id, PASSWORD)
}

pub(super) fn pool(script: FakeScript) -> (FakeImap, ImapPool<FakeImap>) {
    let fake = FakeImap::spawn(script);
    let pooled = ImapPool::new(credentials(), fake.clone());
    (fake, pooled)
}

/// A pool that talks to the recorded iCloud responses in `tests/fixtures/imap`.
pub(super) fn replay_pool() -> ImapPool<ReplayImap> {
    ImapPool::new(credentials(), ReplayImap::load())
}

impl Connect for ReplayImap {
    type Stream = DuplexStream;

    fn connect(&self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send {
        let stream = ReplayImap::connect(self);
        ready(Ok(stream))
    }
}

impl Connect for FakeImap {
    type Stream = DuplexStream;

    fn connect(&self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send {
        let stream = FakeImap::connect(self);
        ready(Ok(stream))
    }
}
