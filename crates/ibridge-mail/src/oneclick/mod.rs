// SPDX-License-Identifier: Apache-2.0

//! RFC 8058 one-click unsubscribe: a credential-less POST to a sender-chosen host.

mod client;
mod guard;

pub(crate) use client::OneClick;
#[cfg(test)]
pub(crate) use client::loopback;

use std::sync::OnceLock;

/// The process-wide client, built on first use because loading the system roots reads the disk.
///
/// `None` when no system root certificate is installed; the caller reports that as unreachable.
pub(crate) async fn shared() -> Option<OneClick> {
    static CLIENT: OnceLock<Option<OneClick>> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return client.clone();
    }
    let built = tokio::task::spawn_blocking(|| OneClick::new().ok())
        .await
        .ok()
        .flatten();
    CLIENT.get_or_init(|| built).clone()
}
