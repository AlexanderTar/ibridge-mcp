// SPDX-License-Identifier: Apache-2.0

//! IMAP session handling.

mod fetch;
mod mailbox;
mod pool;
mod search;
mod tls;
mod write;

#[cfg(test)]
mod integration;
#[cfg(test)]
mod support;

pub use pool::{Connect, ImapPool};
pub use tls::IcloudConnect;
