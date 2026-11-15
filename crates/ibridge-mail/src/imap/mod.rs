// SPDX-License-Identifier: Apache-2.0

//! IMAP session handling.

mod fetch;
mod mailbox;
mod pool;
mod search;
mod write;

#[cfg(test)]
mod integration;
#[cfg(test)]
mod support;

pub(crate) use pool::Connect;
pub use pool::ImapPool;
