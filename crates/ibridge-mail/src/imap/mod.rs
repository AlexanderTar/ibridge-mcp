// SPDX-License-Identifier: Apache-2.0

//! IMAP session handling.

mod fetch;
mod mailbox;
mod pool;
mod search;

#[cfg(test)]
mod integration;
#[cfg(test)]
mod support;

pub use pool::ImapPool;
