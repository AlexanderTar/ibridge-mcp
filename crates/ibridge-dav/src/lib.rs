// SPDX-License-Identifier: Apache-2.0

//! Shared `CalDAV` and `CardDAV` client.

mod client;
mod discovery;
mod error;
mod redirect;
mod sync;

pub use client::{DavClient, Exchange};
pub use discovery::{CollectionHome, DavValidator};
pub use error::DavError;
pub use sync::{SyncReport, SyncedItem};

#[cfg(test)]
mod integration;
#[cfg(test)]
mod test_support;
