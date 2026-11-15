// SPDX-License-Identifier: Apache-2.0

//! Shared `CalDAV` and `CardDAV` client.

mod client;
mod error;
mod redirect;

pub use client::{DavClient, Exchange};
pub use error::DavError;

#[cfg(test)]
mod test_support;
