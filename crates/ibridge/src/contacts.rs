// SPDX-License-Identifier: Apache-2.0

//! The contacts backend: iCloud `CardDAV`, or a stand-in when contacts is off.

use std::sync::Arc;

use ibridge_auth::Credentials;

/// The contacts backend `serve` runs with.
#[cfg(feature = "contacts")]
pub(crate) type Backend = ibridge_contacts::CardDavProvider;
/// The contacts backend `serve` runs with.
#[cfg(not(feature = "contacts"))]
pub(crate) type Backend = ibridge_server::NoContacts;

/// Builds the contacts backend for `credentials`. No request is sent yet.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg(feature = "contacts")]
pub(crate) fn backend(credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    let client = ibridge_dav::DavClient::new(credentials.duplicate())?;
    Ok(Arc::new(ibridge_contacts::CardDavProvider::new(client)))
}

/// Builds the stand-in contacts backend.
///
/// # Errors
///
/// Never fails.
#[cfg(not(feature = "contacts"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the contacts build can fail, and both builds share one signature"
)]
pub(crate) fn backend(_credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    Ok(Arc::new(ibridge_server::NoContacts))
}
