// SPDX-License-Identifier: Apache-2.0

//! The calendar and reminders backend: iCloud `CalDAV`, or a stand-in when calendar is off.

use std::sync::Arc;

use ibridge_auth::Credentials;

/// The calendar backend `serve` runs with.
#[cfg(feature = "calendar")]
pub(crate) type Backend = ibridge_calendar::CalDavProvider;
/// The calendar backend `serve` runs with.
#[cfg(not(feature = "calendar"))]
pub(crate) type Backend = ibridge_server::NoCalendar;

/// Builds the calendar backend for `credentials`. No request is sent yet.
///
/// # Errors
///
/// Returns an error when the system has no root certificates to check iCloud with.
#[cfg(feature = "calendar")]
pub(crate) fn backend(credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    let client = ibridge_dav::DavClient::new(credentials.duplicate())?;
    Ok(Arc::new(ibridge_calendar::CalDavProvider::new(client)))
}

/// Builds the stand-in calendar backend.
///
/// # Errors
///
/// Never fails.
#[cfg(not(feature = "calendar"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the calendar build can fail, and both builds share one signature"
)]
pub(crate) fn backend(_credentials: &Credentials) -> anyhow::Result<Arc<Backend>> {
    Ok(Arc::new(ibridge_server::NoCalendar))
}
