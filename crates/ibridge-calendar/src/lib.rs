// SPDX-License-Identifier: Apache-2.0

//! Calendar and reminders providers over `CalDAV`.

mod collections;
mod events;
mod ical;
mod recurrence;
mod reminders;
#[cfg(test)]
mod test_support;

#[cfg(test)]
mod integration;

use ibridge_dav::DavClient;

/// iCloud calendars and reminders through one `CalDAV` client.
#[derive(Debug)]
pub struct CalDavProvider {
    client: DavClient,
}

impl CalDavProvider {
    /// Wraps a signed-in `CalDAV` client.
    #[must_use]
    pub fn new(client: DavClient) -> Self {
        Self { client }
    }
}
