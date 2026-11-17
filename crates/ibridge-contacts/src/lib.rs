// SPDX-License-Identifier: Apache-2.0

//! Contacts provider over `CardDAV`.

mod books;
mod groups;
#[cfg(test)]
mod integration;
mod provider;
#[cfg(test)]
mod replay;
mod search;
#[cfg(test)]
mod test_support;
mod vcard;
mod writes;

use ibridge_dav::DavClient;

/// iCloud contacts through one `CardDAV` client.
#[derive(Debug)]
pub struct CardDavProvider {
    client: DavClient,
}

impl CardDavProvider {
    /// Wraps a signed-in `CardDAV` client.
    #[must_use]
    pub fn new(client: DavClient) -> Self {
        Self { client }
    }
}
