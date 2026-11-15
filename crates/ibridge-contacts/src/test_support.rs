// SPDX-License-Identifier: Apache-2.0

//! Shared setup for the provider tests.

use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use ibridge_dav::DavClient;
use ibridge_testkit::dav_mock::FakeCardDav;

use crate::CardDavProvider;

/// A fake server with one address book, `card`, and a provider on it.
pub(crate) async fn setup() -> (FakeCardDav, CardDavProvider) {
    let fake = FakeCardDav::start().await;
    fake.add_book("card", "card");
    let credentials = Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    );
    let client = DavClient::for_test_server(credentials, &fake.base_url()).expect("test client");
    (fake, CardDavProvider::new(client))
}

/// A vCard 3.0 with `\n` line ends turned into CRLF.
pub(crate) fn vcard(body: &str) -> String {
    format!(
        "BEGIN:VCARD\r\nVERSION:3.0\r\n{}\r\nEND:VCARD\r\n",
        body.replace('\n', "\r\n")
    )
}
