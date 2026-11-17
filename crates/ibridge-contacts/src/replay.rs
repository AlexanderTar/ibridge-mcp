// SPDX-License-Identifier: Apache-2.0

//! Replays the `CardDAV` responses recorded from real iCloud.

use ibridge_auth::Credentials;
use ibridge_core::{AppleId, ContactQuery, ContactsProvider};
use ibridge_dav::DavClient;
use ibridge_testkit::fixtures::ReplayCardDav;

use crate::CardDavProvider;

#[tokio::test]
async fn fixture_icloud_carddav_replay() {
    let replay = ReplayCardDav::start().await;
    let credentials = Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    );
    let client = DavClient::for_test_server(credentials, &replay.base_url()).expect("test client");
    // The recording shows the well-known path answering without a principal.
    // Discovery has to fall back to the root to reach the address book.
    assert!(
        ibridge_testkit::fixtures::read("carddav", "well-known.xml").contains("404 Not Found"),
        "the recorded well-known reply has no principal"
    );
    let provider = CardDavProvider::new(client);

    let found = provider
        .search(&ContactQuery {
            text: "[ibridge-fixture]".to_owned(),
            limit: 25,
            include_groups: true,
        })
        .await
        .expect("recorded address-book report");
    assert_eq!(found.warnings, 0, "got {found:?}");
    assert_eq!(found.contacts.len(), 1, "got {found:?}");
    let contact = &found.contacts[0];
    assert!(
        contact.full_name.starts_with("[ibridge-fixture] ")
            && contact.full_name.ends_with(" contact"),
        "got {}",
        contact.full_name
    );
    assert_eq!(contact.emails.len(), 1);
    assert_eq!(contact.emails[0].value, "marker@example.invalid");
    assert_eq!(contact.phones.len(), 1);
    assert_eq!(contact.phones[0].value, "+1 555 0100");
    assert!(!contact.is_group);

    let fetched = provider
        .get(&contact.path)
        .await
        .expect("recorded contact GET");
    assert_eq!(fetched.full_name, contact.full_name);
    assert_eq!(fetched.etag, contact.etag);
}
