// SPDX-License-Identifier: Apache-2.0

//! Live smoke test for contacts, against the user's own iCloud account.
//!
//! Ignored by default and never run in CI. Run it with
//! `IBRIDGE_LIVE=1 cargo nextest run --run-ignored ignored-only -E 'test(live_contacts)'`.
//! It reads `~/.config/ibridge/test-account.env`, creates one marker contact,
//! reads it back by its own path, and deletes it (by path with no etag when the
//! read-back fails, so nothing is left behind). It never lists or searches
//! the account's other contacts.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Request, StatusCode};
use ibridge_auth::{CredentialSource, Credentials, FileSource};
use ibridge_contacts::CardDavProvider;
use ibridge_core::{ContactDraft, ContactsProvider, CoreError};
use ibridge_dav::DavClient;

async fn account() -> Credentials {
    assert_eq!(
        std::env::var("IBRIDGE_LIVE").as_deref(),
        Ok("1"),
        "live tests need IBRIDGE_LIVE=1"
    );
    let home = std::env::var_os("HOME").expect("HOME is set");
    let path = PathBuf::from(home).join(".config/ibridge/test-account.env");
    FileSource::new(path)
        .credentials()
        .await
        .expect("the test account file is present, mode 0600 and complete")
}

fn copy(credentials: &Credentials) -> Credentials {
    credentials.with_secret(|secret| Credentials::new(credentials.apple_id.clone(), secret))
}

/// Deletes the resource at `url` with no `If-Match`, so a failed read-back cannot leave the
/// marker behind for want of an etag. A 404 means it is already gone.
async fn delete_regardless(client: &DavClient, url: String) {
    let request = Request::builder()
        .method("DELETE")
        .uri(url)
        .body(String::new())
        .expect("a DELETE request");
    let exchange = client
        .request(request)
        .await
        .expect("send the cleanup DELETE");
    assert!(
        exchange.status.is_success() || exchange.status == StatusCode::NOT_FOUND,
        "the cleanup DELETE removed the marker, got {}",
        exchange.status
    );
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_nanos();
    format!("{nanos:x}")
}

#[tokio::test]
#[ignore = "live: needs IBRIDGE_LIVE=1 and the test account file"]
async fn live_contacts_smoke() {
    let credentials = account().await;
    let cleanup = DavClient::new(copy(&credentials)).expect("DAV client");
    let provider = CardDavProvider::new(DavClient::new(credentials).expect("DAV client"));
    let name = format!("[ibridge-live] {} contact", nonce());

    let path = provider
        .create(&ContactDraft {
            full_name: name.clone(),
            emails: vec!["marker@example.invalid".to_owned()],
            phones: vec!["+1 555 0100".to_owned()],
        })
        .await
        .expect("create the marker contact");
    let fetched = provider.get(&path).await;
    let deleted = match &fetched {
        Ok(contact) => provider.delete(&path, &contact.etag).await,
        Err(_) => Err(CoreError::NotFound),
    };
    if deleted.is_err() {
        let home = cleanup.contacts_home().await.expect("address-book home");
        delete_regardless(&cleanup, home.url_of(path.as_str())).await;
    }
    let after = provider.get(&path).await;

    let contact = fetched.expect("read the marker contact");
    assert_eq!(contact.full_name, name);
    assert_eq!(contact.emails[0].value, "marker@example.invalid");
    deleted.expect("delete the marker contact with its etag");
    assert!(
        matches!(after, Err(CoreError::NotFound)),
        "the marker contact is gone, got {after:?}"
    );
}
