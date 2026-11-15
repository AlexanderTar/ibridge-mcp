// SPDX-License-Identifier: Apache-2.0

//! Radicale covers the contact lifecycle against a real server.

use http::{Method, Request};
use ibridge_auth::Credentials;
use ibridge_core::{
    AppleId, ContactDraft, ContactQuery, ContactsProvider, CoreError, GroupChange, ResourcePath,
};
use ibridge_dav::DavClient;

use crate::CardDavProvider;

/// An iPhone-style card with a group, a label and an unknown property.
const ADA: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Apple Inc.//iPhone OS 26.0//EN\r\n\
    UID:radicale-ada\r\nN:Lovelace;Ada;;;\r\nFN:Ada Lovelace\r\nORG:Analytical Engines;\r\n\
    item1.EMAIL;type=INTERNET;type=pref:ada@example.com\r\nitem1.X-ABLabel:_$!<Home>!$_\r\n\
    TEL;type=CELL;type=VOICE;type=pref:+1 555 0100\r\nX-IBR-UNKNOWN;X-P=1:keep me\r\n\
    END:VCARD\r\n";

const GROUP: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:radicale-group\r\nN:Pioneers;;;;\r\n\
    FN:Pioneers\r\nX-ADDRESSBOOKSERVER-KIND:group\r\nEND:VCARD\r\n";

fn credentials() -> Credentials {
    Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    )
}

fn path(text: &str) -> ResourcePath {
    ResourcePath::try_from(text).expect("path")
}

struct Fixture {
    /// Keeps the container running.
    _server: ibridge_testkit::containers::RunningRadicale,
    raw: DavClient,
    provider: CardDavProvider,
    /// URL of the `card/` address book.
    book: String,
}

async fn fixture() -> Fixture {
    let server = ibridge_testkit::containers::radicale()
        .start()
        .await
        .expect("radicale starts");
    let raw = DavClient::for_test_server(credentials(), server.base_url()).expect("raw client");
    let home = raw.contacts_home().await.expect("discover");
    let book = format!("{}/card/", home.url.trim_end_matches('/'));
    let mkcol = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        <mkcol xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><set><prop>\
        <resourcetype><collection/><C:addressbook/></resourcetype>\
        </prop></set></mkcol>";
    let created = raw
        .request(
            Request::builder()
                .method("MKCOL")
                .uri(&book)
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(mkcol.to_owned())
                .expect("mkcol"),
        )
        .await
        .expect("create address book");
    assert!(
        created.status.is_success(),
        "mkcol status {}",
        created.status
    );
    let provider = CardDavProvider::new(
        DavClient::for_test_server(credentials(), server.base_url()).expect("provider client"),
    );
    Fixture {
        _server: server,
        raw,
        provider,
        book,
    }
}

async fn stored(fixture: &Fixture, file: &str) -> String {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{}{file}", fixture.book))
        .body(String::new())
        .expect("get");
    let exchange = fixture.raw.request(request).await.expect("get card");
    String::from_utf8_lossy(&exchange.body).into_owned()
}

#[tokio::test]
async fn radicale_vcard_edit_preserves_props() {
    let fixture = fixture().await;
    let provider = &fixture.provider;
    fixture
        .raw
        .put_new(&format!("{}ada.vcf", fixture.book), ADA, "text/vcard")
        .await
        .expect("put card");
    fixture
        .raw
        .put_new(
            &format!("{}pioneers.vcf", fixture.book),
            GROUP,
            "text/vcard",
        )
        .await
        .expect("put group");

    let found = provider
        .search(&ContactQuery {
            text: "lovelace".to_owned(),
            limit: 25,
        })
        .await
        .expect("search");
    assert_eq!(found.contacts.len(), 1, "{:?}", found.contacts);
    let ada = &found.contacts[0];
    assert_eq!(ada.path, path("card/ada.vcf"));

    let edited = provider
        .update(
            &ada.path,
            &ada.etag,
            &ContactDraft {
                full_name: "Ada King".to_owned(),
                emails: vec![
                    "ada@example.com".to_owned(),
                    "countess@example.org".to_owned(),
                ],
                phones: vec!["+1 555 0100".to_owned()],
            },
        )
        .await
        .expect("update");
    assert_ne!(edited, ada.etag);
    // Radicale parses and rewrites a card when it stores it (case, parameter
    // layout), so this checks what the card says, not its exact bytes. The
    // byte-for-byte claim is the unit tests' on the text we send.
    let text = stored(&fixture, "ada.vcf").await.to_ascii_lowercase();
    for kept in [
        "x-ibr-unknown;x-p=1:keep me",
        "item1.email;",
        ":ada@example.com",
        "item1.x-ablabel:_$!<home>!$_",
        "org:analytical engines",
        ":+1 555 0100",
        "fn:ada king",
        "countess@example.org",
    ] {
        assert!(text.contains(kept), "lost {kept:?} in {text:?}");
    }
    let read = provider.get(&path("card/ada.vcf")).await.expect("get");
    assert_eq!(read.emails[0].value, "ada@example.com");
    assert_eq!(read.emails[0].label.as_deref(), Some("Home"));
    assert_eq!(read.organization.as_deref(), Some("Analytical Engines"));

    provider
        .set_group_membership(
            &path("card/pioneers.vcf"),
            &path("card/ada.vcf"),
            GroupChange::Add,
        )
        .await
        .expect("add to group");
    let contact = provider.get(&path("card/ada.vcf")).await.expect("get");
    assert_eq!(contact.groups, ["Pioneers"]);
    assert_eq!(contact.full_name, "Ada King");

    let stale = provider.delete(&path("card/ada.vcf"), &ada.etag).await;
    assert_eq!(stale, Err(CoreError::Conflict), "the old ETag is refused");
    provider
        .delete(&path("card/ada.vcf"), &contact.etag)
        .await
        .expect("delete with the current ETag");
    let gone = provider.get(&path("card/ada.vcf")).await;
    assert_eq!(gone, Err(CoreError::NotFound));
}
