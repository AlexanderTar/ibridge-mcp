// SPDX-License-Identifier: Apache-2.0

//! Records scrubbed `CardDAV` fixtures from one marker contact.
//!
//! The recorder creates a single contact whose name carries the run's marker,
//! reads only that contact back, and deletes it again. It never lists, reads or
//! writes any other contact, so no real contact reaches a fixture.

use std::fs;
use std::io;
use std::path::Path;

use ibridge_auth::Credentials;
use ibridge_contacts::CardDavProvider;
use ibridge_core::{ContactDraft, ContactsProvider, ResourcePath};
use ibridge_dav::{DavClient, DavError, multistatus};

use crate::record_calendar::{dav, delete_marked, dsid_of, load, send};
use crate::record_fixtures::{MARKER, RecordError};
use crate::scrub::{Identity, Scrubber};

const PROPFIND_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname/><D:resourcetype/></D:prop></D:propfind>";

const PRINCIPAL_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <D:propfind xmlns:D=\"DAV:\"><D:prop><D:current-user-principal/></D:prop></D:propfind>";

/// Creates a marker contact, records the replies, scrubs them into `out_dir`
/// and deletes the contact.
///
/// The one contact it creates is the only one it asks the server about, and
/// the only one it deletes.
pub(crate) async fn run_contacts(
    account: &Path,
    make_client: impl Fn(&Credentials) -> Result<DavClient, DavError>,
    out_dir: &Path,
    nonce: &str,
    log: &mut impl io::Write,
) -> Result<(), RecordError> {
    let credentials = load(account).await?;
    let provider = CardDavProvider::new(make_client(&credentials).map_err(dav)?);
    let raw = make_client(&credentials).map_err(dav)?;
    let marker = format!("{MARKER} {nonce}");

    let mut created = None;
    let recorded = record(
        &provider,
        &raw,
        &marker,
        &credentials,
        out_dir,
        &mut created,
    )
    .await;
    let cleaned = clean_up(&raw, created.as_ref(), &marker).await;
    let files = recorded?;
    let deleted = cleaned?;
    writeln!(
        log,
        "recorded {files} fixtures, deleted {deleted} marker contact"
    )?;
    Ok(())
}

async fn record(
    provider: &CardDavProvider,
    raw: &DavClient,
    marker: &str,
    credentials: &Credentials,
    out_dir: &Path,
    created: &mut Option<ResourcePath>,
) -> Result<usize, RecordError> {
    let home = raw.contacts_home().await.map_err(dav)?;
    let listing = send(raw, "PROPFIND", &home.url, Some("1"), PROPFIND_BODY).await?;
    // Address book names are the account's own and part of the listing saved below.
    let names = multistatus::parse(listing.as_bytes())
        .map_err(dav)?
        .into_iter()
        .filter_map(|entry| entry.display_name)
        .collect();
    let mut scrubber = Scrubber::new(Identity {
        apple_id: credentials.apple_id.as_str().to_owned(),
        dsid: dsid_of(&home.url),
        names,
    });
    let mut fixtures: Vec<(&str, String)> = Vec::new();
    // Where discovery starts. iCloud answers it without a principal, so the
    // client has to fall back to the server root.
    fixtures.push((
        "well-known.xml",
        send(
            raw,
            "PROPFIND",
            &raw.carddav_root_url(),
            Some("0"),
            PRINCIPAL_BODY,
        )
        .await?,
    ));
    fixtures.push(("propfind-home.xml", listing));

    let path = provider
        .create(&ContactDraft {
            full_name: format!("{marker} contact"),
            emails: vec!["marker@example.invalid".to_owned()],
            phones: vec!["+1 555 0100".to_owned()],
        })
        .await
        .map_err(|_| RecordError::Dav("the marker contact could not be created"))?;
    *created = Some(path.clone());

    let url = home.url_of(path.as_str());
    let href = url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|slash| &rest[slash..]))
        .ok_or(RecordError::Dav("the contact URL has no path"))?;
    // A multiget names the marker's own href, so no other contact comes back.
    let multiget = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <C:addressbook-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
         <D:prop><D:getetag/><C:address-data/></D:prop><D:href>{href}</D:href>\
         </C:addressbook-multiget>"
    );
    let book = path
        .as_str()
        .split_once('/')
        .map_or(path.as_str(), |(book, _)| book);
    fixtures.push((
        "report-multiget.xml",
        send(raw, "REPORT", &home.url_of(book), Some("1"), &multiget).await?,
    ));
    fixtures.push(("contact.vcf", send(raw, "GET", &url, None, "").await?));

    fs::create_dir_all(out_dir)?;
    let count = fixtures.len();
    for (name, body) in fixtures {
        fs::write(out_dir.join(name), scrubber.scrub(&body))?;
    }
    Ok(count)
}

/// Deletes the marker contact, and only while it still carries this run's marker.
async fn clean_up(
    raw: &DavClient,
    created: Option<&ResourcePath>,
    marker: &str,
) -> Result<usize, RecordError> {
    let Some(path) = created else {
        return Ok(0);
    };
    let home = raw.contacts_home().await.map_err(dav)?;
    delete_marked(raw, &home.url_of(path.as_str()), marker).await?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use ibridge_auth::Credentials;
    use ibridge_dav::{DavClient, DavError};
    use ibridge_testkit::dav_mock::FakeCardDav;

    use super::run_contacts;

    const ACCOUNT: &str =
        "IBRIDGE_TEST_APPLE_ID=ada@icloud.com\nIBRIDGE_TEST_APP_PASSWORD=never-print-me\n";
    const REAL: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:real-1\r\nN:Person;Dentist;;;\r\n\
        FN:Dentist Person\r\nTEL:+1 555 0188\r\nEND:VCARD\r\n";

    async fn account_with_contacts() -> FakeCardDav {
        let fake = FakeCardDav::start().await;
        fake.add_book("card", "Private Family Book");
        fake.put("card", "real.vcf", REAL);
        fake
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ibridge-card-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn account_file(dir: &std::path::Path) -> PathBuf {
        let path = dir.join("test-account.env");
        fs::write(&path, ACCOUNT).expect("write account file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        path
    }

    fn client_for(base: String) -> impl Fn(&Credentials) -> Result<DavClient, DavError> {
        move |credentials| DavClient::for_test_server(credentials.duplicate(), &base)
    }

    #[tokio::test]
    async fn contacts_recorder_marker_only_and_cleans_up() {
        let fake = account_with_contacts().await;
        let dir = scratch("marker");
        let account = account_file(&dir);
        let out = dir.join("out");
        let mut log = Vec::new();
        run_contacts(
            &account,
            client_for(fake.base_url()),
            &out,
            "n0nce",
            &mut log,
        )
        .await
        .expect("the recorder runs");

        // The only writes are to one new card, and it is gone again.
        let writes: Vec<(String, String)> = fake
            .requests()
            .into_iter()
            .filter(|r| matches!(r.method.as_str(), "PUT" | "DELETE" | "MKCOL" | "PROPPATCH"))
            .map(|r| (r.method, r.path))
            .collect();
        let created: Vec<&(String, String)> = writes.iter().filter(|(m, _)| m == "PUT").collect();
        assert_eq!(
            created.len(),
            1,
            "one marker contact is created: {writes:?}"
        );
        let marker_path = &created[0].1;
        assert!(
            marker_path.starts_with("/ada/carddavhome/card/"),
            "{marker_path}"
        );
        assert!(
            writes.iter().all(|(_, path)| path == marker_path),
            "every write is to the marker card: {writes:?}"
        );
        assert!(
            writes.iter().any(|(m, _)| m == "DELETE"),
            "the marker is deleted"
        );
        assert_eq!(
            fake.files("card"),
            ["real.vcf"],
            "the real contact is untouched"
        );

        // No request reads another contact, and the fixtures hold none.
        for request in fake.requests() {
            assert_ne!(
                request.path, "/ada/carddavhome/card/real.vcf",
                "{} read a real contact",
                request.method
            );
        }
        for file in ["propfind-home.xml", "report-multiget.xml", "contact.vcf"] {
            let text = fs::read_to_string(out.join(file))
                .unwrap_or_else(|error| panic!("{file} was not recorded: {error}"));
            for private in [
                "Dentist",
                "555 0188",
                "ada@icloud.com",
                "never-print-me",
                "Private Family Book",
            ] {
                assert!(!text.contains(private), "{file} leaks {private}: {text}");
            }
        }
        let contact = fs::read_to_string(out.join("contact.vcf")).expect("contact fixture");
        assert!(
            contact.contains("[ibridge-fixture] n0nce"),
            "the marker is recorded: {contact}"
        );
        let log = String::from_utf8(log).expect("log text");
        assert!(!log.contains("never-print-me"), "{log}");
        let _ = fs::remove_dir_all(dir);
    }
}
