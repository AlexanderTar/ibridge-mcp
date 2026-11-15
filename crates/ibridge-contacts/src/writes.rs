// SPDX-License-Identifier: Apache-2.0

//! Creating, changing and deleting contacts.

use std::fmt::Write as _;

use ibridge_core::{ContactDraft, CoreError, ETag, ResourcePath};

use crate::CardDavProvider;
use crate::books::{VCARD_TYPE, protocol};
use crate::vcard;

impl CardDavProvider {
    pub(crate) async fn create_contact(
        &self,
        draft: &ContactDraft,
    ) -> Result<ResourcePath, CoreError> {
        let home = self.home().await?;
        // iCloud has one address book; any other account gets its first.
        let book = self
            .books(&home)
            .await?
            .into_iter()
            .next()
            .ok_or(CoreError::NotFound)?;
        let uid = new_uid()?;
        let text = vcard::new_card_text(&uid, draft)?;
        let path = ResourcePath::try_from(
            format!("{}/{uid}.vcf", book.as_str().trim_end_matches('/')).as_str(),
        )
        .map_err(|_| protocol())?;
        self.client
            .put_new(&home.url_of(path.as_str()), &text, VCARD_TYPE)
            .await?;
        Ok(path)
    }

    pub(crate) async fn update_contact(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &ContactDraft,
    ) -> Result<ETag, CoreError> {
        let current = self.fetch(path).await?;
        if &current.etag != etag {
            return Err(CoreError::Conflict);
        }
        let text = vcard::update_card_text(&current.text, draft)?;
        let home = self.home().await?;
        Ok(self
            .client
            .put_if_match(&home.url_of(path.as_str()), &text, VCARD_TYPE, etag)
            .await?)
    }

    /// iCloud ignores `If-Match` on a delete, so the card is read again and its
    /// `ETag` compared first. A small window between that read and the delete
    /// remains; the tool says so.
    pub(crate) async fn delete_contact(
        &self,
        path: &ResourcePath,
        etag: &ETag,
    ) -> Result<(), CoreError> {
        let current = self.fetch(path).await?;
        if &current.etag != etag {
            return Err(CoreError::Conflict);
        }
        let home = self.home().await?;
        Ok(self
            .client
            .delete_if_match(&home.url_of(path.as_str()), etag)
            .await?)
    }
}

/// A random UUID, the way Apple names its cards.
fn new_uid() -> Result<String, CoreError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| protocol())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(hex, "{byte:02X}");
    }
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
mod tests {
    use ibridge_core::{ContactDraft, ContactsProvider, CoreError, ETag, ResourcePath};

    use crate::test_support::{setup, vcard};

    const ADA: &str = "UID:ada-uid\nN:Lovelace;Ada;;;\nFN:Ada Lovelace\n\
        item1.EMAIL;type=INTERNET;type=pref:ada@example.com\nitem1.X-ABLabel:_$!<Home>!$_\n\
        X-ABUID:ada-uid:ABPerson\nTEL;type=CELL:+1 555 0100";

    fn draft(name: &str, emails: &[&str], phones: &[&str]) -> ContactDraft {
        ContactDraft {
            full_name: name.to_owned(),
            emails: emails.iter().map(|e| (*e).to_owned()).collect(),
            phones: phones.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    fn etag(text: &str) -> ETag {
        ETag::try_from(text).expect("etag")
    }

    fn ada_path() -> ResourcePath {
        ResourcePath::try_from("card/ada.vcf").expect("path")
    }

    #[tokio::test]
    async fn update_requires_etag() {
        let (fake, provider) = setup().await;
        let first = fake.put("card", "ada.vcf", &vcard(ADA));
        // Someone else saves the card after we read it.
        let second = fake.put("card", "ada.vcf", &vcard(ADA));
        let changed = draft("Ada King", &["ada@example.com"], &["+1 555 0100"]);

        let stale = provider.update(&ada_path(), &etag(&first), &changed).await;
        assert_eq!(stale, Err(CoreError::Conflict));
        assert!(
            fake.requests().iter().all(|r| r.method != "PUT"),
            "a stale ETag must not reach the server as a write"
        );

        let fresh = provider
            .update(&ada_path(), &etag(&second), &changed)
            .await
            .expect("update with the current ETag");
        assert_ne!(fresh.as_str(), second);
        let put = fake
            .requests()
            .into_iter()
            .find(|r| r.method == "PUT")
            .expect("one PUT");
        assert_eq!(put.if_match.as_deref(), Some(second.as_str()));
        let stored = fake.body("card", "ada.vcf").expect("stored");
        assert!(stored.contains("FN:Ada King\r\n"), "{stored:?}");
        for kept in [
            "item1.EMAIL;type=INTERNET;type=pref:ada@example.com\r\nitem1.X-ABLabel:_$!<Home>!$_\r\n",
            "X-ABUID:ada-uid:ABPerson\r\n",
            "TEL;type=CELL:+1 555 0100\r\n",
        ] {
            assert!(stored.contains(kept), "lost {kept:?} in {stored:?}");
        }
    }

    #[tokio::test]
    async fn create_puts_a_new_card_with_if_none_match() {
        let (fake, provider) = setup().await;
        let path = provider
            .create(&draft("Grace Hopper", &["grace@example.com"], &[]))
            .await
            .expect("create");
        assert!(
            path.as_str().starts_with("card/") && path.as_str().rsplit('.').next() == Some("vcf"),
            "{path:?}"
        );
        let put = fake
            .requests()
            .into_iter()
            .find(|r| r.method == "PUT")
            .expect("one PUT");
        assert_eq!(put.if_none_match.as_deref(), Some("*"));
        let (_, file) = path.as_str().split_once('/').expect("book and file");
        let stored = fake.body("card", file).expect("stored");
        assert!(stored.contains("N:Hopper;Grace;;;"), "{stored:?}");
        assert!(
            stored.starts_with("BEGIN:VCARD\r\nVERSION:3.0\r\n"),
            "{stored:?}"
        );
    }

    #[tokio::test]
    async fn delete_rereads_and_refuses_on_etag_mismatch() {
        let (fake, provider) = setup().await;
        let first = fake.put("card", "ada.vcf", &vcard(ADA));
        let second = fake.put("card", "ada.vcf", &vcard(ADA));

        let refused = provider.delete(&ada_path(), &etag(&first)).await;
        assert_eq!(refused, Err(CoreError::Conflict));
        let seen: Vec<String> = fake.requests().into_iter().map(|r| r.method).collect();
        assert!(seen.contains(&"GET".to_owned()), "re-read first: {seen:?}");
        assert!(
            !seen.contains(&"DELETE".to_owned()),
            "no DELETE on a mismatch: {seen:?}"
        );
        assert!(
            fake.body("card", "ada.vcf").is_some(),
            "the card is still there"
        );

        provider
            .delete(&ada_path(), &etag(&second))
            .await
            .expect("delete with the current ETag");
        let requests = fake.requests();
        let get = requests
            .iter()
            .rposition(|r| r.method == "GET")
            .expect("GET");
        let delete = requests
            .iter()
            .position(|r| r.method == "DELETE")
            .expect("DELETE");
        assert!(get < delete, "re-read before delete");
        assert_eq!(requests[delete].if_match.as_deref(), Some(second.as_str()));
        assert!(fake.body("card", "ada.vcf").is_none());
    }

    #[tokio::test]
    async fn delete_of_a_missing_card_is_not_found() {
        let (_fake, provider) = setup().await;
        let result = provider.delete(&ada_path(), &etag("\"x\"")).await;
        assert_eq!(result, Err(CoreError::NotFound));
    }
}
