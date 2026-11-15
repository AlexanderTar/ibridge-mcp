// SPDX-License-Identifier: Apache-2.0

//! Searching and reading contacts. Matching happens here, not on the server.

use ibridge_core::{Contact, ContactList, ContactQuery, CoreError, ETag, ResourcePath};

use crate::CardDavProvider;
use crate::books::protocol;
use crate::vcard::{self, Fields};

/// Hits a search returns at most.
const MAX_HITS: u32 = 100;
/// Fewest digits in a query before it also matches phone numbers.
const MIN_PHONE_DIGITS: usize = 3;

impl CardDavProvider {
    pub(crate) async fn search_contacts(
        &self,
        query: &ContactQuery,
    ) -> Result<ContactList, CoreError> {
        let text = query.text.trim();
        if text.is_empty() {
            return Err(CoreError::InvalidInput(
                "give a name, an email address or a phone number to search for".to_owned(),
            ));
        }
        let matcher = Matcher::new(text);
        let home = self.home().await?;
        let mut found: Vec<(String, Contact)> = Vec::new();
        let mut warnings = 0;
        for book in self.books(&home).await? {
            for entry in self.cards(&home, &book).await? {
                let Some(path) = home
                    .relative(&entry.href)
                    .filter(|relative| !relative.ends_with('/'))
                    .and_then(|relative| ResourcePath::try_from(relative.as_str()).ok())
                else {
                    continue;
                };
                if entry.not_found {
                    continue;
                }
                let parsed = (
                    entry.address_data.as_deref().and_then(vcard::parse),
                    entry.etag.as_deref().and_then(|e| ETag::try_from(e).ok()),
                );
                let (Some(card), Some(etag)) = parsed else {
                    warnings += 1;
                    continue;
                };
                let fields = vcard::read(&card);
                if fields.is_group || !matcher.matches(&fields) {
                    continue;
                }
                found.push((
                    fields.full_name.to_lowercase(),
                    contact(path, etag, fields, Vec::new()),
                ));
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        let limit = usize::try_from(query.limit.clamp(1, MAX_HITS)).unwrap_or(1);
        Ok(ContactList {
            contacts: found.into_iter().take(limit).map(|(_, c)| c).collect(),
            warnings,
        })
    }

    pub(crate) async fn get_contact(&self, path: &ResourcePath) -> Result<Contact, CoreError> {
        let fetched = self.fetch(path).await?;
        let fields = vcard::read(&vcard::parse(&fetched.text).ok_or_else(protocol)?);
        let groups = match &fields.uid {
            Some(uid) => self.groups_of(path, uid).await,
            None => Vec::new(),
        };
        Ok(contact(path.clone(), fetched.etag, fields, groups))
    }

    /// Names of the groups in `path`'s address book that list `uid`. A failure
    /// to read them leaves the list empty: the card itself was read.
    async fn groups_of(&self, path: &ResourcePath, uid: &str) -> Vec<String> {
        let Some((book, _)) = path.as_str().split_once('/') else {
            return Vec::new();
        };
        let Ok(book) = ResourcePath::try_from(book) else {
            return Vec::new();
        };
        let Ok(home) = self.home().await else {
            return Vec::new();
        };
        let Ok(entries) = self.cards(&home, &book).await else {
            return Vec::new();
        };
        entries
            .iter()
            .filter_map(|entry| entry.address_data.as_deref().and_then(vcard::parse))
            .map(|card| vcard::read(&card))
            .filter(|group| group.is_group && group.members.iter().any(|member| member == uid))
            .map(|group| group.full_name)
            .collect()
    }
}

fn contact(path: ResourcePath, etag: ETag, fields: Fields, groups: Vec<String>) -> Contact {
    Contact {
        path,
        etag,
        full_name: fields.full_name,
        emails: fields.emails,
        phones: fields.phones,
        organization: fields.organization,
        note: fields.note,
        groups,
    }
}

/// A case-insensitive text match on name and email, and a digits-only match on phones.
struct Matcher {
    text: String,
    digits: Option<String>,
}

impl Matcher {
    fn new(text: &str) -> Self {
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        let phone_like = text
            .chars()
            .all(|ch| ch.is_ascii_digit() || " +()-.".contains(ch));
        Self {
            text: text.to_lowercase(),
            digits: (phone_like && digits.len() >= MIN_PHONE_DIGITS).then_some(digits),
        }
    }

    fn matches(&self, fields: &Fields) -> bool {
        fields.full_name.to_lowercase().contains(&self.text)
            || fields
                .emails
                .iter()
                .any(|email| email.value.to_lowercase().contains(&self.text))
            || self.digits.as_ref().is_some_and(|wanted| {
                fields.phones.iter().any(|phone| {
                    let digits: String = phone.value.chars().filter(char::is_ascii_digit).collect();
                    digits.contains(wanted.as_str())
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use ibridge_core::{ContactQuery, ContactsProvider, ResourcePath};

    use crate::test_support::{setup, vcard};

    const ADA: &str = "UID:ada-uid\nN:Lovelace;Ada;;;\nFN:Ada Lovelace\nORG:Analytical Engines;\n\
        NOTE:Wrote the first program\\nand more\n\
        item1.EMAIL;type=INTERNET;type=pref:ada@example.com\nitem1.X-ABLabel:_$!<Home>!$_\n\
        TEL;type=CELL;type=VOICE:+1 (555) 010-0100";
    const GRACE: &str = "UID:grace-uid\nN:Hopper;Grace;;;\nFN:Grace Hopper\n\
        EMAIL;TYPE=INTERNET;TYPE=WORK:grace@navy.example\nTEL;TYPE=VOICE:+1 555 0199";
    const GROUP: &str = "UID:group-uid\nFN:Pioneers\nN:Pioneers;;;;\nX-ADDRESSBOOKSERVER-KIND:group\n\
        X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:ada-uid";

    fn query(text: &str, limit: u32) -> ContactQuery {
        ContactQuery {
            text: text.to_owned(),
            limit,
        }
    }

    #[tokio::test]
    async fn search_client_side_name_email_phone() {
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "grace.vcf", &vcard(GRACE));
        fake.put("card", "pioneers.vcf", &vcard(GROUP));
        let names = |list: ibridge_core::ContactList| {
            list.contacts
                .into_iter()
                .map(|c| c.full_name)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            names(provider.search(&query("love", 25)).await.expect("name")),
            ["Ada Lovelace"]
        );
        assert_eq!(
            names(
                provider
                    .search(&query("NAVY.example", 25))
                    .await
                    .expect("email")
            ),
            ["Grace Hopper"]
        );
        assert_eq!(
            names(
                provider
                    .search(&query("555 0100", 25))
                    .await
                    .expect("phone digits")
            ),
            ["Ada Lovelace"]
        );
        assert_eq!(
            names(
                provider
                    .search(&query("5550199", 25))
                    .await
                    .expect("phone digits")
            ),
            ["Grace Hopper"]
        );
        assert_eq!(
            names(provider.search(&query("o", 25)).await.expect("both")),
            ["Ada Lovelace", "Grace Hopper"]
        );
        assert_eq!(
            names(provider.search(&query("o", 1)).await.expect("limit")),
            ["Ada Lovelace"]
        );
        assert!(names(provider.search(&query("zzz", 25)).await.expect("none")).is_empty());
        assert!(
            names(
                provider
                    .search(&query("Pioneers", 25))
                    .await
                    .expect("group")
            )
            .is_empty(),
            "a group card is not a contact"
        );
        for logged in fake.requests().iter().filter(|r| r.method == "REPORT") {
            let body = logged.body.to_ascii_lowercase();
            assert!(
                !body.contains("love") && !body.contains("navy"),
                "the server must not be asked to filter: {body}"
            );
        }
    }

    #[tokio::test]
    async fn photo_uri_never_fetched_with_credentials() {
        let (fake, provider) = setup().await;
        let card = format!("{ADA}\nPHOTO;VALUE=uri:{}photo/ada.jpg", fake.base_url());
        fake.put("card", "ada.vcf", &vcard(&card));
        let found = provider.search(&query("ada", 25)).await.expect("search");
        assert_eq!(found.contacts.len(), 1);
        provider
            .get(&ResourcePath::try_from("card/ada.vcf").expect("path"))
            .await
            .expect("get");
        let fetched: Vec<_> = fake
            .requests()
            .into_iter()
            .filter(|r| r.path.contains("photo"))
            .collect();
        assert!(fetched.is_empty(), "photo URI was fetched: {fetched:?}");
    }

    #[tokio::test]
    async fn bad_card_skipped_with_warning() {
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "bad.vcf", "this is not a vCard at all");
        let found = provider
            .search(&query("ada", 25))
            .await
            .expect("one bad card does not fail the list");
        assert_eq!(found.contacts.len(), 1);
        assert_eq!(found.warnings, 1);
    }

    #[tokio::test]
    async fn get_reads_labels_note_organization_and_groups() {
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "pioneers.vcf", &vcard(GROUP));
        let contact = provider
            .get(&ResourcePath::try_from("card/ada.vcf").expect("path"))
            .await
            .expect("get");
        assert_eq!(contact.full_name, "Ada Lovelace");
        assert_eq!(contact.organization.as_deref(), Some("Analytical Engines"));
        assert_eq!(
            contact.note.as_deref(),
            Some("Wrote the first program\nand more")
        );
        assert_eq!(contact.emails.len(), 1);
        assert_eq!(contact.emails[0].value, "ada@example.com");
        assert_eq!(contact.emails[0].label.as_deref(), Some("Home"));
        assert_eq!(contact.phones[0].value, "+1 (555) 010-0100");
        assert_eq!(contact.phones[0].label.as_deref(), Some("Cell"));
        assert_eq!(contact.groups, ["Pioneers"]);
        assert!(!contact.etag.as_str().is_empty());
    }

    #[tokio::test]
    async fn get_of_a_missing_card_is_not_found() {
        let (_fake, provider) = setup().await;
        let result = provider
            .get(&ResourcePath::try_from("card/none.vcf").expect("path"))
            .await;
        assert_eq!(result.unwrap_err(), ibridge_core::CoreError::NotFound);
    }
}
