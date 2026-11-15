// SPDX-License-Identifier: Apache-2.0

//! Adding contacts to and removing them from existing groups.
//!
//! A group is a card that lists its members. This module only rewrites that
//! list on a group that exists; it never creates or deletes a group.

use ibridge_core::{CoreError, GroupChange, ResourcePath};

use crate::CardDavProvider;
use crate::books::{VCARD_TYPE, protocol};
use crate::vcard::{self, Prop};

/// Apple's member property. A group that has none of its own uses `MEMBER`.
const APPLE_MEMBER: &str = "X-ADDRESSBOOKSERVER-MEMBER";

impl CardDavProvider {
    pub(crate) async fn change_membership(
        &self,
        group: &ResourcePath,
        contact: &ResourcePath,
        change: GroupChange,
    ) -> Result<(), CoreError> {
        let member = self.fetch(contact).await?;
        let uid = vcard::read(&vcard::parse(&member.text).ok_or_else(protocol)?)
            .uid
            .ok_or_else(|| CoreError::InvalidInput("that contact has no UID".to_owned()))?;
        let card = self.fetch(group).await?;
        let fields = vcard::read(&vcard::parse(&card.text).ok_or_else(protocol)?);
        if !fields.is_group {
            return Err(CoreError::InvalidInput(
                "that card is not a group; groups cannot be created here".to_owned(),
            ));
        }
        let Some(text) = with_member(&card.text, &uid, change) else {
            return Ok(());
        };
        vcard::parse(&text).ok_or_else(protocol)?;
        let home = self.home().await?;
        self.client
            .put_if_match(&home.url_of(group.as_str()), &text, VCARD_TYPE, &card.etag)
            .await?;
        Ok(())
    }
}

/// The group card with `uid` added or removed, or `None` when it already is.
fn with_member(text: &str, uid: &str, change: GroupChange) -> Option<String> {
    let mut props = vcard::split(text);
    let lists = |prop: &Prop| {
        matches!(prop.name.as_str(), "MEMBER" | APPLE_MEMBER)
            && prop.value.trim().trim_start_matches("urn:uuid:") == uid
    };
    let listed = props.iter().any(lists);
    match change {
        GroupChange::Add if listed => return None,
        GroupChange::Add => {
            let name = if props.iter().any(|prop| prop.name == "MEMBER") {
                "MEMBER"
            } else {
                APPLE_MEMBER
            };
            let line = vcard::fold(&format!("{name}:urn:uuid:{uid}"), vcard::eol_of(text));
            vcard::insert_before_end(&mut props, vcard::prop_of(&line));
        }
        GroupChange::Remove if !listed => return None,
        GroupChange::Remove => props.retain(|prop| !lists(prop)),
        _ => return None,
    }
    Some(props.iter().map(|prop| prop.raw.as_str()).collect())
}

#[cfg(test)]
mod tests {
    use ibridge_core::{ContactsProvider, CoreError, GroupChange, ResourcePath};

    use crate::test_support::{setup, vcard};

    const ADA: &str = "UID:ada-uid\nN:Lovelace;Ada;;;\nFN:Ada Lovelace";
    const GRACE: &str = "UID:grace-uid\nN:Hopper;Grace;;;\nFN:Grace Hopper";
    const GROUP: &str = "UID:group-uid\nN:Pioneers;;;;\nFN:Pioneers\n\
        X-ADDRESSBOOKSERVER-KIND:group\nX-ABUID:group-uid\n\
        X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:grace-uid";

    fn path(text: &str) -> ResourcePath {
        ResourcePath::try_from(text).expect("path")
    }

    #[tokio::test]
    async fn set_group_membership_rewrites_group_card_with_if_match() {
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "grace.vcf", &vcard(GRACE));
        let group_etag = fake.put("card", "pioneers.vcf", &vcard(GROUP));

        provider
            .set_group_membership(
                &path("card/pioneers.vcf"),
                &path("card/ada.vcf"),
                GroupChange::Add,
            )
            .await
            .expect("add");
        let put = fake
            .requests()
            .into_iter()
            .find(|r| r.method == "PUT")
            .expect("the group card is rewritten");
        assert_eq!(put.path, "/ada/carddavhome/card/pioneers.vcf");
        assert_eq!(put.if_match.as_deref(), Some(group_etag.as_str()));
        let stored = fake.body("card", "pioneers.vcf").expect("stored");
        for kept in [
            "X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:grace-uid\r\n",
            "X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:ada-uid\r\n",
            "X-ADDRESSBOOKSERVER-KIND:group\r\n",
            "X-ABUID:group-uid\r\n",
        ] {
            assert!(stored.contains(kept), "missing {kept:?} in {stored:?}");
        }

        provider
            .set_group_membership(
                &path("card/pioneers.vcf"),
                &path("card/grace.vcf"),
                GroupChange::Remove,
            )
            .await
            .expect("remove");
        let stored = fake.body("card", "pioneers.vcf").expect("stored");
        assert!(!stored.contains("grace-uid"), "{stored:?}");
        assert!(stored.contains("urn:uuid:ada-uid"), "{stored:?}");
        let contact = provider.get(&path("card/ada.vcf")).await.expect("get");
        assert_eq!(contact.groups[0].name, "Pioneers");
    }

    #[tokio::test]
    async fn a_membership_that_already_holds_writes_nothing() {
        let (fake, provider) = setup().await;
        fake.put("card", "grace.vcf", &vcard(GRACE));
        fake.put("card", "pioneers.vcf", &vcard(GROUP));
        provider
            .set_group_membership(
                &path("card/pioneers.vcf"),
                &path("card/grace.vcf"),
                GroupChange::Add,
            )
            .await
            .expect("already a member");
        assert!(fake.requests().iter().all(|r| r.method != "PUT"));
    }

    #[tokio::test]
    async fn a_card_that_is_not_a_group_is_refused() {
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "grace.vcf", &vcard(GRACE));
        let result = provider
            .set_group_membership(
                &path("card/grace.vcf"),
                &path("card/ada.vcf"),
                GroupChange::Add,
            )
            .await;
        assert!(
            matches!(result, Err(CoreError::InvalidInput(_))),
            "{result:?}"
        );
        assert!(fake.requests().iter().all(|r| r.method != "PUT"));
    }

    #[tokio::test]
    async fn a_lost_race_on_the_group_card_is_a_conflict() {
        // The server answers 412 when the group changed between our read and write.
        let (fake, provider) = setup().await;
        fake.put("card", "ada.vcf", &vcard(ADA));
        fake.put("card", "pioneers.vcf", &vcard(GROUP));
        fake.fail_next_put_with(412);
        let result = provider
            .set_group_membership(
                &path("card/pioneers.vcf"),
                &path("card/ada.vcf"),
                GroupChange::Add,
            )
            .await;
        assert_eq!(result, Err(CoreError::Conflict));
    }
}
