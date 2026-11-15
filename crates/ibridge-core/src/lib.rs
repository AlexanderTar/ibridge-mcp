// SPDX-License-Identifier: Apache-2.0

//! Domain newtypes, provider traits and the core error type.

mod account;
mod calendar;
mod contacts;
mod error;
mod ids;
mod mail;

pub use account::AppleId;
pub use calendar::{
    Calendar, CalendarProvider, CompletedFilter, Event, EventDraft, EventQuery, Reminder,
    ReminderDraft, ReminderList, RemindersProvider,
};
pub use contacts::{Contact, ContactDraft, ContactQuery, ContactsProvider, GroupChange};
pub use error::{CoreError, IdError, ParseError};
pub use ids::{ETag, ResourcePath, decode, encode};
pub use mail::{
    Attachment, AttachmentInfo, Draft, FlagChange, MailPage, MailProvider, MailSearch, Mailbox,
    MailboxPath, MailboxRole, Message, MessageId, MessageSummary, Uid, UidValidity,
};

#[cfg(test)]
mod provider_tests {
    use super::{
        CalendarProvider, CompletedFilter, ContactQuery, ContactsProvider, CoreError, MailProvider,
        RemindersProvider,
    };

    fn require_send<T: Send>(value: T) -> T {
        value
    }

    struct NullProvider;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "null provider returns immediately"
    )]
    impl MailProvider for NullProvider {
        async fn list_mailboxes(&self) -> Result<Vec<super::Mailbox>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn search(&self, _query: &super::MailSearch) -> Result<super::MailPage, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn get_message(&self, _id: &super::MessageId) -> Result<super::Message, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn get_attachment(
            &self,
            _id: &super::MessageId,
            _part: &str,
        ) -> Result<super::Attachment, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn create_draft(&self, _draft: &super::Draft) -> Result<super::MessageId, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn send(&self, _draft: &super::Draft) -> Result<super::MessageId, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn move_to(
            &self,
            _id: &super::MessageId,
            _destination: &super::MailboxPath,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn set_flags(
            &self,
            _id: &super::MessageId,
            _flags: &super::FlagChange,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "null provider returns immediately"
    )]
    impl CalendarProvider for NullProvider {
        async fn list_calendars(&self) -> Result<Vec<super::Calendar>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn list_events(
            &self,
            _query: &super::EventQuery,
        ) -> Result<Vec<super::Event>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn get_event(&self, _path: &super::ResourcePath) -> Result<super::Event, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn create_event(
            &self,
            _calendar: &super::ResourcePath,
            _draft: &super::EventDraft,
        ) -> Result<super::ResourcePath, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn update_event(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
            _draft: &super::EventDraft,
        ) -> Result<super::ETag, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn delete_event(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "null provider returns immediately"
    )]
    impl RemindersProvider for NullProvider {
        async fn list_lists(&self) -> Result<Vec<super::ReminderList>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn list(
            &self,
            _list: Option<&super::ResourcePath>,
            _completed: CompletedFilter,
        ) -> Result<Vec<super::Reminder>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn create(
            &self,
            _list: &super::ResourcePath,
            _draft: &super::ReminderDraft,
        ) -> Result<super::ResourcePath, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn update(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
            _draft: &super::ReminderDraft,
        ) -> Result<super::ETag, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn delete(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "null provider returns immediately"
    )]
    impl ContactsProvider for NullProvider {
        async fn search(&self, _query: &ContactQuery) -> Result<Vec<super::Contact>, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn get(&self, _path: &super::ResourcePath) -> Result<super::Contact, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn create(
            &self,
            _draft: &super::ContactDraft,
        ) -> Result<super::ResourcePath, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn update(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
            _draft: &super::ContactDraft,
        ) -> Result<super::ETag, CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn delete(
            &self,
            _path: &super::ResourcePath,
            _etag: &super::ETag,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
        async fn set_group_membership(
            &self,
            _group: &super::ResourcePath,
            _contact: &super::ResourcePath,
            _change: super::GroupChange,
        ) -> Result<(), CoreError> {
            Err(CoreError::Unsupported("null"))
        }
    }

    fn assert_mail_send<P: MailProvider + ?Sized>(provider: &P) {
        let _future = require_send(provider.list_mailboxes());
    }

    fn assert_calendar_send<P: CalendarProvider + ?Sized>(provider: &P) {
        let _future = require_send(provider.list_calendars());
    }

    fn assert_reminders_send<P: RemindersProvider + ?Sized>(provider: &P) {
        let _future = require_send(provider.list_lists());
    }

    fn assert_contacts_send<P: ContactsProvider + ?Sized>(provider: &P) {
        let query = ContactQuery {
            text: String::new(),
            limit: 1,
        };
        let _future = require_send(provider.search(&query));
    }

    #[test]
    fn provider_futures_are_send() {
        let provider = NullProvider;
        assert_mail_send(&provider);
        assert_calendar_send(&provider);
        assert_reminders_send(&provider);
        assert_contacts_send(&provider);
    }

    #[test]
    fn core_error_display_has_no_secrets() {
        let secret = "app-password-do-not-leak";
        let err = CoreError::Protocol(secret.to_owned());
        assert_eq!(err.protocol_detail(), Some(secret));
        assert!(
            !err.to_string().contains(secret),
            "display must not contain the protocol detail"
        );
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        AppleId, ETag, MailboxPath, MessageId, ResourcePath, Uid, UidValidity, decode, encode,
    };
    use crate::ids::encode_raw;

    #[test]
    fn apple_id_rejects_custom_domain_hint() {
        let err = AppleId::try_from("ada@example.com").expect_err("custom domain must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("@icloud.com") && msg.contains("@me.com") && msg.contains("@mac.com"),
            "error should hint at the primary domains, got {msg}"
        );
        assert!(AppleId::try_from("ada@icloud.com").is_ok());
        assert!(AppleId::try_from("ada@me.com").is_ok());
        assert!(AppleId::try_from("ada@mac.com").is_ok());
    }

    #[test]
    fn uid_rejects_zero() {
        assert!(Uid::try_from(0).is_err(), "zero uid must be rejected");
        assert!(
            UidValidity::try_from(0).is_err(),
            "zero uid validity must be rejected"
        );
        assert_eq!(Uid::try_from(1).expect("one").get(), 1);
        assert_eq!(UidValidity::try_from(42).expect("validity").get(), 42);
    }

    #[test]
    fn resource_path_rejects_absolute_url() {
        for url in [
            "https://caldav.icloud.com/123/calendars/a.ics",
            "http://evil.example/a",
            "https://contacts.icloud.com/1/card.vcf",
            "//caldav.icloud.com/1/a",
        ] {
            assert!(
                ResourcePath::try_from(url).is_err(),
                "{url} must be rejected"
            );
        }
        assert!(ResourcePath::try_from("calendars/home/event.ics").is_ok());
    }

    #[test]
    fn resource_path_rejects_dotdot() {
        for path in [
            "..",
            "../secret",
            "calendars/../secret",
            "calendars/../../etc/passwd",
            "foo/..",
            "%2e%2e",
            "calendars/%2e%2e/secret",
            "calendars/%2E%2E/secret",
        ] {
            assert!(
                ResourcePath::try_from(path).is_err(),
                "{path} must be rejected"
            );
        }
        assert!(ResourcePath::try_from("calendars/home/event.ics").is_ok());
    }

    proptest! {
        #[test]
        fn apple_id_roundtrip(
            local in "[a-z][a-z0-9]{0,12}",
            domain in prop_oneof![Just("icloud.com"), Just("me.com"), Just("mac.com")],
        ) {
            let address = format!("{local}@{domain}");
            let parsed = AppleId::try_from(address.as_str()).unwrap();
            prop_assert_eq!(parsed.as_str(), address.as_str());
        }

        #[test]
        fn uid_roundtrip(value in 1u32..=u32::MAX) {
            prop_assert_eq!(Uid::try_from(value).unwrap().get(), value);
            prop_assert_eq!(UidValidity::try_from(value).unwrap().get(), value);
        }

        #[test]
        fn mailbox_path_roundtrip(path in "[A-Za-z0-9][A-Za-z0-9 ]{0,31}") {
            let parsed = MailboxPath::try_from(path.as_str()).unwrap();
            prop_assert_eq!(parsed.as_str(), path.as_str());
        }

        #[test]
        fn resource_path_roundtrip(segments in prop::collection::vec("[a-z0-9]{1,8}", 1..4usize)) {
            let path = segments.join("/");
            let parsed = ResourcePath::try_from(path.as_str()).unwrap();
            prop_assert_eq!(parsed.as_str(), path.as_str());
        }

        #[test]
        fn etag_roundtrip(token in "[A-Za-z0-9]{1,16}") {
            let etag = format!("\"{token}\"");
            let parsed = ETag::try_from(etag.as_str()).unwrap();
            prop_assert_eq!(parsed.as_str(), etag.as_str());
        }

        #[test]
        fn message_id_roundtrip(
            mailbox in "[A-Za-z][A-Za-z0-9]{0,16}",
            validity in 1u32..=u32::MAX,
            uid in 1u32..=u32::MAX,
        ) {
            let id = MessageId {
                mailbox: MailboxPath::try_from(mailbox.as_str()).unwrap(),
                validity: UidValidity::try_from(validity).unwrap(),
                uid: Uid::try_from(uid).unwrap(),
            };
            let decoded = decode(&encode(&id)).unwrap();
            prop_assert_eq!(decoded, id);
        }
    }

    #[test]
    fn decode_rejects_tampered() {
        let id = MessageId {
            mailbox: MailboxPath::try_from("INBOX").expect("mailbox"),
            validity: UidValidity::try_from(9).expect("validity"),
            uid: Uid::try_from(4).expect("uid"),
        };
        let token = encode(&id);
        let mut bytes = token.into_bytes();
        let index = bytes.len() / 2;
        bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("ascii token");
        assert!(
            decode(&tampered).is_err(),
            "a flipped character must not decode"
        );
    }

    #[test]
    fn decode_rejects_url_payload() {
        let url = "https://p12-caldav.icloud.com/123/calendars/x.ics";
        assert!(decode(url).is_err(), "a raw URL is not an id");
        let crafted = encode_raw(url, 7, 9);
        assert!(
            decode(&crafted).is_err(),
            "a length-prefixed URL payload must not decode"
        );
    }
}
