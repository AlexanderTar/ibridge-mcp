// SPDX-License-Identifier: Apache-2.0

//! Domain newtypes, provider traits and the core error type.

mod account;
mod error;
mod ids;
mod mail;

pub use account::AppleId;
pub use error::ParseError;
pub use ids::{ETag, ResourcePath};
pub use mail::{MailboxPath, Uid, UidValidity};

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{AppleId, ETag, MailboxPath, ResourcePath, Uid, UidValidity};

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
    }
}
