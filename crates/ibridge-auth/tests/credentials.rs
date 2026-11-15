// SPDX-License-Identifier: Apache-2.0

//! Credentials and the host allowlist.

use ibridge_auth::{Credentials, is_allowed_host};
use ibridge_core::AppleId;

#[test]
fn credentials_debug_is_redacted() {
    let secret = "app-password-do-not-leak";
    let credentials = Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        secret,
    );
    assert_eq!(credentials.with_secret(str::to_owned), secret);
    let rendered = format!("{credentials:?}");
    assert!(
        !rendered.contains(secret),
        "debug must not show the secret, rendered {rendered}"
    );
}

#[test]
fn credentials_not_serializable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/credentials_not_serializable.rs");
}

#[test]
fn allowed_hosts() {
    for host in [
        "imap.mail.me.com",
        "smtp.mail.me.com",
        "caldav.icloud.com",
        "contacts.icloud.com",
        "p12-caldav.icloud.com",
        "p12-contacts.icloud.com",
        "IMAP.MAIL.ME.COM",
        "imap.mail.me.com:443",
        "p7-caldav.icloud.com:443",
    ] {
        assert!(
            is_allowed_host(host),
            "{host} is an iCloud host on port 443"
        );
    }
    for host in [
        "example.com",
        "imap.mail.me.com:993",
        "imap.mail.me.com.evil.com",
        "https://imap.mail.me.com",
        "user@imap.mail.me.com",
        "imap.mail.me.com.",
        "p-caldav.icloud.com",
        "px-caldav.icloud.com",
        "caldav.icloud.com:80",
        "",
    ] {
        assert!(!is_allowed_host(host), "{host} is not an allowlisted host");
    }
}
