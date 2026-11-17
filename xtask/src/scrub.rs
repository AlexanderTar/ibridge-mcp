// SPDX-License-Identifier: Apache-2.0

//! Removes account identifiers from recorded fixtures.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{NoExpand, Regex};

const MESSAGE_ID: &str = "msg";
const MESSAGE_ID_HOST: &str = "scrub.invalid";
const APPLE_ID: &str = "user@example.com";
const DSID: &str = "0000000000";
const NAME: &str = "Test User";

/// Headers whose values are Message-IDs.
const ID_HEADERS: [&str; 4] = [
    "message-id",
    "in-reply-to",
    "references",
    "resent-message-id",
];

/// Headers a relay adds on the way. They hold the sender's address, hostnames,
/// queue ids and opaque per-account tokens, so they are dropped rather than edited.
const TRACE_HEADERS: [&str; 15] = [
    "received",
    "x-originating-ip",
    "authentication-results",
    "received-spf",
    "arc-authentication-results",
    "x-apple-originating-ip",
    "dkim-signature",
    "original-recipient",
    "x-apple-uuid",
    "x-icl-repid",
    "x-apple-movetofolder",
    "x-apple-action",
    "x-mantsh",
    "x-jnj",
    "x-authority-info-out",
];

/// Header families that vary from message to message (Proofpoint scores, Cloudmark flags).
const TRACE_PREFIXES: [&str; 2] = ["x-proofpoint-", "x-clx-"];
const IPV4: &str = "192.0.2.1";
const IPV6: &str = "2001:db8::1";

static ID_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^<>\s@]+@[^<>\s]+>").expect("message id pattern"));
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "<{MESSAGE_ID}-([0-9]+)@{}>",
        regex::escape(MESSAGE_ID_HOST)
    ))
    .expect("placeholder pattern")
});
static IPV4_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("ipv4 pattern"));
// ponytail: "::" followed by hex also matches in prose such as `std::add`; recorded
// marker mails hold no such text. Tighten this if a fixture ever does.
static IPV6_ADDR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b",
        r"|\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?",
        r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})",
    ))
    .expect("ipv6 pattern")
});
static SHARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bp[0-9]+-([a-z]+)\.icloud\.com").expect("shard pattern"));
static DSID_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/[0-9]{8,}/").expect("dsid path pattern"));
static DSID_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(dsid[=: ]+)[0-9]{6,}").expect("dsid label pattern"));

/// What to remove from a recording. Each value is the account's own.
#[derive(Clone, Debug, Default)]
pub(crate) struct Identity {
    /// The Apple ID, which is also the mailbox address.
    pub(crate) apple_id: String,
    /// The account's numeric DSID, when known.
    pub(crate) dsid: Option<String>,
    /// Display names of people on the account.
    pub(crate) names: Vec<String>,
}

/// Who named a mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MailboxKind {
    /// A special-use mailbox such as Trash: the server's own name.
    SpecialUse,
    /// A folder someone on the account made.
    User,
}

/// Scrubs recordings. One scrubber numbers Message-IDs across every recording
/// it sees, so reply threads keep pointing at the same placeholder.
#[derive(Debug)]
pub(crate) struct Scrubber {
    identity: Identity,
    ids: HashMap<String, String>,
    folders: HashMap<String, String>,
    /// The highest placeholder number handed out or seen in the input.
    highest: usize,
}

impl Scrubber {
    pub(crate) fn new(identity: Identity) -> Self {
        Self {
            identity,
            ids: HashMap::new(),
            folders: HashMap::new(),
            highest: 0,
        }
    }

    /// Returns `text` with the account's identifiers replaced. Scrubbing the
    /// result again changes nothing.
    pub(crate) fn scrub(&mut self, text: &str) -> String {
        let mut out = self.scrub_message_ids(text);
        for (needle, with) in self.literals() {
            out = replace_ignore_case(&out, &needle, with);
        }
        let out = DSID_PATH.replace_all(&out, NoExpand(&format!("/{DSID}/")));
        let out = DSID_LABEL.replace_all(&out, format!("${{1}}{DSID}"));
        let out = IPV4_ADDR.replace_all(&out, NoExpand(IPV4));
        let out = IPV6_ADDR.replace_all(&out, NoExpand(IPV6));
        SHARD.replace_all(&out, "p00-$1.icloud.com").into_owned()
    }

    /// Literals to replace, longest first so a full name goes before its parts.
    fn literals(&self) -> Vec<(String, &'static str)> {
        let mut literals: Vec<(String, &'static str)> = self
            .identity
            .names
            .iter()
            .map(|name| (name.clone(), NAME))
            .collect();
        literals.push((self.identity.apple_id.clone(), APPLE_ID));
        if let Some(dsid) = &self.identity.dsid {
            literals.push((dsid.clone(), DSID));
        }
        literals.retain(|(needle, _)| !needle.is_empty());
        literals.sort_by_key(|(needle, _)| std::cmp::Reverse(needle.len()));
        literals
    }

    /// Replaces Message-IDs and drops trace headers, in header lines only. A body
    /// or address line that happens to contain `<a@b>` is left to the other rules.
    fn scrub_message_ids(&mut self, text: &str) -> String {
        for found in PLACEHOLDER.captures_iter(text) {
            if let Ok(number) = found[1].parse::<usize>() {
                self.highest = self.highest.max(number);
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut in_headers = true;
        let mut id_header = false;
        let mut trace_header = false;
        for line in text.split_inclusive('\n') {
            if in_headers && line.trim_end_matches(['\r', '\n']).is_empty() {
                in_headers = false;
            }
            if in_headers && !line.starts_with([' ', '\t']) {
                let name = line
                    .split_once(':')
                    .map(|(name, _)| name.trim().to_ascii_lowercase());
                id_header = name
                    .as_deref()
                    .is_some_and(|name| ID_HEADERS.contains(&name));
                trace_header = name.as_deref().is_some_and(|name| {
                    TRACE_HEADERS.contains(&name)
                        || TRACE_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
                });
            }
            if in_headers && trace_header {
                continue;
            }
            if in_headers && id_header {
                let replaced = ID_TOKEN.replace_all(line, |found: &regex::Captures<'_>| {
                    self.placeholder(&found[0])
                });
                out.push_str(&replaced);
            } else {
                out.push_str(line);
            }
        }
        out
    }

    /// The name to record for a mailbox. INBOX and special-use mailboxes (Apple's
    /// own names) are kept; a folder the user made becomes `Folder-N`, since its
    /// name may say who or what the account is about.
    pub(crate) fn mailbox_name(&mut self, name: &str, kind: MailboxKind) -> String {
        if kind == MailboxKind::SpecialUse || name.eq_ignore_ascii_case("INBOX") {
            return self.scrub(name);
        }
        let next = self.folders.len() + 1;
        self.folders
            .entry(name.to_owned())
            .or_insert_with(|| format!("Folder-{next}"))
            .clone()
    }

    fn placeholder(&mut self, id: &str) -> String {
        if id.ends_with(&format!("@{MESSAGE_ID_HOST}>")) {
            return id.to_owned();
        }
        if let Some(known) = self.ids.get(id) {
            return known.clone();
        }
        self.highest += 1;
        let placeholder = format!("<{MESSAGE_ID}-{}@{MESSAGE_ID_HOST}>", self.highest);
        self.ids.insert(id.to_owned(), placeholder.clone());
        placeholder
    }
}

fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    let pattern = Regex::new(&format!("(?i){}", regex::escape(needle))).expect("escaped literal");
    pattern.replace_all(text, NoExpand(with)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{Identity, MailboxKind, Scrubber};

    const RECORDING: &str = "\
Received: from [192.168.1.20] (unknown [203.0.113.77])\r\n\
\tby relay-17.mr.icloud.com with ESMTPSA id 9f8e7d\r\n\
\tfor <ada.lovelace@icloud.com>; Wed, 4 Nov 2026 12:30:45 +0000\r\n\
X-Originating-IP: [2001:db8:85a3::8a2e:370:7334]\r\n\
Dkim-Signature: v=1; d=icloud.com; b=opaque\r\n\
X-Apple-UUID: 3e53b733\r\n\
X-Proofpoint-Spam-Info: proofpointtoken\r\n\
X-CLX-Spam: false\r\n\
X-JNJ: opaquetoken\r\n\
\tcontinued\r\n\
Date: Wed, 4 Nov 2026 12:30:45 +0000\r\n\
Message-ID: <aaa111@mail.icloud.com>\r\n\
In-Reply-To: <bbb222@mail.icloud.com>\r\n\
References: <bbb222@mail.icloud.com> <aaa111@mail.icloud.com>\r\n\
From: \"Ada Lovelace\" <ada.lovelace@icloud.com>\r\n\
To: Ada Lovelace <ada.lovelace@icloud.com>\r\n\
Subject: [ibridge-fixture] one\r\n\
\r\n\
Hello Ada Lovelace, this is ada.lovelace@icloud.com.\r\n\
PROPFIND https://p57-caldav.icloud.com:443/12345678901/principal/\r\n\
Also https://p09-contacts.icloud.com/12345678901/carddavhome/\r\n\
dsid 12345678901\r\n";

    fn identity() -> Identity {
        Identity {
            apple_id: "ada.lovelace@icloud.com".to_owned(),
            dsid: Some("12345678901".to_owned()),
            names: vec!["Ada Lovelace".to_owned()],
        }
    }

    #[test]
    fn scrub_replaces_identifiers() {
        let scrubbed = Scrubber::new(identity()).scrub(RECORDING);

        for leaked in [
            "ada.lovelace@icloud.com",
            "Ada Lovelace",
            "12345678901",
            "p57-",
            "p09-",
            "aaa111",
            "bbb222",
            "Dkim-Signature",
            "X-Apple-UUID",
            "opaquetoken",
            "proofpointtoken",
            "X-CLX-Spam",
            "continued",
        ] {
            assert!(
                !scrubbed.contains(leaked),
                "{leaked} survived the scrub:\n{scrubbed}"
            );
        }
        for leaked in [
            "203.0.113.77",
            "2001:db8:85a3::8a2e:370:7334",
            "relay-17.mr.icloud.com",
        ] {
            assert!(
                !scrubbed.contains(leaked),
                "{leaked} survived the scrub:\n{scrubbed}"
            );
        }
        assert!(
            scrubbed.contains("Date: Wed, 4 Nov 2026 12:30:45 +0000"),
            "a clock time is not an IPv6 address:\n{scrubbed}"
        );
        assert!(
            scrubbed.contains("p00-caldav.icloud.com")
                && scrubbed.contains("p00-contacts.icloud.com"),
            "shard numbers become p00, hosts stay recognisable:\n{scrubbed}"
        );
        let header = |name: &str| {
            scrubbed
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} header missing:\n{scrubbed}"))
        };
        let own = header("Message-ID: ");
        let parent = header("In-Reply-To: ");
        assert_ne!(own, parent, "two Message-IDs stay two placeholders");
        assert_eq!(
            header("References: "),
            format!("{parent} {own}"),
            "a reference points at the same placeholder as the header it came from"
        );
    }

    #[test]
    fn scrub_is_idempotent() {
        let once = Scrubber::new(identity()).scrub(RECORDING);
        let twice = Scrubber::new(identity()).scrub(&once);

        assert_ne!(
            once, RECORDING,
            "the first scrub must have scrubbed something"
        );

        assert_eq!(twice, once, "a second scrub must change nothing");
    }

    #[test]
    fn scrub_does_not_reuse_existing_placeholders() {
        let partly = "\
Message-ID: <msg-1@scrub.invalid>\r\n\
In-Reply-To: <fresh999@mail.icloud.com>\r\n\
\r\n";
        let scrubbed = Scrubber::new(identity()).scrub(partly);

        assert!(!scrubbed.contains("fresh999"), "{scrubbed}");
        assert!(
            scrubbed.contains("Message-ID: <msg-1@scrub.invalid>"),
            "an existing placeholder is kept:\n{scrubbed}"
        );
        assert!(
            scrubbed.contains("In-Reply-To: <msg-2@scrub.invalid>"),
            "a new id numbers past the existing placeholder:\n{scrubbed}"
        );
        assert_eq!(Scrubber::new(identity()).scrub(&scrubbed), scrubbed);
    }

    #[test]
    fn scrub_covers_list_and_capability() {
        let mut scrubber = Scrubber::new(identity());

        assert_eq!(scrubber.mailbox_name("INBOX", MailboxKind::User), "INBOX");
        assert_eq!(
            scrubber.mailbox_name("Deleted Messages", MailboxKind::SpecialUse),
            "Deleted Messages",
            "special-use names are Apple's own"
        );
        assert_eq!(
            scrubber.mailbox_name("Ada Lovelace taxes", MailboxKind::User),
            "Folder-1",
            "a user folder is numbered, not copied"
        );
        assert_eq!(
            scrubber.mailbox_name("Other", MailboxKind::User),
            "Folder-2"
        );
        assert_eq!(
            scrubber.mailbox_name("Ada Lovelace taxes", MailboxKind::User),
            "Folder-1",
            "the same folder keeps its number"
        );
        assert_eq!(
            scrubber.mailbox_name("Ada Lovelace", MailboxKind::SpecialUse),
            "Test User",
            "a special-use name still goes through the identity rules"
        );
    }
}
