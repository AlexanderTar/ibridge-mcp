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

static ID_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^<>\s@]+@[^<>\s]+>").expect("message id pattern"));
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

/// Scrubs recordings. One scrubber numbers Message-IDs across every recording
/// it sees, so reply threads keep pointing at the same placeholder.
#[derive(Debug)]
pub(crate) struct Scrubber {
    identity: Identity,
    ids: HashMap<String, String>,
}

impl Scrubber {
    pub(crate) fn new(identity: Identity) -> Self {
        Self {
            identity,
            ids: HashMap::new(),
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

    /// Replaces Message-IDs in header lines only. A body or address line that
    /// happens to contain `<a@b>` is left to the other rules.
    fn scrub_message_ids(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut in_headers = true;
        let mut id_header = false;
        for line in text.split_inclusive('\n') {
            if in_headers && line.trim_end_matches(['\r', '\n']).is_empty() {
                in_headers = false;
            }
            if in_headers && !line.starts_with([' ', '\t']) {
                id_header = line.split_once(':').is_some_and(|(name, _)| {
                    ID_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())
                });
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

    fn placeholder(&mut self, id: &str) -> String {
        if id.ends_with(&format!("@{MESSAGE_ID_HOST}>")) {
            return id.to_owned();
        }
        let next = self.ids.len() + 1;
        self.ids
            .entry(id.to_owned())
            .or_insert_with(|| format!("<{MESSAGE_ID}-{next}@{MESSAGE_ID_HOST}>"))
            .clone()
    }
}

fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    let pattern = Regex::new(&format!("(?i){}", regex::escape(needle))).expect("escaped literal");
    pattern.replace_all(text, NoExpand(with)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{Identity, Scrubber};

    const RECORDING: &str = "\
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
        ] {
            assert!(
                !scrubbed.contains(leaked),
                "{leaked} survived the scrub:\n{scrubbed}"
            );
        }
        assert!(
            scrubbed.contains("p00-caldav.icloud.com")
                && scrubbed.contains("p00-contacts.icloud.com"),
            "shard numbers become p00, hosts stay recognisable:\n{scrubbed}"
        );
        let lines: Vec<&str> = scrubbed.lines().collect();
        let own = lines[0].trim_start_matches("Message-ID: ");
        let parent = lines[1].trim_start_matches("In-Reply-To: ");
        assert_ne!(own, parent, "two Message-IDs stay two placeholders");
        assert_eq!(
            lines[2],
            format!("References: {parent} {own}"),
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
}
