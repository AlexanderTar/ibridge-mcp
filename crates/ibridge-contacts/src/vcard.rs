// SPDX-License-Identifier: Apache-2.0

//! vCard 3.0 text: reading cards and editing them in place.
//!
//! An edit never re-serialises the card. It keeps every property line it does
//! not touch exactly as the server sent it, folds and `item1.` groups included,
//! and replaces, drops or appends only the properties the draft changes.
//! calcard reads the card and checks both the input and the result.

use std::collections::BTreeSet;

use calcard::vcard::{VCard, VCardEntry, VCardParameterName, VCardProperty, VCardValue};
use ibridge_core::{ContactDraft, CoreError, LabeledValue};

/// Longest full name, in characters.
const MAX_NAME: usize = 200;
/// Most emails or phone numbers on one card.
const MAX_VALUES: usize = 50;
/// Longest email address or phone number, in characters.
const MAX_VALUE: usize = 254;
/// Longest line before folding, in bytes.
const FOLD_AT: usize = 75;

/// Parses a vCard. `None` when the text is not one.
pub(crate) fn parse(text: &str) -> Option<VCard> {
    VCard::parse(text).ok()
}

/// The values the contacts tools show for a card.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fields {
    pub(crate) uid: Option<String>,
    pub(crate) full_name: String,
    pub(crate) emails: Vec<LabeledValue>,
    pub(crate) phones: Vec<LabeledValue>,
    pub(crate) organization: Option<String>,
    pub(crate) note: Option<String>,
    /// The card is a group: it lists members and is not a person.
    pub(crate) is_group: bool,
    /// `UID`s of a group's members.
    pub(crate) members: Vec<String>,
}

/// Reads the shown values out of a parsed card.
pub(crate) fn read(card: &VCard) -> Fields {
    let text_of = |entry: &VCardEntry| {
        entry
            .values
            .first()
            .and_then(VCardValue::as_text)
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    let texts = |property: &VCardProperty| -> Vec<String> {
        card.properties(property).filter_map(text_of).collect()
    };
    let labeled = |property: &VCardProperty| -> Vec<LabeledValue> {
        card.properties(property)
            .filter_map(|entry| {
                Some(LabeledValue {
                    value: text_of(entry)?,
                    label: label_of(card, entry),
                })
            })
            .collect()
    };
    let other = |name: &str| -> Vec<&VCardEntry> {
        card.entries
            .iter()
            .filter(|entry| matches!(&entry.name, VCardProperty::Other(n) if n.eq_ignore_ascii_case(name)))
            .collect()
    };
    let organization = texts(&VCardProperty::Org).into_iter().next();
    let emails = labeled(&VCardProperty::Email);
    let full_name = texts(&VCardProperty::Fn)
        .into_iter()
        .next()
        .or_else(|| name_from_n(card))
        .or_else(|| organization.clone())
        .or_else(|| emails.first().map(|email| email.value.clone()))
        .unwrap_or_default();
    let is_group = card
        .properties(&VCardProperty::Kind)
        .chain(other("X-ADDRESSBOOKSERVER-KIND"))
        .filter_map(text_of)
        .any(|kind| kind.eq_ignore_ascii_case("group"));
    let members = card
        .properties(&VCardProperty::Member)
        .chain(other("X-ADDRESSBOOKSERVER-MEMBER"))
        .filter_map(text_of)
        .map(|member| {
            member
                .strip_prefix("urn:uuid:")
                .unwrap_or(&member)
                .to_owned()
        })
        .collect();
    Fields {
        uid: card.uid().map(str::to_owned),
        full_name,
        emails,
        phones: labeled(&VCardProperty::Tel),
        organization,
        note: texts(&VCardProperty::Note).into_iter().next(),
        is_group,
        members,
    }
}

/// The label of a value: the `itemN.X-ABLabel` of its group, else its `TYPE`.
fn label_of(card: &VCard, entry: &VCardEntry) -> Option<String> {
    let from_group = entry.group.as_ref().and_then(|group| {
        card.entries
            .iter()
            .filter(|other| other.group.as_ref() == Some(group))
            .filter(|other| {
                matches!(&other.name, VCardProperty::Other(n) if n.eq_ignore_ascii_case("X-ABLabel"))
            })
            .find_map(|other| other.values.first().and_then(VCardValue::as_text))
    });
    if let Some(label) = from_group {
        let label = label
            .trim()
            .trim_start_matches("_$!<")
            .trim_end_matches(">!$_")
            .trim();
        if !label.is_empty() {
            return Some(label.to_owned());
        }
    }
    entry
        .params
        .iter()
        .filter(|param| param.name == VCardParameterName::Type)
        .filter_map(|param| param.value.as_text())
        .find(|kind| !["voice", "pref", "internet"].contains(&kind.to_ascii_lowercase().as_str()))
        .map(|kind| {
            let mut chars = kind.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
}

/// `given family` from the structured name, for a card that has no `FN`.
fn name_from_n(card: &VCard) -> Option<String> {
    let parts = match card.property(&VCardProperty::N)?.values.first()? {
        VCardValue::Component(parts) => parts.clone(),
        VCardValue::Text(text) => vec![text.clone()],
        _ => return None,
    };
    let name = [parts.get(1), parts.first()]
        .into_iter()
        .flatten()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!name.is_empty()).then_some(name)
}

/// A new vCard 3.0 for `draft`. Always carries `N` and `FN`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] when the draft cannot be written.
pub(crate) fn new_card_text(uid: &str, draft: &ContactDraft) -> Result<String, CoreError> {
    let draft = checked(draft)?;
    let mut lines = vec![
        "BEGIN:VCARD".to_owned(),
        "VERSION:3.0".to_owned(),
        "PRODID:-//ibridge//contacts//EN".to_owned(),
        format!("UID:{uid}"),
        n_line(&draft.name),
        fn_line(&draft.name),
    ];
    lines.extend(draft.emails.iter().map(|email| email_line(email)));
    lines.extend(draft.phones.iter().map(|phone| phone_line(phone)));
    lines.push("END:VCARD".to_owned());
    let text: String = lines.iter().map(|line| fold(line, "\r\n")).collect();
    parse(&text).ok_or_else(|| CoreError::Protocol(String::new()))?;
    Ok(text)
}

/// `existing` with the draft's changes applied and everything else untouched.
///
/// # Errors
///
/// Returns [`CoreError::InvalidInput`] when the draft cannot be written and
/// [`CoreError::Protocol`] when `existing` is not a vCard.
pub(crate) fn update_card_text(existing: &str, draft: &ContactDraft) -> Result<String, CoreError> {
    let draft = checked(draft)?;
    let current = read(&parse(existing).ok_or_else(|| CoreError::Protocol(String::new()))?);
    let eol = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut props = split(existing);
    if draft.name != current.full_name {
        replace_or_insert(&mut props, "FN", fold(&fn_line(&draft.name), eol));
        replace_or_insert(&mut props, "N", fold(&n_line(&draft.name), eol));
    }
    reconcile(&mut props, "EMAIL", &draft.emails, &email_line, eol, |v| {
        v.to_ascii_lowercase()
    });
    reconcile(
        &mut props,
        "TEL",
        &draft.phones,
        &phone_line,
        eol,
        str::to_owned,
    );
    let text: String = props.iter().map(|prop| prop.raw.as_str()).collect();
    parse(&text).ok_or_else(|| CoreError::Protocol(String::new()))?;
    Ok(text)
}

/// A draft that passed the checks, with its text trimmed.
struct Checked {
    name: String,
    emails: Vec<String>,
    phones: Vec<String>,
}

fn checked(draft: &ContactDraft) -> Result<Checked, CoreError> {
    let invalid = |what: &str| CoreError::InvalidInput(what.to_owned());
    let clean = |text: &str, what: &str, max: usize| -> Result<String, CoreError> {
        let text = text.trim();
        if text.is_empty() || text.chars().count() > max {
            return Err(invalid(&format!("{what} is empty or too long")));
        }
        if text.chars().any(char::is_control) {
            return Err(invalid(&format!(
                "{what} has a control character or line break"
            )));
        }
        Ok(text.to_owned())
    };
    let many = |values: &[String], what: &str| -> Result<Vec<String>, CoreError> {
        if values.len() > MAX_VALUES {
            return Err(invalid(&format!("too many {what}")));
        }
        let mut seen = BTreeSet::new();
        let mut kept = Vec::new();
        for value in values {
            let value = clean(value, what, MAX_VALUE)?;
            if seen.insert(value.to_ascii_lowercase()) {
                kept.push(value);
            }
        }
        Ok(kept)
    };
    Ok(Checked {
        name: clean(&draft.full_name, "the name", MAX_NAME)?,
        emails: many(&draft.emails, "email addresses")?,
        phones: many(&draft.phones, "phone numbers")?,
    })
}

/// One property of the card: its lines exactly as sent, and what it is.
pub(crate) struct Prop {
    pub(crate) raw: String,
    group: Option<String>,
    /// Upper case, without the group.
    pub(crate) name: String,
    /// Unfolded and not unescaped.
    pub(crate) value: String,
}

/// Splits `text` into properties. A folded property keeps all its lines.
pub(crate) fn split(text: &str) -> Vec<Prop> {
    let mut props: Vec<Prop> = Vec::new();
    for line in text.split_inclusive('\n') {
        let folded = line.starts_with([' ', '\t']);
        match props.last_mut() {
            Some(last) if folded => {
                last.raw.push_str(line);
                last.value
                    .push_str(line[1..].trim_end_matches(['\r', '\n']));
            }
            _ => props.push(prop_of(line)),
        }
    }
    props
}

pub(crate) fn prop_of(line: &str) -> Prop {
    let content = line.trim_end_matches(['\r', '\n']);
    let mut in_quotes = false;
    let colon = content.char_indices().find_map(|(index, ch)| {
        match ch {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => return Some(index),
            _ => {}
        }
        None
    });
    let (header, value) = colon.map_or((content, ""), |at| (&content[..at], &content[at + 1..]));
    let head = header.split(';').next().unwrap_or_default();
    let (group, name) = head
        .rsplit_once('.')
        .map_or((None, head), |(group, name)| (Some(group.to_owned()), name));
    Prop {
        raw: line.to_owned(),
        group,
        name: name.to_ascii_uppercase(),
        value: value.to_owned(),
    }
}

/// The line ending `text` uses.
pub(crate) fn eol_of(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

/// Swaps the first `name` property for `line`, or adds it before `END`.
fn replace_or_insert(props: &mut Vec<Prop>, name: &str, line: String) {
    let fresh = prop_of(&line);
    match props.iter().position(|prop| prop.name == name) {
        Some(at) => props[at] = fresh,
        None => insert_before_end(props, fresh),
    }
}

pub(crate) fn insert_before_end(props: &mut Vec<Prop>, fresh: Prop) {
    let end = props.iter().rposition(|prop| prop.name == "END");
    props.insert(end.unwrap_or(props.len()), fresh);
}

/// Makes the `name` properties carry exactly `wanted`: a property whose value
/// is still wanted stays as sent, the others go (with their `itemN.` label
/// lines), and new values are appended.
fn reconcile(
    props: &mut Vec<Prop>,
    name: &str,
    wanted: &[String],
    make: &dyn Fn(&str) -> String,
    eol: &str,
    normal: impl Fn(&str) -> String,
) {
    let wanted_keys: Vec<String> = wanted.iter().map(|value| normal(value)).collect();
    let mut present = BTreeSet::new();
    let mut dropped_groups = BTreeSet::new();
    props.retain(|prop| {
        if prop.name != name {
            return true;
        }
        let key = normal(prop.value.trim());
        if wanted_keys.contains(&key) {
            present.insert(key);
            return true;
        }
        if let Some(group) = &prop.group {
            dropped_groups.insert(group.clone());
        }
        false
    });
    // A label line goes only when nothing else of its group is left.
    for group in dropped_groups {
        let in_use = props
            .iter()
            .any(|prop| prop.group.as_ref() == Some(&group) && prop.name != "X-ABLABEL");
        if !in_use {
            props.retain(|prop| prop.group.as_ref() != Some(&group));
        }
    }
    for (value, key) in wanted.iter().zip(&wanted_keys) {
        if !present.contains(key) {
            insert_before_end(props, prop_of(&fold(&make(value), eol)));
        }
    }
}

fn fn_line(name: &str) -> String {
    format!("FN:{}", escape(name))
}

/// `N` from a full name: the last word is the family name, the rest the given names.
fn n_line(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    match words.split_last() {
        Some((family, given)) if !given.is_empty() => {
            format!("N:{};{};;;", escape(family), escape(&given.join(" ")))
        }
        _ => format!("N:;{};;;", escape(name)),
    }
}

fn email_line(email: &str) -> String {
    format!("EMAIL;TYPE=INTERNET:{email}")
}

fn phone_line(phone: &str) -> String {
    format!("TEL;TYPE=VOICE:{phone}")
}

/// Escapes text for a vCard 3.0 value.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '\\' | ',' | ';') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `line` folded at [`FOLD_AT`] bytes, ending in `eol`.
pub(crate) fn fold(line: &str, eol: &str) -> String {
    let mut out = String::with_capacity(line.len() + eol.len());
    let mut width = 0;
    for ch in line.chars() {
        if width + ch.len_utf8() > FOLD_AT {
            out.push_str(eol);
            out.push(' ');
            width = 1;
        }
        out.push(ch);
        width += ch.len_utf8();
    }
    out.push_str(eol);
    out
}

#[cfg(test)]
mod tests {
    use ibridge_core::ContactDraft;
    use proptest::prelude::*;

    use super::{new_card_text, parse, read, update_card_text};

    /// An iPhone-style card: groups, a label, a photo, a long unknown property
    /// folded over two lines, and Apple's own fields.
    const APPLE: &str = "BEGIN:VCARD\r\n\
        VERSION:3.0\r\n\
        PRODID:-//Apple Inc.//iPhone OS 26.0//EN\r\n\
        N:Lovelace;Ada;;;\r\n\
        FN:Ada Lovelace\r\n\
        ORG:Analytical Engines;\r\n\
        item1.EMAIL;type=INTERNET;type=pref:ada@example.com\r\n\
        item1.X-ABLabel:_$!<Home>!$_\r\n\
        item2.URL;type=pref:https://example.com/ada\r\n\
        item2.X-ABLabel:Blog\r\n\
        TEL;type=CELL;type=VOICE;type=pref:+1 555 0100\r\n\
        X-ABUID:5C1E6B6A-0000-4000-8000-000000000001:ABPerson\r\n\
        X-IBR-LONG:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n \
        bbbbbbbb\r\n\
        PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQ\r\n \
        oHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT\r\n\
        UID:5C1E6B6A-0000-4000-8000-000000000001\r\n\
        END:VCARD\r\n";

    /// The property lines of [`APPLE`] that no edit below touches.
    const UNTOUCHED: [&str; 9] = [
        "PRODID:-//Apple Inc.//iPhone OS 26.0//EN\r\n",
        "ORG:Analytical Engines;\r\n",
        "item2.URL;type=pref:https://example.com/ada\r\nitem2.X-ABLabel:Blog\r\n",
        "TEL;type=CELL;type=VOICE;type=pref:+1 555 0100\r\n",
        "X-ABUID:5C1E6B6A-0000-4000-8000-000000000001:ABPerson\r\n",
        "X-IBR-LONG:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n bbbbbbbb\r\n",
        "PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQ\r\n oHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT\r\n",
        "UID:5C1E6B6A-0000-4000-8000-000000000001\r\n",
        "VERSION:3.0\r\n",
    ];

    fn values(items: &[ibridge_core::LabeledValue]) -> Vec<String> {
        items.iter().map(|item| item.value.clone()).collect()
    }

    fn draft(name: &str, emails: &[&str], phones: &[&str]) -> ContactDraft {
        ContactDraft {
            full_name: name.to_owned(),
            emails: emails.iter().map(|e| (*e).to_owned()).collect(),
            phones: phones.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn edit_preserves_unknown_and_grouped_props() {
        // The name changes, one email is added and the existing one stays.
        let edited = update_card_text(
            APPLE,
            &draft(
                "Ada King",
                &["ada@example.com", "countess@example.org"],
                &["+1 555 0100"],
            ),
        )
        .expect("update applies");
        for kept in UNTOUCHED {
            assert!(edited.contains(kept), "lost {kept:?} in {edited:?}");
        }
        // The kept email keeps its group and its label, byte for byte.
        assert!(
            edited.contains(
                "item1.EMAIL;type=INTERNET;type=pref:ada@example.com\r\n\
                 item1.X-ABLabel:_$!<Home>!$_\r\n"
            ),
            "{edited:?}"
        );
        assert!(edited.contains("FN:Ada King\r\n"), "{edited:?}");
        assert!(edited.contains("N:King;Ada;;;\r\n"), "{edited:?}");
        assert!(!edited.contains("Lovelace"), "{edited:?}");
        assert!(edited.contains("countess@example.org"), "{edited:?}");
        assert!(edited.ends_with("END:VCARD\r\n"), "{edited:?}");
    }

    #[test]
    fn edit_with_the_same_values_changes_nothing() {
        let same = update_card_text(
            APPLE,
            &draft("Ada Lovelace", &["ada@example.com"], &["+1 555 0100"]),
        )
        .expect("update applies");
        assert_eq!(same, APPLE);
    }

    #[test]
    fn dropping_an_email_drops_its_group_label_and_nothing_else() {
        let edited = update_card_text(APPLE, &draft("Ada Lovelace", &[], &["+1 555 0100"]))
            .expect("update applies");
        assert!(!edited.contains("ada@example.com"), "{edited:?}");
        assert!(!edited.contains("item1."), "{edited:?}");
        assert!(
            edited.contains(
                "item2.URL;type=pref:https://example.com/ada\r\nitem2.X-ABLabel:Blog\r\n"
            ),
            "{edited:?}"
        );
        assert!(edited.contains("N:Lovelace;Ada;;;\r\n"), "{edited:?}");
    }

    #[test]
    fn create_writes_vcard30_with_n() {
        let text = new_card_text(
            "uid-1",
            &draft("Grace Hopper", &["grace@example.com"], &["+1 555 0101"]),
        )
        .expect("create");
        assert!(
            text.starts_with("BEGIN:VCARD\r\nVERSION:3.0\r\n"),
            "{text:?}"
        );
        assert!(text.contains("\r\nUID:uid-1\r\n"), "{text:?}");
        assert!(text.contains("\r\nFN:Grace Hopper\r\n"), "{text:?}");
        assert!(text.contains("\r\nN:Hopper;Grace;;;\r\n"), "{text:?}");
        assert!(
            text.contains("EMAIL;TYPE=INTERNET:grace@example.com\r\n"),
            "{text:?}"
        );
        assert!(text.contains("TEL;TYPE=VOICE:+1 555 0101\r\n"), "{text:?}");
        assert!(text.ends_with("END:VCARD\r\n"), "{text:?}");
        let card = parse(&text).expect("calcard reads what we wrote");
        let fields = read(&card);
        assert_eq!(fields.full_name, "Grace Hopper");
        assert_eq!(values(&fields.emails), ["grace@example.com"]);
        assert_eq!(values(&fields.phones), ["+1 555 0101"]);
    }

    #[test]
    fn a_single_word_name_still_gets_an_n() {
        let text = new_card_text("uid-2", &draft("Madonna", &[], &[])).expect("create");
        assert!(text.contains("\r\nN:;Madonna;;;\r\n"), "{text:?}");
    }

    #[test]
    fn a_name_with_separators_is_escaped() {
        let text = new_card_text("uid-3", &draft("Smith, John; Jr", &[], &[])).expect("create");
        assert!(text.contains("\r\nFN:Smith\\, John\\; Jr\r\n"), "{text:?}");
        let fields = read(&parse(&text).expect("parses"));
        assert_eq!(fields.full_name, "Smith, John; Jr");
    }

    #[test]
    fn a_draft_with_a_line_break_or_no_name_is_refused() {
        for bad in [
            draft("", &[], &[]),
            draft("Ada\r\nEND:VCARD", &[], &[]),
            draft("Ada", &["a@example.com\r\nX-EVIL:1"], &[]),
            draft("Ada", &[], &["555\nX-EVIL:1"]),
        ] {
            assert!(
                matches!(
                    new_card_text("u", &bad),
                    Err(ibridge_core::CoreError::InvalidInput(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_vcard_is_a_protocol_error() {
        let result = update_card_text("hello", &draft("Ada", &[], &[]));
        assert!(
            matches!(result, Err(ibridge_core::CoreError::Protocol(_))),
            "{result:?}"
        );
    }

    proptest! {
        #[test]
        fn vcard_roundtrip(
            given in "[A-Za-z]{1,10}",
            family in "[A-Za-z]{1,10}",
            emails in proptest::collection::btree_set("[a-z]{1,8}@[a-z]{1,8}\\.com", 0..4),
            phones in proptest::collection::btree_set("\\+[0-9]{6,12}", 0..4),
            later_phones in proptest::collection::btree_set("\\+[0-9]{6,12}", 0..4),
            unknown in "[A-Za-z0-9 ]{1,30}",
        ) {
            let name = format!("{given} {family}");
            let first = draft(
                &name,
                &emails.iter().map(String::as_str).collect::<Vec<_>>(),
                &phones.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            let created = new_card_text("uid-p", &first).expect("create");
            let fields = read(&parse(&created).expect("calcard reads it"));
            prop_assert_eq!(fields.full_name, name.clone());
            prop_assert_eq!(values(&fields.emails), emails.iter().cloned().collect::<Vec<_>>());
            prop_assert_eq!(values(&fields.phones), phones.iter().cloned().collect::<Vec<_>>());
            // Writing the same values back changes no byte.
            prop_assert_eq!(update_card_text(&created, &first).expect("same"), created.clone());
            // An unknown property survives a change of the touched ones.
            let with_unknown = created.replace(
                "END:VCARD\r\n",
                &format!("X-IBR-THING;X-P=1:{unknown}\r\nitem9.X-ABLabel:{unknown}\r\nEND:VCARD\r\n"),
            );
            let second = draft(
                &name,
                &emails.iter().map(String::as_str).collect::<Vec<_>>(),
                &later_phones.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            let edited = update_card_text(&with_unknown, &second).expect("update");
            let thing = format!("X-IBR-THING;X-P=1:{unknown}\r\n");
            let label = format!("item9.X-ABLabel:{unknown}\r\n");
            prop_assert!(edited.contains(&thing), "lost the unknown property in {edited:?}");
            prop_assert!(edited.contains(&label), "lost the grouped label in {edited:?}");
            let again = read(&parse(&edited).expect("still a vCard"));
            prop_assert_eq!(again.phones.len(), later_phones.len());
            for phone in &later_phones {
                prop_assert!(values(&again.phones).contains(phone), "{phone} missing from {edited:?}");
            }
        }
    }
}
