// SPDX-License-Identifier: Apache-2.0

//! MIME bodies for fetched messages.

use std::borrow::Cow;

use ibridge_core::{Attachment, AttachmentInfo, CoreError};
use mail_parser::{AddressList, Message, MessageParser, MessagePart};

const BODY_WINDOW: usize = 40_000;
const BINARY_LIMIT: usize = 65_536;

/// Whether `bytes` is a message the parser can read.
pub(crate) fn parses(bytes: &[u8]) -> bool {
    MessageParser::new().parse(bytes).is_some()
}

pub(crate) struct ReadMessage {
    pub(crate) from: String,
    pub(crate) to: Vec<String>,
    pub(crate) subject: String,
    pub(crate) date: String,
    pub(crate) body: String,
    pub(crate) next_offset: Option<usize>,
    pub(crate) attachments: Vec<AttachmentInfo>,
}

/// `In-Reply-To` and `References` taken from a parent message.
pub(crate) struct ThreadHeaders {
    /// Parent `Message-ID`, with angle brackets.
    pub(crate) in_reply_to: String,
    /// Parent `References`, then the parent `Message-ID` when it is not already last.
    pub(crate) references: Vec<String>,
}

/// Reply headers for `bytes`.
///
/// # Errors
///
/// Returns [`CoreError::NotFound`] when `bytes` is not a message, and
/// [`CoreError::InvalidInput`] when it has no `Message-ID`.
pub(crate) fn thread_headers(bytes: &[u8]) -> Result<ThreadHeaders, CoreError> {
    let message = MessageParser::new()
        .parse(bytes)
        .ok_or(CoreError::NotFound)?;
    let id = message.message_id().ok_or_else(|| {
        CoreError::InvalidInput("the message being replied to has no Message-ID".to_owned())
    })?;
    let in_reply_to = angle(id);
    let mut references = message
        .references()
        .map_or_else(Vec::new, |list| list.iter().map(angle).collect());
    if references.last() != Some(&in_reply_to) {
        references.push(in_reply_to.clone());
    }
    Ok(ThreadHeaders {
        in_reply_to,
        references,
    })
}

fn angle(id: &str) -> String {
    if id.starts_with('<') && id.ends_with('>') && id.len() > 2 {
        id.to_owned()
    } else {
        format!("<{id}>")
    }
}

/// Text window and attachment list for one parsed message.
pub(crate) fn read_message(bytes: &[u8], offset: usize) -> Option<ReadMessage> {
    let message = MessageParser::new().parse(bytes)?;
    let text = message.body_text(0).unwrap_or(Cow::Borrowed(""));
    let (body, next_offset) = window(&text, offset);
    Some(ReadMessage {
        from: first_address(message.from()),
        to: all_addresses(message.to()),
        subject: message.subject().map_or(String::new(), str::to_owned),
        date: message
            .date()
            .map_or(String::new(), |date| date.to_rfc3339()),
        body,
        next_offset,
        attachments: message.attachments().map(attachment_info).collect(),
    })
}

/// One attachment. Text parts use the same 40,000-scalar window as a body.
/// A binary part over 64 KiB is refused.
///
/// # Errors
///
/// Returns [`CoreError::NotFound`] when the part is not an attachment, and
/// [`CoreError::InvalidInput`] when a binary part is over 64 KiB.
pub(crate) fn read_attachment(
    bytes: &[u8],
    part: &str,
    offset: usize,
) -> Result<(Attachment, Option<usize>), CoreError> {
    let message = MessageParser::new()
        .parse(bytes)
        .ok_or(CoreError::NotFound)?;
    let found = attachment_part(&message, part)?;
    let info = attachment_info(found);
    if found.is_text() {
        let text = found.text().unwrap_or(Cow::Borrowed(""));
        let (windowed, next_offset) = window(&text, offset);
        return Ok((
            Attachment {
                info,
                text: Some(windowed),
                bytes: None,
            },
            next_offset,
        ));
    }
    if found.decoded_len() > BINARY_LIMIT {
        return Err(CoreError::InvalidInput(
            "binary attachment is too large".to_owned(),
        ));
    }
    Ok((
        Attachment {
            info,
            text: None,
            bytes: Some(found.decoded().into_owned()),
        },
        None,
    ))
}

/// Every decoded byte of one attachment, with no size cap and no text window.
///
/// # Errors
///
/// Returns [`CoreError::NotFound`] when the part is not an attachment.
pub(crate) fn read_attachment_bytes(bytes: &[u8], part: &str) -> Result<Attachment, CoreError> {
    let message = MessageParser::new()
        .parse(bytes)
        .ok_or(CoreError::NotFound)?;
    let found = attachment_part(&message, part)?;
    Ok(Attachment {
        info: attachment_info(found),
        text: None,
        bytes: Some(found.decoded().into_owned()),
    })
}

fn window(text: &str, offset: usize) -> (String, Option<usize>) {
    let mut chars = text.chars().skip(offset);
    let body: String = chars.by_ref().take(BODY_WINDOW).collect();
    let next_offset = chars.next().map(|_| offset.saturating_add(BODY_WINDOW));
    (body, next_offset)
}

fn attachment_part<'m>(message: &'m Message<'m>, part: &str) -> Result<MessagePart<'m>, CoreError> {
    let id = part
        .parse::<mail_parser::PartId>()
        .map_err(|_| CoreError::NotFound)?;
    message
        .attachments()
        .find(|item| item.id() == id)
        .ok_or(CoreError::NotFound)
}

fn attachment_info(part: MessagePart<'_>) -> AttachmentInfo {
    AttachmentInfo {
        part: part.id().to_string(),
        content_type: content_type(part),
        size: u64::try_from(part.decoded_len()).unwrap_or(u64::MAX),
        name: part.attachment_name().map_or(String::new(), str::to_owned),
    }
}

fn content_type(part: MessagePart<'_>) -> String {
    part.content_type().map_or(String::new(), |kind| {
        kind.subtype().map_or_else(
            || kind.ctype().to_owned(),
            |subtype| format!("{}/{}", kind.ctype(), subtype),
        )
    })
}

fn first_address(list: Option<AddressList<'_>>) -> String {
    list.and_then(|list| list.first())
        .and_then(|mailbox| mailbox.address())
        .map_or(String::new(), str::to_owned)
}

fn all_addresses(list: Option<AddressList<'_>>) -> Vec<String> {
    list.map_or(Vec::new(), |list| {
        list.mailboxes()
            .filter_map(|mailbox| mailbox.address().map(str::to_owned))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::read_message;

    #[test]
    fn fixture_icloud_marker_mail_reads() {
        for (file, word) in [("mail-1.eml", "one"), ("mail-2.eml", "two")] {
            let raw = ibridge_testkit::fixtures::read("imap", file);
            let read = read_message(raw.as_bytes(), 0).expect("recorded mail parses");
            assert_eq!(read.from, "user@example.com");
            assert!(
                read.subject.starts_with("[ibridge-fixture] ")
                    && read.subject.ends_with(&format!("seed {word}")),
                "got {}",
                read.subject
            );
            assert_eq!(read.body.trim(), format!("marker body {word}"));
        }
    }
}
