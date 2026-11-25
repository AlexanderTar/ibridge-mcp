// SPDX-License-Identifier: Apache-2.0

//! Message and attachment fetch.

use async_imap::imap_proto::{AttributeValue, Response};
use ibridge_core::{Attachment, CoreError, Message, MessageId, Unsubscribe};

use super::pool::{Connect, ImapPool, Lease, map_command, run_checked};
use crate::mime;

/// A message body window. `next_offset` is the scalar offset of the unread tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Headers, the body window, and the attachment list.
    pub message: Message,
    /// Set when another window starts at this scalar offset.
    pub next_offset: Option<usize>,
}

/// One attachment. Text parts use the same window as a message body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedAttachment {
    /// The part that was fetched.
    pub attachment: Attachment,
    /// Set when a text part has another window at this scalar offset.
    pub next_offset: Option<usize>,
}

impl<C: Connect> ImapPool<C> {
    /// Fetches one message. `offset` is a Unicode scalar index into the text body.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the message cannot be read.
    pub async fn get_message(
        &self,
        id: &MessageId,
        offset: usize,
    ) -> Result<FetchedMessage, CoreError> {
        let body = load_body(self, id).await?;
        let parsed = mime::read_message(&body, offset).ok_or(CoreError::NotFound)?;
        Ok(FetchedMessage {
            message: Message {
                id: id.clone(),
                from: parsed.from,
                to: parsed.to,
                subject: parsed.subject,
                date: parsed.date,
                body: parsed.body,
                attachments: parsed.attachments,
                unsubscribe: parsed.unsubscribe,
            },
            next_offset: parsed.next_offset,
        })
    }

    /// Fetches one attachment. `offset` is a Unicode scalar index into a text part.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the part cannot be read.
    pub async fn get_attachment(
        &self,
        id: &MessageId,
        part: &str,
        offset: usize,
    ) -> Result<FetchedAttachment, CoreError> {
        let body = load_body(self, id).await?;
        let (attachment, next_offset) = mime::read_attachment(&body, part, offset)?;
        Ok(FetchedAttachment {
            attachment,
            next_offset,
        })
    }

    /// Fetches the decoded bytes of one attachment, whatever its size or type.
    ///
    /// The tool layer limits what a client sees inline. This is for saving the
    /// file to disk, so there is no 64 KiB cap and no text window.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when the part is not an attachment of the message.
    pub async fn get_attachment_bytes(
        &self,
        id: &MessageId,
        part: &str,
    ) -> Result<Attachment, CoreError> {
        let body = load_body(self, id).await?;
        mime::read_attachment_bytes(&body, part)
    }

    /// `In-Reply-To` and `References` for a reply to `id`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when the message is missing or unreadable,
    /// and [`CoreError::InvalidInput`] when it has no `Message-ID`.
    pub(crate) async fn reply_headers(
        &self,
        id: &MessageId,
    ) -> Result<crate::mime::ThreadHeaders, CoreError> {
        let body = load_body(self, id).await?;
        crate::mime::thread_headers(&body)
    }
}

impl<C: Connect> ImapPool<C> {
    /// The unsubscribe options in the headers of `id`, or `None` when it offers none.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when the message is missing or unreadable.
    pub(crate) async fn unsubscribe_options(
        &self,
        id: &MessageId,
    ) -> Result<Option<Unsubscribe>, CoreError> {
        let body = load_body(self, id).await?;
        if !mime::parses(&body) {
            return Err(CoreError::NotFound);
        }
        Ok(mime::unsubscribe(&body))
    }
}

async fn load_body<C: Connect>(pool: &ImapPool<C>, id: &MessageId) -> Result<Vec<u8>, CoreError> {
    let mut lease = pool.checkout().await?;
    let loaded = fetch_body(&mut lease, id).await;
    lease.release();
    loaded
}

async fn fetch_body<C: Connect>(
    lease: &mut Lease<'_, C>,
    id: &MessageId,
) -> Result<Vec<u8>, CoreError> {
    let Some(session) = lease.session_mut() else {
        return Err(CoreError::Network);
    };
    let selected = session
        .select(id.mailbox.as_str())
        .await
        .map_err(|error| map_command(&error))?;
    let server_validity = selected
        .uid_validity
        .ok_or_else(|| CoreError::Protocol("imap command failed".to_owned()))?;
    if server_validity != id.validity.get() {
        return Err(CoreError::NotFound);
    }
    let mut body = None;
    let reply = run_checked(
        session,
        &format!("UID FETCH {} (BODY.PEEK[])", id.uid.get()),
        |response| {
            let Response::Fetch(_, attributes) = response else {
                return;
            };
            let uid = attributes.iter().find_map(|attribute| match attribute {
                AttributeValue::Uid(uid) => Some(*uid),
                _ => None,
            });
            let bytes = attributes.iter().find_map(|attribute| match attribute {
                AttributeValue::BodySection {
                    section: None,
                    data: Some(data),
                    ..
                }
                | AttributeValue::Rfc822(Some(data)) => Some(data.as_ref()),
                _ => None,
            });
            if uid == Some(id.uid.get())
                && let Some(bytes) = bytes
            {
                body = Some(bytes.to_vec());
            }
        },
    )
    .await?;
    if reply.unparsed && body.is_none() {
        return Err(CoreError::Protocol("imap command failed".to_owned()));
    }
    body.ok_or(CoreError::NotFound)
}

#[cfg(test)]
mod tests {
    use ibridge_core::{
        CoreError, MailSearch, MailboxPath, MessageId, Uid, UidValidity, UnsubscribeMethod,
    };
    use ibridge_testkit::imap_fake::FakeScript;

    use super::super::support::pool;

    fn message_id(uid: u32) -> MessageId {
        MessageId {
            mailbox: MailboxPath::try_from("INBOX").expect("inbox"),
            validity: UidValidity::try_from(1).expect("validity"),
            uid: Uid::try_from(uid).expect("uid"),
        }
    }

    fn query() -> MailSearch {
        MailSearch {
            mailbox: Some(MailboxPath::try_from("INBOX").expect("inbox")),
            role: None,
            from: None,
            to: None,
            subject: None,
            text: None,
            since: None,
            before: None,
            unread_only: false,
            flagged_only: false,
            limit: 25,
            cursor: None,
        }
    }

    #[tokio::test]
    async fn get_message_html_to_text() {
        let (_fake, pooled) = pool(FakeScript::default());
        let fetched = pooled
            .get_message(&message_id(4), 0)
            .await
            .expect("html message");
        let body = &fetched.message.body;
        assert!(
            body.contains("Hello") && body.contains("there"),
            "html becomes text, got {body:?}"
        );
        assert!(
            !body.contains("<p>") && !body.contains("<b>"),
            "tags are not left in the text, got {body:?}"
        );
    }

    #[tokio::test]
    async fn get_message_reports_the_unsubscribe_options() {
        let (_fake, pooled) = pool(FakeScript {
            unsubscribe_messages: true,
            ..FakeScript::default()
        });
        let list = pooled
            .get_message(&message_id(70), 0)
            .await
            .expect("newsletter");
        let options = list.message.unsubscribe.expect("the header is read");
        assert_eq!(
            options.methods(),
            vec![
                UnsubscribeMethod::OneClick,
                UnsubscribeMethod::Mailto,
                UnsubscribeMethod::Link
            ]
        );
        let mailto = options.mailto.expect("mailto route");
        assert_eq!(mailto.to, "unsub@example.com");
        assert_eq!(mailto.subject.as_deref(), Some("unsubscribe"));
        assert_eq!(mailto.body.as_deref(), Some("remove me"));
        let link_only = pooled
            .get_message(&message_id(71), 0)
            .await
            .expect("link newsletter")
            .message
            .unsubscribe
            .expect("the header is read");
        assert_eq!(link_only.methods(), vec![UnsubscribeMethod::Link]);
        let plain = pooled
            .get_message(&message_id(4), 0)
            .await
            .expect("plain message");
        assert_eq!(plain.message.unsubscribe, None, "no header, no options");
    }

    #[tokio::test]
    async fn get_message_truncates_at_40000_with_offset() {
        let (_fake, pooled) = pool(FakeScript::default());
        let first = pooled
            .get_message(&message_id(2), 0)
            .await
            .expect("long message");
        assert_eq!(
            first.message.body.chars().count(),
            40_000,
            "the first window is 40000 scalars"
        );
        assert_eq!(first.next_offset, Some(40_000));
        let rest = pooled
            .get_message(&message_id(2), 40_000)
            .await
            .expect("tail");
        assert_eq!(
            rest.message.body.chars().count(),
            10,
            "the tail is the rest"
        );
        assert_eq!(rest.next_offset, None);
        assert_eq!(&rest.message.body, &"0123456789");
    }

    #[tokio::test]
    async fn attachments_listed_with_size() {
        let (_fake, pooled) = pool(FakeScript::default());
        let fetched = pooled
            .get_message(&message_id(50), 0)
            .await
            .expect("message with attachments");
        let text = fetched
            .message
            .attachments
            .iter()
            .find(|part| part.content_type.starts_with("text/plain"))
            .expect("text attachment");
        assert_eq!(text.name, "note.txt");
        assert_eq!(text.size, 4, "size is the decoded byte length");
        let binary = fetched
            .message
            .attachments
            .iter()
            .find(|part| part.content_type == "application/octet-stream")
            .expect("binary attachment");
        assert_eq!(binary.name, "blob.bin");
        assert!(binary.size > 65_536, "the binary is over 64 KiB");
    }

    #[tokio::test]
    async fn get_attachment_text_extracted() {
        let (_fake, pooled) = pool(FakeScript::default());
        let attachment = pooled
            .get_attachment(&message_id(50), "1", 0)
            .await
            .expect("text part");
        assert_eq!(attachment.attachment.text.as_deref(), Some("note"));
        assert!(
            attachment.attachment.bytes.is_none(),
            "text parts are returned as text"
        );
    }

    #[tokio::test]
    async fn get_attachment_bytes_has_no_size_cap() {
        let (_fake, pooled) = pool(FakeScript::default());
        let big = pooled
            .get_attachment_bytes(&message_id(50), "2")
            .await
            .expect("a binary over 64 KiB can be saved");
        assert_eq!(
            big.bytes.as_ref().map(Vec::len),
            Some(65_537),
            "every decoded byte comes back"
        );
        let text = pooled
            .get_attachment_bytes(&message_id(50), "1")
            .await
            .expect("a text part can be saved too");
        assert_eq!(
            text.bytes.as_deref(),
            Some(b"note".as_slice()),
            "a text part comes back as its bytes, not a window"
        );
        let missing = pooled
            .get_attachment_bytes(&message_id(50), "99")
            .await
            .expect_err("a part that is not there");
        assert!(matches!(missing, CoreError::NotFound), "got {missing:?}");
    }

    #[tokio::test]
    async fn get_attachment_binary_over_64k_refused() {
        let (_fake, pooled) = pool(FakeScript::default());
        let error = pooled
            .get_attachment(&message_id(50), "2", 0)
            .await
            .expect_err("a binary over 64 KiB is refused");
        assert!(matches!(error, CoreError::InvalidInput(_)), "got {error:?}");
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains("blob-byte"),
            "the error must not include the attachment bytes, got {rendered}"
        );
    }

    #[tokio::test]
    async fn malformed_message_skipped_with_warning() {
        let (_fake, pooled) = pool(FakeScript::default());
        let page = pooled
            .search(&query())
            .await
            .expect("search still succeeds");
        let uids: Vec<u32> = page
            .messages
            .iter()
            .map(|message| message.id.uid.get())
            .collect();
        assert!(
            uids.contains(&4) && !uids.contains(&7),
            "a bad message is skipped and the others remain, got {uids:?}"
        );
        assert_eq!(page.warnings, 1, "the skip is counted");
    }

    #[tokio::test]
    async fn get_message_rejects_stale_uidvalidity() {
        let (_fake, pooled) = pool(FakeScript {
            uid_validity: Some(9),
            ..FakeScript::default()
        });
        let error = pooled
            .get_message(&message_id(4), 0)
            .await
            .expect_err("a stale UIDVALIDITY is not that message");
        assert!(
            matches!(error, CoreError::NotFound),
            "UIDVALIDITY mismatch is not found, got {error:?}"
        );
    }

    #[tokio::test]
    async fn get_attachment_text_is_windowed() {
        let (_fake, pooled) = pool(FakeScript {
            long_attachment: true,
            ..FakeScript::default()
        });
        let first = pooled
            .get_attachment(&message_id(8), "1", 0)
            .await
            .expect("long text attachment");
        assert_eq!(
            first
                .attachment
                .text
                .as_deref()
                .map(str::chars)
                .map_or(0, std::iter::Iterator::count),
            40_000,
            "a text attachment is capped like a body"
        );
        assert_eq!(first.next_offset, Some(40_000));
        let rest = pooled
            .get_attachment(&message_id(8), "1", 40_000)
            .await
            .expect("attachment tail");
        assert_eq!(
            rest.attachment.text.as_deref(),
            Some("aaaaaaaaaa"),
            "the tail is the unread scalars"
        );
        assert_eq!(rest.next_offset, None);
    }

    #[tokio::test]
    async fn get_attachment_rejects_a_non_attachment() {
        let (_fake, pooled) = pool(FakeScript::default());
        let error = pooled
            .get_attachment(&message_id(50), "0", 0)
            .await
            .expect_err("the whole message is not an attachment");
        assert!(
            matches!(error, CoreError::NotFound),
            "only listed attachments can be fetched, got {error:?}"
        );
    }
}
