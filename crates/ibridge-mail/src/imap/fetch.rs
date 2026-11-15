// SPDX-License-Identifier: Apache-2.0

//! Message and attachment fetch.

use futures::StreamExt;
use ibridge_core::{Attachment, CoreError, Message, MessageId};

use super::mime;
use super::pool::{Connect, ImapPool, Lease, map_command};

/// A message body window. `next_offset` is the scalar offset of the unread tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Headers, the body window, and the attachment list.
    pub message: Message,
    /// Set when another window starts at this scalar offset.
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
            },
            next_offset: parsed.next_offset,
        })
    }

    /// Fetches one attachment.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the part cannot be read.
    pub async fn get_attachment(
        &self,
        id: &MessageId,
        part: &str,
    ) -> Result<Attachment, CoreError> {
        let body = load_body(self, id).await?;
        mime::read_attachment(&body, part)
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
    session
        .select(id.mailbox.as_str())
        .await
        .map_err(|error| map_command(&error))?;
    let mut fetches = session
        .uid_fetch(id.uid.get().to_string(), "(BODY.PEEK[])")
        .await
        .map_err(|error| map_command(&error))?;
    let mut body = None;
    while let Some(item) = fetches.next().await {
        let fetch = item.map_err(|error| map_command(&error))?;
        if fetch.uid == Some(id.uid.get())
            && let Some(bytes) = fetch.body()
        {
            body = Some(bytes.to_vec());
        }
    }
    drop(fetches);
    body.ok_or(CoreError::NotFound)
}

#[cfg(test)]
mod tests {
    use ibridge_core::{CoreError, MailSearch, MailboxPath, MessageId, Uid, UidValidity};
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
            .get_attachment(&message_id(50), "1")
            .await
            .expect("text part");
        assert_eq!(attachment.text.as_deref(), Some("note"));
        assert!(
            attachment.bytes.is_none(),
            "text parts are returned as text"
        );
    }

    #[tokio::test]
    async fn get_attachment_binary_over_64k_refused() {
        let (_fake, pooled) = pool(FakeScript::default());
        let error = pooled
            .get_attachment(&message_id(50), "2")
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
}
