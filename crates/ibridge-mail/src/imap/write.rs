// SPDX-License-Identifier: Apache-2.0

//! Append a message, then move and flags.

use async_imap::imap_proto::rfc4315::UidSetMember;
use async_imap::imap_proto::{RequestId, Response, ResponseCode};
use ibridge_core::{CoreError, MailboxPath, MailboxRole, MessageId, Uid, UidValidity};
use tokio::io::AsyncWriteExt;

use super::pool::{Connect, ImapPool, done_status, map_command};

impl<C: Connect> ImapPool<C> {
    /// Appends `bytes` to the mailbox with `role`.
    ///
    /// `flags` is an IMAP flag list such as `(\\Draft)`, or none.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::NotFound`] when no mailbox has `role`, and
    /// [`CoreError::Protocol`] when the server does not return `APPENDUID`.
    pub(crate) async fn append(
        &self,
        role: MailboxRole,
        flags: Option<&str>,
        bytes: &[u8],
    ) -> Result<MessageId, CoreError> {
        let path = path_for_role(self, role).await?;
        let mut lease = self.checkout().await?;
        let appended = append_on(&mut lease, path.as_str(), flags, bytes).await;
        lease.release();
        appended
    }
}

async fn path_for_role<C: Connect>(
    pool: &ImapPool<C>,
    role: MailboxRole,
) -> Result<MailboxPath, CoreError> {
    let mailboxes = pool.list_mailboxes().await?;
    mailboxes
        .into_iter()
        .find(|mailbox| mailbox.role == role)
        .map(|mailbox| mailbox.path)
        .ok_or(CoreError::NotFound)
}

async fn append_on<C: Connect>(
    lease: &mut super::pool::Lease<'_, C>,
    mailbox: &str,
    flags: Option<&str>,
    bytes: &[u8],
) -> Result<MessageId, CoreError> {
    let Some(session) = lease.session_mut() else {
        return Err(CoreError::Network);
    };
    let quoted = quote_mailbox(mailbox)?;
    let flag_suffix = flags.map_or(String::new(), |flags| format!(" {flags}"));
    let command = format!("APPEND {quoted}{flag_suffix} {{{}}}", bytes.len());
    let request = session
        .run_command(&command)
        .await
        .map_err(|error| map_command(&error))?;
    read_until_continue(session, &request).await?;
    session
        .get_mut()
        .write_all(bytes)
        .await
        .map_err(|_| CoreError::Network)?;
    session
        .get_mut()
        .write_all(b"\r\n")
        .await
        .map_err(|_| CoreError::Network)?;
    session
        .get_mut()
        .flush()
        .await
        .map_err(|_| CoreError::Network)?;
    let (validity, uid) = read_append_uid(session, &request).await?;
    message_id(mailbox, validity, uid)
}

async fn read_until_continue<S>(
    session: &mut async_imap::Session<S>,
    request: &RequestId,
) -> Result<(), CoreError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    loop {
        match session.read_response().await {
            Ok(Some(response)) => match response.parsed() {
                Response::Continue(_) => return Ok(()),
                Response::Done {
                    tag,
                    status,
                    outcome,
                } if tag == request => return done_status(status, outcome),
                _ => {}
            },
            Ok(None) | Err(_) => return Err(CoreError::Network),
        }
    }
}

async fn read_append_uid<S>(
    session: &mut async_imap::Session<S>,
    request: &RequestId,
) -> Result<(u32, u32), CoreError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    loop {
        match session.read_response().await {
            Ok(Some(response)) => {
                if let Response::Done {
                    tag,
                    status,
                    outcome,
                } = response.parsed()
                    && tag == request
                {
                    let ids = append_uid(outcome.code.as_ref());
                    done_status(status, outcome)?;
                    return ids.ok_or(CoreError::Protocol("imap command failed".to_owned()));
                }
            }
            Ok(None) | Err(_) => return Err(CoreError::Network),
        }
    }
}

fn append_uid(code: Option<&ResponseCode<'_>>) -> Option<(u32, u32)> {
    let ResponseCode::AppendUid(validity, members) = code? else {
        return None;
    };
    let uid = match members.first()? {
        UidSetMember::Uid(uid) => *uid,
        UidSetMember::UidRange(range) => *range.start(),
    };
    Some((*validity, uid))
}

fn message_id(mailbox: &str, validity: u32, uid: u32) -> Result<MessageId, CoreError> {
    let mailbox = MailboxPath::try_from(mailbox)
        .map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
    let validity = UidValidity::try_from(validity)
        .map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
    let uid =
        Uid::try_from(uid).map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
    Ok(MessageId {
        mailbox,
        validity,
        uid,
    })
}

fn quote_mailbox(name: &str) -> Result<String, CoreError> {
    if name.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return Err(CoreError::InvalidInput(
            "a mailbox name contains a line break".to_owned(),
        ));
    }
    let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}
