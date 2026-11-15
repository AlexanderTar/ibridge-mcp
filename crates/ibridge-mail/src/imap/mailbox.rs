// SPDX-License-Identifier: Apache-2.0

//! Mailbox listing.

use async_imap::types::NameAttribute;
use futures::StreamExt;
use ibridge_core::{CoreError, Mailbox, MailboxPath, MailboxRole};

use super::pool::{Connect, ImapPool, map_command};

impl<C: Connect> ImapPool<C> {
    /// Lists mailboxes and maps SPECIAL-USE attributes to roles.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the list cannot be read.
    pub async fn list_mailboxes(&self) -> Result<Vec<Mailbox>, CoreError> {
        let mut lease = self.checkout().await?;
        let listed = list_with(&mut lease).await;
        lease.release();
        listed
    }
}

async fn list_with<C: Connect>(
    lease: &mut super::pool::Lease<'_, C>,
) -> Result<Vec<Mailbox>, CoreError> {
    let Some(session) = lease.session_mut() else {
        return Err(CoreError::Network);
    };
    let mut names = session
        .list(Some(""), Some("*"))
        .await
        .map_err(|error| map_command(&error))?;
    let mut found = Vec::new();
    while let Some(name) = names.next().await {
        let name = name.map_err(|error| map_command(&error))?;
        let path = name.name();
        let role = role_of(path, name.attributes());
        found.push((path.to_owned(), role));
    }
    drop(names);

    let Some(session) = lease.session_mut() else {
        return Err(CoreError::Network);
    };
    let mut mailboxes = Vec::with_capacity(found.len());
    for (path, role) in found {
        let status = session
            .status(&path, "(MESSAGES UNSEEN)")
            .await
            .map_err(|error| map_command(&error))?;
        let mailbox_path = MailboxPath::try_from(path.as_str())
            .map_err(|_| CoreError::Protocol("imap command failed".to_owned()))?;
        mailboxes.push(Mailbox {
            path: mailbox_path,
            role,
            total: status.exists,
            unread: status.unseen.unwrap_or(0),
        });
    }
    Ok(mailboxes)
}

/// `\Sent` and the other RFC 6154 attributes win. iCloud's Notes mailbox has no
/// special-use attribute, so the name `Notes` is the signal. `INBOX` is always inbox.
fn role_of(name: &str, attributes: &[NameAttribute<'_>]) -> MailboxRole {
    for attribute in attributes {
        let role = match attribute {
            NameAttribute::Archive => Some(MailboxRole::Archive),
            NameAttribute::Drafts => Some(MailboxRole::Drafts),
            NameAttribute::Junk => Some(MailboxRole::Junk),
            NameAttribute::Sent => Some(MailboxRole::Sent),
            NameAttribute::Trash => Some(MailboxRole::Trash),
            _ => None,
        };
        if let Some(role) = role {
            return role;
        }
    }
    if name.eq_ignore_ascii_case("INBOX") {
        MailboxRole::Inbox
    } else if name.eq_ignore_ascii_case("Notes") {
        MailboxRole::Notes
    } else {
        MailboxRole::Other
    }
}

#[cfg(test)]
mod tests {
    use ibridge_core::MailboxRole;
    use ibridge_testkit::imap_fake::FakeScript;

    use super::super::support::pool;

    #[tokio::test]
    async fn list_mailboxes_maps_special_use() {
        let (_fake, pooled) = pool(FakeScript::default());
        let boxes = pooled.list_mailboxes().await.expect("mailboxes");
        let role = |name: &str| {
            boxes
                .iter()
                .find(|mailbox| mailbox.path.as_str() == name)
                .map(|mailbox| mailbox.role)
        };
        assert_eq!(role("INBOX"), Some(MailboxRole::Inbox), "got {boxes:?}");
        assert_eq!(role("Sent Messages"), Some(MailboxRole::Sent));
        assert_eq!(role("Deleted Messages"), Some(MailboxRole::Trash));
        assert_eq!(role("Junk"), Some(MailboxRole::Junk));
        assert_eq!(role("Drafts"), Some(MailboxRole::Drafts));
        assert_eq!(role("Archive"), Some(MailboxRole::Archive));
        assert_eq!(role("Notes"), Some(MailboxRole::Notes));
        let sent = boxes
            .iter()
            .find(|mailbox| mailbox.path.as_str() == "Sent Messages")
            .expect("sent");
        assert_eq!(sent.total, 4, "STATUS MESSAGES");
        assert_eq!(sent.unread, 2, "STATUS UNSEEN");
    }
}
