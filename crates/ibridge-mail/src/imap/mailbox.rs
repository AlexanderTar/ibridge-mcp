// SPDX-License-Identifier: Apache-2.0

//! Mailbox listing.

use async_imap::imap_proto::{MailboxDatum, Response};
use async_imap::types::NameAttribute;
use ibridge_core::{CoreError, Mailbox, MailboxPath, MailboxRole};

use super::pool::{Connect, ImapPool, map_command, run_checked};

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
    let mut found = Vec::new();
    let reply = run_checked(session, "LIST \"\" *", |response| {
        let Response::MailboxData(MailboxDatum::List(data)) = response else {
            return;
        };
        if unselectable(&data.name_attributes) {
            return;
        }
        let Ok(path) = MailboxPath::try_from(data.name.as_ref()) else {
            return;
        };
        let role = role_of(data.name.as_ref(), &data.name_attributes);
        found.push((path, role));
    })
    .await?;
    if reply.unparsed {
        return Err(CoreError::Protocol("imap command failed".to_owned()));
    }
    let mut mailboxes = Vec::with_capacity(found.len());
    for (path, role) in found {
        let status = session.status(path.as_str(), "(MESSAGES UNSEEN)").await;
        let (total, unread) = match status {
            Ok(status) => (status.exists, status.unseen.unwrap_or(0)),
            Err(error) => {
                let mapped = map_command(&error);
                if matches!(mapped, CoreError::RateLimited { .. }) {
                    return Err(mapped);
                }
                (0, 0)
            }
        };
        mailboxes.push(Mailbox {
            path,
            role,
            total,
            unread,
        });
    }
    Ok(mailboxes)
}

fn unselectable(attributes: &[NameAttribute<'_>]) -> bool {
    attributes.iter().any(|attribute| match attribute {
        NameAttribute::NoSelect => true,
        NameAttribute::Extension(name) => name.eq_ignore_ascii_case("\\NonExistent"),
        _ => false,
    })
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

    #[tokio::test]
    async fn list_skips_unselectable_and_a_bad_path() {
        let (_fake, pooled) = pool(FakeScript {
            list_noselect: true,
            ..FakeScript::default()
        });
        let boxes = pooled
            .list_mailboxes()
            .await
            .expect("the list still succeeds");
        let names: Vec<&str> = boxes.iter().map(|mailbox| mailbox.path.as_str()).collect();
        assert!(
            names.contains(&"INBOX"),
            "selectable mailboxes remain, got {names:?}"
        );
        assert!(
            !names.contains(&"All Mail")
                && !names.contains(&"Ghost")
                && !names.contains(&"http://evil"),
            "unselectable rows and a path that is not a mailbox id are skipped, got {names:?}"
        );
    }

    #[tokio::test]
    async fn list_keeps_a_mailbox_when_its_status_fails() {
        let (_fake, pooled) = pool(FakeScript {
            fail_status: true,
            ..FakeScript::default()
        });
        let boxes = pooled
            .list_mailboxes()
            .await
            .expect("one STATUS failure does not fail the list");
        let notes = boxes
            .iter()
            .find(|mailbox| mailbox.path.as_str() == "Notes")
            .expect("Notes is still listed");
        assert_eq!(notes.total, 0, "a failed STATUS leaves the counts unknown");
        assert_eq!(notes.unread, 0);
        assert!(
            boxes.iter().any(|mailbox| mailbox.path.as_str() == "INBOX"),
            "the other mailboxes are still returned"
        );
    }
}
