// SPDX-License-Identifier: Apache-2.0

//! Contacts tools.

use ibridge_core::{
    CalendarProvider, Contact, ContactDraft, ContactList, ContactQuery, ContactUpdate,
    ContactsProvider, CoreError, ETag, GroupChange, LabeledValue, RemindersProvider, ResourcePath,
    encode_resource,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorData};
use rmcp::tool;
use rmcp::tool_router;

use crate::calendar_dto::{DeleteOut, DeleteParams, GetByIdParams, WriteOut};
use crate::calendar_tools::{capped, require_etag, require_path};
use crate::contacts_dto::{
    ContactListOut, ContactOut, CreateContactParams, GroupOut, LabeledOut, MembershipOut,
    SearchContactsParams, SetGroupMembershipParams, UpdateContactParams,
};
use crate::handler::{IbridgeServer, mapped, page_limit, respond};
use crate::mail_api::MailApi;
use crate::sanitize::strip_hidden;

pub(crate) const CONTACTS_TOOLS: &[&str] = &[
    "contacts_create",
    "contacts_delete",
    "contacts_get",
    "contacts_search",
    "contacts_set_group_membership",
    "contacts_update",
];

pub(crate) const CONTACTS_WRITE_TOOLS: &[&str] = &[
    "contacts_create",
    "contacts_delete",
    "contacts_set_group_membership",
    "contacts_update",
];

/// The contacts backend of a server that has none. Its tools stay hidden.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContacts;

fn off<T>() -> Result<T, CoreError> {
    Err(CoreError::Unsupported("contacts is not enabled"))
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the stand-in answers without waiting"
)]
impl ContactsProvider for NoContacts {
    async fn search(&self, _query: &ContactQuery) -> Result<ContactList, CoreError> {
        off()
    }
    async fn get(&self, _path: &ResourcePath) -> Result<Contact, CoreError> {
        off()
    }
    async fn create(&self, _draft: &ContactDraft) -> Result<ResourcePath, CoreError> {
        off()
    }
    async fn update(
        &self,
        _path: &ResourcePath,
        _etag: &ETag,
        _update: &ContactUpdate,
    ) -> Result<ETag, CoreError> {
        off()
    }
    async fn delete(&self, _path: &ResourcePath, _etag: &ETag) -> Result<(), CoreError> {
        off()
    }
    async fn set_group_membership(
        &self,
        _group: &ResourcePath,
        _contact: &ResourcePath,
        _change: GroupChange,
    ) -> Result<(), CoreError> {
        off()
    }
}

macro_rules! try_contacts {
    ($call:expr) => {
        match $call {
            Ok(value) => value,
            Err(error) => return mapped(&error),
        }
    };
}

#[tool_router(router = contacts_router, vis = "pub(crate)")]
impl<M, C, K> IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    /// Searches contacts by name, email address or phone number.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the query is empty or the
    /// limit is above 100, and an MCP error when the search cannot be run.
    #[tool(
        title = "Search contacts",
        description = "Searches contacts by name, email address or phone number. Matching is done by this server, not by iCloud.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<ContactListOut>(),
    )]
    pub async fn contacts_search(
        &self,
        Parameters(params): Parameters<SearchContactsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = page_limit(params.limit)?;
        if params.query.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "query must be a name, an email address or a phone number",
                None,
            ));
        }
        let query = ContactQuery {
            text: params.query,
            limit,
            include_groups: params.include_groups.unwrap_or(false),
        };
        let _permit = self.permit().await?;
        let found = try_contacts!(self.contacts.search(&query).await);
        let summary = if found.warnings == 0 {
            format!("{} contacts", found.contacts.len())
        } else {
            format!(
                "{} contacts, {} skipped",
                found.contacts.len(),
                found.warnings
            )
        };
        respond(
            &ContactListOut {
                contacts: found.contacts.iter().map(contact_out).collect(),
                warnings: found.warnings,
            },
            summary,
        )
    }

    /// Fetches one contact in full.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id is not usable, and an
    /// MCP error when the contact cannot be read.
    #[tool(
        title = "Get contact",
        description = "Fetches one contact in full: labels, note, company and the groups it is in.",
        annotations(read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<ContactOut>(),
    )]
    pub async fn contacts_get(
        &self,
        Parameters(params): Parameters<GetByIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = require_path(&params.id)?;
        let _permit = self.permit().await?;
        let contact = try_contacts!(self.contacts.get(&path).await);
        respond(&contact_out(&contact), "contact".to_owned())
    }

    /// Creates a contact.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the name is empty, and an MCP
    /// error when the contact cannot be written.
    #[tool(
        title = "Create contact",
        description = "Creates a contact from a name, email addresses and phone numbers.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn contacts_create(
        &self,
        Parameters(params): Parameters<CreateContactParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let draft = ContactDraft {
            full_name: params.full_name,
            emails: params.emails,
            phones: params.phones,
        };
        let _permit = self.permit().await?;
        let path = try_contacts!(self.contacts.create(&draft).await);
        respond(
            &WriteOut {
                id: encode_resource(&path),
                etag: None,
            },
            "contact created".to_owned(),
        )
    }

    /// Changes a contact. Needs the current `ETag`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or etag is not usable,
    /// and an MCP error when the contact cannot be written.
    #[tool(
        title = "Update contact",
        description = "Changes a contact. Needs the etag from the last read; a changed contact is refused. Fields you omit, and everything else on the card, are kept.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<WriteOut>(),
    )]
    pub async fn contacts_update(
        &self,
        Parameters(params): Parameters<UpdateContactParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        let _permit = self.permit().await?;
        // What the caller leaves out stays as the card has it; the provider fills it in.
        let changes = ContactUpdate {
            full_name: params.full_name,
            emails: params.emails,
            phones: params.phones,
        };
        let new_etag = try_contacts!(self.contacts.update(&path, &etag, &changes).await);
        respond(
            &WriteOut {
                id: params.id,
                etag: Some(new_etag.as_str().to_owned()),
            },
            "contact updated".to_owned(),
        )
    }

    /// Deletes a contact.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the id or etag is not usable,
    /// and an MCP error when the contact cannot be deleted.
    #[tool(
        title = "Delete contact",
        description = "Deletes a contact. Needs the etag from the last read. iCloud ignores the etag on delete, so the card is read again and compared first; a small race window remains between that read and the delete.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<DeleteOut>(),
    )]
    pub async fn contacts_delete(
        &self,
        Parameters(params): Parameters<DeleteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let path = require_path(&params.id)?;
        let etag = require_etag(&params.etag)?;
        let _permit = self.permit().await?;
        try_contacts!(self.contacts.delete(&path, &etag).await);
        respond(&DeleteOut { deleted: true }, "contact deleted".to_owned())
    }

    /// Adds a contact to a group or removes it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when an id or the action is not
    /// usable, and an MCP error when the group cannot be rewritten.
    #[tool(
        title = "Change contact group membership",
        description = "Adds a contact to an existing group or removes it, by rewriting the group card. Groups cannot be created or deleted.",
        annotations(read_only_hint = false, destructive_hint = true, open_world_hint = true),
        output_schema = rmcp::handler::server::tool::schema_for_output::<MembershipOut>(),
    )]
    pub async fn contacts_set_group_membership(
        &self,
        Parameters(params): Parameters<SetGroupMembershipParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.reject_write()?;
        let change = match params.action.as_str() {
            "add" => GroupChange::Add,
            "remove" => GroupChange::Remove,
            _ => {
                return Err(ErrorData::invalid_params(
                    "action must be add or remove",
                    None,
                ));
            }
        };
        let group = require_path(&params.group)?;
        let contact = require_path(&params.contact)?;
        let _permit = self.permit().await?;
        try_contacts!(
            self.contacts
                .set_group_membership(&group, &contact, change)
                .await
        );
        respond(&MembershipOut { updated: true }, "group updated".to_owned())
    }
}

fn labeled_out(value: &LabeledValue) -> LabeledOut {
    LabeledOut {
        value: strip_hidden(&value.value),
        label: value.label.as_deref().map(strip_hidden),
    }
}

fn contact_out(contact: &Contact) -> ContactOut {
    ContactOut {
        id: encode_resource(&contact.path),
        etag: contact.etag.as_str().to_owned(),
        name: strip_hidden(&contact.full_name),
        emails: contact.emails.iter().map(labeled_out).collect(),
        phones: contact.phones.iter().map(labeled_out).collect(),
        organization: contact.organization.as_deref().map(strip_hidden),
        note: contact
            .note
            .as_deref()
            .map(|note| strip_hidden(&capped(note))),
        is_group: contact.is_group,
        groups: contact
            .groups
            .iter()
            .map(|group| GroupOut {
                id: encode_resource(&group.path),
                name: strip_hidden(&group.name),
            })
            .collect(),
    }
}
