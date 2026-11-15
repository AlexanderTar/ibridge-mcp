// SPDX-License-Identifier: Apache-2.0

//! The [`ContactsProvider`] implementation.

use ibridge_core::{
    Contact, ContactDraft, ContactList, ContactQuery, ContactsProvider, CoreError, ETag,
    GroupChange, ResourcePath,
};

use crate::CardDavProvider;

impl ContactsProvider for CardDavProvider {
    async fn search(&self, query: &ContactQuery) -> Result<ContactList, CoreError> {
        self.search_contacts(query).await
    }

    async fn get(&self, path: &ResourcePath) -> Result<Contact, CoreError> {
        self.get_contact(path).await
    }

    async fn create(&self, draft: &ContactDraft) -> Result<ResourcePath, CoreError> {
        self.create_contact(draft).await
    }

    async fn update(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &ContactDraft,
    ) -> Result<ETag, CoreError> {
        self.update_contact(path, etag, draft).await
    }

    async fn delete(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError> {
        self.delete_contact(path, etag).await
    }

    async fn set_group_membership(
        &self,
        group: &ResourcePath,
        contact: &ResourcePath,
        change: GroupChange,
    ) -> Result<(), CoreError> {
        self.change_membership(group, contact, change).await
    }
}
