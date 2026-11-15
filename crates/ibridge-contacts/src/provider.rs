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

    async fn create(&self, _draft: &ContactDraft) -> Result<ResourcePath, CoreError> {
        Err(CoreError::Unsupported("not yet"))
    }

    async fn update(
        &self,
        _path: &ResourcePath,
        _etag: &ETag,
        _draft: &ContactDraft,
    ) -> Result<ETag, CoreError> {
        Err(CoreError::Unsupported("not yet"))
    }

    async fn delete(&self, _path: &ResourcePath, _etag: &ETag) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("not yet"))
    }

    async fn set_group_membership(
        &self,
        _group: &ResourcePath,
        _contact: &ResourcePath,
        _change: GroupChange,
    ) -> Result<(), CoreError> {
        Err(CoreError::Unsupported("not yet"))
    }
}
