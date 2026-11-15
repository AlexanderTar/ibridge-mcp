// SPDX-License-Identifier: Apache-2.0

//! Contacts values and the contacts provider trait.

use crate::error::CoreError;
use crate::ids::{ETag, ResourcePath};

/// A contact search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactQuery {
    /// Name, email or phone text. Matching is done by the provider.
    pub text: String,
    /// Maximum hits. Callers cap this at 100.
    pub limit: u32,
}

/// One contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Path relative to the address book home.
    pub path: ResourcePath,
    /// `ETag` for a conditional write.
    pub etag: ETag,
    /// Full name. Untrusted content.
    pub full_name: String,
    /// Email addresses.
    pub emails: Vec<String>,
    /// Phone numbers.
    pub phones: Vec<String>,
}

/// Fields written by create and update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactDraft {
    /// Full name.
    pub full_name: String,
    /// Email addresses.
    pub emails: Vec<String>,
    /// Phone numbers.
    pub phones: Vec<String>,
}

/// Add or remove a contact in an existing group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GroupChange {
    /// Put the contact in the group.
    Add,
    /// Take the contact out of the group.
    Remove,
}

/// Contacts read and write operations.
#[trait_variant::make(Send)]
pub trait ContactsProvider {
    /// Searches contacts.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the search cannot be run.
    async fn search(&self, query: &ContactQuery) -> Result<Vec<Contact>, CoreError>;

    /// Fetches one contact.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the contact cannot be read.
    async fn get(&self, path: &ResourcePath) -> Result<Contact, CoreError>;

    /// Creates a contact.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the contact cannot be written.
    async fn create(&self, draft: &ContactDraft) -> Result<ResourcePath, CoreError>;

    /// Replaces a contact when the `ETag` still matches.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Conflict`] when the `ETag` does not match.
    async fn update(
        &self,
        path: &ResourcePath,
        etag: &ETag,
        draft: &ContactDraft,
    ) -> Result<ETag, CoreError>;

    /// Deletes a contact.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the contact cannot be deleted.
    async fn delete(&self, path: &ResourcePath, etag: &ETag) -> Result<(), CoreError>;

    /// Adds or removes a contact in an existing group.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the group card cannot be rewritten.
    async fn set_group_membership(
        &self,
        group: &ResourcePath,
        contact: &ResourcePath,
        change: GroupChange,
    ) -> Result<(), CoreError>;
}
