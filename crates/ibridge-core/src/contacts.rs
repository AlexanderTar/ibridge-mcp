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
    /// Also return groups, so a caller can find one to put a contact in.
    pub include_groups: bool,
}

/// A group a contact is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRef {
    /// Path of the group card, for `set_group_membership`.
    pub path: ResourcePath,
    /// Group name.
    pub name: String,
}

/// An email address or phone number with the label the card gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabeledValue {
    /// The address or number.
    pub value: String,
    /// `Home`, `Work`, `Cell` or a custom label.
    pub label: Option<String>,
}

/// Contacts from a search, with a count of cards that were skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactList {
    /// Matching contacts in name order.
    pub contacts: Vec<Contact>,
    /// Cards that could not be read and were left out.
    pub warnings: u32,
}

/// One contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Path relative to the address book home.
    pub path: ResourcePath,
    /// `ETag` for a conditional write.
    pub etag: ETag,
    /// Full name.
    pub full_name: String,
    /// Email addresses.
    pub emails: Vec<LabeledValue>,
    /// Phone numbers.
    pub phones: Vec<LabeledValue>,
    /// Company.
    pub organization: Option<String>,
    /// Free-text note.
    pub note: Option<String>,
    /// The card is a group, not a person.
    pub is_group: bool,
    /// The groups the contact is in. Filled by `get` only.
    pub groups: Vec<GroupRef>,
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

/// Changes to a contact. A field left as `None` stays as the card has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactUpdate {
    /// New full name.
    pub full_name: Option<String>,
    /// New email addresses, replacing the current ones.
    pub emails: Option<Vec<String>>,
    /// New phone numbers, replacing the current ones.
    pub phones: Option<Vec<String>>,
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
    async fn search(&self, query: &ContactQuery) -> Result<ContactList, CoreError>;

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
        update: &ContactUpdate,
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
