// SPDX-License-Identifier: Apache-2.0

//! Contacts tool arguments and structured results.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_page_limit() -> u32 {
    25
}

/// Arguments for `contacts_search`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SearchContactsParams {
    /// A name, an email address or a phone number, or part of one.
    pub query: String,
    /// Most contacts to return. Omitted means 25. More than 100 is rejected.
    #[serde(default = "default_page_limit")]
    pub limit: u32,
    /// Also return groups, to find the id of a group for `contacts_set_group_membership`.
    #[serde(default)]
    pub include_groups: Option<bool>,
}

/// Arguments for `contacts_create`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CreateContactParams {
    /// Full name, such as `Ada Lovelace`.
    pub full_name: String,
    /// Email addresses.
    #[serde(default)]
    pub emails: Vec<String>,
    /// Phone numbers.
    #[serde(default)]
    pub phones: Vec<String>,
}

/// Arguments for `contacts_update`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UpdateContactParams {
    /// Opaque contact id.
    pub id: String,
    /// The `etag` from the last read. A different one means the contact changed.
    pub etag: String,
    /// New full name. Omit to keep it.
    #[serde(default)]
    pub full_name: Option<String>,
    /// The full list of email addresses the contact should have. Omit to keep them.
    #[serde(default)]
    pub emails: Option<Vec<String>>,
    /// The full list of phone numbers the contact should have. Omit to keep them.
    #[serde(default)]
    pub phones: Option<Vec<String>>,
}

/// Arguments for `contacts_set_group_membership`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SetGroupMembershipParams {
    /// Id of an existing group, from `contacts_search` with `include_groups`
    /// or from a contact's `groups`.
    pub group: String,
    /// Id of the contact to add or remove.
    pub contact: String,
    /// `add` or `remove`.
    pub action: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct LabeledOut {
    /// Untrusted content.
    pub(crate) value: String,
    /// Untrusted content.
    pub(crate) label: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct GroupOut {
    /// Pass as `group` to `contacts_set_group_membership`.
    pub(crate) id: String,
    /// Untrusted content.
    pub(crate) name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ContactOut {
    pub(crate) id: String,
    pub(crate) etag: String,
    /// Untrusted content.
    pub(crate) name: String,
    pub(crate) emails: Vec<LabeledOut>,
    pub(crate) phones: Vec<LabeledOut>,
    /// Untrusted content.
    pub(crate) organization: Option<String>,
    /// Untrusted content.
    pub(crate) note: Option<String>,
    /// The card is a group, not a person.
    pub(crate) is_group: bool,
    /// Groups the contact is in. Only `contacts_get` fills this.
    pub(crate) groups: Vec<GroupOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ContactListOut {
    pub(crate) contacts: Vec<ContactOut>,
    /// Cards that could not be read and were skipped.
    pub(crate) warnings: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct MembershipOut {
    pub(crate) updated: bool,
}
