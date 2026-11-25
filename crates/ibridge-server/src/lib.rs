// SPDX-License-Identifier: Apache-2.0

//! MCP server, tool routers and error mapping.

mod account;
mod calendar_dto;
mod calendar_tools;
mod contacts_dto;
mod contacts_tools;
mod dto;
mod error_map;
mod handler;
pub mod http;
mod mail_api;
mod sanitize;
mod save;

#[cfg(test)]
mod tests;

pub use account::{AccountSnapshot, ServiceStatus};
pub use calendar_dto::{
    CreateEventParams, CreateReminderParams, DeleteParams, GetByIdParams, ListEventsParams,
    ListRemindersParams, UpdateEventParams, UpdateReminderParams,
};
pub use calendar_tools::NoCalendar;
pub use contacts_dto::{
    CreateContactParams, SearchContactsParams, SetGroupMembershipParams, UpdateContactParams,
};
pub use contacts_tools::NoContacts;
pub use dto::{
    FlagParams, GetAttachmentParams, GetMessageParams, MoveParams, SaveAttachmentParams,
    SearchParams, SendParams,
};
pub use error_map::{MappedError, map_core_error};
pub use handler::IbridgeServer;
pub use mail_api::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail, Unsubscribed};
