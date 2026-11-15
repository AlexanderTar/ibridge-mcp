// SPDX-License-Identifier: Apache-2.0

//! MCP server, tool routers and error mapping.

mod account;
mod dto;
mod error_map;
mod handler;
mod mail_api;
mod untrusted;

#[cfg(test)]
mod tests;

pub use account::{AccountSnapshot, ServiceStatus};
pub use dto::{
    FlagParams, GetAttachmentParams, GetMessageParams, MoveParams, SearchParams, SendParams,
};
pub use error_map::{MappedError, map_core_error};
pub use handler::IbridgeServer;
pub use mail_api::{MailApi, MailBody, MailDest, MailHitPage, MailPart, SentMail};
pub use untrusted::wrap_untrusted;
