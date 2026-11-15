// SPDX-License-Identifier: Apache-2.0

//! IMAP and SMTP mail provider.

mod imap;
mod mime;
mod smtp;

pub use imap::ImapPool;
pub use smtp::{OutgoingMail, SmtpClient};
