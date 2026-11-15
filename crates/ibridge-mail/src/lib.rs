// SPDX-License-Identifier: Apache-2.0

//! IMAP and SMTP mail provider.

mod imap;
mod mime;
mod session;
mod smtp;

pub use imap::ImapPool;
pub use session::MailSession;
pub use smtp::{OutgoingMail, SmtpClient};
