// SPDX-License-Identifier: Apache-2.0

//! IMAP and SMTP mail provider.

mod html;
mod imap;
mod limits;
mod mime;
mod session;
mod smtp;

pub use imap::{Connect, IcloudConnect, ImapPool};
pub use limits::{SendLimits, SendWindow};
pub use session::{MailSession, SendOutcome, UnsubscribeOutcome};
pub use smtp::{OutgoingMail, SmtpClient};
