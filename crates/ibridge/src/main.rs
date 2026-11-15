// SPDX-License-Identifier: Apache-2.0

//! iCloud Mail, Calendar, Reminders and Contacts MCP server.

mod account;
mod calendar;
mod cli;
mod contacts;
#[cfg(feature = "http")]
mod daemon;
mod login;
mod mail;
mod platform;
mod serve;
#[cfg(test)]
mod testing;
#[cfg(feature = "http")]
mod token;
mod validate;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
