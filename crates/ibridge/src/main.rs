// SPDX-License-Identifier: Apache-2.0

//! iCloud Mail, Calendar, Reminders and Contacts MCP server.

mod account;
mod calendar;
mod cli;
mod login;
mod mail;
mod platform;
mod serve;
mod validate;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
