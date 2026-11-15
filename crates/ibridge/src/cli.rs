// SPDX-License-Identifier: Apache-2.0

//! Command line.

use clap::{Parser, Subcommand};

use crate::serve::Access;

/// iCloud Mail, Calendar, Reminders and Contacts for MCP clients.
#[derive(Debug, Parser)]
#[command(name = "ibridge", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Checks an app-specific password, stores it in the keychain and prints the setup line for Claude Code.
    Login,
    /// Removes the stored password and account state.
    Logout,
    /// Runs the MCP server.
    Serve {
        /// Speak MCP over stdin and stdout. Logs go to stderr.
        #[arg(long)]
        stdio: bool,
        /// Hide and reject every tool that changes mail.
        #[arg(long)]
        read_only: bool,
    },
}

/// Parses the command line and runs the command.
pub(crate) async fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Login => crate::login::run().await,
        Command::Logout => {
            crate::platform::install_keychain()?;
            crate::login::logout()
        }
        Command::Serve { stdio, read_only } => {
            if !stdio {
                anyhow::bail!("choose a transport: --stdio");
            }
            let access = if read_only {
                Access::ReadOnly
            } else {
                Access::ReadWrite
            };
            crate::serve::stdio(access).await
        }
    }
}
