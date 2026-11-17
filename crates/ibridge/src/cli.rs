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
    /// Checks the keychain, the network and the sign-in for each service.
    Doctor,
    /// Installs, removes or checks the background service that serves MCP on loopback.
    #[cfg(feature = "http")]
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Runs the MCP server.
    Serve {
        /// Speak MCP over stdin and stdout. Logs go to stderr.
        #[arg(long)]
        stdio: bool,
        /// Speak MCP over HTTP on a loopback address, for example 127.0.0.1:8765.
        #[cfg(feature = "http")]
        #[arg(long, value_name = "ADDR", conflicts_with = "stdio")]
        http: Option<std::net::SocketAddr>,
        /// Hide and reject every tool that changes mail.
        #[arg(long)]
        read_only: bool,
        /// Run the hosted service: OAuth sign-in for many accounts, with `--http` as the listen address.
        #[cfg(feature = "hosted")]
        #[arg(
            long,
            conflicts_with_all = ["stdio", "read_only"],
            requires_all = ["http", "public_url", "data_dir"]
        )]
        hosted: bool,
        /// The https origin clients reach, for example `https://ibridge.fyi`.
        #[cfg(feature = "hosted")]
        #[arg(long, value_name = "URL", requires = "hosted")]
        public_url: Option<String>,
        /// Where the hosted database and its backups live.
        #[cfg(feature = "hosted")]
        #[arg(long, value_name = "DIR", requires = "hosted")]
        data_dir: Option<std::path::PathBuf>,
        /// Let any iCloud account sign in (the public service).
        #[cfg(feature = "hosted")]
        #[arg(long, requires = "hosted")]
        multi_tenant: bool,
    },
}

#[cfg(feature = "http")]
#[derive(Debug, Subcommand)]
enum DaemonAction {
    /// Installs and starts the service, then prints the setup line for Claude Code.
    Install {
        /// The loopback port the service listens on.
        #[arg(long, default_value_t = crate::daemon::DEFAULT_PORT)]
        port: u16,
        /// Hide and reject every tool that changes mail.
        #[arg(long)]
        read_only: bool,
    },
    /// Stops the service and removes it.
    Uninstall,
    /// Says whether the service is installed and running.
    Status,
}

/// Parses the command line and runs the command.
pub(crate) async fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Login => crate::login::run().await,
        Command::Doctor => crate::doctor::run().await,
        Command::Logout => {
            crate::platform::install_keychain()?;
            crate::login::logout()
        }
        #[cfg(feature = "http")]
        Command::Daemon { action } => match action {
            DaemonAction::Install { port, read_only } => crate::daemon::run_install(
                port,
                if read_only {
                    Access::ReadOnly
                } else {
                    Access::ReadWrite
                },
            ),
            DaemonAction::Uninstall => crate::daemon::run_uninstall(),
            DaemonAction::Status => crate::daemon::run_status(),
        },
        Command::Serve {
            stdio,
            #[cfg(feature = "http")]
            http,
            read_only,
            #[cfg(feature = "hosted")]
            hosted,
            #[cfg(feature = "hosted")]
            public_url,
            #[cfg(feature = "hosted")]
            data_dir,
            #[cfg(feature = "hosted")]
            multi_tenant,
        } => {
            #[cfg(feature = "hosted")]
            if hosted {
                // clap's `requires_all` guarantees these three are set.
                let (Some(addr), Some(public_url), Some(data_dir)) = (http, public_url, data_dir)
                else {
                    anyhow::bail!("--hosted needs --http, --public-url and --data-dir");
                };
                return crate::hosted::run(ibridge_hosted::HostedOptions {
                    addr,
                    public_url,
                    data_dir,
                    multi_tenant,
                })
                .await;
            }
            let access = if read_only {
                Access::ReadOnly
            } else {
                Access::ReadWrite
            };
            #[cfg(feature = "http")]
            if let Some(addr) = http {
                return crate::serve::http(addr, access).await;
            }
            if !stdio {
                anyhow::bail!("choose a transport: --stdio or --http <ADDR>");
            }
            crate::serve::stdio(access).await
        }
    }
}
