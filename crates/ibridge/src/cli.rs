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
    /// Operator commands for the hosted service, run on its host (for example with `railway ssh`).
    #[cfg(feature = "hosted")]
    Admin {
        /// Where the hosted database lives.
        #[arg(long, value_name = "DIR", default_value = "/data", global = true)]
        data_dir: std::path::PathBuf,
        #[command(subcommand)]
        action: AdminCommand,
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

#[cfg(feature = "hosted")]
#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Blocks an account: its tokens, API keys and sign-in stop working. Nothing is deleted.
    Suspend {
        /// The account's iCloud address, in any letter case.
        apple_id: String,
    },
    /// Deletes an account and every sealed copy of its password.
    Delete {
        /// The account's iCloud address, in any letter case.
        apple_id: String,
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
        #[cfg(feature = "hosted")]
        Command::Admin { data_dir, action } => {
            let (action, apple_id) = match action {
                AdminCommand::Suspend { apple_id } => {
                    (ibridge_hosted::AdminAction::Suspend, apple_id)
                }
                AdminCommand::Delete { apple_id } => {
                    (ibridge_hosted::AdminAction::Delete, apple_id)
                }
            };
            crate::hosted::admin(&data_dir, action, &apple_id).await
        }
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

#[cfg(all(test, feature = "hosted"))]
mod tests {
    use clap::Parser;

    use super::{AdminCommand, Cli, Command};

    #[test]
    fn admin_takes_an_action_an_address_and_a_data_dir() {
        let cli =
            Cli::try_parse_from(["ibridge", "admin", "suspend", "ada@icloud.com"]).expect("parses");
        let Command::Admin { data_dir, action } = cli.command else {
            panic!("not the admin command");
        };
        assert_eq!(
            data_dir,
            std::path::Path::new("/data"),
            "the container's volume by default"
        );
        assert!(
            matches!(action, AdminCommand::Suspend { apple_id } if apple_id == "ada@icloud.com")
        );

        let cli = Cli::try_parse_from([
            "ibridge",
            "admin",
            "delete",
            "ada@icloud.com",
            "--data-dir",
            "/tmp/x",
        ])
        .expect("the flag comes after the action");
        let Command::Admin { data_dir, action } = cli.command else {
            panic!("not the admin command");
        };
        assert_eq!(data_dir, std::path::Path::new("/tmp/x"));
        assert!(matches!(action, AdminCommand::Delete { .. }));
        assert!(
            Cli::try_parse_from(["ibridge", "admin", "suspend"]).is_err(),
            "an address is required"
        );
    }
}
