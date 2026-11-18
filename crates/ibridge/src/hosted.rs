// SPDX-License-Identifier: Apache-2.0

//! `ibridge serve --hosted`: the OAuth server and the MCP endpoint for many accounts.

use std::io::Write as _;
use std::sync::Arc;

use anyhow::Context as _;
use ibridge_auth::{AuthError, Credentials, ValidationReport, Validator};
use ibridge_core::AppleId;
use ibridge_hosted::{HostedConfig, HostedOptions, IcloudBackend, validated_by};
use ibridge_server::{AccountSnapshot, IbridgeServer, ServiceStatus};
use tokio::net::TcpListener;

use crate::mail::NoMail;

/// A sign-in check built from this build's validators, or a refusal when they cannot be built.
struct Check<V>(Option<V>);

impl<V: Validator + Sync> Validator for Check<V> {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        match &self.0 {
            Some(validator) => validator.validate().await,
            None => Err(AuthError::Validation),
        }
    }
}

/// What `initialize` reports. The account named here is never shown: each call builds its own.
fn info() -> rmcp::model::ServerConfig {
    let placeholder = AccountSnapshot {
        apple_id: AppleId::try_from("placeholder@icloud.com").expect("a valid address"),
        mail: ServiceStatus::On,
        calendar: ServiceStatus::On,
        contacts: ServiceStatus::On,
    };
    rmcp::ServerHandler::get_info(&IbridgeServer::read_only(placeholder, Arc::new(NoMail)))
}

/// Serves the hosted server until the process is asked to stop.
///
/// # Errors
///
/// Returns an error when the configuration is refused, the socket or database
/// cannot be opened, or serving fails.
pub(crate) async fn run(options: HostedOptions) -> anyhow::Result<()> {
    ibridge_hosted::logging::init();
    let config = HostedConfig::resolve(options, |name| std::env::var(name).ok())?;
    let backend = IcloudBackend::icloud()
        .map_err(|_| anyhow::anyhow!("the system has no root certificates to check iCloud with"))?;
    let listener = TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("could not listen on {}", config.addr))?;
    tracing::info!(addr = %listener.local_addr()?, "serving MCP over HTTP, hosted");
    ibridge_hosted::serve(
        config,
        listener,
        backend,
        validated_by(|credentials: &Credentials| {
            Check(crate::validate::hosted_validator(credentials).ok())
        }),
        info(),
        crate::platform::shutdown_signal(),
    )
    .await?;
    Ok(())
}

/// Runs an operator command against the database under `data_dir`.
///
/// # Errors
///
/// Returns an error when an address is not an iCloud address, nothing matches, or the
/// database cannot be opened or updated.
pub(crate) async fn admin(
    data_dir: &std::path::Path,
    command: crate::cli::AdminCommand,
) -> anyhow::Result<()> {
    use crate::cli::AdminCommand;
    use ibridge_hosted::AdminAction;

    let text = match &command {
        AdminCommand::Suspend { apple_id } | AdminCommand::Delete { apple_id } => {
            let address = AppleId::try_from(apple_id.trim()).context("not an iCloud address")?;
            let suspend = matches!(command, AdminCommand::Suspend { .. });
            let action = if suspend {
                AdminAction::Suspend(&address)
            } else {
                AdminAction::Delete(&address)
            };
            let matched = ibridge_hosted::admin(data_dir, action).await?;
            anyhow::ensure!(matched > 0, "no account has the address {address}");
            if suspend {
                format!(
                    "Suspended {matched} account(s) for {address}. The running server refuses their tokens from the next call and closes their idle sessions within minutes."
                )
            } else {
                format!(
                    "Deleted {matched} account(s) for {address}, with every sealed copy of their password."
                )
            }
        }
        AdminCommand::Comp { user } | AdminCommand::Uncomp { user } => {
            let user = user.trim();
            let comp = matches!(command, AdminCommand::Comp { .. });
            let action = if comp {
                AdminAction::Comp(user)
            } else {
                AdminAction::Uncomp(user)
            };
            let matched = ibridge_hosted::admin(data_dir, action).await?;
            anyhow::ensure!(matched > 0, "no user has the email or uid {user}");
            if comp {
                format!("{user} now has the plan for free.")
            } else {
                format!("{user} no longer has free access.")
            }
        }
    };
    writeln!(std::io::stdout().lock(), "{text}")?;
    Ok(())
}
