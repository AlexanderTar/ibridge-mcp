// SPDX-License-Identifier: Apache-2.0

//! `ibridge serve --hosted`: the OAuth server and the MCP endpoint for many accounts.

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
