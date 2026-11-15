// SPDX-License-Identifier: Apache-2.0

//! `ibridge serve --stdio`.

use std::sync::Arc;

use anyhow::Context as _;
use ibridge_auth::{CredentialSource as _, Credentials, EnvSource, KeyringSource};
use ibridge_core::{CalendarProvider, RemindersProvider};
use ibridge_server::{AccountSnapshot, IbridgeServer, MailApi};

use crate::account::{Services, State, snapshot};

/// Whether write tools are offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Write tools are hidden and rejected.
    ReadOnly,
    /// Read and write tools are offered.
    ReadWrite,
}

/// Builds the server for one account.
///
/// A build without mail hides the mail tools. [`Access::ReadOnly`] hides every write tool.
pub(crate) fn assemble<M, C>(
    services: Services,
    access: Access,
    account: AccountSnapshot,
    mail: Arc<M>,
    calendar: Arc<C>,
) -> IbridgeServer<M, C>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
{
    let server = match access {
        Access::ReadOnly => IbridgeServer::read_only(account, mail),
        Access::ReadWrite => IbridgeServer::read_write(account, mail),
    }
    .with_calendar(calendar);
    let server = if services.calendar {
        server
    } else {
        server.without_calendar()
    };
    if services.mail {
        server
    } else {
        server.without_mail()
    }
}

/// Sends logs to stderr. stdout is reserved for JSON-RPC.
pub(crate) fn init_logging() {
    let level = std::env::var("IBRIDGE_LOG")
        .ok()
        .and_then(|value| value.parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    let _already_set = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

/// Reads the account from the environment, then from the keychain.
async fn credentials() -> anyhow::Result<(Credentials, Option<State>)> {
    if let Ok(credentials) = EnvSource::new().credentials().await {
        return Ok((credentials, None));
    }
    crate::platform::install_keychain()?;
    let state = State::load()?.context("no account is signed in; run `ibridge login`")?;
    let credentials = KeyringSource::new(state.apple_id()?)
        .credentials()
        .await
        .context("the saved password is missing; run `ibridge login`")?;
    Ok((credentials, Some(state)))
}

/// Serves MCP on stdin and stdout until the client closes the pipe.
///
/// # Errors
///
/// Returns an error when no account is signed in or the transport fails.
#[cfg(feature = "stdio")]
pub(crate) async fn stdio(access: Access) -> anyhow::Result<()> {
    use rmcp::ServiceExt as _;

    init_logging();
    let (credentials, state) = credentials().await?;
    let services = Services::built();
    let account = snapshot(credentials.apple_id.clone(), services, state.as_ref());
    let mail = crate::mail::backend(&credentials)?;
    let calendar = crate::calendar::backend(&credentials)?;
    let server = assemble(services, access, account, mail, calendar);
    tracing::info!(?access, "serving MCP over stdio");
    server
        .serve(rmcp::transport::stdio())
        .await
        .context("could not start the MCP session")?
        .waiting()
        .await
        .context("the MCP session ended with an error")?;
    Ok(())
}

/// A build without stdio cannot serve it.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(feature = "stdio"))]
#[expect(
    clippy::unused_async,
    reason = "keeps the signature the same as the stdio build"
)]
pub(crate) async fn stdio(_access: Access) -> anyhow::Result<()> {
    anyhow::bail!("this build has no stdio transport")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ibridge_core::AppleId;
    use ibridge_server::{NoCalendar, ServiceStatus};

    use super::{Access, assemble};
    use crate::account::{Services, snapshot};
    use crate::mail::NoMail;

    #[test]
    fn mail_feature_off_hides_mail_tools() {
        let services = Services {
            mail: false,
            calendar: true,
            contacts: true,
        };
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        let account = snapshot(apple_id, services, None);
        assert!(
            matches!(account.mail, ServiceStatus::Off { .. }),
            "a build without mail reports mail off, got {:?}",
            account.mail
        );
        let server = assemble(
            services,
            Access::ReadWrite,
            account,
            Arc::new(NoMail),
            Arc::new(NoCalendar),
        );
        let names: Vec<String> = server
            .tools()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        assert!(
            !names.iter().any(|name| name.starts_with("mail_")),
            "mail tools are hidden when mail is off, got {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "account_status"),
            "account_status stays, got {names:?}"
        );
    }

    #[test]
    fn calendar_tools_follow_the_calendar_service() {
        let names = |calendar: bool| -> Vec<String> {
            let services = Services {
                mail: true,
                calendar,
                contacts: true,
            };
            let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
            let account = snapshot(apple_id, services, None);
            assemble(
                services,
                Access::ReadWrite,
                account,
                Arc::new(NoMail),
                Arc::new(NoCalendar),
            )
            .tools()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect()
        };
        let on = names(true);
        for tool in ["calendar_list_events", "reminders_list"] {
            assert!(
                on.iter().any(|name| name == tool),
                "{tool} is listed, got {on:?}"
            );
        }
        let off = names(false);
        assert!(
            !off.iter()
                .any(|name| name.starts_with("calendar_") || name.starts_with("reminders_")),
            "a build without calendar hides its tools, got {off:?}"
        );
    }
}
