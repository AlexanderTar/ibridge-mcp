// SPDX-License-Identifier: Apache-2.0

//! `ibridge serve --stdio` and `ibridge serve --http`.

use std::sync::Arc;

use anyhow::Context as _;
use ibridge_auth::{CredentialSource as _, Credentials, EnvSource, KeyringSource};
use ibridge_core::{CalendarProvider, ContactsProvider, RemindersProvider};
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
pub(crate) fn assemble<M, C, K>(
    services: Services,
    access: Access,
    account: AccountSnapshot,
    mail: Arc<M>,
    calendar: Arc<C>,
    contacts: Arc<K>,
) -> IbridgeServer<M, C, K>
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    let server = match access {
        Access::ReadOnly => IbridgeServer::read_only(account, mail),
        Access::ReadWrite => IbridgeServer::read_write(account, mail),
    }
    .with_calendar(calendar)
    .with_contacts(contacts);
    // Stdio and the local daemon both build here. A hosted server does not, so it never writes files.
    let server = match crate::downloads::dir() {
        Some(dir) => server.with_downloads(dir),
        None => server,
    };
    let server = if services.calendar {
        server
    } else {
        server.without_calendar()
    };
    let server = if services.contacts {
        server
    } else {
        server.without_contacts()
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
pub(crate) async fn credentials() -> anyhow::Result<(Credentials, Option<State>)> {
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
    let contacts = crate::contacts::backend(&credentials)?;
    let server = assemble(services, access, account, mail, calendar, contacts);
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

/// The local daemon's router: every request needs the daemon token.
#[cfg(feature = "http")]
fn http_app<M, C, K>(
    server: IbridgeServer<M, C, K>,
    token: crate::token::DaemonToken,
) -> ibridge_server::http::Router
where
    M: MailApi + Send + Sync + 'static,
    C: CalendarProvider + RemindersProvider + Send + Sync + 'static,
    K: ContactsProvider + Send + Sync + 'static,
{
    use ibridge_server::http::{base_config, local_router, mcp_service};

    let service = mcp_service(move || server.clone(), base_config());
    local_router(service, Arc::new(move |presented| token.matches(presented)))
}

/// Serves MCP over HTTP on a loopback address until the process is stopped.
///
/// # Errors
///
/// Returns an error when `addr` is not a loopback address, when no account is
/// signed in, or when the socket cannot be served.
#[cfg(feature = "http")]
pub(crate) async fn http(addr: std::net::SocketAddr, access: Access) -> anyhow::Result<()> {
    init_logging();
    ibridge_server::http::check_loopback(addr)?;
    crate::platform::install_keychain()?;
    let token = crate::token::DaemonToken::get_or_create()?;
    let (credentials, state) = credentials().await?;
    let services = Services::built();
    let account = snapshot(credentials.apple_id.clone(), services, state.as_ref());
    let mail = crate::mail::backend(&credentials)?;
    let calendar = crate::calendar::backend(&credentials)?;
    let contacts = crate::contacts::backend(&credentials)?;
    let server = assemble(services, access, account, mail, calendar, contacts);
    let listener = ibridge_server::http::bind_loopback(addr).await?;
    tracing::info!(addr = %listener.local_addr()?, ?access, "serving MCP over HTTP");
    ibridge_server::http::serve(
        listener,
        http_app(server, token),
        crate::platform::shutdown_signal(),
    )
    .await?;
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

#[cfg(all(test, feature = "http"))]
mod http_tests {
    use std::sync::Arc;

    use ibridge_core::AppleId;
    use ibridge_server::http::{bind_loopback, serve};
    use ibridge_server::{NoCalendar, NoContacts};
    use ibridge_testkit::http::{Reply, send};
    use serde_json::{Value, json};
    use tokio::sync::oneshot;

    use super::{Access, assemble, http_app};
    use crate::account::{Services, snapshot};
    use crate::mail::NoMail;
    use crate::testing::{KEYCHAIN, mock_keychain};
    use crate::token::DaemonToken;

    struct Daemon {
        url: String,
        bearer: String,
        stop: Option<oneshot::Sender<()>>,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    impl Daemon {
        async fn start(access: Access) -> Self {
            let services = Services {
                mail: true,
                calendar: true,
                contacts: true,
            };
            let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
            let account = snapshot(apple_id, services, None);
            let server = assemble(
                services,
                access,
                account,
                Arc::new(NoMail),
                Arc::new(NoCalendar),
                Arc::new(NoContacts),
            );
            let token = DaemonToken::get_or_create().expect("token");
            let bearer = token.with_secret(|secret| format!("Bearer {secret}"));
            let listener = bind_loopback("127.0.0.1:0".parse().expect("address"))
                .await
                .expect("loopback binds");
            let addr = listener.local_addr().expect("bound address");
            let (stop, stopped) = oneshot::channel();
            tokio::spawn(async move {
                let _ = serve(listener, http_app(server, token), async move {
                    let _ = stopped.await;
                })
                .await;
            });
            Self {
                url: format!("http://{addr}/mcp"),
                bearer,
                stop: Some(stop),
            }
        }

        async fn post(&self, extra: &[(&str, &str)], body: &Value) -> Reply {
            let mut headers = vec![
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("authorization", self.bearer.as_str()),
            ];
            headers.extend_from_slice(extra);
            send("POST", &self.url, &headers, &body.to_string()).await
        }
    }

    /// The JSON-RPC message in a reply, whether it came as JSON or as one SSE event.
    fn message(reply: &Reply) -> Value {
        let text = reply
            .body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .find(|data| !data.trim().is_empty())
            .unwrap_or(&reply.body);
        serde_json::from_str(text.trim())
            .unwrap_or_else(|error| panic!("a JSON-RPC message, got {:?}: {error}", reply.body))
    }

    fn tool_names(reply: &Reply) -> Vec<String> {
        message(reply)["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a tool list, got {:?}", reply.body))
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect()
    }

    /// A stateless `tools/list` or `tools/call`.
    async fn stateless(daemon: &Daemon, method: &str, params: &Value) -> Reply {
        let mut params = params.clone();
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        daemon
            .post(
                &[
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", method),
                ],
                &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            )
            .await
    }

    #[tokio::test]
    async fn read_only_flag_hides_writes_over_http() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();

        let read_only = Daemon::start(Access::ReadOnly).await;
        let listed = stateless(&read_only, "tools/list", &json!({})).await;
        let tools = message(&listed)["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a tool list, got {:?}", listed.body))
            .clone();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        for tool in &tools {
            assert_eq!(
                tool["annotations"]["readOnlyHint"], true,
                "{} is listed in a read-only daemon but is not a read tool",
                tool["name"]
            );
        }
        for read in [
            "account_status",
            "mail_search",
            "calendar_list_events",
            "contacts_search",
        ] {
            assert!(names.contains(&read), "{read} stays, got {names:?}");
        }
        for write in [
            "mail_send",
            "mail_save_attachment",
            "calendar_create_event",
            "contacts_create",
        ] {
            assert!(!names.contains(&write), "{write} is hidden, got {names:?}");
        }
        let refused = stateless(
            &read_only,
            "tools/call",
            &json!({"name": "mail_send", "arguments": {"to": ["bob@example.com"], "subject": "s", "body": "b"}}),
        )
        .await;
        assert!(
            message(&refused).get("error").is_some(),
            "a direct write call over HTTP is refused, got {:?}",
            refused.body
        );

        let read_write = Daemon::start(Access::ReadWrite).await;
        let listed = stateless(&read_write, "tools/list", &json!({})).await;
        let names = tool_names(&listed);
        for write in ["mail_send", "mail_save_attachment", "calendar_create_event"] {
            assert!(
                names.iter().any(|name| name == write),
                "a read-write daemon offers {write}, got {names:?}"
            );
        }
    }

    #[tokio::test]
    async fn e2e_http_tools_list() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let daemon = Daemon::start(Access::ReadWrite).await;
        let list = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }},
        });
        let unauthenticated = send(
            "POST",
            &daemon.url,
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
            &list.to_string(),
        )
        .await;
        assert_eq!(unauthenticated.status, 401, "the daemon needs the token");
        let reply = daemon
            .post(
                &[
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/list"),
                ],
                &list,
            )
            .await;
        assert_eq!(reply.status, 200, "stateless client: {}", reply.body);
        assert!(
            reply.header("mcp-session-id").is_none(),
            "a 2026-07-28 client gets no session"
        );
        assert_eq!(
            reply.header("content-type"),
            Some("application/json"),
            "a stateless client gets a plain JSON response"
        );
        assert!(
            tool_names(&reply)
                .iter()
                .any(|name| name == "account_status"),
            "the tool list is served, got {:?}",
            reply.body
        );
    }

    #[tokio::test]
    async fn e2e_legacy_session_client() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let daemon = Daemon::start(Access::ReadWrite).await;
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1.0"},
            },
        });
        let opened = daemon.post(&[], &initialize).await;
        assert_eq!(opened.status, 200, "initialize: {}", opened.body);
        assert_eq!(
            message(&opened)["result"]["protocolVersion"],
            "2025-11-25",
            "the server speaks the client's protocol version"
        );
        let session = opened
            .header("mcp-session-id")
            .expect("a legacy client is given a session")
            .to_owned();
        let session_header = [
            ("mcp-session-id", session.as_str()),
            ("mcp-protocol-version", "2025-11-25"),
        ];
        let ready = daemon
            .post(
                &session_header,
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .await;
        assert_eq!(ready.status, 202, "initialized: {}", ready.body);
        let listed = daemon
            .post(
                &session_header,
                &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            )
            .await;
        assert_eq!(listed.status, 200, "tools/list: {}", listed.body);
        assert!(
            tool_names(&listed)
                .iter()
                .any(|name| name == "account_status"),
            "the session lists tools, got {:?}",
            listed.body
        );
        let stray = daemon
            .post(
                &[("mcp-session-id", "no-such-session")],
                &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            )
            .await;
        assert_eq!(stray.status, 404, "an unknown session is refused");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ibridge_core::AppleId;
    use ibridge_server::{NoCalendar, NoContacts, ServiceStatus};

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
            Arc::new(NoContacts),
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
    fn local_servers_offer_save_attachment_unless_read_only() {
        let names = |access: Access| -> Vec<String> {
            let services = Services::built();
            let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
            assemble(
                services,
                access,
                snapshot(apple_id, services, None),
                Arc::new(NoMail),
                Arc::new(NoCalendar),
                Arc::new(NoContacts),
            )
            .tools()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect()
        };
        assert!(
            names(Access::ReadWrite)
                .iter()
                .any(|name| name == "mail_save_attachment"),
            "stdio and the daemon both build with assemble, which turns the tool on"
        );
        assert!(
            !names(Access::ReadOnly)
                .iter()
                .any(|name| name == "mail_save_attachment"),
            "read-only hides it"
        );
    }

    #[test]
    fn contacts_tools_follow_the_contacts_service() {
        let names = |contacts: bool| -> Vec<String> {
            let services = Services {
                mail: true,
                calendar: true,
                contacts,
            };
            let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
            let account = snapshot(apple_id, services, None);
            assemble(
                services,
                Access::ReadWrite,
                account,
                Arc::new(NoMail),
                Arc::new(NoCalendar),
                Arc::new(NoContacts),
            )
            .tools()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect()
        };
        let on = names(true);
        for tool in ["contacts_search", "contacts_set_group_membership"] {
            assert!(
                on.iter().any(|name| name == tool),
                "{tool} is listed, got {on:?}"
            );
        }
        let off = names(false);
        assert!(
            !off.iter().any(|name| name.starts_with("contacts_")),
            "contacts tools are hidden when contacts is off, got {off:?}"
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
                Arc::new(NoContacts),
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
