// SPDX-License-Identifier: Apache-2.0

//! The MCP handler behind `/mcp`: one handler for every account, choosing a server per call.
//!
//! The Streamable HTTP service builds its handler before it sees a request, so the
//! account and scope cannot be baked in. This handler reads who is calling from the
//! request's extensions, where the middleware put it, and hands the call to that
//! account's server for the grant's scope.

use std::sync::Arc;

use axum::Router;
use ibridge_server::http::{base_config, mcp_service};
use rmcp::RoleServer;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData, Icon,
    ListToolsResult, PaginatedRequestParams, ServerConfig,
};
use rmcp::service::RequestContext;

use crate::billing::Access;
use crate::middleware::CallAuth;
use crate::oauth::OAuthConfig;
use crate::store::Scope;

/// An account's two servers: the one a read-only grant gets and the one a read-write grant gets.
#[derive(Debug)]
pub struct ScopedServers<S> {
    /// Hides write tools and rejects write calls.
    pub read_only: S,
    /// Shows every tool.
    pub read_write: S,
}

impl<S> ScopedServers<S> {
    fn for_scope(&self, scope: Scope) -> &S {
        match scope {
            Scope::Read => &self.read_only,
            // `Scope` is non-exhaustive; any other scope must not gain writes by default.
            _ => &self.read_write,
        }
    }
}

/// Finds the servers for the account a call belongs to.
pub trait ServerSource: Send + Sync + 'static {
    /// The server type, one per scope.
    type Server: ServerHandler + Send + Sync + 'static;

    /// The account's servers. `call` names the account.
    fn servers(&self, call: &CallAuth) -> Arc<ScopedServers<Self::Server>>;
}

/// The `/mcp` route, serving `source`'s accounts.
///
/// The service answers only to the public host, so a request that reached it under
/// another name (DNS rebinding) is refused. It has no auth of its own: pass the
/// router to [`crate::router`], which puts it behind the token check.
///
/// `info` is reported as given, with `serverInfo.icons` set to the root favicons at the public URL.
pub fn mcp_router<P: ServerSource>(
    source: Arc<P>,
    mut info: ServerConfig,
    config: &OAuthConfig,
) -> Router {
    // The icons are the root favicons `assets::routes` serves, at the public URL.
    info.server_info.icons = Some(vec![
        Icon::new(config.url("/favicon.svg"))
            .with_mime_type("image/svg+xml")
            .with_sizes(vec!["any".to_owned()]),
        Icon::new(config.url("/favicon-32.png"))
            .with_mime_type("image/png")
            .with_sizes(vec!["32x32".to_owned()]),
    ]);
    let handler = HostedHandler::new(source, info).with_account_url(config.url("/account"));
    let service = mcp_service(
        move || handler.clone(),
        base_config().with_allowed_hosts([config.host()]),
    );
    Router::new().nest_service("/mcp", service)
}

/// Who is calling, as the middleware recorded it on the request.
pub(crate) fn call_auth(context: &RequestContext<RoleServer>) -> Result<&CallAuth, ErrorData> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<CallAuth>())
        .ok_or_else(|| ErrorData::internal_error("internal error", None))
}

/// An account's servers, and the scope of the call that asked.
type Picked<S> = (Arc<ScopedServers<S>>, Scope);

/// The handler for the hosted `/mcp` endpoint.
#[derive(Debug)]
pub struct HostedHandler<P> {
    source: Arc<P>,
    info: ServerConfig,
    account_url: Option<String>,
}

impl<P> Clone for HostedHandler<P> {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
            info: self.info.clone(),
            account_url: self.account_url.clone(),
        }
    }
}

impl<P: ServerSource> HostedHandler<P> {
    /// Builds the handler. `info` is what `initialize` reports for every account.
    #[must_use]
    pub fn new(source: Arc<P>, info: ServerConfig) -> Self {
        Self {
            source,
            info,
            account_url: None,
        }
    }

    /// The account page a caller without a plan is pointed to.
    #[must_use]
    pub fn with_account_url(mut self, url: String) -> Self {
        self.account_url = Some(url);
        self
    }

    /// The tool error a caller without a plan gets, in place of the tool's answer.
    fn no_plan(&self) -> CallToolResponse {
        let text = match &self.account_url {
            Some(url) => format!(
                "Your ibridge subscription is not active. Subscribe or manage your plan at {url}, then try again."
            ),
            None => "Your ibridge subscription is not active.".to_owned(),
        };
        CallToolResponse::Complete(CallToolResult::error(vec![ContentBlock::text(text)]))
    }

    fn server_for(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<Picked<P::Server>, ErrorData> {
        let call = call_auth(context)?;
        Ok((self.source.servers(call), call.scope()))
    }
}

impl<P: ServerSource> ServerHandler for HostedHandler<P> {
    fn get_info(&self) -> ServerConfig {
        self.info.clone()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let (servers, scope) = self.server_for(&context)?;
        servers.for_scope(scope).list_tools(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // `initialize`, discovery and `tools/list` need no plan; a call to a tool does.
        if call_auth(&context)?.access() == Access::Denied {
            return Ok(self.no_plan());
        }
        let (servers, scope) = self.server_for(&context)?;
        servers.for_scope(scope).call_tool(request, context).await
    }
}
