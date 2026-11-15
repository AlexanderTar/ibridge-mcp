// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.1 authorization server for the hosted MCP endpoint.

mod cimd;
mod client;
mod dcr;
mod metadata;

use std::fmt;
use std::sync::Arc;

use axum::Router;
use url::Url;

use crate::store::{Store, StoreError};

/// Where this server lives, as clients see it.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    public_url: Url,
}

/// The public URL cannot be used as an OAuth issuer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Not a URL, not https, or it carries a path, query or fragment.
    #[error("the public URL must be an https origin such as https://ibridge.fyi")]
    PublicUrl,
}

impl OAuthConfig {
    /// Builds the configuration for the public origin clients reach.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::PublicUrl`] unless `public_url` is an https origin
    /// (plain http is accepted for loopback hosts, which tests and local runs use).
    pub fn new(public_url: &str) -> Result<Self, ConfigError> {
        let url = Url::parse(public_url).map_err(|_| ConfigError::PublicUrl)?;
        let loopback = matches!(
            url.host(),
            Some(url::Host::Ipv4(ip)) if ip.is_loopback()
        ) || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
            || url.host_str() == Some("localhost");
        let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        let origin_only = matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none();
        if !scheme_ok || !origin_only {
            return Err(ConfigError::PublicUrl);
        }
        Ok(Self { public_url: url })
    }

    /// The issuer identifier: the public origin with no trailing slash.
    pub(crate) fn issuer(&self) -> String {
        self.public_url.as_str().trim_end_matches('/').to_owned()
    }

    /// An absolute URL on this server.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer())
    }
}

pub(crate) struct Shared {
    pub(crate) config: OAuthConfig,
    pub(crate) registry: dcr::ClientRegistry,
    pub(crate) clients: Arc<dyn cimd::ClientSource>,
}

impl Shared {
    /// The client `client_id` names: a metadata document URL, or an id DCR issued.
    #[expect(
        dead_code,
        reason = "the authorize page looks clients up in the next unit"
    )]
    pub(crate) async fn resolve_client(&self, client_id: &str) -> Option<client::ClientInfo> {
        if client_id.starts_with("https://") || client_id.starts_with("http://") {
            return self.clients.resolve(client_id).await.ok();
        }
        self.registry.get(client_id).await.ok().flatten()
    }
}

impl fmt::Debug for Shared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// Routes for discovery, registration, sign-in and tokens.
///
/// # Errors
///
/// Returns [`StoreError`] when the client table cannot be created.
pub async fn router(config: OAuthConfig, store: &Store) -> Result<Router, StoreError> {
    let transport = cimd::HttpsTransport::new().map_err(|_| StoreError::Rejected)?;
    router_with(config, store, Arc::new(cimd::CimdFetcher::new(transport))).await
}

/// [`router`] with the client lookup replaced, so tests can name clients without a network.
pub(crate) async fn router_with(
    config: OAuthConfig,
    store: &Store,
    clients: Arc<dyn cimd::ClientSource>,
) -> Result<Router, StoreError> {
    let registry = dcr::ClientRegistry::open(store).await?;
    let shared = Arc::new(Shared {
        config,
        registry,
        clients,
    });
    Ok(Router::new()
        .merge(metadata::routes(&shared))
        .merge(dcr::routes(&shared)))
}
