// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.1 authorization server for the hosted MCP endpoint.

mod authorize;
mod check;
mod cimd;
mod client;
mod codes;
mod dcr;
mod metadata;

#[cfg(test)]
mod test_support;

use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ibridge_core::AppleId;
use url::Url;

use crate::limits::{Limiter, SignInLimits};
use crate::store::{Store, StoreError};

pub use check::{Combined, SignInCheck, ValidatedBy, validated_by};

/// Who may sign in.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Access {
    /// Anyone with a valid iCloud address and app-specific password (the public service).
    MultiTenant,
    /// Only these addresses (self-host).
    AllowList(Vec<AppleId>),
}

/// Where this server lives, as clients see it, and who may sign in.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    public_url: Url,
    allowed: Option<HashSet<String>>,
    behind_proxy: bool,
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
    pub fn new(public_url: &str, access: Access) -> Result<Self, ConfigError> {
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
        let allowed = match access {
            Access::AllowList(ids) => Some(ids.iter().map(address_key).collect()),
            Access::MultiTenant => None,
        };
        Ok(Self {
            public_url: url,
            allowed,
            behind_proxy: false,
        })
    }

    /// Reads the client address from the last `X-Forwarded-For` entry, which the
    /// platform's proxy appends. Turn this on only behind such a proxy: anyone
    /// who can reach the server directly could otherwise pick their own address.
    #[must_use]
    pub fn behind_proxy(mut self) -> Self {
        self.behind_proxy = true;
        self
    }

    /// The issuer identifier: the public origin with no trailing slash.
    pub(crate) fn issuer(&self) -> String {
        self.public_url.as_str().trim_end_matches('/').to_owned()
    }

    /// An absolute URL on this server.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer())
    }

    /// False when an allowlist is set and `apple_id` is not on it.
    pub(crate) fn may_sign_in(&self, apple_id: &AppleId) -> bool {
        self.allowed
            .as_ref()
            .is_none_or(|allowed| allowed.contains(&address_key(apple_id)))
    }
}

/// The form of an address used for allowlists and rate limits.
pub(crate) fn address_key(apple_id: &AppleId) -> String {
    apple_id.as_str().to_ascii_lowercase()
}

/// The address a request came from, for rate limits.
#[derive(Debug)]
pub(crate) struct Peer(pub(crate) String);

impl FromRequestParts<Arc<Shared>> for Peer {
    type Rejection = Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "reads the request head and never waits"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        shared: &Arc<Shared>,
    ) -> Result<Self, Self::Rejection> {
        let forwarded = shared
            .config
            .behind_proxy
            .then(|| {
                parts
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.rsplit(',').next())
                    .map(|entry| entry.trim().to_owned())
            })
            .flatten();
        let direct = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip().to_string());
        Ok(Self(
            forwarded.or(direct).unwrap_or_else(|| "unknown".to_owned()),
        ))
    }
}

pub(crate) struct Shared {
    pub(crate) config: OAuthConfig,
    pub(crate) store: Store,
    pub(crate) registry: dcr::ClientRegistry,
    pub(crate) clients: Arc<dyn cimd::ClientSource>,
    pub(crate) checker: Arc<dyn SignInCheck>,
    pub(crate) limits: SignInLimits,
    pub(crate) lookups: Limiter,
    pub(crate) registrations: Limiter,
    pub(crate) codes: codes::PendingCodes,
}

impl Shared {
    /// The client `client_id` names: a metadata document URL, or an id DCR issued.
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
/// Returns [`StoreError`] when the client table cannot be created or the
/// system has no TLS roots to fetch client metadata with.
pub async fn router(
    config: OAuthConfig,
    store: &Store,
    checker: impl SignInCheck,
) -> Result<Router, StoreError> {
    let transport = cimd::HttpsTransport::new().map_err(|_| StoreError::Rejected)?;
    router_with(
        config,
        store,
        Arc::new(cimd::CimdFetcher::new(transport)),
        Arc::new(checker),
    )
    .await
}

/// [`router`] with the client lookup replaced, so tests can name clients without a network.
pub(crate) async fn router_with(
    config: OAuthConfig,
    store: &Store,
    clients: Arc<dyn cimd::ClientSource>,
    checker: Arc<dyn SignInCheck>,
) -> Result<Router, StoreError> {
    let registry = dcr::ClientRegistry::open(store).await?;
    let shared = Arc::new(Shared {
        config,
        store: store.clone(),
        registry,
        clients,
        checker,
        limits: SignInLimits::new(),
        lookups: Limiter::new(30, Duration::from_mins(1)),
        registrations: Limiter::new(10, Duration::from_hours(1)),
        codes: codes::PendingCodes::default(),
    });
    Ok(Router::new()
        .merge(metadata::routes(&shared))
        .merge(dcr::routes(&shared))
        .merge(authorize::routes(&shared)))
}
