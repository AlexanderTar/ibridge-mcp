// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.1 authorization server for the hosted MCP endpoint.

mod authorize;
mod check;
mod cimd;
mod client;
mod codes;
mod dcr;
mod metadata;
pub(crate) mod pending;
mod token;

#[cfg(test)]
mod signup_tests;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ibridge_core::AppleId;
use url::Url;

use crate::billing::BillingConfig;
use crate::identity::{Identity, IdentityConfig};
use crate::limits::{Limiter, SignInLimits};
use crate::store::{Store, StoreError};

pub use check::{Combined, SignInCheck, ValidatedBy, validated_by};

/// Forgets an account's pooled sessions. The account page calls it when it revokes a grant or deletes an account.
pub type Evict = Arc<dyn Fn(&AppleId) + Send + Sync>;

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
    contact: Option<String>,
    identity: Option<IdentityConfig>,
    billing: Option<BillingConfig>,
}

/// The public URL cannot be used as an OAuth issuer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Not a URL, not https, or it carries a path, query or fragment.
    #[error("the public URL must be an https origin such as https://ibridge.fyi")]
    PublicUrl,
    /// Some of the Sign in with Apple and Firebase settings are set, but not all.
    #[error(
        "set all of the Apple and Firebase sign-in settings or none of them; missing: {}",
        missing.join(", ")
    )]
    IdentityIncomplete {
        /// The names of the settings that are not set.
        missing: Vec<&'static str>,
    },
    /// The Apple private key is not a P-256 key in PEM form.
    #[error("the Apple private key must be a P-256 key in PEM form")]
    IdentityKey,
    /// Some of the Stripe settings are set, but not all four required ones.
    #[error(
        "set all of the Stripe billing settings or none of them; missing: {}",
        missing.join(", ")
    )]
    BillingIncomplete {
        /// The names of the settings that are not set.
        missing: Vec<&'static str>,
    },
    /// `IBRIDGE_STRIPE_TAX` is neither `managed` nor `automatic`.
    #[error("IBRIDGE_STRIPE_TAX must be managed or automatic")]
    BadStripeTax,
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
            contact: None,
            identity: None,
            billing: None,
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

    /// Whether the client address comes from `X-Forwarded-For`.
    pub(crate) fn is_behind_proxy(&self) -> bool {
        self.behind_proxy
    }

    /// The address the privacy policy and terms give for questions and deletion requests.
    #[must_use]
    pub fn contact(mut self, contact: impl Into<String>) -> Self {
        self.contact = Some(contact.into());
        self
    }

    /// Turns on Sign in with Apple through Firebase.
    #[must_use]
    pub fn identity(mut self, identity: IdentityConfig) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Turns on paid plans through Stripe. Billing needs Sign in with Apple as well.
    #[must_use]
    pub fn billing(mut self, billing: BillingConfig) -> Self {
        self.billing = Some(billing);
        self
    }

    /// The contact address, when the operator set one.
    pub(crate) fn contact_address(&self) -> Option<&str> {
        self.contact.as_deref()
    }

    /// The issuer identifier: the public origin with no trailing slash.
    pub(crate) fn issuer(&self) -> String {
        self.public_url.as_str().trim_end_matches('/').to_owned()
    }

    /// The `host` or `host:port` clients send as the `Host` header.
    pub(crate) fn host(&self) -> String {
        match (self.public_url.host_str(), self.public_url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_owned(),
            (None, _) => String::new(),
        }
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
            .is_behind_proxy()
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
        let peer = forwarded.or(direct).unwrap_or_else(|| "unknown".to_owned());
        Ok(Self(budget_key(&peer)))
    }
}

/// The key a peer's rate-limit budget is kept under. A client usually holds a whole
/// IPv6 /64, so every address in one /64 shares a budget; anything else is kept as is.
fn budget_key(peer: &str) -> String {
    match peer.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) if ip.to_ipv4_mapped().is_some() => {
            // A dual-stack socket reports an IPv4 client this way; it is one host, not a /64.
            ip.to_ipv4_mapped()
                .map_or_else(|| peer.to_owned(), |v4| v4.to_string())
        }
        Ok(IpAddr::V6(ip)) => {
            let [a, b, c, d, ..] = ip.segments();
            format!("{}/64", Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
        _ => peer.to_owned(),
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
    pub(crate) sessions: crate::pages::account::Sessions,
    pub(crate) evict: Evict,
    /// Sign in with Apple, when its settings are present.
    pub(crate) identity: Option<Identity>,
    /// `/authorize` requests waiting for a sign-in or a payment.
    pub(crate) pending_authorize: pending::PendingAuthorize,
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

/// Routes for discovery, registration, sign-in and tokens, with `mcp` behind the token check.
///
/// `mcp` holds the `/mcp` route. Every request to it needs a valid access token or API key.
/// `evict` closes an account's pooled sessions when the account page revokes or deletes.
///
/// Serve the router with `into_make_service_with_connect_info::<SocketAddr>()`.
/// Rate limits key on the peer address, and without it every request shares
/// one "unknown" budget. Behind a proxy, call [`OAuthConfig::behind_proxy`]
/// instead.
///
/// # Errors
///
/// Returns [`StoreError`] when the client table cannot be created or the
/// system has no TLS roots to fetch client metadata with.
pub async fn router(
    config: OAuthConfig,
    store: &Store,
    checker: impl SignInCheck,
    evict: Evict,
    mcp: Router,
) -> Result<Router, StoreError> {
    let transport = cimd::HttpsTransport::new().map_err(|_| StoreError::Rejected)?;
    let identity = config
        .identity
        .as_ref()
        .map(|identity| Identity::new(identity, &config.issuer()))
        .transpose()
        .map_err(|_| StoreError::Rejected)?;
    let (router, _) = router_with(
        config,
        store,
        Arc::new(cimd::CimdFetcher::new(transport)),
        Arc::new(checker),
        evict,
        mcp,
        identity,
    )
    .await?;
    Ok(router)
}

/// [`router`] with the client lookup replaced, so tests can name clients without a network.
/// Also returns the shared state, so a test can reach the stores the pages use.
pub(crate) async fn router_with(
    config: OAuthConfig,
    store: &Store,
    clients: Arc<dyn cimd::ClientSource>,
    checker: Arc<dyn SignInCheck>,
    evict: Evict,
    mcp: Router,
    identity: Option<Identity>,
) -> Result<(Router, Arc<Shared>), StoreError> {
    let metadata_url = config.url(metadata::PRM_MCP_PATH);
    let registry = dcr::ClientRegistry::open(store).await?;
    let shared = Arc::new(Shared {
        config,
        store: store.clone(),
        registry,
        clients,
        checker,
        // One budget for every page that checks a password, so switching pages gains nothing.
        limits: SignInLimits::new(),
        lookups: Limiter::new(30, Duration::from_mins(1)),
        registrations: Limiter::new(10, Duration::from_hours(1)),
        codes: codes::PendingCodes::default(),
        sessions: crate::pages::account::Sessions::default(),
        evict,
        identity,
        pending_authorize: pending::PendingAuthorize::new(pending::MAX_PENDING),
    });
    let router = Router::new()
        .merge(crate::middleware::protect(mcp, store.clone(), metadata_url))
        .merge(metadata::routes(&shared))
        .merge(dcr::routes(&shared))
        .merge(authorize::routes(&shared))
        .merge(token::routes(&shared))
        .merge(crate::pages::account::routes(&shared))
        .merge(crate::pages::signin::routes(&shared))
        .merge(crate::pages::landing::routes(&shared))
        .layer(tracing_layer());
    Ok((router, shared))
}

/// Request logging that records the method, the path and the outcome, and nothing else.
///
/// Tokens are keys here, and they travel in the `Authorization` header, in
/// query strings and in form bodies. This layer never records a header, a query or a
/// body, and it scrubs the path in case a client puts a token there.
pub(crate) fn tracing_layer<B>() -> tower_http::trace::TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl tower_http::trace::MakeSpan<B> + Clone,
> {
    tower_http::trace::TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<B>| {
            tracing::info_span!(
                "http",
                method = %request.method(),
                path = %crate::store::redact(request.uri().path()),
            )
        },
    )
}
