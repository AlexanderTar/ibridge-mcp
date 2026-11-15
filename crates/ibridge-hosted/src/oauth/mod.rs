// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.1 authorization server for the hosted MCP endpoint.

mod metadata;

use std::sync::Arc;

use axum::Router;
use url::Url;

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

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) config: OAuthConfig,
}

/// Routes for discovery, registration, sign-in and tokens.
pub fn router(config: OAuthConfig) -> Router {
    let shared = Arc::new(Shared { config });
    Router::new().merge(metadata::routes(&shared))
}
