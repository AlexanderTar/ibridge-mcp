// SPDX-License-Identifier: Apache-2.0

//! Hosted OAuth server and token-sealed credential store.

mod limits;
mod middleware;
mod oauth;
mod server;
mod store;

#[cfg(test)]
mod test_mail;

pub use oauth::{
    Access, Combined, ConfigError, OAuthConfig, SignInCheck, ValidatedBy, router, validated_by,
};

pub use middleware::CallAuth;
pub use server::{HostedHandler, ScopedServers, ServerSource, mcp_router};
pub use store::{RedactingFields, Store, StoreError, ValidatedCredentials, redact};
