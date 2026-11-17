// SPDX-License-Identifier: Apache-2.0

//! Hosted OAuth server and token-sealed credential store.

mod app;
mod backup;
mod config;
mod health;
mod limits;
pub mod logging;
mod middleware;
mod oauth;
mod provider;
mod serve;
mod server;
mod store;

#[cfg(test)]
mod test_app;
#[cfg(test)]
mod test_mail;

pub use oauth::{
    Access, Combined, ConfigError, OAuthConfig, SignInCheck, ValidatedBy, router, validated_by,
};

pub use app::app;
pub use backup::{BackupError, KEEP as BACKUPS_KEPT, spawn_daily as spawn_daily_backups};
pub use config::{ALLOWED_APPLE_IDS, HostedConfig, HostedOptions, SIGNUP_CAP, SIGNUPS, StartError};
pub use limits::Guards;
pub use middleware::CallAuth;
pub use provider::{Account, AccountCache, AccountServer, Backend, Providers};
pub use serve::{BACKUP_DIR, DATABASE_FILE, ServeError, serve};
pub use server::{HostedHandler, ScopedServers, ServerSource, mcp_router};
pub use store::{NotReady, RedactingFields, Store, StoreError, ValidatedCredentials, redact};
