// SPDX-License-Identifier: Apache-2.0

//! Hosted OAuth server and token-sealed credential store.

mod admin;
#[cfg(test)]
mod anonymous_tests;
mod app;
mod assets;
mod backup;
pub mod billing;
mod config;
#[cfg(test)]
mod e2e;
mod health;
mod icloud;
pub mod identity;
#[cfg(test)]
mod integration;
mod limits;
pub mod logging;
mod middleware;
mod no_mail;
mod oauth;
mod pages;
mod provider;
mod serve;
mod server;
mod store;
#[cfg(test)]
pub mod testing;
mod web;

#[cfg(test)]
mod test_app;

pub use oauth::{
    Access, Combined, ConfigError, Evict, OAuthConfig, SignInCheck, ValidatedBy, router,
    validated_by,
};

pub use admin::{AdminAction, AdminError, admin};
pub use app::app;
pub use backup::{BackupError, KEEP as BACKUPS_KEPT, spawn_daily as spawn_daily_backups};
pub use config::{
    ALLOWED_APPLE_IDS, BEHIND_PROXY, CONTACT, HostedConfig, HostedOptions, SIGNUP_CAP, SIGNUPS,
    StartError,
};
pub use icloud::{IcloudBackend, SessionMail};
pub use limits::Guards;
pub use middleware::CallAuth;
pub use provider::{Account, AccountCache, AccountServer, Backend, Providers};
pub use serve::{BACKUP_DIR, DATABASE_FILE, ServeError, serve};
pub use server::{HostedHandler, ScopedServers, ServerSource, mcp_router};
pub use store::{
    NotReady, RedactingFields, Services, Store, StoreError, User, UserId, ValidatedCredentials,
    redact,
};
