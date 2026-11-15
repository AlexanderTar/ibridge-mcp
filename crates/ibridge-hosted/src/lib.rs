// SPDX-License-Identifier: Apache-2.0

//! Hosted OAuth server and token-sealed credential store.

mod limits;
mod oauth;
mod store;

pub use oauth::{
    Access, Combined, ConfigError, OAuthConfig, SignInCheck, ValidatedBy, router, validated_by,
};

pub use store::{RedactingFields, Store, StoreError, ValidatedCredentials, redact};
