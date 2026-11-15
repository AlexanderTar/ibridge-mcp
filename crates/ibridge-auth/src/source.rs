// SPDX-License-Identifier: Apache-2.0

//! Where an Apple ID and app-specific password are loaded from.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ibridge_core::AppleId;

use crate::credentials::{AuthError, Credentials};
use crate::platform::is_mode_0600;

/// Keychain service name for the app-specific password.
const KEYRING_SERVICE: &str = "ibridge";

/// Loads credentials for one account.
#[trait_variant::make(Send)]
pub trait CredentialSource {
    /// Reads the Apple ID and app-specific password.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Unavailable`] when the source has no usable secret.
    /// The error text never includes the secret.
    async fn credentials(&self) -> Result<Credentials, AuthError>;
}

/// OS keychain entry under the service name `ibridge`.
///
/// The process chooses the store, which tests replace with the in-memory mock.
/// This type never opens the login keychain itself.
#[derive(Debug)]
pub struct KeyringSource {
    apple_id: AppleId,
}

impl KeyringSource {
    /// Reads the password stored for `apple_id`.
    #[must_use]
    pub const fn new(apple_id: AppleId) -> Self {
        Self { apple_id }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the keychain read is synchronous"
)]
impl CredentialSource for KeyringSource {
    async fn credentials(&self) -> Result<Credentials, AuthError> {
        let entry = keyring_core::Entry::new(KEYRING_SERVICE, self.apple_id.as_str())
            .map_err(|_| AuthError::Unavailable)?;
        let secret = entry.get_password().map_err(|_| AuthError::Unavailable)?;
        Ok(Credentials::new(self.apple_id.clone(), secret))
    }
}

/// A `KEY=VALUE` file that must be mode `0600`.
///
/// Accepts `IBRIDGE_APPLE_ID` and `IBRIDGE_APP_PASSWORD`, and falls back to
/// `IBRIDGE_TEST_APPLE_ID` and `IBRIDGE_TEST_APP_PASSWORD` when those are absent.
#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
}

impl FileSource {
    /// Reads credentials from `path` after checking its mode.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the file read is synchronous"
)]
impl CredentialSource for FileSource {
    async fn credentials(&self) -> Result<Credentials, AuthError> {
        if !is_mode_0600(&self.path) {
            return Err(AuthError::Unavailable);
        }
        let text = fs::read_to_string(&self.path).map_err(|_| AuthError::Unavailable)?;
        credentials_from_pairs(&pairs(&text))
    }
}

/// Process environment variables `IBRIDGE_APPLE_ID` and `IBRIDGE_APP_PASSWORD`.
#[derive(Debug, Default)]
pub struct EnvSource;

impl EnvSource {
    /// Reads the process environment.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the environment read is synchronous"
)]
impl CredentialSource for EnvSource {
    async fn credentials(&self) -> Result<Credentials, AuthError> {
        let id = std::env::var("IBRIDGE_APPLE_ID").map_err(|_| AuthError::Unavailable)?;
        let secret = std::env::var("IBRIDGE_APP_PASSWORD").map_err(|_| AuthError::Unavailable)?;
        let apple_id = AppleId::try_from(id.as_str()).map_err(|_| AuthError::Unavailable)?;
        Ok(Credentials::new(apple_id, secret))
    }
}

fn pairs(text: &str) -> HashMap<&str, &str> {
    let mut pairs = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        pairs.insert(key.trim(), value.trim());
    }
    pairs
}

fn credentials_from_pairs(pairs: &HashMap<&str, &str>) -> Result<Credentials, AuthError> {
    let id = field(pairs, "IBRIDGE_APPLE_ID", "IBRIDGE_TEST_APPLE_ID")?;
    let secret = field(pairs, "IBRIDGE_APP_PASSWORD", "IBRIDGE_TEST_APP_PASSWORD")?;
    let apple_id = AppleId::try_from(id).map_err(|_| AuthError::Unavailable)?;
    Ok(Credentials::new(apple_id, secret))
}

fn field<'a>(
    pairs: &HashMap<&str, &'a str>,
    primary: &str,
    fallback: &str,
) -> Result<&'a str, AuthError> {
    [primary, fallback]
        .into_iter()
        .find_map(|key| pairs.get(key).copied().filter(|value| !value.is_empty()))
        .ok_or(AuthError::Unavailable)
}
