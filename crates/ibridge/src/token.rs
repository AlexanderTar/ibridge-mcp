// SPDX-License-Identifier: Apache-2.0

//! The bearer token the local daemon requires.

use anyhow::Context as _;
use base64::Engine as _;
use keyring_core::Entry;
use secrecy::{ExposeSecret as _, SecretString};
use subtle::ConstantTimeEq as _;

use crate::account::KEYCHAIN_SERVICE;

/// Keychain entry holding the daemon token.
const TOKEN_USER: &str = "daemon-token";
const TOKEN_BYTES: usize = 32;

/// A 256-bit random token kept in the keychain.
///
/// It is a [`SecretString`]: no `Serialize`, and `Debug` prints a redaction.
#[derive(Debug)]
pub(crate) struct DaemonToken(SecretString);

impl DaemonToken {
    /// Reads the token from the keychain, creating it first when there is none.
    ///
    /// # Errors
    ///
    /// Returns an error when the keychain cannot be read or written.
    pub(crate) fn get_or_create() -> anyhow::Result<Self> {
        let entry = Entry::new(KEYCHAIN_SERVICE, TOKEN_USER)?;
        match entry.get_password() {
            Ok(token) => Ok(Self(SecretString::from(token))),
            Err(keyring_core::Error::NoEntry) => {
                let mut random = [0_u8; TOKEN_BYTES];
                getrandom::fill(&mut random)
                    .map_err(|error| anyhow::anyhow!("no random numbers: {error}"))
                    .context("could not create the daemon token")?;
                let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
                entry.set_password(&token)?;
                Ok(Self(SecretString::from(token)))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Whether `presented` is this token, compared in constant time.
    pub(crate) fn matches(&self, presented: &str) -> bool {
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(presented.as_bytes())
            .into()
    }

    /// Passes the token to `read` and ends the borrow before returning.
    pub(crate) fn with_secret<T>(&self, read: impl FnOnce(&str) -> T) -> T {
        read(self.0.expose_secret())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use keyring_core::Entry;

    use super::DaemonToken;
    use crate::account::KEYCHAIN_SERVICE;
    use crate::testing::{KEYCHAIN, mock_keychain};

    fn stored() -> Option<String> {
        Entry::new(KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .get_password()
            .ok()
    }

    #[tokio::test]
    async fn daemon_token_created_once() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let _ = Entry::new(KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .delete_credential();
        let first = DaemonToken::get_or_create().expect("created");
        let in_keychain = stored().expect("the token is saved in the keychain");
        first.with_secret(|token| {
            assert_eq!(
                token, in_keychain,
                "the keychain holds the token handed out"
            );
        });
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&in_keychain)
            .expect("the token is base64url");
        assert_eq!(bytes.len(), 32, "the token is 256 bits");
        let second = DaemonToken::get_or_create().expect("read back");
        second.with_secret(|token| {
            assert_eq!(token, in_keychain, "a second call reads the same token");
        });
        assert_eq!(
            stored().as_deref(),
            Some(in_keychain.as_str()),
            "and does not rewrite it"
        );
    }

    #[tokio::test]
    async fn daemon_token_accepts_only_exact_match() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let token = DaemonToken::get_or_create().expect("token");
        let exact = token.with_secret(str::to_owned);
        assert!(token.matches(&exact), "the exact token is accepted");
        for wrong in [
            String::new(),
            exact[..exact.len() - 1].to_owned(),
            format!("{exact}A"),
            format!(" {exact}"),
            format!("{exact} "),
            exact.to_uppercase(),
            exact.to_lowercase(),
        ] {
            if wrong == exact {
                continue;
            }
            assert!(!token.matches(&wrong), "{wrong:?} must not match");
        }
    }
}
