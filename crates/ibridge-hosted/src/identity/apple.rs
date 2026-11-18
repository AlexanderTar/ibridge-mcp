// SPDX-License-Identifier: Apache-2.0

//! Apple's side of Sign in with Apple: the authorize URL, the code exchange and the revoke.

use std::time::{SystemTime, UNIX_EPOCH};

use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use super::http::Http;
use super::jwt::sign_es256;
use super::{IdentityConfig, IdentityError};

/// Apple's `aud` for a client secret.
const APPLE_AUDIENCE: &str = "https://appleid.apple.com";
/// How long a client secret lives, in seconds. Apple allows six months; it is used at once.
const CLIENT_SECRET_TTL: u64 = 300;

/// The tokens Apple's code exchange returns that this server keeps for the sign-in.
///
/// Apple's refresh token is read by nobody and never stored.
#[derive(Debug)]
pub struct AppleTokens {
    /// The identity token, which Firebase checks.
    pub id_token: SecretString,
    /// Revokes the user's grant at Apple when they delete their account.
    pub access_token: SecretString,
}

/// Talks to `appleid.apple.com`.
#[derive(Debug)]
pub struct AppleClient {
    services_id: String,
    team_id: String,
    key_id: String,
    private_key: SecretString,
    redirect_uri: String,
    base: Url,
    http: Http,
}

impl AppleClient {
    /// A client for the real Apple, which sends users back to `redirect_uri`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    pub fn new(config: &IdentityConfig, redirect_uri: &str) -> Result<Self, IdentityError> {
        Ok(Self::build(
            config,
            redirect_uri,
            Url::parse("https://appleid.apple.com").map_err(|_| IdentityError::Unreachable)?,
            Http::https()?,
        ))
    }

    /// A client that talks to a fake on loopback.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_base(
        config: &IdentityConfig,
        redirect_uri: &str,
        base: Url,
    ) -> Result<Self, IdentityError> {
        Ok(Self::build(config, redirect_uri, base, Http::loopback()?))
    }

    fn build(config: &IdentityConfig, redirect_uri: &str, base: Url, http: Http) -> Self {
        Self {
            services_id: config.apple_services_id.clone(),
            team_id: config.apple_team_id.clone(),
            key_id: config.apple_key_id.clone(),
            private_key: config.apple_private_key.clone(),
            redirect_uri: redirect_uri.to_owned(),
            base,
            http,
        }
    }

    /// Where to send the browser. `nonce` is the raw value; Apple gets its SHA-256.
    #[must_use]
    pub fn authorize_url(&self, state: &str, nonce: &str) -> Url {
        let hashed = hex(&Sha256::digest(nonce.as_bytes()));
        let mut url = self.base.clone();
        url.set_path("/auth/authorize");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("response_mode", "form_post")
            .append_pair("scope", "email")
            .append_pair("client_id", &self.services_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("state", state)
            .append_pair("nonce", &hashed);
        url
    }

    /// Exchanges the callback's `code` for Apple's tokens.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Refused`] when Apple rejects the code and
    /// [`IdentityError::Unreachable`] when it cannot be reached or answers nonsense.
    pub async fn exchange_code(
        &self,
        code: &str,
        now: SystemTime,
    ) -> Result<AppleTokens, IdentityError> {
        let secret = self.client_secret(now)?;
        let reply = self
            .http
            .post_form(
                &self.endpoint("/auth/token"),
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", &self.services_id),
                    ("client_secret", secret.expose_secret()),
                    ("redirect_uri", &self.redirect_uri),
                ],
            )
            .await?;
        check(reply.status)?;
        let tokens: TokenReply =
            serde_json::from_slice(&reply.body).map_err(|_| IdentityError::Unreachable)?;
        Ok(AppleTokens {
            id_token: SecretString::from(tokens.id_token),
            access_token: SecretString::from(tokens.access_token),
        })
    }

    /// Revokes the user's grant at Apple.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Refused`] when Apple rejects the token and
    /// [`IdentityError::Unreachable`] when it cannot be reached.
    pub async fn revoke(
        &self,
        access_token: &SecretString,
        now: SystemTime,
    ) -> Result<(), IdentityError> {
        let secret = self.client_secret(now)?;
        let reply = self
            .http
            .post_form(
                &self.endpoint("/auth/revoke"),
                &[
                    ("client_id", &self.services_id),
                    ("client_secret", secret.expose_secret()),
                    ("token", access_token.expose_secret()),
                    ("token_type_hint", "access_token"),
                ],
            )
            .await?;
        check(reply.status)
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(path);
        url
    }

    /// The JWT Apple takes as this app's password, good for five minutes.
    fn client_secret(&self, now: SystemTime) -> Result<SecretString, IdentityError> {
        let issued = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let claims = json!({
            "iss": self.team_id,
            "iat": issued,
            "exp": issued + CLIENT_SECRET_TTL,
            "aud": APPLE_AUDIENCE,
            "sub": self.services_id,
        });
        sign_es256(&self.private_key, &self.key_id, &claims).map_err(|_| IdentityError::Refused)
    }
}

/// Lowercase hex, which is how Apple and Firebase compare a nonce's hash.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

/// What Apple's token endpoint returns. Its refresh token is left unread on purpose.
#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    id_token: String,
}

/// Apple answers 200 for success and 400 or 401 for a refusal.
fn check(status: StatusCode) -> Result<(), IdentityError> {
    if status.is_success() {
        Ok(())
    } else if matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
        Err(IdentityError::Refused)
    } else {
        Err(IdentityError::Unreachable)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{Duration, UNIX_EPOCH};

    use super::AppleClient;
    use crate::identity::IdentityConfig;
    use crate::identity::IdentityError;
    use crate::identity::fakes::{FAKE_NOW_SECS, FakeApple, identity_config};
    use crate::identity::jwt::test_key::es256_signed_by;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::Value;

    const REDIRECT: &str = "https://ibridge.example/signin/apple/callback";

    fn now() -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(FAKE_NOW_SECS)
    }

    fn query(url: &url::Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect()
    }

    async fn client() -> (FakeApple, AppleClient, IdentityConfig) {
        let fake = FakeApple::start().await;
        let config = identity_config("ibridge-fyi");
        let client = AppleClient::with_base(&config, REDIRECT, fake.base()).unwrap();
        (fake, client, config)
    }

    fn claims_of(token: &str) -> (Value, Value) {
        let parts: Vec<&str> = token.split('.').collect();
        let decode = |part: &str| -> Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
        };
        (decode(parts[0]), decode(parts[1]))
    }

    #[test]
    fn apple_authorize_url_has_form_post_scope_email_and_hashed_nonce() {
        let config = identity_config("ibridge-fyi");
        let base = url::Url::parse("https://appleid.apple.com").unwrap();
        let client = AppleClient::with_base(&config, REDIRECT, base).unwrap();
        let url = client.authorize_url("state-1", "raw-nonce");
        assert_eq!(url.host_str(), Some("appleid.apple.com"));
        assert_eq!(url.path(), "/auth/authorize");
        let sent = query(&url);
        assert_eq!(sent["response_type"], "code");
        assert_eq!(sent["response_mode"], "form_post");
        assert_eq!(sent["scope"], "email");
        assert_eq!(sent["client_id"], "fyi.ibridge.signin");
        assert_eq!(sent["redirect_uri"], REDIRECT);
        assert_eq!(sent["state"], "state-1");
        // `printf raw-nonce | shasum -a 256`
        let hashed = "2c5d107938053a2275f022c153c9a71f65ee07754b8bca543ee97a0c3cc66990";
        assert_eq!(
            sent["nonce"], hashed,
            "Apple gets the hash, never the raw nonce"
        );
        assert!(!url.as_str().contains("raw-nonce"));
    }

    #[tokio::test]
    async fn apple_code_exchange_sends_client_secret() {
        let (fake, client, config) = client().await;
        let tokens = client.exchange_code("code-1", now()).await.unwrap();
        assert_eq!(tokens.id_token.expose_secret(), "apple-id-code-1");
        assert_eq!(tokens.access_token.expose_secret(), "apple-access-code-1");
        let sent = fake.token_requests();
        assert_eq!(sent.len(), 1);
        let form = &sent[0];
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "code-1");
        assert_eq!(form["client_id"], "fyi.ibridge.signin");
        assert_eq!(form["redirect_uri"], REDIRECT);
        let secret = &form["client_secret"];
        let (header, claims) = claims_of(secret);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY1234567");
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], "fyi.ibridge.signin");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        let issued = claims["iat"].as_u64().unwrap();
        let expires = claims["exp"].as_u64().unwrap();
        assert_eq!(issued, FAKE_NOW_SECS);
        assert!(
            expires > issued && expires - issued <= 600,
            "a short-lived secret"
        );
        assert!(
            es256_signed_by(secret, config.apple_private_key.expose_secret()),
            "signed with the configured key"
        );
    }

    #[tokio::test]
    async fn apple_code_exchange_refused_code_is_refused() {
        let (_fake, client, _) = client().await;
        let error = client.exchange_code("bad-code", now()).await.unwrap_err();
        assert_eq!(error, IdentityError::Refused);
    }

    #[tokio::test]
    async fn apple_unreachable_server_is_unreachable() {
        let config = identity_config("ibridge-fyi");
        let dead = {
            let fake = FakeApple::start().await;
            fake.base()
        };
        let client = AppleClient::with_base(&config, REDIRECT, dead).unwrap();
        let error = client.exchange_code("code-1", now()).await.unwrap_err();
        assert_eq!(error, IdentityError::Unreachable);
    }

    #[tokio::test]
    async fn apple_revoke_posts_token() {
        let (fake, client, config) = client().await;
        client
            .revoke(&SecretString::from("apple-access-code-1"), now())
            .await
            .unwrap();
        let sent = fake.revoke_requests();
        assert_eq!(sent.len(), 1);
        let form = &sent[0];
        assert_eq!(form["token"], "apple-access-code-1");
        assert_eq!(form["token_type_hint"], "access_token");
        assert_eq!(form["client_id"], "fyi.ibridge.signin");
        assert!(es256_signed_by(
            &form["client_secret"],
            config.apple_private_key.expose_secret()
        ));
    }
}
