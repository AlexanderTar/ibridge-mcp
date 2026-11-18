// SPDX-License-Identifier: Apache-2.0

//! Firebase's side of Sign in with Apple: exchange Apple's identity token for a Firebase user,
//! check the Firebase ID token that comes back, and delete the user.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use url::Url;

use super::http::Http;
use super::jwt::{Claims, JwkSet, verify_rs256};
use super::{IdentityConfig, IdentityError};

/// Longest a Firebase uid may be.
const MAX_UID: usize = 128;
/// How far ahead of this server's clock a token's issue time may be, in seconds.
const ISSUED_SKEW: u64 = 60;
/// How long the keys live when Google sends no `max-age`, in seconds.
const DEFAULT_KEY_LIFETIME: u64 = 300;
/// The longest the keys are kept, in seconds, whatever Google says.
const MAX_KEY_LIFETIME: u64 = 24 * 60 * 60;

/// A Firebase user whose ID token passed every check.
#[derive(Debug)]
pub struct FirebaseUser {
    /// Firebase's stable id for the user.
    pub uid: String,
    /// Apple's `sub` for the identity.
    pub apple_sub: String,
    /// The email Apple gave, which may be a relay address.
    pub email: Option<String>,
    /// The Firebase ID token, for deleting the user right after a fresh sign-in.
    pub id_token: SecretString,
}

/// Google's signing keys and when to fetch them again.
struct CachedKeys {
    keys: JwkSet,
    until: SystemTime,
}

/// Talks to Firebase Auth (`identitytoolkit.googleapis.com`) and Google's key set.
pub struct FirebaseClient {
    project_id: String,
    api_key: SecretString,
    request_uri: String,
    identity_base: Url,
    keys_base: Url,
    http: Http,
    keys: Mutex<Option<CachedKeys>>,
}

impl std::fmt::Debug for FirebaseClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirebaseClient")
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl FirebaseClient {
    /// A client for the real Firebase. `request_uri` is the page Apple sent the user back to.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    pub fn new(config: &IdentityConfig, request_uri: &str) -> Result<Self, IdentityError> {
        let parse = |text: &str| Url::parse(text).map_err(|_| IdentityError::Unreachable);
        Ok(Self::build(
            config,
            request_uri,
            parse("https://identitytoolkit.googleapis.com")?,
            parse("https://www.googleapis.com")?,
            Http::https()?,
        ))
    }

    /// A client that talks to a fake on loopback, which serves both Firebase and the key set.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_base(
        config: &IdentityConfig,
        request_uri: &str,
        base: Url,
    ) -> Result<Self, IdentityError> {
        Ok(Self::build(
            config,
            request_uri,
            base.clone(),
            base,
            Http::loopback()?,
        ))
    }

    fn build(
        config: &IdentityConfig,
        request_uri: &str,
        identity_base: Url,
        keys_base: Url,
        http: Http,
    ) -> Self {
        Self {
            project_id: config.firebase_project_id.clone(),
            api_key: config.firebase_api_key.clone(),
            request_uri: request_uri.to_owned(),
            identity_base,
            keys_base,
            http,
            keys: Mutex::new(None),
        }
    }

    /// Signs the user in at Firebase with the identity token Apple issued for `raw_nonce`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::TooManySignUps`] when Firebase refuses for its per-address
    /// sign-up limit, [`IdentityError::Refused`] for any other refusal,
    /// [`IdentityError::InvalidToken`] when the Firebase ID token fails its checks, and
    /// [`IdentityError::Unreachable`] when Firebase or Google cannot be reached.
    pub async fn sign_in_with_idp(
        &self,
        apple_id_token: &SecretString,
        raw_nonce: &str,
        now: SystemTime,
    ) -> Result<FirebaseUser, IdentityError> {
        let post_body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("id_token", apple_id_token.expose_secret())
            .append_pair("providerId", "apple.com")
            .append_pair("nonce", raw_nonce)
            .finish();
        let body = json!({
            "requestUri": self.request_uri,
            "postBody": post_body,
            "returnSecureToken": true,
            "returnIdpCredential": true,
        });
        let reply = self
            .http
            .post_json(&self.endpoint("/v1/accounts:signInWithIdp"), &body)
            .await?;
        if !reply.status.is_success() {
            return Err(refusal(reply.status, &reply.body));
        }
        let signed_in: SignInReply =
            serde_json::from_slice(&reply.body).map_err(|_| IdentityError::Unreachable)?;
        let claims = self.verify(&signed_in.id_token, now).await?;
        let uid = claims
            .sub
            .filter(|sub| !sub.is_empty() && sub.len() <= MAX_UID)
            .ok_or(IdentityError::InvalidToken)?;
        let apple_sub = claims
            .firebase
            .and_then(|firebase| {
                firebase
                    .identities
                    .get("apple.com")
                    .and_then(|ids| ids.first().cloned())
            })
            .filter(|sub| !sub.is_empty())
            .ok_or(IdentityError::InvalidToken)?;
        Ok(FirebaseUser {
            uid,
            apple_sub,
            email: claims.email,
            id_token: SecretString::from(signed_in.id_token),
        })
    }

    /// Deletes the Firebase user the ID token belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Refused`] when Firebase refuses and
    /// [`IdentityError::Unreachable`] when it cannot be reached.
    pub async fn delete_account(&self, id_token: &SecretString) -> Result<(), IdentityError> {
        let body = json!({ "idToken": id_token.expose_secret() });
        let reply = self
            .http
            .post_json(&self.endpoint("/v1/accounts:delete"), &body)
            .await?;
        if reply.status.is_success() {
            Ok(())
        } else {
            Err(refusal(reply.status, &reply.body))
        }
    }

    /// The API URL for `path`, with the API key as Firebase wants it.
    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.identity_base.clone();
        url.set_path(path);
        url.query_pairs_mut()
            .append_pair("key", self.api_key.expose_secret());
        url
    }

    /// Checks signature, issuer, audience, expiry and issue time of a Firebase ID token.
    async fn verify(&self, token: &str, now: SystemTime) -> Result<Claims, IdentityError> {
        let keys = self.keys(now).await?;
        let claims = verify_rs256(token, &keys).map_err(|_| IdentityError::InvalidToken)?;
        let seconds = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let expected_issuer = format!("https://securetoken.google.com/{}", self.project_id);
        let live = claims
            .exp
            .and_then(|exp| u64::try_from(exp).ok())
            .is_some_and(|exp| exp > seconds);
        // A little skew between this clock and Google's is normal; none is allowed for expiry.
        let not_in_future = claims
            .iat
            .and_then(|iat| u64::try_from(iat).ok())
            .is_some_and(|iat| iat <= seconds + ISSUED_SKEW);
        if claims.iss.as_deref() == Some(&expected_issuer)
            && claims.aud.as_deref() == Some(&self.project_id)
            && live
            && not_in_future
        {
            Ok(claims)
        } else {
            Err(IdentityError::InvalidToken)
        }
    }

    /// Google's signing keys, fetched again once their `max-age` has passed.
    async fn keys(&self, now: SystemTime) -> Result<JwkSet, IdentityError> {
        let mut cached = self.keys.lock().await;
        if let Some(fresh) = cached.as_ref().filter(|keys| now < keys.until) {
            return Ok(fresh.keys.clone());
        }
        let mut url = self.keys_base.clone();
        url.set_path("/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
        let reply = self.http.get(&url).await?;
        if !reply.status.is_success() {
            return Err(IdentityError::Unreachable);
        }
        let keys = JwkSet::parse(&reply.body).map_err(|_| IdentityError::Unreachable)?;
        let max_age = reply
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .and_then(max_age)
            .map_or(DEFAULT_KEY_LIFETIME, |seconds| {
                seconds.min(MAX_KEY_LIFETIME)
            });
        let until = now.checked_add(Duration::from_secs(max_age)).unwrap_or(now);
        *cached = Some(CachedKeys {
            keys: keys.clone(),
            until,
        });
        Ok(keys)
    }
}

/// The `max-age` of a `Cache-Control` value, in seconds.
fn max_age(value: &str) -> Option<u64> {
    value
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|seconds| seconds.trim().parse().ok())
}

/// What `signInWithIdp` returns that this server uses. The ID token is checked, not trusted.
#[derive(Deserialize)]
struct SignInReply {
    #[serde(rename = "idToken")]
    id_token: String,
}

/// Maps a failed Firebase call onto the error the caller can act on.
///
/// Firebase answers a refused sign-up over its per-address limit with a 400 whose message
/// starts `QUOTA_EXCEEDED` or `TOO_MANY_ATTEMPTS_TRY_LATER`, or with a 429.
fn refusal(status: StatusCode, body: &[u8]) -> IdentityError {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|json| json["error"]["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    if status == StatusCode::TOO_MANY_REQUESTS
        || message.starts_with("QUOTA_EXCEEDED")
        || message.starts_with("TOO_MANY_ATTEMPTS_TRY_LATER")
    {
        IdentityError::TooManySignUps
    } else if status.is_client_error() {
        IdentityError::Refused
    } else {
        IdentityError::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::http::StatusCode;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;

    use super::FirebaseClient;
    use crate::identity::IdentityError;
    use crate::identity::fakes::{FAKE_NOW_SECS, FakeFirebase, identity_config};

    const REQUEST_URI: &str = "https://ibridge.example/signin/apple/callback";

    fn at(offset: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(FAKE_NOW_SECS + offset)
    }

    async fn setup() -> (FakeFirebase, FirebaseClient) {
        let config = identity_config("ibridge-fyi");
        let fake = FakeFirebase::start("ibridge-fyi", "test-api-key").await;
        let client = FirebaseClient::with_base(&config, REQUEST_URI, fake.base()).unwrap();
        (fake, client)
    }

    async fn sign_in(
        client: &FirebaseClient,
        now: SystemTime,
    ) -> Result<super::FirebaseUser, IdentityError> {
        client
            .sign_in_with_idp(&SecretString::from("apple-id-1"), "raw-nonce", now)
            .await
    }

    #[tokio::test]
    async fn firebase_sign_in_with_idp_returns_uid_from_verified_token() {
        let (fake, client) = setup().await;
        let user = sign_in(&client, at(0)).await.unwrap();
        assert_eq!(user.uid, FakeFirebase::UID);
        assert_eq!(user.apple_sub, FakeFirebase::APPLE_SUB);
        assert_eq!(user.email.as_deref(), Some(FakeFirebase::EMAIL));
        assert_eq!(user.id_token.expose_secret().split('.').count(), 3);
        let sent = fake.sign_ins();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["requestUri"], REQUEST_URI);
        assert_eq!(sent[0]["returnSecureToken"], true);
        let post_body = sent[0]["postBody"].as_str().unwrap();
        for part in [
            "id_token=apple-id-1",
            "providerId=apple.com",
            "nonce=raw-nonce",
        ] {
            assert!(post_body.contains(part), "{part} in the post body");
        }
    }

    #[tokio::test]
    async fn firebase_token_wrong_aud_rejected() {
        let (fake, client) = setup().await;
        fake.edit_claims(|claims| claims["aud"] = json!("some-other-project"));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
    }

    #[tokio::test]
    async fn firebase_token_wrong_iss_rejected() {
        let (fake, client) = setup().await;
        fake.edit_claims(|claims| claims["iss"] = json!("https://securetoken.google.com/other"));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
    }

    #[tokio::test]
    async fn firebase_token_expired_rejected() {
        let (fake, client) = setup().await;
        fake.edit_claims(|claims| claims["exp"] = json!(FAKE_NOW_SECS - 10));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
    }

    #[tokio::test]
    async fn firebase_token_issued_in_the_future_rejected() {
        let (fake, client) = setup().await;
        fake.edit_claims(|claims| claims["iat"] = json!(FAKE_NOW_SECS + 3000));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
        fake.edit_claims(|claims| claims["iat"] = json!(FAKE_NOW_SECS + 30));
        sign_in(&client, at(0))
            .await
            .expect("a little clock skew is fine");
    }

    #[tokio::test]
    async fn firebase_token_without_subject_or_apple_identity_rejected() {
        let (fake, client) = setup().await;
        fake.edit_claims(|claims| claims["sub"] = json!(""));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
        fake.edit_claims(|claims| claims["firebase"]["identities"] = json!({}));
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
    }

    #[tokio::test]
    async fn firebase_token_signed_under_an_unpublished_key_rejected() {
        let (fake, client) = setup().await;
        fake.sign_with_kid("not-a-google-key");
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::InvalidToken
        );
    }

    #[tokio::test]
    async fn firebase_keys_cached_until_max_age() {
        let (fake, client) = setup().await;
        fake.set_key_max_age(100);
        sign_in(&client, at(0)).await.unwrap();
        sign_in(&client, at(50)).await.unwrap();
        assert_eq!(fake.key_fetches(), 1, "the second sign-in reuses the keys");
        sign_in(&client, at(101)).await.unwrap();
        assert_eq!(
            fake.key_fetches(),
            2,
            "after max-age the keys are fetched again"
        );
    }

    #[tokio::test]
    async fn firebase_too_many_sign_ups_maps_to_too_many_sign_ups() {
        let (fake, client) = setup().await;
        fake.fail_sign_in(
            StatusCode::BAD_REQUEST,
            "QUOTA_EXCEEDED : Exceeded quota for creating accounts.",
        );
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::TooManySignUps
        );
        fake.fail_sign_in(StatusCode::BAD_REQUEST, "TOO_MANY_ATTEMPTS_TRY_LATER");
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::TooManySignUps
        );
        fake.fail_sign_in(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::TooManySignUps
        );
    }

    #[tokio::test]
    async fn firebase_other_failures_are_refused_or_unreachable() {
        let (fake, client) = setup().await;
        fake.fail_sign_in(StatusCode::BAD_REQUEST, "INVALID_IDP_RESPONSE : bad token");
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::Refused
        );
        fake.fail_sign_in(StatusCode::INTERNAL_SERVER_ERROR, "backend error");
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::Unreachable
        );
    }

    #[tokio::test]
    async fn firebase_wrong_api_key_is_refused() {
        let fake = FakeFirebase::start("ibridge-fyi", "another-key").await;
        let config = identity_config("ibridge-fyi");
        let client = FirebaseClient::with_base(&config, REQUEST_URI, fake.base()).unwrap();
        assert_eq!(
            sign_in(&client, at(0)).await.unwrap_err(),
            IdentityError::Refused
        );
    }

    #[tokio::test]
    async fn firebase_delete_posts_id_token() {
        let (fake, client) = setup().await;
        client
            .delete_account(&SecretString::from("firebase-id-token"))
            .await
            .unwrap();
        assert_eq!(
            fake.deletes(),
            vec![json!({ "idToken": "firebase-id-token" })]
        );
    }
}
