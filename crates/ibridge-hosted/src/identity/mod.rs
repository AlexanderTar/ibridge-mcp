// SPDX-License-Identifier: Apache-2.0

//! Sign in with Apple through Firebase: the settings that switch it on, and the clients.

pub mod apple;
#[cfg(test)]
pub mod fakes;
pub mod firebase;
pub(crate) mod http;
pub mod jwt;
pub(crate) mod pending;

use secrecy::SecretString;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::web::random_token;

use crate::oauth::ConfigError;

/// The Services ID registered with Apple for web sign-in.
pub const APPLE_SERVICES_ID: &str = "IBRIDGE_APPLE_SERVICES_ID";
/// The Apple developer team id.
pub const APPLE_TEAM_ID: &str = "IBRIDGE_APPLE_TEAM_ID";
/// The id of the Sign in with Apple key.
pub const APPLE_KEY_ID: &str = "IBRIDGE_APPLE_KEY_ID";
/// The Sign in with Apple private key, as the PEM text of the `.p8` file.
pub const APPLE_PRIVATE_KEY: &str = "IBRIDGE_APPLE_PRIVATE_KEY";
/// The Firebase project id; Firebase ID tokens carry it as their audience.
pub const FIREBASE_PROJECT_ID: &str = "IBRIDGE_FIREBASE_PROJECT_ID";
/// The Firebase web API key.
pub const FIREBASE_API_KEY: &str = "IBRIDGE_FIREBASE_API_KEY";

/// Why a sign-in step failed. The text is safe to log: it never holds a token or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Firebase refused a new account because this server's address made too many sign-ups.
    #[error("too many sign-ups right now, try again in an hour")]
    TooManySignUps,
    /// Apple or Google could not be reached, or answered nonsense.
    #[error("the sign-in service could not be reached")]
    Unreachable,
    /// Apple or Firebase refused the code or token it was given.
    #[error("the sign-in was refused")]
    Refused,
    /// A token failed its checks: signature, issuer, audience, expiry or issue time.
    #[error("the sign-in token is not valid")]
    InvalidToken,
    /// The callback's `state` is unknown, expired or already used, or the browser's binder
    /// cookie does not match it.
    #[error("the sign-in link is not valid")]
    StateRejected,
    /// Too many sign-ins are waiting, so a new one is refused.
    #[error("too many sign-ins are waiting")]
    Busy,
    /// The system has no randomness, so a sign-in cannot be started safely.
    #[error("a sign-in could not be started")]
    Unavailable,
}

/// Where a sign-in sends the person afterwards. It travels in server memory, never in a URL.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReturnTo {
    /// The account page.
    Account,
    /// A stored `/authorize` request, by its pending id.
    Authorize(String),
    /// The delete-account step, which needs a fresh sign-in. It names the user who asked,
    /// because Apple's callback is a cross-site POST that carries no session cookie.
    DeleteAccount(crate::store::UserId),
}

/// The form Apple posts to the callback. It has no `Debug`, so a code cannot reach a log.
#[derive(serde::Deserialize)]
pub struct CallbackForm {
    /// The authorization code.
    pub code: Option<String>,
    /// The `state` this server sent.
    pub state: Option<String>,
    /// Set when the person cancelled or Apple refused.
    pub error: Option<String>,
}

impl std::fmt::Debug for CallbackForm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallbackForm")
            .finish_non_exhaustive()
    }
}

/// Who signed in, with Firebase and Apple's answers already checked.
pub struct SignedIn {
    /// Firebase's stable id for the user.
    pub firebase_uid: String,
    /// Apple's `sub` for the identity.
    pub apple_sub: String,
    /// The email Apple gave, which may be a relay address.
    pub email: Option<String>,
    /// Where the person was going.
    pub return_to: ReturnTo,
    /// Apple's access token, for revoking at delete. Never stored.
    pub apple_access: Option<SecretString>,
    /// The Firebase ID token from this sign-in, for deleting the Firebase user. Never stored.
    pub firebase_id_token: SecretString,
}

// No derive: the uid, Apple's `sub` and the email identify a person, so a log must not get them.
impl std::fmt::Debug for SignedIn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedIn")
            .field("return_to", &self.return_to)
            .finish_non_exhaustive()
    }
}

/// The Apple and Firebase clients and the sign-ins waiting for Apple's callback.
#[derive(Debug)]
pub struct Identity {
    apple: apple::AppleClient,
    firebase: firebase::FirebaseClient,
    pending: pending::PendingSignIns,
}

/// The hash the pending sign-in keeps instead of the cookie value itself.
fn binder_hash(binder: &str) -> [u8; 32] {
    Sha256::digest(binder.as_bytes()).into()
}

/// The cookie that ties a callback to the browser that began the sign-in.
pub const BINDER_COOKIE: &str = "__Host-ibridge_siwa";

impl Identity {
    /// The real Apple and Firebase, for a server whose public origin is `issuer`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    pub fn new(config: &IdentityConfig, issuer: &str) -> Result<Self, IdentityError> {
        let callback = format!("{issuer}/signin/apple/callback");
        Ok(Self {
            apple: apple::AppleClient::new(config, &callback)?,
            firebase: firebase::FirebaseClient::new(config, &callback)?,
            pending: pending::PendingSignIns::standard(),
        })
    }

    /// Fakes on loopback, for tests.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Unreachable`] when the system's root certificates cannot be loaded.
    #[cfg(test)]
    pub fn with_bases(
        config: &IdentityConfig,
        issuer: &str,
        apple: url::Url,
        firebase: url::Url,
    ) -> Result<Self, IdentityError> {
        let callback = format!("{issuer}/signin/apple/callback");
        Ok(Self {
            apple: apple::AppleClient::with_base(config, &callback, apple)?,
            firebase: firebase::FirebaseClient::with_base(config, &callback, firebase)?,
            pending: pending::PendingSignIns::standard(),
        })
    }

    /// Replaces the pending-sign-in store, so a test can shorten the lifetime or the cap.
    #[cfg(test)]
    pub(crate) fn with_pending(mut self, pending: pending::PendingSignIns) -> Self {
        self.pending = pending;
        self
    }

    /// Starts a sign-in: returns the Apple URL to send the browser to and the binder cookie value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Busy`] when too many sign-ins are waiting and
    /// [`IdentityError::Unavailable`] when the system has no randomness.
    pub fn begin(
        &self,
        return_to: ReturnTo,
        now: std::time::Instant,
    ) -> Result<(String, String), IdentityError> {
        let (Some(state), Some(nonce), Some(binder)) =
            (random_token(), random_token(), random_token())
        else {
            return Err(IdentityError::Unavailable);
        };
        let pending = pending::PendingSignIn {
            nonce: nonce.clone(),
            binder: binder_hash(&binder),
            return_to,
        };
        self.pending
            .insert(state.clone(), pending, now)
            .map_err(|_| IdentityError::Busy)?;
        Ok((self.apple.authorize_url(&state, &nonce).into(), binder))
    }

    /// Finishes a sign-in from Apple's callback. The `state` is used up whatever happens.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::StateRejected`] for an unknown, expired, replayed or
    /// wrong-browser callback, and the clients' errors for anything Apple or Firebase refuses.
    pub async fn finish(
        &self,
        form: CallbackForm,
        binder: Option<&str>,
        now: std::time::Instant,
        wall: std::time::SystemTime,
    ) -> Result<SignedIn, IdentityError> {
        // The state is taken first, so every outcome below uses it up: a replayed callback,
        // or one finished in another browser, finds nothing to try again.
        let state = form.state.as_deref().ok_or(IdentityError::StateRejected)?;
        let pending = self
            .pending
            .take(state, now)
            .ok_or(IdentityError::StateRejected)?;
        let binder = binder.ok_or(IdentityError::StateRejected)?;
        if !bool::from(pending.binder.ct_eq(&binder_hash(binder))) {
            return Err(IdentityError::StateRejected);
        }
        if form.error.is_some() {
            return Err(IdentityError::Refused);
        }
        let code = form
            .code
            .as_deref()
            .filter(|code| !code.is_empty())
            .ok_or(IdentityError::Refused)?;
        let tokens = self.apple.exchange_code(code, wall).await?;
        let user = self
            .firebase
            .sign_in_with_idp(&tokens.id_token, &pending.nonce, wall)
            .await?;
        Ok(SignedIn {
            firebase_uid: user.uid,
            apple_sub: user.apple_sub,
            email: user.email,
            return_to: pending.return_to,
            apple_access: Some(tokens.access_token),
            firebase_id_token: user.id_token,
        })
    }

    /// Revokes the grant Apple made at a sign-in, so the app no longer appears in the
    /// person's Apple account.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Refused`] when Apple rejects the token and
    /// [`IdentityError::Unreachable`] when it cannot be reached.
    pub async fn revoke_apple(
        &self,
        access_token: &SecretString,
        wall: std::time::SystemTime,
    ) -> Result<(), IdentityError> {
        self.apple.revoke(access_token, wall).await
    }

    /// Deletes the Firebase user a fresh sign-in's ID token belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Refused`] when Firebase refuses and
    /// [`IdentityError::Unreachable`] when it cannot be reached.
    pub async fn delete_firebase(&self, id_token: &SecretString) -> Result<(), IdentityError> {
        self.firebase.delete_account(id_token).await
    }
}

/// Sign in with Apple and Firebase settings. All six are set, or none.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Apple Services ID, the OAuth client id.
    pub apple_services_id: String,
    /// Apple developer team id, the issuer of the client secret.
    pub apple_team_id: String,
    /// Id of the Sign in with Apple key.
    pub apple_key_id: String,
    /// The key itself, PEM.
    pub apple_private_key: SecretString,
    /// Firebase project id.
    pub firebase_project_id: String,
    /// Firebase web API key.
    pub firebase_api_key: SecretString,
}

impl IdentityConfig {
    /// Reads the group from `env`. `None` when none of it is set.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the settings that are missing when only some are set,
    /// or when the private key is not a P-256 key in PEM form. Values are never in the error.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let read = |name: &str| {
            env(name)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let names = [
            APPLE_SERVICES_ID,
            APPLE_TEAM_ID,
            APPLE_KEY_ID,
            APPLE_PRIVATE_KEY,
            FIREBASE_PROJECT_ID,
            FIREBASE_API_KEY,
        ];
        let values = names.map(read);
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let missing: Vec<&'static str> = names
            .iter()
            .zip(&values)
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| *name)
            .collect();
        let [
            Some(services),
            Some(team),
            Some(key_id),
            Some(key),
            Some(project),
            Some(api_key),
        ] = values
        else {
            return Err(ConfigError::IdentityIncomplete { missing });
        };
        // A host that keeps one line per variable writes the PEM's line breaks as `\n`.
        let pem = Zeroizing::new(key.replace("\\n", "\n"));
        jwt::check_es256_key(&pem).map_err(|_| ConfigError::IdentityKey)?;
        Ok(Some(Self {
            apple_services_id: services,
            apple_team_id: team,
            apple_key_id: key_id,
            apple_private_key: SecretString::from(pem.as_str()),
            firebase_project_id: project,
            firebase_api_key: SecretString::from(api_key),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::jwt::test_key::es256_pem;
    use super::{
        APPLE_KEY_ID, APPLE_PRIVATE_KEY, APPLE_SERVICES_ID, APPLE_TEAM_ID, FIREBASE_API_KEY,
        FIREBASE_PROJECT_ID, IdentityConfig, ReturnTo, SignedIn,
    };
    use crate::oauth::ConfigError;

    #[test]
    fn debug_of_a_signed_in_person_hides_who_they_are() {
        let signed = SignedIn {
            firebase_uid: "uid-that-must-not-leak".to_owned(),
            apple_sub: "apple-sub-that-must-not-leak".to_owned(),
            email: Some("ada@example.com".to_owned()),
            return_to: ReturnTo::Account,
            apple_access: Some(secrecy::SecretString::from("token-that-must-not-leak")),
            firebase_id_token: secrecy::SecretString::from("jwt-that-must-not-leak"),
        };
        let text = format!("{signed:?}");
        for secret in [
            "uid-that",
            "apple-sub-that",
            "ada@example.com",
            "must-not-leak",
        ] {
            assert!(!text.contains(secret), "{secret} reached Debug: {text}");
        }
        assert!(text.contains("SignedIn"), "{text}");
    }

    const SECRET_VALUE: &str = "value-that-must-not-leak";

    fn full(pem: &str) -> HashMap<&'static str, String> {
        HashMap::from([
            (APPLE_SERVICES_ID, "fyi.ibridge.signin".to_owned()),
            (APPLE_TEAM_ID, "TEAM123456".to_owned()),
            (APPLE_KEY_ID, "KEY1234567".to_owned()),
            (APPLE_PRIVATE_KEY, pem.to_owned()),
            (FIREBASE_PROJECT_ID, "ibridge-fyi".to_owned()),
            (FIREBASE_API_KEY, SECRET_VALUE.to_owned()),
        ])
    }

    fn read(vars: &HashMap<&'static str, String>) -> Result<Option<IdentityConfig>, ConfigError> {
        IdentityConfig::from_env(&|name| vars.get(name).cloned())
    }

    #[test]
    fn identity_absent_group_is_none() {
        assert!(read(&HashMap::new()).unwrap().is_none());
        let blanks: HashMap<_, _> = full("")
            .keys()
            .map(|name| (*name, "  ".to_owned()))
            .collect();
        assert!(
            read(&blanks).unwrap().is_none(),
            "blank values count as unset"
        );
    }

    #[test]
    fn identity_partial_group_is_error_naming_missing_variables_without_values() {
        let mut vars = full(&es256_pem());
        vars.remove(FIREBASE_PROJECT_ID);
        vars.insert(APPLE_TEAM_ID, "  ".to_owned());
        let error = read(&vars).unwrap_err();
        let ConfigError::IdentityIncomplete { missing } = &error else {
            panic!("expected IdentityIncomplete, got {error:?}");
        };
        assert_eq!(missing, &[APPLE_TEAM_ID, FIREBASE_PROJECT_ID]);
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(
                text.contains(APPLE_TEAM_ID) && text.contains(FIREBASE_PROJECT_ID),
                "{text}"
            );
            assert!(!text.contains(SECRET_VALUE), "no value in {text}");
            assert!(!text.contains("PRIVATE KEY"), "no key in {text}");
        }
    }

    #[test]
    fn identity_reads_private_key_pem() {
        let pem = es256_pem();
        let config = read(&full(&pem)).unwrap().expect("all six set");
        assert_eq!(config.apple_services_id, "fyi.ibridge.signin");
        assert_eq!(config.apple_team_id, "TEAM123456");
        assert_eq!(config.apple_key_id, "KEY1234567");
        assert_eq!(config.firebase_project_id, "ibridge-fyi");
        assert_eq!(config.apple_private_key.expose_secret(), pem.trim());
        assert_eq!(config.firebase_api_key.expose_secret(), SECRET_VALUE);
        // A host that keeps one line per variable writes the PEM with literal `\n`.
        let one_line = pem.trim().replace('\n', "\\n");
        let config = read(&full(&one_line)).unwrap().expect("all six set");
        assert_eq!(config.apple_private_key.expose_secret(), pem.trim());
        let shown = format!("{config:?}");
        assert!(
            !shown.contains(SECRET_VALUE) && !shown.contains("BEGIN"),
            "{shown}"
        );
    }

    #[test]
    fn identity_rejects_a_private_key_that_is_not_p256_pem() {
        let error = read(&full("not a key")).unwrap_err();
        assert!(matches!(error, ConfigError::IdentityKey), "{error:?}");
        assert!(!error.to_string().contains("not a key"));
    }
}
