// SPDX-License-Identifier: Apache-2.0

//! Sign in with Apple through Firebase: the settings that switch it on, and the clients.

pub mod apple;
#[cfg(any(test, feature = "testing"))]
pub mod fakes;
pub mod firebase;
mod http;
pub mod jwt;

use secrecy::SecretString;
use zeroize::Zeroizing;

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
        FIREBASE_PROJECT_ID, IdentityConfig,
    };
    use crate::oauth::ConfigError;

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
