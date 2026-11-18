// SPDX-License-Identifier: Apache-2.0

//! The little JWT this server needs: verify RS256 tokens against a JWK set, sign ES256.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_2048_8192_SHA256,
    RsaPublicKeyComponents,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Why a token was refused or could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// Not three base64url parts holding JSON.
    #[error("the token is malformed")]
    Malformed,
    /// The header names an algorithm other than the one the caller expects.
    #[error("the token uses an algorithm that is not accepted")]
    Algorithm,
    /// No key in the set has the token's `kid`.
    #[error("the token names an unknown key")]
    UnknownKey,
    /// The signature does not match the header and payload.
    #[error("the token signature is not valid")]
    Signature,
    /// The key set or private key could not be read.
    #[error("the key is not usable")]
    Key,
}

/// One public key of a JWK set (`kty` RSA).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    kid: String,
    n: String,
    e: String,
}

/// The keys a provider publishes.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Reads a provider's key document.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::Key`] when `json` is not a JWK set.
    pub fn parse(json: &[u8]) -> Result<Self, JwtError> {
        serde_json::from_slice(json).map_err(|_| JwtError::Key)
    }
}

/// The claims this server reads. Checking them is the caller's job.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Claims {
    /// Issuer.
    pub iss: Option<String>,
    /// Audience.
    pub aud: Option<String>,
    /// Subject.
    pub sub: Option<String>,
    /// Expiry, in Unix seconds.
    pub exp: Option<i64>,
    /// Issued-at, in Unix seconds.
    pub iat: Option<i64>,
    /// Email, when the provider vouches for one.
    pub email: Option<String>,
    /// Firebase's own claim: how the user signed in.
    pub firebase: Option<FirebaseClaim>,
}

/// The `firebase` claim of a Firebase ID token.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirebaseClaim {
    /// The ids the user has with each provider, such as `apple.com`.
    #[serde(default)]
    pub identities: std::collections::HashMap<String, Vec<String>>,
}

/// The header fields this server reads.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

fn decode(part: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| JwtError::Malformed)
}

/// Checks an RS256 token's signature against `keys` and returns its claims.
///
/// The header must say `RS256`: `none`, `HS256` and every other algorithm are refused, so a
/// token cannot choose how it is checked. The claims are read only after the signature holds.
/// Whether they say what the caller needs (issuer, audience, expiry) is the caller's check.
///
/// # Errors
///
/// Returns a [`JwtError`] saying what was wrong.
pub fn verify_rs256(token: &str, keys: &JwkSet) -> Result<Claims, JwtError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let header: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| JwtError::Malformed)?;
    if header.alg != "RS256" {
        return Err(JwtError::Algorithm);
    }
    let signature = decode(signature)?;
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.keys.iter().find(|key| key.kid == kid))
        .ok_or(JwtError::UnknownKey)?;
    let public = RsaPublicKeyComponents {
        n: URL_SAFE_NO_PAD.decode(&key.n).map_err(|_| JwtError::Key)?,
        e: URL_SAFE_NO_PAD.decode(&key.e).map_err(|_| JwtError::Key)?,
    };
    // The signature covers the first two parts exactly as sent, dot included.
    let (signed, _) = token.rsplit_once('.').ok_or(JwtError::Malformed)?;
    public
        .verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &signature)
        .map_err(|_| JwtError::Signature)?;
    serde_json::from_slice(&decode(payload)?).map_err(|_| JwtError::Malformed)
}

/// The DER of a PKCS#8 PEM private key, wiped on drop.
fn pem_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|rest| rest.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or(JwtError::Key)?;
    let compact: Zeroizing<String> = Zeroizing::new(body.split_whitespace().collect());
    STANDARD
        .decode(compact.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| JwtError::Key)
}

fn es256_pair(pem: &str) -> Result<EcdsaKeyPair, JwtError> {
    EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &pem_der(pem)?,
        &SystemRandom::new(),
    )
    .map_err(|_| JwtError::Key)
}

/// Whether `pem` is a P-256 PKCS#8 private key in PEM form.
///
/// # Errors
///
/// Returns [`JwtError::Key`] when it is not.
pub fn check_es256_key(pem: &str) -> Result<(), JwtError> {
    es256_pair(pem).map(drop)
}

/// Signs `claims` as an ES256 JWT with the PKCS#8 PEM key, the way Apple wants its client secret.
///
/// # Errors
///
/// Returns [`JwtError::Key`] when `key` is not a P-256 PKCS#8 PEM key.
pub fn sign_es256(
    key: &SecretString,
    kid: &str,
    claims: &serde_json::Value,
) -> Result<SecretString, JwtError> {
    let pair = es256_pair(key.expose_secret())?;
    let header = serde_json::json!({ "alg": "ES256", "kid": kid });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = pair
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| JwtError::Key)?;
    Ok(SecretString::from(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )))
}

/// A fixed RSA key and a P-256 key generator for tests and the fake providers.
///
/// The RSA key signs nothing real: it exists only here, and only a test compiles it in.
#[cfg(test)]
pub mod test_key {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::rsa::KeyPair;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256};

    /// The `kid` the fake providers publish the key under.
    pub const KID: &str = "test-key-1";

    fn pair() -> KeyPair {
        KeyPair::from_pkcs8(include_bytes!("test_rsa_2048.pk8")).expect("the test key is valid")
    }

    /// A JWK set document holding the test key under `kid`.
    pub fn jwks(kid: &str) -> String {
        let components: ring::rsa::PublicKeyComponents<Vec<u8>> = pair().public().into();
        let n = URL_SAFE_NO_PAD.encode(components.n);
        let e = URL_SAFE_NO_PAD.encode(components.e);
        format!(
            r#"{{"keys":[{{"kid":"{kid}","kty":"RSA","alg":"RS256","use":"sig","n":"{n}","e":"{e}"}}]}}"#
        )
    }

    /// A token with header `{alg, kid}` and `claims`, always signed with the test key's RS256.
    ///
    /// # Panics
    ///
    /// Never, unless the test key stops being valid.
    pub fn sign(kid: &str, alg: &str, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": alg, "kid": kid, "typ": "JWT" });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0_u8; pair().public().modulus_len()];
        pair()
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .expect("signing works");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// Whether `token` is an ES256 JWT signed by the P-256 key in `pem`.
    ///
    /// # Panics
    ///
    /// When `pem` is not a P-256 key or `token` is not a compact JWT.
    pub fn es256_signed_by(token: &str, pem: &str) -> bool {
        use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair as _, UnparsedPublicKey};
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pkcs8 = base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("the key is base64");
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &SystemRandom::new(),
        )
        .expect("the key is P-256");
        let (signed, signature) = token.rsplit_once('.').expect("a compact JWT");
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .expect("a base64url signature");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref())
            .verify(signed.as_bytes(), &signature)
            .is_ok()
    }

    /// A fresh P-256 key in the PEM form of Apple's `.p8` file.
    ///
    /// # Panics
    ///
    /// Never, unless the system random source fails.
    pub fn es256_pem() -> String {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("key generation works");
        let body = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ascii"))
            .collect();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
        UnparsedPublicKey,
    };
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};

    use super::test_key::{self, KID};
    use super::{JwkSet, JwtError, sign_es256, verify_rs256};

    fn claims() -> Value {
        json!({
            "iss": "https://securetoken.google.com/ibridge-fyi",
            "aud": "ibridge-fyi",
            "sub": "user-1",
            "exp": 2_000_000_000,
            "iat": 1_700_000_000,
            "email": "ada@example.com"
        })
    }

    fn keys() -> JwkSet {
        JwkSet::parse(test_key::jwks(KID).as_bytes()).unwrap()
    }

    #[test]
    fn jwt_rs256_verifies_good_token() {
        let token = test_key::sign(KID, "RS256", &claims());
        let read = verify_rs256(&token, &keys()).expect("a good token verifies");
        assert_eq!(read.sub.as_deref(), Some("user-1"));
        assert_eq!(read.aud.as_deref(), Some("ibridge-fyi"));
        assert_eq!(read.exp, Some(2_000_000_000));
        assert_eq!(read.email.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn jwt_rejects_wrong_kid() {
        let token = test_key::sign("someone-elses-key", "RS256", &claims());
        assert_eq!(
            verify_rs256(&token, &keys()).unwrap_err(),
            JwtError::UnknownKey
        );
    }

    #[test]
    fn jwt_rejects_tampered_payload() {
        let token = test_key::sign(KID, "RS256", &claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let forged =
            json!({ "iss": "x", "aud": "ibridge-fyi", "sub": "admin", "exp": 2_000_000_000 });
        parts[1] = URL_SAFE_NO_PAD.encode(forged.to_string());
        assert_eq!(
            verify_rs256(&parts.join("."), &keys()).unwrap_err(),
            JwtError::Signature
        );
    }

    #[test]
    fn jwt_rejects_alg_none_and_hs256() {
        // HS256 with a genuine RS256 signature over the header: only the header lies.
        let hs256 = test_key::sign(KID, "HS256", &claims());
        assert_eq!(
            verify_rs256(&hs256, &keys()).unwrap_err(),
            JwtError::Algorithm
        );
        let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "none", "kid": KID }).to_string());
        let payload = URL_SAFE_NO_PAD.encode(claims().to_string());
        for token in [
            format!("{header}.{payload}."),
            format!("{header}.{payload}.AAAA"),
        ] {
            assert_eq!(
                verify_rs256(&token, &keys()).unwrap_err(),
                JwtError::Algorithm
            );
        }
    }

    #[test]
    fn jwt_rejects_malformed_tokens() {
        for token in ["", "abc", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert_eq!(
                verify_rs256(token, &keys()).unwrap_err(),
                JwtError::Malformed,
                "{token:?}"
            );
        }
    }

    #[test]
    fn es256_client_secret_verifies_with_public_key() {
        let pem = test_key::es256_pem();
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pkcs8 = STANDARD.decode(body).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();

        let token = sign_es256(&SecretString::from(pem), "KEYID12345", &claims()).unwrap();
        let token = token.expose_secret();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWT");
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID12345");
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload, claims());
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(
            signature.len(),
            64,
            "ES256 signatures are the fixed r||s form"
        );
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref());
        let input = format!("{}.{}", parts[0], parts[1]);
        public
            .verify(input.as_bytes(), &signature)
            .expect("the signature verifies with the key's public half");
        public
            .verify(format!("{}.x", parts[0]).as_bytes(), &signature)
            .expect_err("and with nothing else");
    }

    #[test]
    fn es256_refuses_a_key_that_is_not_p256_pem() {
        for key in [
            "",
            "not a key",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            assert_eq!(
                sign_es256(&SecretString::from(key), "K", &claims()).unwrap_err(),
                JwtError::Key
            );
        }
    }
}
