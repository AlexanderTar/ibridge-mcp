// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM seals whose keys are HKDF outputs of the caller's token.

use aes_gcm::aead::Aead;
use aes_gcm::aead::AeadCore;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, Key, Nonce};

type AesNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;
use hkdf::Hkdf;
use secrecy::SecretString;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF `info` for the AES-256-GCM key.
pub(crate) const SEAL_INFO: &[u8] = b"ibridge-seal-v1";

/// HKDF `info` for the lookup hash stored in the database.
pub(crate) const LOOKUP_INFO: &[u8] = b"ibridge-lookup-v1";

/// A sealed password. `lookup` is not the encryption key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    /// HKDF output under [`LOOKUP_INFO`]. Safe to store.
    pub lookup: [u8; 32],
    /// AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Ciphertext with the authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Why a seal could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum SealError {
    /// The token or the associated data does not match.
    #[error("authentication failed")]
    Authentication,
    /// The decrypted bytes were not UTF-8.
    #[error("plaintext is not text")]
    Plaintext,
    /// The operating system could not supply random bytes.
    #[error("randomness is unavailable")]
    Random,
}

/// Seals `plaintext` under a key derived from `token`, bound to `aad`.
///
/// # Errors
///
/// Returns [`SealError::Random`] when the operating system refuses to supply a nonce,
/// and [`SealError::Authentication`] when the cipher rejects the input.
pub(crate) fn seal(aad: &[u8], token: &[u8], plaintext: &[u8]) -> Result<Sealed, SealError> {
    let mut key_bytes = derive(token, SEAL_INFO);
    let lookup = derive(token, LOOKUP_INFO);
    let key = match aes_key(&key_bytes) {
        Ok(key) => key,
        Err(err) => {
            key_bytes.zeroize();
            return Err(err);
        }
    };
    let cipher = Aes256Gcm::new(&key);
    key_bytes.zeroize();

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|_| SealError::Random)?;
    let nonce = aes_nonce(&nonce_bytes)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError::Authentication)?;

    Ok(Sealed {
        lookup,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Opens `sealed` with `token` and `aad`.
///
/// # Errors
///
/// Returns [`SealError::Authentication`] when the token or associated data is wrong,
/// and [`SealError::Plaintext`] when the opened bytes are not UTF-8.
pub(crate) fn open(aad: &[u8], token: &[u8], sealed: &Sealed) -> Result<SecretString, SealError> {
    let mut key_bytes = derive(token, SEAL_INFO);
    let key = match aes_key(&key_bytes) {
        Ok(key) => key,
        Err(err) => {
            key_bytes.zeroize();
            return Err(err);
        }
    };
    let cipher = Aes256Gcm::new(&key);
    key_bytes.zeroize();
    let nonce = aes_nonce(&sealed.nonce)?;

    let mut plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError::Authentication)?;
    let secret = match std::str::from_utf8(&plain) {
        Ok(text) => SecretString::from(text),
        Err(_err) => {
            plain.zeroize();
            return Err(SealError::Plaintext);
        }
    };
    plain.zeroize();
    Ok(secret)
}

/// Lookup hash for `token`. Safe to store; it is not the encryption key.
#[must_use]
pub(crate) fn lookup(token: &[u8]) -> [u8; 32] {
    derive(token, LOOKUP_INFO)
}

/// HKDF-SHA256 with an empty salt.
///
/// # Panics
///
/// Panics if the 32-byte output exceeds the HKDF length limit. It does not:
/// the limit is 255 SHA-256 blocks.
fn derive(token: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, token);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte HKDF output is within the 255-block limit");
    okm
}

fn aes_key(bytes: &[u8; 32]) -> Result<Key<Aes256Gcm>, SealError> {
    Key::<Aes256Gcm>::try_from(bytes.as_slice()).map_err(|_| SealError::Authentication)
}

fn aes_nonce(bytes: &[u8; 12]) -> Result<AesNonce, SealError> {
    AesNonce::try_from(bytes.as_slice()).map_err(|_| SealError::Authentication)
}

#[cfg(test)]
mod tests {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::Key;
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::KeyInit;
    use aes_gcm::aead::Payload;
    use secrecy::ExposeSecret;

    use super::{AesNonce, SealError, open, seal};

    const TOKEN: &[u8] = b"token-value";
    const AAD: &[u8] = b"user@icloud.com|0123456789abcdef";

    /// Independent HKDF-SHA256 (empty salt, info `ibridge-seal-v1`) of `token-value`.
    const SEAL_KEY: [u8; 32] = [
        0x14, 0xf9, 0x2a, 0x9d, 0x8b, 0x01, 0xff, 0x31, 0x8b, 0x88, 0x1a, 0xee, 0xea, 0x7e, 0x37,
        0x44, 0xdd, 0xc0, 0x04, 0xb1, 0x4d, 0xa4, 0x72, 0xdc, 0x5a, 0xc1, 0xa7, 0x7c, 0x54, 0x80,
        0x69, 0xfa,
    ];

    /// Independent HKDF-SHA256 (empty salt, info `ibridge-lookup-v1`) of `token-value`.
    const LOOKUP: [u8; 32] = [
        0x04, 0xba, 0xc3, 0x3c, 0xd5, 0x3b, 0x08, 0x17, 0x7c, 0xd6, 0x64, 0x39, 0xe6, 0xd8, 0x2b,
        0x8a, 0xdb, 0x42, 0x69, 0x15, 0x80, 0xeb, 0x64, 0x44, 0x57, 0xd7, 0x45, 0x0c, 0xc2, 0x68,
        0x23, 0x32,
    ];

    #[test]
    fn seal_open_roundtrip() {
        for plain in [b"asp-one".as_slice(), b"asp-two".as_slice()] {
            let sealed = seal(AAD, TOKEN, plain).unwrap();
            let opened = open(AAD, TOKEN, &sealed).unwrap();
            let text = std::str::from_utf8(plain).unwrap();
            assert_eq!(
                opened.expose_secret(),
                text,
                "opened plaintext must be the bytes that were sealed"
            );
        }
    }

    #[test]
    fn open_with_wrong_token_fails() {
        let sealed = seal(AAD, TOKEN, b"asp-secret").unwrap();
        let opened = open(AAD, b"other-token", &sealed);
        assert!(
            matches!(opened, Err(SealError::Authentication)),
            "wrong token must fail authentication, got {opened:?}"
        );
        let wrong_aad = open(b"other@icloud.com|0123456789abcdef", TOKEN, &sealed);
        assert!(
            matches!(wrong_aad, Err(SealError::Authentication)),
            "wrong associated data must fail authentication, got {wrong_aad:?}"
        );
    }

    #[test]
    fn hash_label_differs_from_key_label() {
        let sealed = seal(AAD, TOKEN, b"asp-secret").unwrap();
        assert_eq!(
            sealed.lookup, LOOKUP,
            "stored lookup must be HKDF info ibridge-lookup-v1, not the encryption key"
        );
        let key = Key::<Aes256Gcm>::try_from(SEAL_KEY.as_slice()).expect("seal key is 32 bytes");
        let nonce = AesNonce::try_from(sealed.nonce.as_slice()).expect("nonce is 12 bytes");
        let opened = cipher_decrypt(&key, &nonce, &sealed.ciphertext);
        assert_eq!(
            opened.expect("ciphertext must open with HKDF info ibridge-seal-v1"),
            b"asp-secret"
        );
    }

    fn cipher_decrypt(
        key: &Key<Aes256Gcm>,
        nonce: &AesNonce,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        Aes256Gcm::new(key).decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
    }
}
