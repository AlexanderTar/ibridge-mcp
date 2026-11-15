// SPDX-License-Identifier: Apache-2.0

//! What each authorization code is bound to, until it is exchanged or expires.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Codes live 60 seconds, as in the store.
const LIFETIME: Duration = Duration::from_secs(60);

/// What the token endpoint must check against the authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingCode {
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    /// The PKCE S256 challenge the client sent.
    pub(crate) challenge: String,
}

/// Pending codes, keyed by the SHA-256 of the code so the map holds no usable code.
///
/// ponytail: in memory, so a restart inside a code's 60 seconds makes that
/// sign-in fail and the client retries. Moving this into SQLite is the upgrade
/// if the server ever runs as more than one instance.
#[derive(Debug, Default)]
pub(crate) struct PendingCodes {
    inner: Mutex<HashMap<[u8; 32], (Instant, PendingCode)>>,
}

impl PendingCodes {
    pub(crate) fn insert(&self, code: &str, pending: PendingCode, now: Instant) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.retain(|_, (issued, _)| now.saturating_duration_since(*issued) < LIFETIME);
        inner.insert(key(code), (now, pending));
    }

    /// Removes and returns the binding. A code can be looked up once.
    pub(crate) fn take(&self, code: &str, now: Instant) -> Option<PendingCode> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (issued, pending) = inner.remove(&key(code))?;
        (now.saturating_duration_since(issued) < LIFETIME).then_some(pending)
    }
}

fn key(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}
