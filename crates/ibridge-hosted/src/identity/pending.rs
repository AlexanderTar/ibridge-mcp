// SPDX-License-Identifier: Apache-2.0

//! Sign-ins waiting for Apple's callback, keyed by `state`.

use std::time::{Duration, Instant};

use super::ReturnTo;
use crate::oauth::pending::{Full, MAX_PENDING, Pending};

/// How long a person has to finish at Apple.
pub(crate) const LIFETIME: Duration = Duration::from_mins(10);

/// What the callback must find again: the raw nonce, the hash of the browser's binder
/// cookie, and where to go afterwards.
#[derive(Clone)]
pub(crate) struct PendingSignIn {
    pub(crate) nonce: String,
    pub(crate) binder: [u8; 32],
    pub(crate) return_to: ReturnTo,
}

/// The pending sign-ins. An entry is taken once, so a replayed callback finds nothing.
pub(crate) struct PendingSignIns(Pending<PendingSignIn>);

impl std::fmt::Debug for PendingSignIns {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingSignIns")
    }
}

impl PendingSignIns {
    pub(crate) fn new(lifetime: Duration, cap: usize) -> Self {
        Self(Pending::new(lifetime, cap))
    }

    pub(crate) fn standard() -> Self {
        Self::new(LIFETIME, MAX_PENDING)
    }

    pub(crate) fn insert(
        &self,
        state: String,
        pending: PendingSignIn,
        now: Instant,
    ) -> Result<(), Full> {
        self.0.insert(state, pending, now)
    }

    pub(crate) fn take(&self, state: &str, now: Instant) -> Option<PendingSignIn> {
        self.0.take(state, now)
    }
}
