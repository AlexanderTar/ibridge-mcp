// SPDX-License-Identifier: Apache-2.0

//! Short-lived server-side state that anonymous visitors can create, so it is capped.
//!
//! [`Pending`] is the shared bounded map. [`PendingAuthorize`] keeps an `/authorize`
//! request for an hour, owned by the browser that started it, so the request survives a
//! trip through Sign in with Apple or Stripe and comes back only to the same browser.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::authorize::Params;
use crate::web::{random_token, tokens_match};

/// Most entries either pending store holds. Anyone can ask to create one, so the count is
/// bounded: past it a store drops its expired entries, and then refuses new ones.
pub(crate) const MAX_PENDING: usize = 10_000;
/// The cookie that says which browser stored a pending `/authorize` request.
pub(crate) const PENDING_COOKIE: &str = "__Host-ibridge_pending";
/// How long a pending `/authorize` request waits.
const AUTHORIZE_LIFETIME: Duration = Duration::from_hours(1);

/// The store is full of live entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Full;

/// A map of live entries that expire and cannot grow without bound.
///
/// ponytail: in memory, so a restart ends every pending entry and the person starts the
/// step again. SQLite is the upgrade if the server ever runs as more than one instance.
#[derive(Debug)]
pub(crate) struct Pending<V> {
    entries: Mutex<HashMap<String, (Instant, V)>>,
    lifetime: Duration,
    cap: usize,
}

impl<V: Clone> Pending<V> {
    pub(crate) fn new(lifetime: Duration, cap: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            lifetime,
            cap,
        }
    }

    fn live(&self, made: Instant, now: Instant) -> bool {
        now.saturating_duration_since(made) < self.lifetime
    }

    /// Stores `value` under `id`. At the cap, expired entries go first; if none do, [`Full`].
    pub(crate) fn insert(&self, id: String, value: V, now: Instant) -> Result<(), Full> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.cap {
            entries.retain(|_, (made, _)| self.live(*made, now));
            if entries.len() >= self.cap {
                return Err(Full);
            }
        }
        entries.insert(id, (now, value));
        Ok(())
    }

    /// The entry, when it exists and has not expired.
    pub(crate) fn get(&self, id: &str, now: Instant) -> Option<V> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (made, value) = entries.get(id)?;
        self.live(*made, now).then(|| value.clone())
    }

    /// Removes and returns the entry: it can be taken once. An expired entry is removed too,
    /// and returns nothing.
    pub(crate) fn take(&self, id: &str, now: Instant) -> Option<V> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (made, value) = entries.remove(id)?;
        self.live(made, now).then_some(value)
    }

    /// How many entries are held, expired ones included.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[derive(Clone)]
struct Stored {
    params: Params,
    /// SHA-256 of the owner cookie, so the map holds no usable cookie.
    owner: [u8; 32],
}

/// Pending `/authorize` requests, each owned by the cookie of the browser that made it.
#[derive(Debug)]
pub(crate) struct PendingAuthorize(Pending<Stored>);

impl std::fmt::Debug for Stored {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Stored")
    }
}

impl PendingAuthorize {
    pub(crate) fn new(cap: usize) -> Self {
        Self(Pending::new(AUTHORIZE_LIFETIME, cap))
    }

    /// Keeps `params` for `owner` and returns the id to resume it with.
    ///
    /// `None` when the store is full or the system has no randomness.
    pub(crate) fn put(&self, params: Params, owner: &str, now: Instant) -> Option<String> {
        if owner.is_empty() {
            return None;
        }
        let id = random_token()?;
        self.0
            .insert(
                id.clone(),
                Stored {
                    params,
                    owner: owner_key(owner),
                },
                now,
            )
            .ok()?;
        Some(id)
    }

    /// The stored request, only for the browser that made it.
    pub(crate) fn get(&self, id: &str, owner: &str, now: Instant) -> Option<Params> {
        let stored = self.0.get(id, now)?;
        owns(&stored, owner).then_some(stored.params)
    }

    /// Removes and returns the stored request, only for the browser that made it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the checkout return takes the request with this")
    )]
    pub(crate) fn take(&self, id: &str, owner: &str, now: Instant) -> Option<Params> {
        let stored = self.0.get(id, now)?;
        if !owns(&stored, owner) {
            return None;
        }
        self.0.take(id, now).map(|stored| stored.params)
    }
}

fn owner_key(owner: &str) -> [u8; 32] {
    Sha256::digest(owner.as_bytes()).into()
}

fn owns(stored: &Stored, owner: &str) -> bool {
    if owner.is_empty() {
        return false;
    }
    // Both sides are hashes of equal length, so the comparison takes the same time either way.
    let left = hex_of(&stored.owner);
    let right = hex_of(&owner_key(owner));
    tokens_match(&left, &right)
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{AUTHORIZE_LIFETIME, Full, Pending, PendingAuthorize};
    use crate::oauth::authorize::Params;

    fn params() -> Params {
        serde_json::from_value(json!({ "client_id": "c", "state": "s" })).expect("params")
    }

    #[test]
    fn pending_stores_refuse_past_cap() {
        let now = Instant::now();
        let store: Pending<u32> = Pending::new(Duration::from_secs(60), 3);
        for id in ["a", "b", "c"] {
            store.insert(id.to_owned(), 1, now).expect("room");
        }
        assert_eq!(store.insert("d".to_owned(), 1, now), Err(Full));
        assert_eq!(store.len(), 3, "a refused entry is not kept");
        // Once the old ones expire, the same store takes new entries again.
        let later = now + Duration::from_secs(61);
        store
            .insert("d".to_owned(), 1, later)
            .expect("expired entries make room");
        assert_eq!(store.len(), 1, "the expired entries were dropped");

        let authorize = PendingAuthorize::new(2);
        assert!(authorize.put(params(), "owner", now).is_some());
        assert!(authorize.put(params(), "owner", now).is_some());
        assert!(
            authorize.put(params(), "owner", now).is_none(),
            "the third is refused"
        );
    }

    #[test]
    fn pending_entries_are_taken_once_and_expire() {
        let now = Instant::now();
        let store: Pending<u32> = Pending::new(Duration::from_secs(60), 10);
        store.insert("a".to_owned(), 7, now).expect("room");
        assert_eq!(store.get("a", now), Some(7), "reading does not use it up");
        assert_eq!(store.take("a", now + Duration::from_secs(59)), Some(7));
        assert_eq!(store.take("a", now + Duration::from_secs(59)), None, "once");
        store.insert("b".to_owned(), 8, now).expect("room");
        assert_eq!(
            store.take("b", now + Duration::from_secs(60)),
            None,
            "expired"
        );
        assert_eq!(store.len(), 0, "an expired entry is dropped when asked for");
    }

    #[test]
    fn pending_authorize_other_owner_refused() {
        let now = Instant::now();
        let store = PendingAuthorize::new(10);
        let id = store.put(params(), "owner-a", now).expect("stored");
        assert!(store.get(&id, "owner-b", now).is_none(), "another browser");
        assert!(store.get(&id, "", now).is_none(), "no cookie");
        assert!(
            store.take(&id, "owner-b", now).is_none(),
            "another browser cannot take it"
        );
        assert!(
            store.get(&id, "owner-a", now).is_some(),
            "and did not use it up"
        );
        assert!(store.take(&id, "owner-a", now).is_some());
        assert!(store.take(&id, "owner-a", now).is_none(), "once");
    }

    #[test]
    fn pending_authorize_expires_after_an_hour() {
        let now = Instant::now();
        let store = PendingAuthorize::new(10);
        let id = store.put(params(), "owner", now).expect("stored");
        let almost = now + Duration::from_secs(3_599);
        assert!(store.get(&id, "owner", almost).is_some());
        assert!(store.get(&id, "owner", now + AUTHORIZE_LIFETIME).is_none());
    }
}
