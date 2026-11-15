// SPDX-License-Identifier: Apache-2.0

//! Sliding-window rate limits for the public sign-in surfaces.
//!
//! `/authorize` and `/account` share one [`SignInLimits`] so an attacker cannot
//! get a second budget by switching pages.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Keys tracked before expired ones are swept out.
const SWEEP_AT: usize = 10_000;

/// At most `limit` hits per key in any `window`.
#[derive(Debug)]
pub(crate) struct Limiter {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Limiter {
    pub(crate) fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit for `key` and returns true while the key is within its limit.
    ///
    /// A refused hit is not recorded, so waiting out the window always works.
    pub(crate) fn allow(&self, key: &str, now: Instant) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        if hits.len() >= SWEEP_AT {
            hits.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|last| now.saturating_duration_since(*last) < self.window)
            });
        }
        let times = hits.entry(key.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= self.window)
        {
            times.pop_front();
        }
        if times.len() >= self.limit {
            return false;
        }
        times.push_back(now);
        true
    }
}

/// The sign-in budget: 10 attempts a minute per IP and 5 per 15 minutes per address.
#[derive(Debug)]
pub(crate) struct SignInLimits {
    per_ip: Limiter,
    per_address: Limiter,
}

impl SignInLimits {
    pub(crate) fn new() -> Self {
        Self {
            per_ip: Limiter::new(10, Duration::from_secs(60)),
            per_address: Limiter::new(5, Duration::from_mins(15)),
        }
    }

    /// Counts one sign-in attempt. An attempt refused for its IP does not use up the address's budget.
    pub(crate) fn allow(&self, ip: &str, address: Option<&str>, now: Instant) -> bool {
        self.per_ip.allow(ip, now)
            && address.is_none_or(|address| self.per_address.allow(address, now))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Limiter, SignInLimits};

    #[test]
    fn a_key_gets_its_limit_per_window_and_then_a_fresh_window() {
        let limiter = Limiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.allow("a", start));
        assert!(limiter.allow("a", start + Duration::from_secs(1)));
        assert!(
            !limiter.allow("a", start + Duration::from_secs(2)),
            "third hit in the window"
        );
        assert!(
            limiter.allow("b", start + Duration::from_secs(2)),
            "other keys are separate"
        );
        assert!(
            limiter.allow("a", start + Duration::from_secs(61)),
            "the first hit has left the window"
        );
    }

    #[test]
    fn an_ip_refusal_does_not_spend_the_address_budget() {
        let limits = SignInLimits::new();
        let start = Instant::now();
        for _ in 0..10 {
            assert!(limits.allow("203.0.113.1", None, start));
        }
        for _ in 0..20 {
            assert!(!limits.allow("203.0.113.1", Some("ada@icloud.com"), start));
        }
        for other in 0..5 {
            assert!(
                limits.allow(
                    &format!("198.51.100.{other}"),
                    Some("ada@icloud.com"),
                    start
                ),
                "the address budget is untouched by the blocked IP"
            );
        }
    }
}
