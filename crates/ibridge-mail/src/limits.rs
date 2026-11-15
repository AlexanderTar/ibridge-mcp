// SPDX-License-Identifier: Apache-2.0

//! Per-account send limits. Both caps are configurable.

use std::sync::Mutex;
use std::time::Duration;

use ibridge_core::CoreError;

/// How many recipients one message may have, and how many sends an hour allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLimits {
    /// Recipients allowed on one message.
    pub max_recipients: usize,
    /// Sends allowed in a rolling hour.
    pub max_per_hour: usize,
}

impl Default for SendLimits {
    fn default() -> Self {
        Self {
            max_recipients: 50,
            max_per_hour: 20,
        }
    }
}

/// Rolling hour of send times for one account.
#[derive(Debug)]
pub(crate) struct SendWindow {
    limits: SendLimits,
    sent_at: Mutex<Vec<tokio::time::Instant>>,
}

impl SendWindow {
    pub(crate) fn new(limits: SendLimits) -> Self {
        Self {
            limits,
            sent_at: Mutex::new(Vec::new()),
        }
    }

    /// Refuses an oversized recipient list or a send past the hourly cap.
    ///
    /// A refusal is not recorded. The clock is [`tokio::time::Instant`], so a
    /// paused test clock can move the window.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidInput`] when `recipients` is over the cap,
    /// and [`CoreError::RateLimited`] when this hour is full.
    pub(crate) fn admit(&self, recipients: usize) -> Result<(), CoreError> {
        if recipients > self.limits.max_recipients {
            return Err(CoreError::InvalidInput(
                "a message has too many recipients".to_owned(),
            ));
        }
        let mut sent = self.sent_at.lock().expect("send window");
        let hour = Duration::from_hours(1);
        sent.retain(|at| at.elapsed() < hour);
        if sent.len() >= self.limits.max_per_hour {
            let retry_after = sent
                .first()
                .map(|oldest| hour.saturating_sub(oldest.elapsed()));
            return Err(CoreError::RateLimited { retry_after });
        }
        sent.push(tokio::time::Instant::now());
        Ok(())
    }
}
