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

#[derive(Debug)]
struct Slot {
    id: u64,
    at: tokio::time::Instant,
}

#[derive(Debug)]
struct Window {
    next_id: u64,
    sent: Vec<Slot>,
}

/// Rolling hour of send times for one account.
#[derive(Debug)]
pub(crate) struct SendWindow {
    limits: SendLimits,
    state: Mutex<Window>,
}

/// One reserved send. Drop releases it. [`Self::commit`] keeps it.
pub(crate) struct Reservation<'a> {
    window: &'a SendWindow,
    id: u64,
    armed: bool,
}

impl SendWindow {
    pub(crate) fn new(limits: SendLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(Window {
                next_id: 0,
                sent: Vec::new(),
            }),
        }
    }

    /// Refuses an oversized recipient list or a send past the hourly cap.
    ///
    /// A refusal is not reserved. The returned reservation holds a slot until
    /// it is committed or dropped, so a failed SMTP attempt does not count.
    /// The clock is [`tokio::time::Instant`], so a paused test clock can move
    /// the window.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidInput`] when `recipients` is over the cap,
    /// and [`CoreError::RateLimited`] when this hour is full.
    pub(crate) fn admit(&self, recipients: usize) -> Result<Reservation<'_>, CoreError> {
        if recipients > self.limits.max_recipients {
            return Err(CoreError::InvalidInput(
                "a message has too many recipients".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("send window");
        let hour = Duration::from_hours(1);
        state.sent.retain(|slot| slot.at.elapsed() < hour);
        if state.sent.len() >= self.limits.max_per_hour {
            let retry_after = state
                .sent
                .first()
                .map(|oldest| hour.saturating_sub(oldest.at.elapsed()));
            return Err(CoreError::RateLimited { retry_after });
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.sent.push(Slot {
            id,
            at: tokio::time::Instant::now(),
        });
        drop(state);
        Ok(Reservation {
            window: self,
            id,
            armed: true,
        })
    }

    fn release(&self, id: u64) {
        let mut state = self.state.lock().expect("send window");
        state.sent.retain(|slot| slot.id != id);
    }
}

impl Reservation<'_> {
    /// Keeps the slot. SMTP has accepted the message.
    pub(crate) fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.window.release(self.id);
        }
    }
}
