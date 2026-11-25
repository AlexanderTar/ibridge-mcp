// SPDX-License-Identifier: Apache-2.0

//! Per-account send limits. Both caps are configurable.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use ibridge_core::CoreError;

/// How many recipients one message may have, and how many sends an hour allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLimits {
    /// Recipients allowed on one message.
    pub max_recipients: usize,
    /// Sends allowed in a rolling hour.
    pub max_per_hour: usize,
    /// One-click unsubscribe POSTs allowed in a rolling hour. Counted apart from sends.
    pub max_one_click_per_hour: usize,
}

impl Default for SendLimits {
    fn default() -> Self {
        Self {
            max_recipients: 50,
            max_per_hour: 20,
            max_one_click_per_hour: 10,
        }
    }
}

#[derive(Debug)]
struct Slot {
    id: u64,
    at: tokio::time::Instant,
}

#[derive(Debug, Default)]
struct Window {
    next_id: u64,
    sent: Vec<Slot>,
}

/// Rolling hour of send times for one account.
///
/// A [`crate::MailSession`] built with [`crate::MailSession::with_window`] shares it, so a
/// host that rebuilds sessions keeps one cap per account.
#[derive(Debug)]
pub struct SendWindow {
    limits: SendLimits,
    state: Mutex<Window>,
    /// One-click unsubscribe POSTs, counted apart from sends.
    one_click: Mutex<Window>,
}

/// One reserved send. Drop releases it. [`Self::commit`] keeps it.
pub(crate) struct Reservation<'a> {
    window: &'a SendWindow,
    id: u64,
    armed: bool,
}

impl SendWindow {
    /// An empty window with `limits`.
    #[must_use]
    pub fn new(limits: SendLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(Window::default()),
            one_click: Mutex::new(Window::default()),
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
        let id = take_slot(&self.state, self.limits.max_per_hour)?;
        Ok(Reservation {
            window: self,
            id,
            armed: true,
        })
    }

    /// Counts one one-click unsubscribe POST, or refuses it past the hourly cap.
    ///
    /// Every attempt that passes counts, even one that then fails: a failed attempt may have
    /// reached the sender's host. The cap bounds how often an account can make this server
    /// POST to a host that the message's sender chose.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RateLimited`] when this hour is full.
    pub(crate) fn admit_one_click(&self) -> Result<(), CoreError> {
        take_slot(&self.one_click, self.limits.max_one_click_per_hour).map(drop)
    }

    /// Nothing is inside the rolling hour, so the window can be forgotten.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        let hour = Duration::from_hours(1);
        [&self.state, &self.one_click].into_iter().all(|window| {
            let state = window.lock().unwrap_or_else(PoisonError::into_inner);
            state.sent.iter().all(|slot| slot.at.elapsed() >= hour)
        })
    }

    fn release(&self, id: u64) {
        let mut state = self.state.lock().expect("send window");
        state.sent.retain(|slot| slot.id != id);
    }
}

/// Adds a slot to `window`, or refuses when `max` slots are already inside the rolling hour.
fn take_slot(window: &Mutex<Window>, max: usize) -> Result<u64, CoreError> {
    let mut state = window.lock().expect("send window");
    let hour = Duration::from_hours(1);
    state.sent.retain(|slot| slot.at.elapsed() < hour);
    if state.sent.len() >= max {
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
    Ok(id)
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ibridge_core::CoreError;

    use super::{SendLimits, SendWindow};

    fn window(max_per_hour: usize, max_one_click_per_hour: usize) -> SendWindow {
        SendWindow::new(SendLimits {
            max_recipients: 50,
            max_per_hour,
            max_one_click_per_hour,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn one_click_slots_come_back_after_an_hour_and_are_not_send_slots() {
        let window = window(1, 2);
        window.admit_one_click().expect("first");
        window.admit_one_click().expect("second");
        let err = window.admit_one_click().expect_err("over the cap");
        assert!(
            matches!(err, CoreError::RateLimited { retry_after: Some(wait) } if wait > Duration::from_mins(59)),
            "got {err:?}"
        );
        window.admit(1).expect("a send has its own cap").commit();
        assert!(!window.is_idle(), "slots are inside the hour");
        tokio::time::advance(Duration::from_hours(1)).await;
        window.admit_one_click().expect("the hour has rolled");
    }

    #[tokio::test(start_paused = true)]
    async fn a_window_is_idle_only_when_both_counters_are_empty() {
        let window = window(5, 5);
        assert!(window.is_idle());
        window.admit_one_click().expect("one-click");
        assert!(!window.is_idle(), "a one-click POST keeps the window");
        tokio::time::advance(Duration::from_hours(1)).await;
        assert!(window.is_idle());
    }
}
