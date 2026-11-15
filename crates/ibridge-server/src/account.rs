// SPDX-License-Identifier: Apache-2.0

//! Signed-in account as the tools report it. No secrets.

use ibridge_core::AppleId;

/// Whether one service can be used, and why not.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceStatus {
    /// The service validated and its tools may run.
    On,
    /// The service is off. `reason` is safe to show to the model.
    Off {
        /// Why the service is off. No secrets and no server banners.
        reason: String,
    },
}

/// What `account_status` reports for one local server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSnapshot {
    /// Signed-in Apple ID.
    pub apple_id: AppleId,
    /// Mail reachability.
    pub mail: ServiceStatus,
    /// Calendar reachability.
    pub calendar: ServiceStatus,
    /// Contacts reachability.
    pub contacts: ServiceStatus,
}
