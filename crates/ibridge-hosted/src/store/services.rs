// SPDX-License-Identifier: Apache-2.0

//! What a sign-in found out about each service, kept with the grant it created.

use ibridge_auth::{ServiceCheck, ValidationReport};
use serde::{Deserialize, Serialize};

/// Why each service is off for a grant. `None` means the service accepted the password.
///
/// The reasons come from the sign-in check, which words them to be safe to show. They never
/// hold a password. A grant from before this was recorded has every service on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Services {
    /// Why mail is off.
    pub mail: Option<String>,
    /// Why calendar and reminders are off.
    pub calendar: Option<String>,
    /// Why contacts are off.
    pub contacts: Option<String>,
}

impl Services {
    /// What the sign-in check reported.
    ///
    /// Only a refusal turns a service off. A service the check could not reach
    /// ([`ServiceCheck::Unreachable`]) stays on, so a brief outage at sign-in does not hide
    /// it for the life of the grant.
    #[must_use]
    pub fn from_report(report: &ValidationReport) -> Self {
        let reason = |check: &ServiceCheck| match check {
            ServiceCheck::Failed { reason } => Some(reason.clone()),
            _ => None,
        };
        Self {
            mail: reason(&report.mail),
            calendar: reason(&report.calendar),
            contacts: reason(&report.contacts),
        }
    }
}
