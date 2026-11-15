// SPDX-License-Identifier: Apache-2.0

//! The account `ibridge login` remembers, and what the server reports for each service.

use anyhow::Context as _;
use ibridge_auth::{ServiceCheck, ValidationReport};
use ibridge_core::AppleId;
use ibridge_server::{AccountSnapshot, ServiceStatus};
use keyring_core::Entry;
use serde::{Deserialize, Serialize};

/// Keychain service name. The password entry is `(ibridge, <apple id>)`.
pub(crate) const KEYCHAIN_SERVICE: &str = "ibridge";
/// Keychain entry holding the signed-in address and which services are off.
const STATE_USER: &str = "state";

/// Which services this build includes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Services {
    pub(crate) mail: bool,
    pub(crate) calendar: bool,
    pub(crate) contacts: bool,
}

impl Services {
    /// The services the binary was compiled with.
    pub(crate) const fn built() -> Self {
        Self {
            mail: cfg!(feature = "mail"),
            calendar: cfg!(feature = "calendar"),
            contacts: cfg!(feature = "contacts"),
        }
    }
}

/// The signed-in address and, per service, why it is off. `None` means on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct State {
    apple_id: String,
    mail: Option<String>,
    calendar: Option<String>,
    contacts: Option<String>,
}

impl State {
    /// Records the result of a sign-in.
    pub(crate) fn from_report(apple_id: &AppleId, report: &ValidationReport) -> Self {
        Self {
            apple_id: apple_id.as_str().to_owned(),
            mail: reason(&report.mail),
            calendar: reason(&report.calendar),
            contacts: reason(&report.contacts),
        }
    }

    /// Reads the saved state. `None` when nobody has signed in.
    pub(crate) fn load() -> anyhow::Result<Option<Self>> {
        let entry = Entry::new(KEYCHAIN_SERVICE, STATE_USER)?;
        match entry.get_password() {
            Ok(json) => Ok(Some(
                serde_json::from_str(&json).context("the saved account state is damaged")?,
            )),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Saves the state.
    pub(crate) fn save(&self) -> anyhow::Result<()> {
        Entry::new(KEYCHAIN_SERVICE, STATE_USER)?.set_password(&serde_json::to_string(self)?)?;
        Ok(())
    }

    /// Forgets the state. A missing entry is fine.
    pub(crate) fn clear() -> anyhow::Result<()> {
        match Entry::new(KEYCHAIN_SERVICE, STATE_USER)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// The signed-in address.
    pub(crate) fn apple_id(&self) -> anyhow::Result<AppleId> {
        AppleId::try_from(self.apple_id.as_str()).context("the saved Apple ID is not valid")
    }
}

fn reason(check: &ServiceCheck) -> Option<String> {
    match check {
        ServiceCheck::Failed { reason } => Some(reason.clone()),
        _ => None,
    }
}

/// What `account_status` reports.
///
/// `recorded` is the sign-in result, when there is one. Calendar and contacts
/// have no tools in this release, so they report off even when sign-in worked.
pub(crate) fn snapshot(
    apple_id: AppleId,
    services: Services,
    recorded: Option<&State>,
) -> AccountSnapshot {
    let failed = |pick: fn(&State) -> Option<&String>| recorded.and_then(pick).cloned();
    let not_built =
        |built: bool, name: &str| (!built).then(|| format!("{name} is not enabled in this build"));
    let no_tools = |name: &str| Some(format!("{name} tools are not available in this release"));
    AccountSnapshot {
        apple_id,
        mail: status([
            not_built(services.mail, "mail"),
            failed(|state| state.mail.as_ref()),
            None,
        ]),
        calendar: status([
            not_built(services.calendar, "calendar"),
            failed(|state| state.calendar.as_ref()),
            no_tools("calendar"),
        ]),
        contacts: status([
            not_built(services.contacts, "contacts"),
            failed(|state| state.contacts.as_ref()),
            no_tools("contacts"),
        ]),
    }
}

/// Off with the first reason given, or on when there is none.
fn status(reasons: [Option<String>; 3]) -> ServiceStatus {
    match reasons.into_iter().flatten().next() {
        Some(reason) => ServiceStatus::Off { reason },
        None => ServiceStatus::On,
    }
}
