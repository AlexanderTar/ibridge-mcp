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

impl Services {
    /// The services the saved sign-in left on.
    ///
    /// A service the login recorded as off keeps its tools hidden. With no saved
    /// sign-in, such as an account from the environment, nothing changes.
    pub(crate) fn after_login(self, recorded: Option<&State>) -> Self {
        let on = |built: bool, pick: fn(&State) -> Option<&String>| {
            built && recorded.and_then(pick).is_none()
        };
        Self {
            mail: on(self.mail, |state| state.mail.as_ref()),
            calendar: on(self.calendar, |state| state.calendar.as_ref()),
            contacts: on(self.contacts, |state| state.contacts.as_ref()),
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
/// `recorded` is the sign-in result, when there is one.
pub(crate) fn snapshot(
    apple_id: AppleId,
    services: Services,
    recorded: Option<&State>,
) -> AccountSnapshot {
    let failed = |pick: fn(&State) -> Option<&String>| recorded.and_then(pick).cloned();
    let not_built =
        |built: bool, name: &str| (!built).then(|| format!("{name} is not enabled in this build"));
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
            None,
        ]),
        contacts: status([
            not_built(services.contacts, "contacts"),
            failed(|state| state.contacts.as_ref()),
            None,
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

#[cfg(test)]
mod tests {
    use ibridge_auth::{ServiceCheck, ValidationReport};
    use ibridge_core::AppleId;
    use ibridge_server::ServiceStatus;

    use super::{Services, State, snapshot};

    fn apple_id() -> AppleId {
        AppleId::try_from("ada@icloud.com").expect("apple id")
    }

    fn with_calendar() -> Services {
        Services {
            mail: true,
            calendar: true,
            contacts: true,
        }
    }

    fn without_calendar() -> Services {
        Services {
            calendar: false,
            ..with_calendar()
        }
    }

    #[test]
    fn account_status_reports_calendar() {
        let signed_in = State::from_report(
            &apple_id(),
            &ValidationReport {
                mail: ServiceCheck::Ok,
                calendar: ServiceCheck::Ok,
                contacts: ServiceCheck::Ok,
            },
        );
        assert_eq!(
            snapshot(apple_id(), with_calendar(), Some(&signed_in)).calendar,
            ServiceStatus::On,
            "calendar is on when sign-in worked and the build has it"
        );

        let rejected = State::from_report(
            &apple_id(),
            &ValidationReport {
                mail: ServiceCheck::Ok,
                calendar: ServiceCheck::Failed {
                    reason: "calendar rejected".to_owned(),
                },
                contacts: ServiceCheck::Ok,
            },
        );
        assert_eq!(
            snapshot(apple_id(), with_calendar(), Some(&rejected)).calendar,
            ServiceStatus::Off {
                reason: "calendar rejected".to_owned()
            },
            "a failed sign-in check turns calendar off with its reason"
        );
        assert_eq!(
            snapshot(apple_id(), without_calendar(), Some(&signed_in)).calendar,
            ServiceStatus::Off {
                reason: "calendar is not enabled in this build".to_owned()
            },
            "a build without calendar says so"
        );
    }

    #[test]
    fn account_status_reports_contacts() {
        let signed_in = State::from_report(
            &apple_id(),
            &ValidationReport {
                mail: ServiceCheck::Ok,
                calendar: ServiceCheck::Ok,
                contacts: ServiceCheck::Ok,
            },
        );
        assert_eq!(
            snapshot(apple_id(), with_calendar(), Some(&signed_in)).contacts,
            ServiceStatus::On,
            "contacts is on when sign-in worked and the build has it"
        );

        let rejected = State::from_report(
            &apple_id(),
            &ValidationReport {
                mail: ServiceCheck::Ok,
                calendar: ServiceCheck::Ok,
                contacts: ServiceCheck::Failed {
                    reason: "contacts rejected".to_owned(),
                },
            },
        );
        assert_eq!(
            snapshot(apple_id(), with_calendar(), Some(&rejected)).contacts,
            ServiceStatus::Off {
                reason: "contacts rejected".to_owned()
            },
            "a failed sign-in check turns contacts off with its reason"
        );
        let no_contacts = Services {
            contacts: false,
            ..with_calendar()
        };
        assert_eq!(
            snapshot(apple_id(), no_contacts, Some(&signed_in)).contacts,
            ServiceStatus::Off {
                reason: "contacts is not enabled in this build".to_owned()
            },
            "a build without contacts says so"
        );
    }
}
