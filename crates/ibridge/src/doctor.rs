// SPDX-License-Identifier: Apache-2.0

//! `ibridge doctor`: the keychain, the network and the sign-in, for each service.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::Duration;

use ibridge_auth::{ServiceCheck, ValidationReport, Validator};

use crate::account::Services;

/// Each service and the iCloud host `doctor` reaches for it.
const ENDPOINTS: [(&str, &str, u16); 3] = [
    ("mail", "imap.mail.me.com", 993),
    ("calendar", "caldav.icloud.com", 443),
    ("contacts", "contacts.icloud.com", 443),
];
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// One check's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    /// It worked. The text says what was checked, or is empty.
    Ok(String),
    /// It did not work. The text is a safe reason, never a secret.
    Failed(String),
    /// It was not run. The text says why.
    Skipped(String),
}

/// What `doctor` found for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceReport {
    pub(crate) name: &'static str,
    pub(crate) network: Check,
    pub(crate) auth: Check,
}

/// Everything `doctor` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) keychain: Check,
    pub(crate) services: Vec<ServiceReport>,
}

impl Check {
    fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    fn text(&self) -> String {
        match self {
            Self::Ok(detail) if detail.is_empty() => "ok".to_owned(),
            Self::Ok(detail) => format!("ok ({detail})"),
            Self::Failed(reason) => format!("failed ({reason})"),
            Self::Skipped(reason) => format!("skipped ({reason})"),
        }
    }
}

impl Report {
    /// Whether no check failed. A skipped check is not a failure.
    pub(crate) fn healthy(&self) -> bool {
        !self.keychain.failed()
            && self
                .services
                .iter()
                .all(|service| !service.network.failed() && !service.auth.failed())
    }

    /// The report as text: the keychain line, then one line per service.
    pub(crate) fn render(&self) -> String {
        let mut text = format!("keychain: {}\n", self.keychain.text());
        for service in &self.services {
            let _ = writeln!(
                text,
                "{}: network {}, auth {}",
                service.name,
                service.network.text(),
                service.auth.text()
            );
        }
        text
    }
}

/// Opens a connection to a host, to see whether the network reaches it.
pub(crate) trait Probe {
    /// Connects to `host:port`.
    async fn reach(&self, host: &str, port: u16) -> Result<(), String>;
}

/// Runs every check.
///
/// `account` is the keychain result: the account found, or why it was not.
/// `validator` is `None` when there are no credentials to check.
pub(crate) async fn diagnose<P: Probe, V: Validator>(
    account: Result<String, String>,
    probe: &P,
    validator: Option<&V>,
    services: Services,
) -> Report {
    let keychain = match account {
        Ok(account) => Check::Ok(account),
        Err(reason) => Check::Failed(reason),
    };
    let signed_in = match validator {
        Some(validator) => Some(validator.validate().await.ok()),
        None => None,
    };
    let (mail, calendar, contacts) = tokio::join!(
        probe.reach(ENDPOINTS[0].1, ENDPOINTS[0].2),
        probe.reach(ENDPOINTS[1].1, ENDPOINTS[1].2),
        probe.reach(ENDPOINTS[2].1, ENDPOINTS[2].2),
    );
    let reached = [mail, calendar, contacts];
    let built = [services.mail, services.calendar, services.contacts];
    let services = ENDPOINTS
        .iter()
        .zip(reached)
        .zip(built)
        .map(|(((name, host, port), reached), built)| {
            if !built {
                let off = || Check::Skipped("not enabled in this build".to_owned());
                return ServiceReport {
                    name,
                    network: off(),
                    auth: off(),
                };
            }
            let network = match reached {
                Ok(()) => Check::Ok(format!("{host}:{port}")),
                Err(reason) => Check::Failed(reason),
            };
            let auth = match (&network, &signed_in) {
                (Check::Ok(_), Some(Some(report))) => from_sign_in(report, name),
                (Check::Ok(_), Some(None)) => {
                    Check::Failed("the sign-in check could not run".to_owned())
                }
                (Check::Ok(_), None) => Check::Skipped("no credentials".to_owned()),
                _ => Check::Skipped("no connection".to_owned()),
            };
            ServiceReport {
                name,
                network,
                auth,
            }
        })
        .collect();
    Report { keychain, services }
}

fn from_sign_in(report: &ValidationReport, name: &str) -> Check {
    let check = match name {
        "mail" => &report.mail,
        "calendar" => &report.calendar,
        _ => &report.contacts,
    };
    match check {
        ServiceCheck::Failed { reason } | ServiceCheck::Unreachable { reason } => {
            Check::Failed(reason.clone())
        }
        _ => Check::Ok(String::new()),
    }
}

/// Opens a real TCP connection.
#[derive(Debug)]
struct TcpProbe;

impl Probe for TcpProbe {
    async fn reach(&self, host: &str, port: u16) -> Result<(), String> {
        let connect = tokio::net::TcpStream::connect((host, port));
        match tokio::time::timeout(PROBE_TIMEOUT, connect).await {
            Ok(Ok(_stream)) => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_elapsed) => Err("timed out".to_owned()),
        }
    }
}

/// `ibridge doctor`: prints the report, and fails when a check failed.
pub(crate) async fn run() -> anyhow::Result<()> {
    let found = crate::serve::credentials().await;
    let validator = match &found {
        Ok((credentials, _)) => Some(crate::validate::validator(credentials)?),
        Err(_) => None,
    };
    let account = match &found {
        Ok((credentials, Some(_))) => Ok(format!("{}, from the keychain", credentials.apple_id)),
        Ok((credentials, None)) => Ok(format!("{}, from the environment", credentials.apple_id)),
        Err(error) => Err(format!("{error:#}")),
    };
    let report = diagnose(account, &TcpProbe, validator.as_ref(), Services::built()).await;
    write!(std::io::stdout().lock(), "{}", report.render())?;
    anyhow::ensure!(report.healthy(), "doctor found a problem");
    Ok(())
}

#[cfg(test)]
mod tests {
    use ibridge_auth::{AuthError, ServiceCheck, ValidationReport, Validator};

    use super::{Check, Probe, diagnose};
    use crate::account::Services;

    /// Every host answers except the ones listed.
    struct FakeProbe {
        down: &'static [&'static str],
    }

    impl Probe for FakeProbe {
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the fake answers without waiting"
        )]
        async fn reach(&self, host: &str, _port: u16) -> Result<(), String> {
            if self.down.contains(&host) {
                Err("timed out".to_owned())
            } else {
                Ok(())
            }
        }
    }

    struct Fixed(ValidationReport);

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the fixed validator answers without waiting"
    )]
    impl Validator for Fixed {
        async fn validate(&self) -> Result<ValidationReport, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn everything() -> Services {
        Services {
            mail: true,
            calendar: true,
            contacts: true,
        }
    }

    fn failed(reason: &str) -> ServiceCheck {
        ServiceCheck::Failed {
            reason: reason.to_owned(),
        }
    }

    #[tokio::test]
    async fn doctor_reports_each_service() {
        let validator = Fixed(ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: ServiceCheck::Ok,
            contacts: failed("contacts rejected"),
        });
        let report = diagnose(
            Ok("ada@icloud.com".to_owned()),
            &FakeProbe {
                down: &["caldav.icloud.com"],
            },
            Some(&validator),
            everything(),
        )
        .await;
        assert_eq!(
            report.keychain,
            Check::Ok("ada@icloud.com".to_owned()),
            "the keychain result names the account"
        );
        let names: Vec<&str> = report.services.iter().map(|service| service.name).collect();
        assert_eq!(
            names,
            ["mail", "calendar", "contacts"],
            "one entry per service"
        );
        let [mail, calendar, contacts] = &report.services[..] else {
            panic!("three services, got {:?}", report.services);
        };
        assert_eq!(mail.network, Check::Ok("imap.mail.me.com:993".to_owned()));
        assert_eq!(mail.auth, Check::Ok(String::new()));
        assert_eq!(
            calendar.network,
            Check::Failed("timed out".to_owned()),
            "an unreachable host fails the network check"
        );
        assert!(
            matches!(calendar.auth, Check::Skipped(_)),
            "sign-in is not judged when the network is down, got {:?}",
            calendar.auth
        );
        assert_eq!(
            contacts.network,
            Check::Ok("contacts.icloud.com:443".to_owned())
        );
        assert_eq!(
            contacts.auth,
            Check::Failed("contacts rejected".to_owned()),
            "a rejected sign-in carries its reason"
        );
        assert!(
            !report.healthy(),
            "a failed check makes the report unhealthy"
        );
        let text = report.render();
        for line in [
            "keychain: ok (ada@icloud.com)",
            "mail: network ok (imap.mail.me.com:993), auth ok",
            "calendar: network failed (timed out), auth skipped (no connection)",
            "contacts: network ok (contacts.icloud.com:443), auth failed (contacts rejected)",
        ] {
            assert!(
                text.lines().any(|found| found == line),
                "missing {line:?} in:\n{text}"
            );
        }
    }

    #[tokio::test]
    async fn doctor_skips_sign_in_when_the_keychain_fails() {
        let report = diagnose::<_, Fixed>(
            Err("no account is signed in; run `ibridge login`".to_owned()),
            &FakeProbe { down: &[] },
            None,
            everything(),
        )
        .await;
        assert_eq!(
            report.keychain,
            Check::Failed("no account is signed in; run `ibridge login`".to_owned())
        );
        for service in &report.services {
            assert!(
                matches!(service.network, Check::Ok(_)),
                "the network is still probed for {}",
                service.name
            );
            assert!(
                matches!(service.auth, Check::Skipped(_)),
                "no credentials, so no sign-in check for {}, got {:?}",
                service.name,
                service.auth
            );
        }
        assert!(!report.healthy(), "a keychain failure is a problem");
    }

    #[tokio::test]
    async fn doctor_is_healthy_when_every_built_service_works() {
        let validator = Fixed(ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: failed("ignored: calendar is not built"),
            contacts: ServiceCheck::Ok,
        });
        let services = Services {
            calendar: false,
            ..everything()
        };
        let report = diagnose(
            Ok("ada@icloud.com".to_owned()),
            &FakeProbe { down: &[] },
            Some(&validator),
            services,
        )
        .await;
        let calendar = report
            .services
            .iter()
            .find(|service| service.name == "calendar")
            .expect("calendar is listed");
        assert!(
            matches!(calendar.network, Check::Skipped(_))
                && matches!(calendar.auth, Check::Skipped(_)),
            "a service missing from the build is skipped, got {calendar:?}"
        );
        assert!(
            report.healthy(),
            "skipped checks are not failures: {}",
            report.render()
        );
    }
}
