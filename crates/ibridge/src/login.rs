// SPDX-License-Identifier: Apache-2.0

//! `ibridge login` and `ibridge logout`.

use std::io::{BufRead as _, Write as _};

use anyhow::Context as _;
use ibridge_auth::{Credentials, ServiceCheck, ValidationReport, Validator};
use ibridge_core::AppleId;
use keyring_core::Entry;

use crate::account::{KEYCHAIN_SERVICE, State};

const ASP_PAGE: &str = "https://account.apple.com/account/manage/section/security";

/// Validates `credentials`, then stores them. Nothing is stored when no service accepts them.
///
/// # Errors
///
/// Returns an error when validation cannot run, when every service rejects the
/// credentials (the message lists why), or when the keychain write fails.
pub(crate) async fn store_if_valid<V: Validator>(
    validator: &V,
    credentials: &Credentials,
) -> anyhow::Result<ValidationReport> {
    let report = validator
        .validate()
        .await
        .map_err(|_| anyhow::anyhow!("sign-in could not be checked"))?;
    if !report.any_service_ok() {
        anyhow::bail!("{}", rejection(&report));
    }
    credentials.with_secret(|secret| {
        Entry::new(KEYCHAIN_SERVICE, credentials.apple_id.as_str())?.set_password(secret)
    })?;
    State::from_report(&credentials.apple_id, &report).save()?;
    #[cfg(feature = "http")]
    crate::token::DaemonToken::get_or_create()?;
    Ok(report)
}

fn rejection(report: &ValidationReport) -> String {
    let checks = [
        ("mail", &report.mail),
        ("calendar", &report.calendar),
        ("contacts", &report.contacts),
    ];
    // When no service refused, iCloud was never reached: don't say it rejected the sign-in.
    let refused = checks
        .iter()
        .any(|(_, check)| matches!(check, ServiceCheck::Failed { .. }));
    let mut lines = vec![if refused {
        "iCloud did not accept this sign-in:".to_owned()
    } else {
        "Could not check this sign-in with iCloud:".to_owned()
    }];
    for (name, check) in checks {
        match check {
            ServiceCheck::Failed { reason } => lines.push(format!("  {name}: {reason}")),
            ServiceCheck::Unreachable { reason } => {
                lines.push(format!("  {name}: not checked ({reason})"));
            }
            _ => {}
        }
    }
    lines.join("\n")
}

/// One line of the per-service summary printed after a successful login.
fn service_line(name: &str, check: &ServiceCheck) -> String {
    match check {
        ServiceCheck::Failed { reason } => format!("{name}: off ({reason})"),
        ServiceCheck::Unreachable { reason } => format!("{name}: not checked ({reason})"),
        _ => format!("{name}: ok"),
    }
}

/// Forgets the saved password and account state.
pub(crate) fn logout() -> anyhow::Result<()> {
    if let Some(state) = State::load()? {
        match Entry::new(KEYCHAIN_SERVICE, state.apple_id()?.as_str())?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => {}
            Err(error) => return Err(error.into()),
        }
    }
    State::clear()
}

/// Prompts for the address and app-specific password, validates, stores and prints the Claude Code setup line.
pub(crate) async fn run() -> anyhow::Result<()> {
    crate::platform::install_keychain()?;
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "Create an app-specific password at {ASP_PAGE}\nUse your primary iCloud address (@icloud.com, @me.com or @mac.com)."
    )?;
    crate::platform::open_url(ASP_PAGE);
    write!(out, "iCloud address: ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let apple_id = AppleId::try_from(line.trim())?;
    let password = rpassword::prompt_password("App-specific password: ")?;
    let credentials = Credentials::new(apple_id, password);
    let validator = crate::validate::validator(&credentials)?;
    let report = store_if_valid(&validator, &credentials)
        .await
        .context("login failed; nothing was stored")?;
    for (name, check) in [
        ("mail", &report.mail),
        ("calendar", &report.calendar),
        ("contacts", &report.contacts),
    ] {
        writeln!(out, "{}", service_line(name, check))?;
    }
    let exe = std::env::current_exe().context("cannot find this program's path")?;
    writeln!(
        out,
        "\nAdd it to Claude Code:\n  claude mcp add ibridge -- {} serve --stdio",
        exe.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ibridge_auth::{
        AuthError, CredentialSource as _, Credentials, KeyringSource, ServiceCheck,
        ValidationReport, Validator,
    };
    use ibridge_core::AppleId;
    use ibridge_server::ServiceStatus;

    use super::{rejection, service_line, store_if_valid};
    use crate::account::{Services, State, snapshot};
    use crate::testing::{KEYCHAIN, mock_keychain};
    use crate::validate::Combined;

    fn credentials(address: &str) -> Credentials {
        Credentials::new(AppleId::try_from(address).expect("apple id"), "app-secret")
    }

    fn failed(reason: &str) -> ServiceCheck {
        ServiceCheck::Failed {
            reason: reason.to_owned(),
        }
    }

    fn unreachable(reason: &str) -> ServiceCheck {
        ServiceCheck::Unreachable {
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn offline_login_says_the_check_could_not_run() {
        let offline = ValidationReport {
            mail: unreachable("network error"),
            calendar: unreachable("network error"),
            contacts: unreachable("network error"),
        };
        let message = rejection(&offline);
        assert!(
            !message.contains("did not accept"),
            "iCloud was never reached, so it did not refuse anything: {message}"
        );
        assert!(
            message.contains("mail: not checked (network error)"),
            "every unreachable service is listed with its reason: {message}"
        );
        assert!(message.contains("calendar: not checked (network error)"));
        assert!(message.contains("contacts: not checked (network error)"));
    }

    #[test]
    fn mixed_rejection_lists_refusals_and_unreachable_checks() {
        let mixed = ValidationReport {
            mail: failed("mail rejected"),
            calendar: unreachable("rate limited"),
            contacts: unreachable("rate limited"),
        };
        let message = rejection(&mixed);
        assert!(message.starts_with("iCloud did not accept this sign-in:"));
        assert!(message.contains("mail: mail rejected"));
        assert!(message.contains("calendar: not checked (rate limited)"));
    }

    #[test]
    fn unreachable_service_is_not_printed_as_ok() {
        assert_eq!(service_line("mail", &ServiceCheck::Ok), "mail: ok");
        assert_eq!(
            service_line("mail", &failed("rejected")),
            "mail: off (rejected)"
        );
        assert_eq!(
            service_line("mail", &unreachable("rate limited")),
            "mail: not checked (rate limited)",
            "a check that could not run must not read as ok"
        );
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

    #[tokio::test]
    async fn login_stores_on_success_only() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let rejected = credentials("rejected@icloud.com");
        let none = Fixed(ValidationReport {
            mail: failed("mail rejected"),
            calendar: failed("calendar rejected"),
            contacts: failed("contacts rejected"),
        });
        store_if_valid(&none, &rejected)
            .await
            .expect_err("every service failed, so login fails");
        KeyringSource::new(rejected.apple_id.clone())
            .credentials()
            .await
            .expect_err("a rejected login must not store the password");

        let accepted = credentials("accepted@icloud.com");
        let mail_only = Fixed(ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: failed("calendar rejected"),
            contacts: failed("contacts rejected"),
        });
        store_if_valid(&mail_only, &accepted)
            .await
            .expect("one service accepted, so login succeeds");
        KeyringSource::new(accepted.apple_id.clone())
            .credentials()
            .await
            .expect("an accepted login stores the password");
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn login_creates_daemon_token() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let _ = keyring_core::Entry::new(crate::account::KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .delete_credential();
        let none = Fixed(ValidationReport {
            mail: failed("mail rejected"),
            calendar: failed("calendar rejected"),
            contacts: failed("contacts rejected"),
        });
        store_if_valid(&none, &credentials("no-token@icloud.com"))
            .await
            .expect_err("a rejected login fails");
        keyring_core::Entry::new(crate::account::KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .get_password()
            .expect_err("a rejected login makes no daemon token");
        let ok = Fixed(ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Ok,
        });
        store_if_valid(&ok, &credentials("token@icloud.com"))
            .await
            .expect("login succeeds");
        keyring_core::Entry::new(crate::account::KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .get_password()
            .expect("a successful login leaves a daemon token in the keychain");
    }

    #[tokio::test]
    async fn login_disables_failed_service() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let account = credentials("partial@icloud.com");
        let calendar_only = Fixed(ValidationReport {
            mail: failed("mail login was rejected"),
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Ok,
        });
        store_if_valid(&calendar_only, &account)
            .await
            .expect("calendar accepted, so login succeeds");
        let saved = State::load()
            .expect("state reads")
            .expect("login saved the account state");
        let reported = snapshot(account.apple_id.clone(), Services::built(), Some(&saved));
        assert_eq!(
            reported.mail,
            ServiceStatus::Off {
                reason: "mail login was rejected".to_owned()
            },
            "the failed service is off with its reason"
        );
    }

    #[tokio::test]
    async fn login_succeeds_with_caldav_only() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let imap = Fixed(ValidationReport {
            mail: failed("iCloud Mail rejected the sign-in"),
            calendar: failed("the mail check does not look at calendar"),
            contacts: failed("the mail check does not look at contacts"),
        });
        let dav = Fixed(ValidationReport {
            mail: failed("the CalDAV check does not look at mail"),
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Ok,
        });
        let combined = Combined { mail: imap, dav };
        let report = combined.validate().await.expect("the check runs");
        assert_eq!(
            report.calendar,
            ServiceCheck::Ok,
            "calendar comes from CalDAV"
        );
        assert_eq!(
            report.contacts,
            ServiceCheck::Ok,
            "contacts come from CalDAV"
        );
        assert_eq!(
            report.mail,
            failed("iCloud Mail rejected the sign-in"),
            "mail comes from IMAP"
        );
        let account = credentials("caldav-only@icloud.com");
        store_if_valid(&combined, &account)
            .await
            .expect("login succeeds with a CalDAV-only account");
        KeyringSource::new(account.apple_id.clone())
            .credentials()
            .await
            .expect("the password is stored");
    }
}
