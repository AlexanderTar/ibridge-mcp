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
    Ok(report)
}

fn rejection(report: &ValidationReport) -> String {
    let mut lines = vec!["iCloud did not accept this sign-in:".to_owned()];
    for (name, check) in [
        ("mail", &report.mail),
        ("calendar", &report.calendar),
        ("contacts", &report.contacts),
    ] {
        if let ServiceCheck::Failed { reason } = check {
            lines.push(format!("  {name}: {reason}"));
        }
    }
    lines.join("\n")
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
    let validator = crate::mail::validator(&credentials)?;
    let report = store_if_valid(&validator, &credentials)
        .await
        .context("login failed; nothing was stored")?;
    for (name, check) in [
        ("mail", &report.mail),
        ("calendar", &report.calendar),
        ("contacts", &report.contacts),
    ] {
        match check {
            ServiceCheck::Failed { reason } => writeln!(out, "{name}: off ({reason})")?,
            _ => writeln!(out, "{name}: ok")?,
        }
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
    use std::sync::Once;

    use ibridge_auth::{
        AuthError, CredentialSource as _, Credentials, KeyringSource, ServiceCheck,
        ValidationReport, Validator,
    };
    use ibridge_core::AppleId;
    use ibridge_server::ServiceStatus;
    use tokio::sync::Mutex;

    use super::store_if_valid;
    use crate::account::{Services, State, snapshot};

    /// Tests share the keychain's `state` entry, so they take turns.
    static KEYCHAIN: Mutex<()> = Mutex::const_new(());

    fn mock_keychain() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            keyring_core::set_default_store(
                keyring_core::mock::Store::new().expect("mock keychain"),
            );
        });
    }

    fn credentials(address: &str) -> Credentials {
        Credentials::new(AppleId::try_from(address).expect("apple id"), "app-secret")
    }

    fn failed(reason: &str) -> ServiceCheck {
        ServiceCheck::Failed {
            reason: reason.to_owned(),
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
}
