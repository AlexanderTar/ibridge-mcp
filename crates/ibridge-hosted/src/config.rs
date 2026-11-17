// SPDX-License-Identifier: Apache-2.0

//! What `ibridge serve --hosted` needs to know, and the checks that stop it starting without it.

use std::net::SocketAddr;
use std::path::PathBuf;

use ibridge_core::AppleId;

use crate::limits::Guards;
use crate::oauth::{Access, ConfigError, OAuthConfig};

/// The environment variable listing the addresses that may sign in (self-host).
pub const ALLOWED_APPLE_IDS: &str = "IBRIDGE_ALLOWED_APPLE_IDS";

/// The environment variable that closes or opens sign-ups: `closed` or `open` (the default).
pub const SIGNUPS: &str = "IBRIDGE_SIGNUPS";
/// The environment variable that sets how many accounts an open service holds.
pub const SIGNUP_CAP: &str = "IBRIDGE_SIGNUP_CAP";

/// Accounts an open service holds unless `IBRIDGE_SIGNUP_CAP` says otherwise.
const DEFAULT_SIGNUP_CAP: usize = 50;

/// The command-line half of the configuration.
#[derive(Debug, Clone)]
pub struct HostedOptions {
    /// Where to listen.
    pub addr: SocketAddr,
    /// The origin clients reach, such as `https://ibridge.fyi`.
    pub public_url: String,
    /// Where the database and its backups live.
    pub data_dir: PathBuf,
    /// Run the public service, open to any iCloud account.
    pub multi_tenant: bool,
}

/// A hosted configuration that is safe to start with.
#[derive(Debug, Clone)]
pub struct HostedConfig {
    /// Where to listen.
    pub addr: SocketAddr,
    /// Where the database and its backups live.
    pub data_dir: PathBuf,
    /// The OAuth settings, including who may sign in.
    pub oauth: OAuthConfig,
    /// Accounts the service may hold, when it is open to anyone.
    pub signup_cap: Option<usize>,
    /// Call, size and time limits.
    pub guards: Guards,
}

/// Why the hosted server refuses to start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// Neither an allowlist nor `--multi-tenant`: the server would not know who may sign in.
    #[error("hosted mode needs {ALLOWED_APPLE_IDS} (self-host) or --multi-tenant (public service)")]
    NoAccessPolicy,
    /// An entry in the allowlist is not an iCloud address.
    #[error("an entry in {ALLOWED_APPLE_IDS} is not an iCloud address")]
    BadAllowList,
    /// `IBRIDGE_SIGNUPS=closed` with nobody on the allowlist: nobody could ever sign in.
    #[error("closed sign-ups need {ALLOWED_APPLE_IDS} to say who may sign in")]
    ClosedWithoutAllowlist,
    /// `IBRIDGE_SIGNUPS` is neither `open` nor `closed`.
    #[error("{SIGNUPS} must be open or closed")]
    BadSignups,
    /// `IBRIDGE_SIGNUP_CAP` is not a whole number of at least 1.
    #[error("{SIGNUP_CAP} must be a whole number of at least 1")]
    BadSignupCap,
    /// The public URL cannot be an OAuth issuer.
    #[error(transparent)]
    PublicUrl(#[from] ConfigError),
}

impl HostedConfig {
    /// Checks `options` and the environment `env` reads from.
    ///
    /// # Errors
    ///
    /// Returns [`StartError`] when nobody is said to be allowed to sign in, or a
    /// value is malformed. Nothing is created or opened before these checks pass.
    pub fn resolve(
        options: HostedOptions,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, StartError> {
        let HostedOptions {
            addr,
            public_url,
            data_dir,
            multi_tenant,
        } = options;
        let listed = allowed_apple_ids(env(ALLOWED_APPLE_IDS).as_deref().unwrap_or_default())?;
        let closed = match env(SIGNUPS).as_deref() {
            None | Some("open") => false,
            Some("closed") => true,
            Some(_) => return Err(StartError::BadSignups),
        };
        // An allowlist always restricts sign-in, even next to --multi-tenant, and it
        // bounds the accounts by itself.
        let (access, signup_cap) = if !listed.is_empty() {
            (Access::AllowList(listed), None)
        } else if closed {
            return Err(StartError::ClosedWithoutAllowlist);
        } else if multi_tenant {
            (Access::MultiTenant, Some(signup_cap(env(SIGNUP_CAP))?))
        } else {
            return Err(StartError::NoAccessPolicy);
        };
        let oauth = OAuthConfig::new(&public_url, access)?;
        Ok(Self {
            addr,
            data_dir,
            oauth,
            signup_cap,
            guards: Guards::default(),
        })
    }
}

/// The account cap: `value` when the operator set one, else the default.
fn signup_cap(value: Option<String>) -> Result<usize, StartError> {
    match value {
        None => Ok(DEFAULT_SIGNUP_CAP),
        Some(text) => text
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|cap| *cap >= 1)
            .ok_or(StartError::BadSignupCap),
    }
}

/// Reads a comma-separated list of addresses. Blank entries are skipped.
fn allowed_apple_ids(list: &str) -> Result<Vec<AppleId>, StartError> {
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| AppleId::try_from(entry).map_err(|_| StartError::BadAllowList))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{ALLOWED_APPLE_IDS, HostedConfig, HostedOptions, StartError};

    #[derive(Clone, Copy)]
    enum Mode {
        SelfHost,
        Public,
    }

    fn options(mode: Mode) -> HostedOptions {
        HostedOptions {
            addr: "0.0.0.0:8080".parse().expect("address"),
            public_url: "https://ibridge.example".to_owned(),
            data_dir: "/data".into(),
            multi_tenant: matches!(mode, Mode::Public),
        }
    }

    fn resolve(mode: Mode, vars: &[(&str, &str)]) -> Result<HostedConfig, StartError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        HostedConfig::resolve(options(mode), |name| vars.get(name).cloned())
    }

    #[test]
    fn hosted_refuses_start_without_allowlist_or_multi_tenant() {
        for vars in [
            vec![],
            vec![(ALLOWED_APPLE_IDS, "")],
            vec![(ALLOWED_APPLE_IDS, " , ")],
        ] {
            let error = resolve(Mode::SelfHost, &vars).expect_err("no policy, no start");
            assert!(
                matches!(error, StartError::NoAccessPolicy),
                "{vars:?}: {error}"
            );
            let text = error.to_string();
            assert!(
                text.contains(ALLOWED_APPLE_IDS) && text.contains("--multi-tenant"),
                "the message names both ways forward: {text}"
            );
        }
    }

    use super::{SIGNUP_CAP as CAP, SIGNUPS};

    #[test]
    fn signups_closed_allows_only_allowlist() {
        let ada = ibridge_core::AppleId::try_from("ada@icloud.com").expect("apple id");
        let eve = ibridge_core::AppleId::try_from("eve@icloud.com").expect("apple id");
        for mode in [Mode::SelfHost, Mode::Public] {
            let closed = resolve(
                mode,
                &[(SIGNUPS, "closed"), (ALLOWED_APPLE_IDS, "ada@icloud.com")],
            )
            .expect("closed with an allowlist starts");
            assert!(
                closed.oauth.may_sign_in(&ada),
                "the listed address signs in"
            );
            assert!(
                !closed.oauth.may_sign_in(&eve),
                "nobody else does, even when public"
            );
            assert_eq!(closed.signup_cap, None, "the list already bounds accounts");

            let error =
                resolve(mode, &[(SIGNUPS, "closed")]).expect_err("closed with nobody listed");
            assert!(
                matches!(error, StartError::ClosedWithoutAllowlist),
                "{error}"
            );
        }
        let error = resolve(Mode::Public, &[(SIGNUPS, "sometimes")]).expect_err("unknown mode");
        assert!(matches!(error, StartError::BadSignups), "{error}");
    }

    #[test]
    fn open_signups_are_capped_at_50_unless_told_otherwise() {
        let open = resolve(Mode::Public, &[]).expect("starts");
        assert_eq!(open.signup_cap, Some(50), "the default cap");
        let spelled = resolve(Mode::Public, &[(SIGNUPS, "open")]).expect("starts");
        assert_eq!(spelled.signup_cap, Some(50), "open is the default");
        let raised = resolve(Mode::Public, &[(CAP, "75")]).expect("starts");
        assert_eq!(raised.signup_cap, Some(75), "the operator may raise it");
        for bad in ["0", "many", "-1", ""] {
            let error = resolve(Mode::Public, &[(CAP, bad)]).expect_err("bad cap");
            assert!(
                matches!(error, StartError::BadSignupCap),
                "{bad:?}: {error}"
            );
        }
    }

    #[test]
    fn an_allowlist_or_multi_tenant_lets_it_start() {
        let listed = resolve(
            Mode::SelfHost,
            &[(ALLOWED_APPLE_IDS, "ada@icloud.com, Bob@me.com")],
        )
        .expect("an allowlist starts it");
        let ada = ibridge_core::AppleId::try_from("ada@icloud.com").expect("apple id");
        let eve = ibridge_core::AppleId::try_from("eve@icloud.com").expect("apple id");
        assert!(listed.oauth.may_sign_in(&ada), "listed");
        assert!(
            listed
                .oauth
                .may_sign_in(&ibridge_core::AppleId::try_from("bob@me.com").expect("apple id")),
            "case does not matter"
        );
        assert!(!listed.oauth.may_sign_in(&eve), "not listed");

        let open = resolve(Mode::Public, &[]).expect("multi-tenant starts it");
        assert!(open.oauth.may_sign_in(&eve), "anyone may sign in");
    }

    #[test]
    fn a_bad_allowlist_entry_or_public_url_refuses() {
        let error = resolve(
            Mode::SelfHost,
            &[(ALLOWED_APPLE_IDS, "ada@icloud.com, not-an-address")],
        )
        .expect_err("bad entry");
        assert!(matches!(error, StartError::BadAllowList), "{error}");
        assert!(
            !error.to_string().contains("not-an-address"),
            "the message does not echo the entry"
        );

        let mut bad = options(Mode::Public);
        bad.public_url = "http://ibridge.example".to_owned();
        let error = HostedConfig::resolve(bad, |_| None).expect_err("http is not an issuer");
        assert!(matches!(error, StartError::PublicUrl(_)), "{error}");
    }
}
