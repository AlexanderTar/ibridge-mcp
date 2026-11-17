// SPDX-License-Identifier: Apache-2.0

//! What `ibridge serve --hosted` needs to know, and the checks that stop it starting without it.

use std::net::SocketAddr;
use std::path::PathBuf;

use ibridge_core::AppleId;

use crate::oauth::{Access, ConfigError, OAuthConfig};

/// The environment variable listing the addresses that may sign in (self-host).
pub const ALLOWED_APPLE_IDS: &str = "IBRIDGE_ALLOWED_APPLE_IDS";

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
        // An allowlist always restricts sign-in, even next to --multi-tenant.
        let access = if !listed.is_empty() {
            Access::AllowList(listed)
        } else if multi_tenant {
            Access::MultiTenant
        } else {
            return Err(StartError::NoAccessPolicy);
        };
        let oauth = OAuthConfig::new(&public_url, access)?;
        Ok(Self {
            addr,
            data_dir,
            oauth,
        })
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
