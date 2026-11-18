// SPDX-License-Identifier: Apache-2.0

//! Paid plans: the settings that switch billing on, the access rule, and the Stripe client.

#[cfg(any(test, feature = "testing"))]
pub mod fakes;
#[cfg(test)]
mod gate_tests;
pub(crate) mod routes;
pub mod stripe;
pub(crate) mod webhook;

use secrecy::SecretString;

use self::stripe::{BillingError, Stripe};
use crate::oauth::ConfigError;
use crate::store::User;

/// The Stripe secret key the server calls the API with.
pub const STRIPE_SECRET_KEY: &str = "IBRIDGE_STRIPE_SECRET_KEY";
/// The signing secret of the webhook endpoint (`whsec_...`).
pub const STRIPE_WEBHOOK_SECRET: &str = "IBRIDGE_STRIPE_WEBHOOK_SECRET";
/// The id of the monthly price.
pub const STRIPE_PRICE_MONTHLY: &str = "IBRIDGE_STRIPE_PRICE_MONTHLY";
/// The id of the yearly price.
pub const STRIPE_PRICE_YEARLY: &str = "IBRIDGE_STRIPE_PRICE_YEARLY";
/// How tax is handled: `managed` (the default) or `automatic`.
pub const STRIPE_TAX: &str = "IBRIDGE_STRIPE_TAX";

/// The price, as every page states it.
pub(crate) const PRICE_TEXT: &str = "US$1.99 per month or US$19.99 per year";

/// Who collects and files tax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaxMode {
    /// Stripe Managed Payments: Stripe is the seller of record.
    Managed,
    /// Stripe Tax: the operator registers for and files tax where it is due.
    Automatic,
}

/// The two plans one subscription can be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Plan {
    /// US$1.99 a month.
    Monthly,
    /// US$19.99 a year.
    Yearly,
}

impl Plan {
    /// The plan a form field names, if it names one.
    #[must_use]
    pub fn from_form(value: &str) -> Option<Self> {
        match value {
            "monthly" => Some(Self::Monthly),
            "yearly" => Some(Self::Yearly),
            _ => None,
        }
    }
}

/// The Stripe settings. All four required ones are set, or none.
#[derive(Debug, Clone)]
pub struct BillingConfig {
    /// The API key.
    pub secret_key: SecretString,
    /// The webhook signing secret.
    pub webhook_secret: SecretString,
    /// The monthly price id.
    pub price_monthly: String,
    /// The yearly price id.
    pub price_yearly: String,
    /// How tax is handled.
    pub tax: TaxMode,
}

impl BillingConfig {
    /// Reads the group from `env`. `None` when none of it is set.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the settings that are missing when only some are set,
    /// or when `IBRIDGE_STRIPE_TAX` is not `managed` or `automatic`. Values are never in the error.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let read = |name: &str| {
            env(name)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let names = [
            STRIPE_SECRET_KEY,
            STRIPE_WEBHOOK_SECRET,
            STRIPE_PRICE_MONTHLY,
            STRIPE_PRICE_YEARLY,
        ];
        let values = names.map(read);
        let tax = read(STRIPE_TAX);
        // The tax setting alone is a half-made group, not a reason to stay quiet.
        if values.iter().all(Option::is_none) && tax.is_none() {
            return Ok(None);
        }
        let missing: Vec<&'static str> = names
            .iter()
            .zip(&values)
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| *name)
            .collect();
        let [Some(secret), Some(webhook), Some(monthly), Some(yearly)] = values else {
            return Err(ConfigError::BillingIncomplete { missing });
        };
        let tax = match tax.map(|value| value.to_ascii_lowercase()).as_deref() {
            None | Some("managed") => TaxMode::Managed,
            Some("automatic") => TaxMode::Automatic,
            Some(_) => return Err(ConfigError::BadStripeTax),
        };
        Ok(Some(Self {
            secret_key: SecretString::from(secret),
            webhook_secret: SecretString::from(webhook),
            price_monthly: monthly,
            price_yearly: yearly,
            tax,
        }))
    }
}

/// The live Stripe client and the webhook secret, kept for the life of the server.
#[derive(Debug)]
pub(crate) struct Billing {
    pub(crate) stripe: Stripe,
    pub(crate) webhook_secret: SecretString,
}

impl Billing {
    /// The real Stripe.
    pub(crate) fn new(config: &BillingConfig) -> Result<Self, BillingError> {
        Ok(Self {
            stripe: Stripe::new(config)?,
            webhook_secret: config.webhook_secret.clone(),
        })
    }

    /// Stripe replaced by a fake on loopback, for tests.
    #[cfg(test)]
    pub(crate) fn with_base(config: &BillingConfig, base: url::Url) -> Result<Self, BillingError> {
        Ok(Self {
            stripe: Stripe::with_base(config, base)?,
            webhook_secret: config.webhook_secret.clone(),
        })
    }
}

/// Whether a user may use the tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// The subscription is paid up, in its retry window, or complimentary.
    Allowed,
    /// There is no plan.
    Denied,
}

/// Whether a Stripe subscription status keeps a user's access: paid up, or in the card retry window.
pub(crate) fn grants_access(status: &str) -> bool {
    matches!(status, "active" | "past_due")
}

/// The access rule: Stripe status `active` or `past_due`, or a complimentary user.
#[must_use]
pub fn access(user: &User) -> Access {
    if user.complimentary || user.status.as_deref().is_some_and(grants_access) {
        Access::Allowed
    } else {
        Access::Denied
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::{
        Access, BillingConfig, STRIPE_PRICE_MONTHLY, STRIPE_PRICE_YEARLY, STRIPE_SECRET_KEY,
        STRIPE_TAX, STRIPE_WEBHOOK_SECRET, TaxMode, access,
    };
    use crate::oauth::ConfigError;
    use crate::store::{Store, User, UserId};

    const SECRET_VALUE: &str = "sk_test_value-that-must-not-leak";

    fn full() -> HashMap<&'static str, String> {
        HashMap::from([
            (STRIPE_SECRET_KEY, SECRET_VALUE.to_owned()),
            (STRIPE_WEBHOOK_SECRET, "whsec_abc".to_owned()),
            (STRIPE_PRICE_MONTHLY, "price_month".to_owned()),
            (STRIPE_PRICE_YEARLY, "price_year".to_owned()),
        ])
    }

    fn read(vars: &HashMap<&'static str, String>) -> Result<Option<BillingConfig>, ConfigError> {
        BillingConfig::from_env(&|name| vars.get(name).cloned())
    }

    #[test]
    fn billing_absent_is_none() {
        assert!(read(&HashMap::new()).unwrap().is_none());
        let blanks: HashMap<_, _> = full().keys().map(|name| (*name, "  ".to_owned())).collect();
        assert!(
            read(&blanks).unwrap().is_none(),
            "blank values count as unset"
        );
    }

    #[test]
    fn billing_full_group_reads_and_defaults_to_managed_tax() {
        let config = read(&full()).unwrap().expect("all four set");
        assert_eq!(config.secret_key.expose_secret(), SECRET_VALUE);
        assert_eq!(config.webhook_secret.expose_secret(), "whsec_abc");
        assert_eq!(config.price_monthly, "price_month");
        assert_eq!(config.price_yearly, "price_year");
        assert_eq!(config.tax, TaxMode::Managed, "managed is the default");
        let shown = format!("{config:?}");
        assert!(
            !shown.contains(SECRET_VALUE) && !shown.contains("whsec_abc"),
            "no secret in Debug: {shown}"
        );
        for (spelled, mode) in [
            ("managed", TaxMode::Managed),
            (" Automatic ", TaxMode::Automatic),
        ] {
            let mut vars = full();
            vars.insert(STRIPE_TAX, spelled.to_owned());
            assert_eq!(read(&vars).unwrap().expect("set").tax, mode, "{spelled:?}");
        }
        let mut vars = full();
        vars.insert(STRIPE_TAX, "sometimes".to_owned());
        let error = read(&vars).unwrap_err();
        assert!(matches!(error, ConfigError::BadStripeTax), "{error:?}");
    }

    #[test]
    fn billing_partial_is_error() {
        let mut vars = full();
        vars.remove(STRIPE_PRICE_YEARLY);
        vars.insert(STRIPE_WEBHOOK_SECRET, "  ".to_owned());
        let error = read(&vars).unwrap_err();
        let ConfigError::BillingIncomplete { missing } = &error else {
            panic!("expected BillingIncomplete, got {error:?}");
        };
        assert_eq!(missing, &[STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_YEARLY]);
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(SECRET_VALUE), "no value in {text}");
        }
        // The tax setting alone does not switch billing on, and is not ignored either.
        let only_tax = HashMap::from([(STRIPE_TAX, "automatic".to_owned())]);
        let error = read(&only_tax).unwrap_err();
        assert!(
            matches!(error, ConfigError::BillingIncomplete { .. }),
            "{error:?}"
        );
    }

    fn user(status: Option<&str>) -> User {
        User {
            id: UserId::from_raw(1),
            firebase_uid: "uid".to_owned(),
            apple_sub: "sub".to_owned(),
            email: None,
            account: None,
            stripe_customer: None,
            stripe_subscription: None,
            status: status.map(str::to_owned),
            period_end: None,
            complimentary: false,
        }
    }

    fn comp(status: Option<&str>) -> User {
        User {
            complimentary: true,
            ..user(status)
        }
    }

    #[test]
    fn access_active_and_past_due_allowed() {
        for status in ["active", "past_due"] {
            assert_eq!(access(&user(Some(status))), Access::Allowed, "{status}");
        }
    }

    #[test]
    fn access_canceled_unpaid_incomplete_incomplete_expired_paused_and_none_denied() {
        for status in [
            Some("canceled"),
            Some("unpaid"),
            Some("incomplete"),
            Some("incomplete_expired"),
            Some("paused"),
            Some("trialing"),
            Some("something_new"),
            None,
        ] {
            assert_eq!(access(&user(status)), Access::Denied, "{status:?}");
        }
    }

    #[test]
    fn access_complimentary_allowed() {
        for status in [None, Some("canceled"), Some("active")] {
            assert_eq!(access(&comp(status)), Access::Allowed, "{status:?}");
        }
    }

    #[tokio::test]
    async fn access_follows_what_the_store_holds() {
        let store = Store::memory().await.expect("store");
        let stored = store
            .upsert_user("uid-1", "sub-1", None)
            .await
            .expect("user");
        assert_eq!(access(&stored), Access::Denied, "a new user has no plan");
        store
            .set_subscription(stored.id, "sub_x", "past_due", Some(1))
            .await
            .expect("set");
        let stored = store.user(stored.id).await.expect("read").expect("user");
        assert_eq!(access(&stored), Access::Allowed, "past_due keeps access");
    }
}
