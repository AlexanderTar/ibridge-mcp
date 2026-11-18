// SPDX-License-Identifier: Apache-2.0

//! A signed-in-with-Apple rig for the page tests: the fakes, a store and browsers with sessions.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use ibridge_core::AppleId;
use secrecy::SecretString;

use super::account::{Principal, SESSION_COOKIE};
use crate::billing::fakes::{FAKE_SECRET_KEY, FakeStripe};
use crate::billing::{Billing, BillingConfig, TaxMode};
use crate::identity::Identity;
use crate::identity::fakes::{FakeApple, FakeFirebase, identity_config};
use crate::oauth::pending::PENDING_COOKIE;
use crate::oauth::test_support::{ASP_ALL, Harness, PUBLIC, Reply, harness_featured};
use crate::oauth::{Access, Shared};
use crate::store::{Scope, Store, User};

pub(crate) const IP: &str = "198.51.100.7";
pub(crate) const OWNER: &str = "pending-owner-cookie-a";

/// A hosted server with Sign in with Apple on, and Stripe on when asked, over fakes.
pub(crate) struct Rig {
    pub(crate) harness: Harness,
    pub(crate) shared: Arc<Shared>,
    _apple: FakeApple,
    _firebase: FakeFirebase,
    stripe: Option<FakeStripe>,
}

/// A browser with a session: the cookies it sends and the token its forms carry.
pub(crate) struct Browser {
    pub(crate) cookie: String,
    pub(crate) csrf: String,
}

fn billing_config() -> BillingConfig {
    BillingConfig {
        secret_key: SecretString::from(FAKE_SECRET_KEY),
        webhook_secret: SecretString::from("whsec_page_tests"),
        price_monthly: "price_month".to_owned(),
        price_yearly: "price_year".to_owned(),
        tax: TaxMode::Managed,
    }
}

/// How to build a [`Rig`]: Stripe off, an open service with no cap, unless told otherwise.
#[derive(Default)]
pub(crate) struct Setup {
    billing: bool,
    cap: Option<usize>,
    only: Option<Vec<AppleId>>,
}

impl Setup {
    /// Turns Stripe on.
    pub(crate) fn billing(mut self) -> Self {
        self.billing = true;
        self
    }

    /// Takes at most `cap` iCloud accounts.
    pub(crate) fn cap(mut self, cap: usize) -> Self {
        self.cap = Some(cap);
        self
    }

    /// Lets only these addresses connect: a closed service.
    pub(crate) fn only(mut self, addresses: &[&str]) -> Self {
        self.only = Some(
            addresses
                .iter()
                .map(|address| AppleId::try_from(*address).expect("address"))
                .collect(),
        );
        self
    }

    pub(crate) async fn build(self) -> Rig {
        let (apple, firebase, identity) = identity().await;
        let (stripe, billing) = if self.billing {
            let stripe = FakeStripe::start().await;
            let billing = Billing::with_base(&billing_config(), stripe.base()).expect("billing");
            (Some(stripe), Some(billing))
        } else {
            (None, None)
        };
        let mut store = Store::memory().await.expect("store");
        if let Some(cap) = self.cap {
            store = store.with_signup_cap(cap);
        }
        let access = self.only.map_or(Access::MultiTenant, Access::AllowList);
        let (harness, shared) = harness_featured(access, store, identity, billing).await;
        Rig {
            harness,
            shared,
            _apple: apple,
            _firebase: firebase,
            stripe,
        }
    }
}

impl Rig {
    /// Sign in with Apple on, Stripe off.
    pub(crate) async fn identity_only() -> Self {
        Setup::default().build().await
    }

    /// Sign in with Apple and Stripe on.
    pub(crate) async fn billing() -> Self {
        Setup::default().billing().build().await
    }

    /// What the Stripe fake was asked, in order; empty when Stripe is off.
    pub(crate) fn stripe_requests(&self) -> Vec<crate::billing::fakes::Recorded> {
        self.stripe.as_ref().map_or_default(FakeStripe::requests)
    }

    /// A user with the email Apple gave, not yet linked to an iCloud address.
    pub(crate) async fn user(&self, uid: &str, email: Option<&str>) -> User {
        self.harness
            .store
            .upsert_user(uid, &format!("sub-{uid}"), email)
            .await
            .expect("user")
    }

    /// A user linked to `address`, by a first connect.
    pub(crate) async fn linked_user(&self, uid: &str, email: &str, address: &str) -> User {
        let user = self.user(uid, Some(email)).await;
        self.harness
            .store
            .seal_under_code(
                &AppleId::try_from(address).expect("address"),
                &SecretString::from(ASP_ALL),
                Scope::ReadWrite,
                SystemTime::now(),
                Some(user.id),
            )
            .await
            .expect("link");
        self.reload(&user).await
    }

    /// The user as stored now.
    pub(crate) async fn reload(&self, user: &User) -> User {
        self.harness
            .store
            .user(user.id)
            .await
            .expect("read")
            .expect("a user")
    }

    /// Gives the user a Stripe subscription in `status`.
    pub(crate) async fn subscribe(&self, user: &User, status: &str) {
        self.harness
            .store
            .set_customer(user.id, "cus_page")
            .await
            .expect("customer");
        self.harness
            .store
            .set_subscription(user.id, "sub_page", status, Some(1_900_000_000))
            .await
            .expect("subscription");
    }

    /// A browser signed in as `user`, holding a pending-request owner cookie as well.
    pub(crate) fn browser(&self, user: &User) -> Browser {
        let (token, csrf) = self
            .shared
            .sessions
            .start(Principal::User(user.id), Instant::now())
            .expect("a session");
        Browser {
            cookie: format!("{SESSION_COOKIE}={token}; {PENDING_COOKIE}={OWNER}"),
            csrf,
        }
    }

    pub(crate) async fn get(&self, path: &str, browser: Option<&Browser>) -> Reply {
        self.harness
            .get_path(path, IP, browser.map(|browser| browser.cookie.as_str()))
            .await
    }

    /// Posts `fields` and the browser's own token to `path`.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        fields: &[(&str, &str)],
    ) -> Reply {
        let mut all = vec![("csrf", browser.csrf.as_str())];
        all.extend_from_slice(fields);
        self.harness
            .post_path(path, IP, Some(&browser.cookie), &all)
            .await
    }
}

async fn identity() -> (FakeApple, FakeFirebase, Identity) {
    let apple = FakeApple::start().await;
    let firebase = FakeFirebase::start("ibridge-fyi", "test-api-key").await;
    firebase.issue_at_real_time();
    let identity = Identity::with_bases(
        &identity_config("ibridge-fyi"),
        PUBLIC,
        apple.base(),
        firebase.base(),
    )
    .expect("identity");
    (apple, firebase, identity)
}
