// SPDX-License-Identifier: Apache-2.0

//! The `users` table: one row per Sign in with Apple identity.
//!
//! A user links to at most one iCloud account, and an account to at most one user. The link
//! is made inside the seal transaction ([`link_in`]), so it is bound by the same sign-up cap
//! and rolls back with a refused seal.

use std::fmt;
use std::time::SystemTime;

use ibridge_core::AppleId;
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::manage::delete_account_in;
use super::{GrantId, Store, StoreError, StoreFault, WriteTx, begin, internal, settle, unix};

/// Opaque id of one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(i64);

impl UserId {
    /// The id as a number, for a session cookie or a log line.
    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }

    /// Reads an id written by [`UserId::get`].
    #[must_use]
    pub fn from_raw(raw: i64) -> Self {
        Self(raw)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A Sign in with Apple identity and what it pays for.
///
/// `Debug` leaves out the email and the provider ids, so a stray `{:?}` never logs them.
#[derive(Clone)]
pub struct User {
    /// The user's id.
    pub id: UserId,
    /// Firebase's stable id for this Apple identity.
    pub firebase_uid: String,
    /// Apple's `sub` for this identity.
    pub apple_sub: String,
    /// The email Apple gave, which may be a relay address.
    pub email: Option<String>,
    /// The iCloud address this user is linked to, once it has connected one.
    pub account: Option<AppleId>,
    /// The Stripe customer, once checkout has started.
    pub stripe_customer: Option<String>,
    /// The Stripe subscription last seen.
    pub stripe_subscription: Option<String>,
    /// Its Stripe status.
    pub status: Option<String>,
    /// When the paid period ends, in Unix seconds.
    pub period_end: Option<i64>,
    /// An operator granted access without payment.
    pub complimentary: bool,
}

impl fmt::Debug for User {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("User")
            .field("id", &self.id)
            .field("linked", &self.account.is_some())
            .field("status", &self.status)
            .field("complimentary", &self.complimentary)
            .finish_non_exhaustive()
    }
}

const SELECT_USER: &str = "SELECT u.id, u.firebase_uid, u.apple_sub, u.email,
        a.apple_id AS account, u.stripe_customer, u.stripe_subscription,
        u.status, u.period_end, u.complimentary
    FROM users u LEFT JOIN accounts a ON a.id = u.account_id";

/// How long a handled Stripe event id is remembered, in seconds.
const EVENT_MEMORY_SECS: i64 = 7 * 24 * 60 * 60;

fn user_from(row: &SqliteRow) -> Result<User, StoreError> {
    let account: Option<String> = row.try_get("account").map_err(internal)?;
    Ok(User {
        id: UserId(row.try_get("id").map_err(internal)?),
        firebase_uid: row.try_get("firebase_uid").map_err(internal)?,
        apple_sub: row.try_get("apple_sub").map_err(internal)?,
        email: row.try_get("email").map_err(internal)?,
        account: account
            .map(|address| AppleId::try_from(address.as_str()).map_err(internal))
            .transpose()?,
        stripe_customer: row.try_get("stripe_customer").map_err(internal)?,
        stripe_subscription: row.try_get("stripe_subscription").map_err(internal)?,
        status: row.try_get("status").map_err(internal)?,
        period_end: row.try_get("period_end").map_err(internal)?,
        complimentary: row.try_get::<i64, _>("complimentary").map_err(internal)? != 0,
    })
}

/// Links `account` to `user` inside the caller's transaction.
///
/// Refuses, so the caller rolls back its whole seal, when the user already has another
/// address ([`StoreError::LinkedToOther`]) or another user has this one
/// ([`StoreError::AddressTaken`]).
pub(super) async fn link_in(
    tx: &mut WriteTx,
    user: UserId,
    account: i64,
) -> Result<(), StoreError> {
    let row = sqlx::query("SELECT account_id FROM users WHERE id = ?")
        .bind(user.0)
        .fetch_optional(&mut **tx)
        .await
        .map_err(internal)?
        .ok_or_else(|| internal(StoreFault("the user to link does not exist")))?;
    let current: Option<i64> = row.try_get("account_id").map_err(internal)?;
    match current {
        Some(current) if current == account => Ok(()),
        Some(current) => {
            let linked: String = sqlx::query_scalar("SELECT apple_id FROM accounts WHERE id = ?")
                .bind(current)
                .fetch_one(&mut **tx)
                .await
                .map_err(internal)?;
            Err(StoreError::LinkedToOther {
                linked: AppleId::try_from(linked.as_str()).map_err(internal)?,
            })
        }
        None => {
            let taken: Option<i64> =
                sqlx::query_scalar("SELECT id FROM users WHERE account_id = ?")
                    .bind(account)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(internal)?;
            if taken.is_some() {
                return Err(StoreError::AddressTaken);
            }
            sqlx::query("UPDATE users SET account_id = ? WHERE id = ?")
                .bind(account)
                .bind(user.0)
                .execute(&mut **tx)
                .await
                .map_err(internal)?;
            Ok(())
        }
    }
}

impl Store {
    /// Finds the user for a Firebase uid, or creates it.
    ///
    /// A later sign-in keeps the stored Apple `sub`, and replaces the email only when
    /// Apple sent one, because Apple sends it on the first authorization only.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn upsert_user(
        &self,
        firebase_uid: &str,
        apple_sub: &str,
        email: Option<&str>,
    ) -> Result<User, StoreError> {
        let now = unix(SystemTime::now())?;
        let mut tx = begin(self.pool()).await?;
        let result = async {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO users (firebase_uid, apple_sub, email, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (firebase_uid) DO UPDATE SET email = COALESCE(?3, users.email)
                 RETURNING id",
            )
            .bind(firebase_uid)
            .bind(apple_sub)
            .bind(email)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
            let row = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT_USER} WHERE u.id = ?")))
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?;
            user_from(&row)
        }
        .await;
        settle(tx, result).await
    }

    /// The user with this id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn user(&self, id: UserId) -> Result<Option<User>, StoreError> {
        self.one_user("u.id = ?", id.0).await
    }

    /// The user whose Stripe customer is `customer`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn user_by_customer(&self, customer: &str) -> Result<Option<User>, StoreError> {
        self.one_user("u.stripe_customer = ?", customer).await
    }

    /// The user with this Firebase uid or email, for an operator command.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn user_by_email_or_uid(&self, key: &str) -> Result<Option<User>, StoreError> {
        self.one_user(
            "(u.firebase_uid = ?1 OR lower(u.email) = lower(?1)) ORDER BY u.id",
            key,
        )
        .await
    }

    /// The user a grant's account is linked to, if it is linked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn user_for_grant(&self, grant: GrantId) -> Result<Option<User>, StoreError> {
        self.one_user(
            "u.account_id = (SELECT account_id FROM grants WHERE id = ?)",
            grant.0.as_slice(),
        )
        .await
    }

    async fn one_user<'q, T>(&self, filter: &str, value: T) -> Result<Option<User>, StoreError>
    where
        T: sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Send + 'q,
    {
        // `filter` is one of this module's literals, never caller text.
        let sql = format!("{SELECT_USER} WHERE {filter} LIMIT 1");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(value)
            .fetch_optional(self.pool())
            .await
            .map_err(internal)?
            .as_ref()
            .map(user_from)
            .transpose()
    }

    /// Records the Stripe customer made for a user.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated, including when
    /// the customer already belongs to another user.
    pub async fn set_customer(&self, id: UserId, customer: &str) -> Result<(), StoreError> {
        self.update_user("SET stripe_customer = ?2", id, customer)
            .await
    }

    /// Records the subscription Stripe reports.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn set_subscription(
        &self,
        id: UserId,
        subscription: &str,
        status: &str,
        period_end: Option<i64>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE users SET stripe_subscription = ?2, status = ?3, period_end = ?4 WHERE id = ?1",
        )
        .bind(id.0)
        .bind(subscription)
        .bind(status)
        .bind(period_end)
        .execute(self.pool())
        .await
        .map_err(internal)?;
        Ok(())
    }

    /// Grants or removes access without payment.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "one flag on one user; the admin comp and uncomp commands call it with each value"
    )]
    pub async fn set_complimentary(&self, id: UserId, on: bool) -> Result<(), StoreError> {
        self.update_user("SET complimentary = ?2", id, i64::from(on))
            .await
    }

    async fn update_user<'q, T>(&self, set: &str, id: UserId, value: T) -> Result<(), StoreError>
    where
        T: sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Send + 'q,
    {
        // `set` is one of this module's literals, never caller text.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE users {set} WHERE id = ?1"
        )))
        .bind(id.0)
        .bind(value)
        .execute(self.pool())
        .await
        .map_err(internal)?;
        Ok(())
    }

    /// Whether this Stripe event id was already handled.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn event_seen(&self, id: &str) -> Result<bool, StoreError> {
        let seen: Option<i64> = sqlx::query_scalar("SELECT 1 FROM stripe_events WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(internal)?;
        Ok(seen.is_some())
    }

    /// Records that a Stripe event was handled, and forgets events older than a week:
    /// Stripe stops retrying after three days.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn record_event(&self, id: &str) -> Result<(), StoreError> {
        let now = unix(SystemTime::now())?;
        let mut tx = begin(self.pool()).await?;
        let result = async {
            sqlx::query("DELETE FROM stripe_events WHERE seen_at < ?")
                .bind(now - EVENT_MEMORY_SECS)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            sqlx::query("INSERT OR IGNORE INTO stripe_events (id, seen_at) VALUES (?, ?)")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            Ok(())
        }
        .await;
        settle(tx, result).await
    }

    /// Deletes the user, its linked account, and that account's grants and seals, in one
    /// transaction.
    ///
    /// Returns the address deleted (none when the user never linked one), so the caller can
    /// close its pooled sessions like after [`Store::delete_accounts_of`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn delete_user(&self, id: UserId) -> Result<Vec<AppleId>, StoreError> {
        let mut tx = begin(self.pool()).await?;
        let result = async {
            let row = sqlx::query(
                "SELECT u.account_id AS account_id, a.apple_id AS apple_id
                 FROM users u LEFT JOIN accounts a ON a.id = u.account_id WHERE u.id = ?",
            )
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
            let Some(row) = row else {
                return Ok(Vec::new());
            };
            sqlx::query("DELETE FROM users WHERE id = ?")
                .bind(id.0)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            let account: Option<i64> = row.try_get("account_id").map_err(internal)?;
            let address: Option<String> = row.try_get("apple_id").map_err(internal)?;
            let (Some(account), Some(address)) = (account, address) else {
                return Ok(Vec::new());
            };
            delete_account_in(&mut tx, account).await?;
            Ok(vec![AppleId::try_from(address.as_str()).map_err(internal)?])
        }
        .await;
        settle(tx, result).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ibridge_core::AppleId;
    use secrecy::SecretString;

    use crate::admin::delete as admin_delete;
    use crate::store::{Scope, Services, Store, StoreError, UserId, ValidatedCredentials};

    const ASP: &str = "abcd-efgh-ijkl-mnop";

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn apple(address: &str) -> AppleId {
        AppleId::try_from(address).unwrap()
    }

    async fn user(store: &Store, uid: &str) -> UserId {
        store
            .upsert_user(
                uid,
                &format!("sub-{uid}"),
                Some(&format!("{uid}@example.com")),
            )
            .await
            .unwrap()
            .id
    }

    async fn seal(
        store: &Store,
        address: &str,
        link: Option<UserId>,
    ) -> Result<crate::store::IssuedCode, StoreError> {
        store
            .seal_under_code(
                &apple(address),
                &SecretString::from(ASP),
                Scope::ReadWrite,
                now(),
                link,
            )
            .await
    }

    async fn count(store: &Store, table: &'static str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn upsert_user_is_idempotent_by_uid() {
        let store = Store::memory().await.unwrap();
        let first = store
            .upsert_user("uid-1", "sub-1", Some("ada@example.com"))
            .await
            .unwrap();
        let again = store.upsert_user("uid-1", "sub-1", None).await.unwrap();
        assert_eq!(first.id, again.id, "one uid is one user");
        assert_eq!(count(&store, "users").await, 1);
        assert_eq!(
            again.email.as_deref(),
            Some("ada@example.com"),
            "a sign-in without an email keeps the one on file"
        );
        let renamed = store
            .upsert_user("uid-1", "sub-1", Some("new@example.com"))
            .await
            .unwrap();
        assert_eq!(renamed.email.as_deref(), Some("new@example.com"));
        assert!(!renamed.complimentary);
        assert_eq!(renamed.account, None);
    }

    #[tokio::test]
    async fn seal_with_link_links_first_address() {
        let store = Store::memory().await.unwrap();
        let id = user(&store, "ada").await;
        seal(&store, "ada@icloud.com", Some(id)).await.unwrap();
        let linked = store.user(id).await.unwrap().unwrap();
        assert_eq!(linked.account, Some(apple("ada@icloud.com")));
        seal(&store, "ada@icloud.com", Some(id))
            .await
            .expect("the same address links again");
        assert_eq!(count(&store, "accounts").await, 1);
    }

    #[tokio::test]
    async fn seal_with_link_other_address_is_linked_to_other_and_seals_nothing() {
        let store = Store::memory().await.unwrap();
        let id = user(&store, "ada").await;
        seal(&store, "ada@icloud.com", Some(id)).await.unwrap();
        let (accounts, grants, seals) = (
            count(&store, "accounts").await,
            count(&store, "grants").await,
            count(&store, "seals").await,
        );
        let refused = seal(&store, "bea@icloud.com", Some(id)).await.unwrap_err();
        match refused {
            StoreError::LinkedToOther { linked } => assert_eq!(linked, apple("ada@icloud.com")),
            other => panic!("expected LinkedToOther, got {other:?}"),
        }
        assert_eq!(count(&store, "accounts").await, accounts, "no account made");
        assert_eq!(count(&store, "grants").await, grants, "no grant made");
        assert_eq!(count(&store, "seals").await, seals, "nothing sealed");
    }

    #[tokio::test]
    async fn seal_with_link_address_of_other_user_is_taken_and_seals_nothing() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        let bea = user(&store, "bea").await;
        seal(&store, "ada@icloud.com", Some(ada)).await.unwrap();
        let (grants, seals) = (count(&store, "grants").await, count(&store, "seals").await);
        let refused = seal(&store, "ada@icloud.com", Some(bea)).await.unwrap_err();
        assert!(
            matches!(refused, StoreError::AddressTaken),
            "got {refused:?}"
        );
        assert_eq!(store.user(bea).await.unwrap().unwrap().account, None);
        assert_eq!(count(&store, "grants").await, grants);
        assert_eq!(count(&store, "seals").await, seals);
    }

    #[tokio::test]
    async fn seal_with_link_when_cap_full_refuses_and_links_nothing() {
        let store = Store::memory().await.unwrap().with_signup_cap(1);
        seal(&store, "ada@icloud.com", None).await.unwrap();
        let bea = user(&store, "bea").await;
        let refused = seal(&store, "bea@icloud.com", Some(bea)).await.unwrap_err();
        assert!(
            matches!(refused, StoreError::SignupsFull),
            "got {refused:?}"
        );
        assert_eq!(store.user(bea).await.unwrap().unwrap().account, None);
        assert_eq!(count(&store, "accounts").await, 1);
    }

    #[tokio::test]
    async fn mint_api_key_with_link_follows_the_same_rule() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        let validated = |address: &str| ValidatedCredentials {
            apple_id: apple(address),
            secret: SecretString::from(ASP),
            services: Services::default(),
        };
        store
            .mint_api_key(
                &validated("ada@icloud.com"),
                "key",
                Scope::Read,
                now(),
                Some(ada),
            )
            .await
            .unwrap();
        assert_eq!(
            store.user(ada).await.unwrap().unwrap().account,
            Some(apple("ada@icloud.com"))
        );
        let keys = count(&store, "grants").await;
        let refused = store
            .mint_api_key(
                &validated("bea@icloud.com"),
                "key",
                Scope::Read,
                now(),
                Some(ada),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(refused, StoreError::LinkedToOther { .. }),
            "got {refused:?}"
        );
        assert_eq!(count(&store, "grants").await, keys, "no second key");
    }

    #[tokio::test]
    async fn delete_user_removes_account_grants_seals_and_returns_addresses() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        let other = user(&store, "bea").await;
        seal(&store, "ada@icloud.com", Some(ada)).await.unwrap();
        seal(&store, "bea@icloud.com", Some(other)).await.unwrap();
        let addresses = store.delete_user(ada).await.unwrap();
        assert_eq!(addresses, vec![apple("ada@icloud.com")]);
        assert!(store.user(ada).await.unwrap().is_none());
        assert_eq!(count(&store, "users").await, 1, "the other user stays");
        assert_eq!(
            count(&store, "accounts").await,
            1,
            "only bea's account stays"
        );
        assert_eq!(count(&store, "grants").await, 1);
        assert_eq!(count(&store, "seals").await, 1);
        assert!(
            store.delete_user(ada).await.unwrap().is_empty(),
            "already gone"
        );
    }

    #[tokio::test]
    async fn delete_user_without_a_linked_address_returns_nothing() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        assert_eq!(store.delete_user(ada).await.unwrap(), Vec::<AppleId>::new());
        assert_eq!(count(&store, "users").await, 0);
    }

    #[tokio::test]
    async fn delete_accounts_of_linked_account_succeeds_with_foreign_keys_on() {
        let store = Store::memory().await.unwrap();
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(fk, 1, "the test needs foreign keys on");
        let ada = user(&store, "ada").await;
        seal(&store, "ada@icloud.com", Some(ada)).await.unwrap();
        let deleted = store
            .delete_accounts_of(&apple("ADA@icloud.com"))
            .await
            .unwrap();
        assert_eq!(deleted, vec![apple("ada@icloud.com")]);
        let after = store.user(ada).await.unwrap().expect("the user stays");
        assert_eq!(after.account, None, "the link is cleared");
        assert_eq!(count(&store, "accounts").await, 0);
    }

    #[tokio::test]
    async fn admin_delete_of_linked_account_succeeds_with_foreign_keys_on() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        seal(&store, "ada@icloud.com", Some(ada)).await.unwrap();
        let matched = admin_delete(&store, &apple("ada@icloud.com"), &|_| {})
            .await
            .unwrap();
        assert_eq!(matched, 1);
        assert_eq!(count(&store, "accounts").await, 0);
        assert_eq!(store.user(ada).await.unwrap().unwrap().account, None);
    }

    #[tokio::test]
    async fn billing_fields_round_trip_and_look_up() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        store.set_customer(ada, "cus_1").await.unwrap();
        store
            .set_subscription(ada, "sub_1", "active", Some(1_800_000_000))
            .await
            .unwrap();
        store.set_complimentary(ada, true).await.unwrap();
        let read = store.user_by_customer("cus_1").await.unwrap().unwrap();
        assert_eq!(read.id, ada);
        assert_eq!(read.stripe_subscription.as_deref(), Some("sub_1"));
        assert_eq!(read.status.as_deref(), Some("active"));
        assert_eq!(read.period_end, Some(1_800_000_000));
        assert!(read.complimentary);
        assert!(store.user_by_customer("cus_x").await.unwrap().is_none());
        store.set_complimentary(ada, false).await.unwrap();
        assert!(!store.user(ada).await.unwrap().unwrap().complimentary);
    }

    #[tokio::test]
    async fn user_found_by_email_or_uid() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        for key in ["ada", "ADA@example.com"] {
            let found = store.user_by_email_or_uid(key).await.unwrap().unwrap();
            assert_eq!(found.id, ada, "key {key}");
        }
        assert!(
            store
                .user_by_email_or_uid("nobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn user_for_grant_returns_the_linked_user_only() {
        let store = Store::memory().await.unwrap();
        let ada = user(&store, "ada").await;
        let linked = seal(&store, "ada@icloud.com", Some(ada)).await.unwrap();
        let plain = seal(&store, "bea@icloud.com", None).await.unwrap();
        let found = store
            .user_for_grant(linked.grant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, ada);
        assert!(
            store
                .user_for_grant(plain.grant_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
