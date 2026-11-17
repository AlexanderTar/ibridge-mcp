// SPDX-License-Identifier: Apache-2.0

//! What an operator does to an account: suspend it, or delete it.

use std::path::{Path, PathBuf};

use ibridge_core::AppleId;

use crate::serve::DATABASE_FILE;
use crate::store::{Store, StoreError};

/// What an operator can do to an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdminAction {
    /// Block the account's tokens, keys and sign-in. Nothing is deleted.
    Suspend,
    /// Delete the account and everything sealed for it.
    Delete,
}

/// Why an admin command did not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdminError {
    /// The data directory holds no database, so there is nothing to change.
    #[error("no database at {0}")]
    NoDatabase(PathBuf),
    /// The database could not be opened or updated.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Runs `action` against the database in `data_dir`, for the `ibridge admin` command.
///
/// This runs in its own process, next to the server, so it cannot reach the server's pooled
/// sessions. The server refuses the account's tokens from the next call, which is what
/// blocks it; the idle sessions it still holds close within minutes.
///
/// Returns how many accounts matched.
///
/// # Errors
///
/// Returns [`AdminError::NoDatabase`] when `data_dir` holds no database (one is never created
/// here), and [`AdminError::Store`] when it cannot be opened or updated.
pub async fn admin(
    data_dir: &Path,
    action: AdminAction,
    address: &AppleId,
) -> Result<usize, AdminError> {
    let path = data_dir.join(DATABASE_FILE);
    if !path.is_file() {
        return Err(AdminError::NoDatabase(path));
    }
    let store = Store::open(&path).await?;
    let nothing = |_: &AppleId| {};
    let matched = match action {
        AdminAction::Suspend => suspend(&store, address, &nothing).await?,
        AdminAction::Delete => delete(&store, address, &nothing).await?,
    };
    Ok(matched)
}

/// Suspends every account spelled like `address`, then calls `evict` for each.
///
/// Returns how many accounts matched.
///
/// # Errors
///
/// Returns [`StoreError::Internal`] when the database cannot be updated.
pub(crate) async fn suspend(
    store: &Store,
    address: &AppleId,
    evict: &dyn Fn(&AppleId),
) -> Result<usize, StoreError> {
    let accounts = store.suspend_accounts_of(address).await?;
    accounts.iter().for_each(evict);
    Ok(accounts.len())
}

/// Deletes every account spelled like `address` with everything sealed for it, then calls `evict` for each.
///
/// Returns how many accounts were deleted.
///
/// # Errors
///
/// Returns [`StoreError::Internal`] when the database cannot be updated.
pub(crate) async fn delete(
    store: &Store,
    address: &AppleId,
    evict: &dyn Fn(&AppleId),
) -> Result<usize, StoreError> {
    let accounts = store.delete_accounts_of(address).await?;
    accounts.iter().for_each(evict);
    Ok(accounts.len())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::SystemTime;

    use axum::http::StatusCode;
    use ibridge_core::AppleId;
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;

    use super::{AdminAction, AdminError, admin, delete, suspend};
    use crate::oauth::test_support::{ASP_ALL, Harness, harness, harness_with};
    use crate::oauth::{Access, Evict};
    use crate::provider::AccountCache;
    use crate::server::mcp_router;
    use crate::store::{IssuedTokens, Scope, Store, StoreError};
    use crate::test_app::{FakeBackend, app_over, call, config, info, token};

    const ADA: &str = "ada@icloud.com";
    const BEA: &str = "bea@icloud.com";

    fn apple(id: &str) -> AppleId {
        AppleId::try_from(id).expect("apple id")
    }

    async fn tokens(store: &Store, id: &str) -> IssuedTokens {
        let now = SystemTime::now();
        let code = store
            .seal_under_code(
                &apple(id),
                &SecretString::from(ASP_ALL),
                Scope::ReadWrite,
                now,
            )
            .await
            .expect("seal");
        store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .expect("exchange")
    }

    async fn count(store: &Store, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(store.pool())
            .await
            .expect("count")
    }

    #[tokio::test]
    async fn admin_suspend_blocks_calls() {
        let store = Store::memory().await.expect("store");
        let app = app_over(&store).await;
        let ada = tokens(&store, ADA).await;
        let bea = token(&store, BEA, ASP_ALL, Scope::ReadWrite).await;
        let ada_access = ada.access.expose_secret();
        let (status, body) = call(&app, ada_access, "mail_search", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let suspended = suspend(&store, &apple("Ada@iCloud.com"), &|_| {}).await;
        assert_eq!(
            suspended.expect("suspend"),
            1,
            "one account matched, in any letter case"
        );

        let (status, _body) = call(&app, ada_access, "mail_search", &json!({})).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a suspended account's token is refused"
        );
        let (status, body) = call(&app, &bea, "mail_search", &json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "another account is untouched: {body}"
        );
        let now = SystemTime::now();
        assert!(
            matches!(
                store.refresh(ada.refresh.expose_secret(), now).await,
                Err(StoreError::Suspended)
            ),
            "it cannot refresh its way back in"
        );
        let again = store
            .seal_under_code(&apple(ADA), &SecretString::from(ASP_ALL), Scope::Read, now)
            .await;
        assert!(
            matches!(again, Err(StoreError::Suspended)),
            "it cannot sign in again: {again:?}"
        );
        assert_eq!(
            suspend(&store, &apple("nobody@icloud.com"), &|_| {})
                .await
                .expect("suspend"),
            0,
            "an address with no account matches nothing"
        );
    }

    #[tokio::test]
    async fn suspended_account_cannot_sign_in_again() {
        let h = harness(Access::MultiTenant).await;
        let _ = tokens(&h.store, ADA).await;
        suspend(&h.store, &apple(ADA), &|_| {})
            .await
            .expect("suspend");
        let page = h
            .get_authorize(&Harness::authorize_path(&[], &[]), "203.0.113.7")
            .await;
        let reply = h.post_form(&page, "203.0.113.7", ADA, ASP_ALL, None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text);
        assert_eq!(
            reply.error_text().as_deref(),
            Some(crate::web::GENERIC_FAILURE),
            "the page does not say why"
        );
        assert!(
            reply.headers.get(axum::http::header::LOCATION).is_none(),
            "no code"
        );
        assert_eq!(
            h.checks.load(Ordering::SeqCst),
            1,
            "it was only refused after the live check"
        );
    }

    #[tokio::test]
    async fn admin_suspend_drops_pooled_sessions() {
        let (h, cache) = pooled().await;
        let ada = tokens(&h.store, ADA).await;
        let (status, body) = call(
            &h.app,
            ada.access.expose_secret(),
            "mail_search",
            &json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            cache.len(),
            1,
            "the account's providers are pooled after a call"
        );

        let evict: Evict = {
            let cache = Arc::clone(&cache);
            Arc::new(move |apple_id| cache.drop_account(apple_id))
        };
        suspend(&h.store, &apple(ADA), &*evict)
            .await
            .expect("suspend");

        assert!(
            cache.is_empty(),
            "suspending closes the account's pooled sessions"
        );
    }

    #[tokio::test]
    async fn admin_delete_removes_account() {
        let store = Store::memory().await.expect("store");
        let app = app_over(&store).await;
        let ada = tokens(&store, ADA).await;
        let bea = token(&store, BEA, ASP_ALL, Scope::ReadWrite).await;
        let bea_seals = count(&store, "SELECT COUNT(*) FROM seals WHERE grant_id IN (SELECT id FROM grants WHERE account_id = (SELECT id FROM accounts WHERE apple_id = 'bea@icloud.com'))").await;
        let evicted = Mutex::new(Vec::new());

        let deleted = delete(&store, &apple(ADA), &|id| {
            evicted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(id.clone());
        })
        .await;
        assert_eq!(deleted.expect("delete"), 1);

        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM accounts WHERE apple_id = 'ada@icloud.com'"
            )
            .await,
            0
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM grants").await,
            1,
            "only bea's grant is left"
        );
        assert_eq!(
            count(&store, "SELECT COUNT(*) FROM seals").await,
            bea_seals,
            "every sealed copy of ada's password is gone"
        );
        let (status, _body) =
            call(&app, ada.access.expose_secret(), "mail_search", &json!({})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "her token opens nothing");
        let (status, body) = call(&app, &bea, "mail_search", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            *evicted.lock().unwrap_or_else(PoisonError::into_inner),
            vec![apple(ADA)]
        );
        assert_eq!(
            delete(&store, &apple(ADA), &|_| {}).await.expect("delete"),
            0,
            "a second delete finds nothing"
        );
    }

    #[tokio::test]
    async fn admin_command_changes_the_database_in_the_data_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = admin(dir.path(), AdminAction::Suspend, &apple(ADA)).await;
        assert!(
            matches!(missing, Err(AdminError::NoDatabase(_))),
            "{missing:?}"
        );
        assert!(
            !dir.path().join(crate::serve::DATABASE_FILE).exists(),
            "a typo never creates a database"
        );

        let store = Store::open(&dir.path().join(crate::serve::DATABASE_FILE))
            .await
            .expect("store");
        let ada = tokens(&store, ADA).await;
        assert_eq!(
            admin(dir.path(), AdminAction::Suspend, &apple(ADA))
                .await
                .expect("suspend"),
            1
        );
        let opened = store
            .open_for_call(ada.access.expose_secret(), SystemTime::now())
            .await;
        assert!(matches!(opened, Err(StoreError::Suspended)), "{opened:?}");
        assert_eq!(
            admin(dir.path(), AdminAction::Delete, &apple(ADA))
                .await
                .expect("delete"),
            1
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM accounts").await, 0);
    }

    /// A harness whose `/mcp` runs over a real account cache.
    async fn pooled() -> (Harness, Arc<AccountCache<FakeBackend>>) {
        let store = Store::memory().await.expect("store");
        let cache = Arc::new(AccountCache::new(
            FakeBackend,
            store.clone(),
            "https://ibridge.example/account".to_owned(),
        ));
        let mcp = mcp_router(Arc::clone(&cache), info(), &config(Access::MultiTenant));
        let evict: Evict = Arc::new(|_| {});
        let h = harness_with(
            "https://ibridge.example",
            Access::MultiTenant,
            store,
            evict,
            mcp,
        )
        .await;
        (h, cache)
    }
}
