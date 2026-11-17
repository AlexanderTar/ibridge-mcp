// SPDX-License-Identifier: Apache-2.0

//! What the account page does to the store: list grants, revoke one, delete everything.
//!
//! None of it opens a seal, so none of it needs a token or can read a password.
//! An address matches in any letter case, because Apple treats `Ada@iCloud.com` and
//! `ada@icloud.com` as one account even though the store keeps them apart.

use ibridge_core::AppleId;
use sqlx::Row;

use super::{
    GrantId, KIND_API_KEY, PURPOSE_CODE, PURPOSE_CODE_SPENT, Scope, Store, StoreError, begin,
    grant_bytes, internal, revoke, settle,
};

/// What kind of connection a grant is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantKind {
    /// A client that signed in with OAuth.
    OAuth,
    /// A personal API key.
    ApiKey,
}

/// A connection the account page lists.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    /// The grant's id.
    pub id: GrantId,
    /// OAuth sign-in or API key.
    pub kind: GrantKind,
    /// The name a key was given. OAuth grants carry none.
    pub name: Option<String>,
    /// What the grant may do.
    pub scope: Scope,
    /// The grant was revoked, by the user or after three failed logins.
    pub revoked: bool,
    /// When it was created, in Unix seconds.
    pub created_at: i64,
}

impl GrantId {
    /// The id as 32 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{self:?}")
    }

    /// Reads an id written by [`GrantId::to_hex`].
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl Store {
    /// The grants and API keys of every account spelled like `address`, newest first.
    ///
    /// A grant whose sign-in was never finished is left out.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be read.
    pub async fn grants_of(&self, address: &AppleId) -> Result<Vec<GrantSummary>, StoreError> {
        let rows = sqlx::query(
            "SELECT g.id AS id, g.kind AS kind, g.name AS name, g.scope AS scope,
                    g.status AS status, g.created_at AS created_at
             FROM grants g JOIN accounts a ON a.id = g.account_id
             WHERE lower(a.apple_id) = lower(?1)
               AND EXISTS (SELECT 1 FROM seals s
                           WHERE s.grant_id = g.id AND s.purpose NOT IN (?2, ?3))
             ORDER BY g.created_at DESC, g.rowid DESC",
        )
        .bind(address.as_str())
        .bind(PURPOSE_CODE)
        .bind(PURPOSE_CODE_SPENT)
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        rows.iter()
            .map(|row| {
                let id: Vec<u8> = row.try_get("id").map_err(internal)?;
                let kind: String = row.try_get("kind").map_err(internal)?;
                let scope: String = row.try_get("scope").map_err(internal)?;
                let status: String = row.try_get("status").map_err(internal)?;
                Ok(GrantSummary {
                    id: GrantId(grant_bytes(&id)?),
                    kind: if kind == KIND_API_KEY {
                        GrantKind::ApiKey
                    } else {
                        GrantKind::OAuth
                    },
                    name: row.try_get("name").map_err(internal)?,
                    scope: Scope::parse(&scope)?,
                    revoked: status != super::STATUS_ACTIVE,
                    created_at: row.try_get("created_at").map_err(internal)?,
                })
            })
            .collect()
    }

    /// Revokes `grant` when it belongs to an account spelled like `address`.
    ///
    /// Returns the exact addresses whose pooled sessions the caller should close:
    /// empty when the grant is not this person's, or does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn revoke_grant_of(
        &self,
        address: &AppleId,
        grant: GrantId,
    ) -> Result<Vec<AppleId>, StoreError> {
        let mut tx = begin(self.pool()).await?;
        let result = async {
            let owner: Option<String> = sqlx::query_scalar(
                "SELECT a.apple_id FROM grants g JOIN accounts a ON a.id = g.account_id
                 WHERE g.id = ?1 AND lower(a.apple_id) = lower(?2)",
            )
            .bind(grant.0.as_slice())
            .bind(address.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
            let Some(owner) = owner else {
                return Ok(Vec::new());
            };
            revoke(&mut tx, &grant.0).await?;
            Ok(vec![AppleId::try_from(owner.as_str()).map_err(internal)?])
        }
        .await;
        settle(tx, result).await
    }

    /// Suspends every account spelled like `address`. Its tokens and keys stop working
    /// and it cannot sign in or mint keys, until an operator undoes it in the database.
    /// Nothing is deleted, so the accounts and their grants stay as they were.
    ///
    /// Returns the exact addresses suspended, whose pooled sessions the caller should close.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn suspend_accounts_of(&self, address: &AppleId) -> Result<Vec<AppleId>, StoreError> {
        let owners: Vec<String> = sqlx::query_scalar(
            "UPDATE accounts SET suspended = 1 WHERE lower(apple_id) = lower(?) RETURNING apple_id",
        )
        .bind(address.as_str())
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        owners
            .iter()
            .map(|owner| AppleId::try_from(owner.as_str()).map_err(internal))
            .collect()
    }

    /// Deletes every account spelled like `address`, with its grants and every sealed copy.
    ///
    /// Returns the exact addresses deleted, whose pooled sessions the caller should close.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the database cannot be updated.
    pub async fn delete_accounts_of(&self, address: &AppleId) -> Result<Vec<AppleId>, StoreError> {
        let mut tx = begin(self.pool()).await?;
        let result = async {
            let rows = sqlx::query("SELECT id, apple_id FROM accounts WHERE lower(apple_id) = lower(?)")
                .bind(address.as_str())
                .fetch_all(&mut *tx)
                .await
                .map_err(internal)?;
            let mut deleted = Vec::with_capacity(rows.len());
            for row in &rows {
                let id: i64 = row.try_get("id").map_err(internal)?;
                let apple_id: String = row.try_get("apple_id").map_err(internal)?;
                sqlx::query(
                    "DELETE FROM seals WHERE grant_id IN (SELECT id FROM grants WHERE account_id = ?)",
                )
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
                sqlx::query("DELETE FROM grants WHERE account_id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                sqlx::query("DELETE FROM accounts WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                deleted.push(AppleId::try_from(apple_id.as_str()).map_err(internal)?);
            }
            Ok(deleted)
        }
        .await;
        settle(tx, result).await
    }
}
