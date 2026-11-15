// SPDX-License-Identifier: Apache-2.0

//! SQLite credential store. Tokens are the keys; the database holds ciphertext.

mod seal;

use std::error::Error;
use std::str::FromStr;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

/// Failures a caller can act on. Display text never includes a token or a password.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database could not be opened or updated.
    #[error("the store failed")]
    Internal {
        /// Driver error. Queries bind secrets, so this text does not contain one.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}

/// Open credential store.
#[derive(Clone, Debug)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Opens an in-memory store and applies the schema.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when SQLite cannot be opened or the schema fails.
    pub async fn memory() -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(internal)?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(internal)?;
        apply_schema(&pool).await?;
        Ok(Self { pool })
    }
}

async fn apply_schema(pool: &SqlitePool) -> Result<(), StoreError> {
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(pool)
        .await
        .map_err(internal)?;
    Ok(())
}

fn internal(err: impl Error + Send + Sync + 'static) -> StoreError {
    StoreError::Internal {
        source: Box::new(err),
    }
}

#[cfg(test)]
mod tests {
    use super::Store;

    #[tokio::test]
    async fn schema_migration_creates_store_tables() {
        let store = Store::memory().await.unwrap();
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            names,
            vec![
                "accounts".to_owned(),
                "grants".to_owned(),
                "seals".to_owned(),
            ],
            "migration must create the credential tables"
        );
    }
}
