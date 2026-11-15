// SPDX-License-Identifier: Apache-2.0

//! SQLite credential store. Tokens are the keys; the database holds ciphertext.

mod seal;

use std::error::Error;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ibridge_auth::{Credentials, Validator};
use ibridge_core::AppleId;
use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use zeroize::Zeroize;

/// Failures a caller can act on. Display text never includes a token or a password.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No seal matches this token.
    #[error("the token is not valid")]
    InvalidToken,
    /// The token's lifetime has ended.
    #[error("the token has expired")]
    Expired,
    /// The grant was revoked, including after a refresh token was reused.
    #[error("the grant was revoked")]
    InvalidGrant,
    /// No iCloud service accepted the app-specific password.
    #[error("the password was not accepted")]
    Rejected,
    /// The database could not be opened or updated.
    #[error("the store failed")]
    Internal {
        /// Driver error. Queries bind secrets, so this text does not contain one.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}

/// What a hosted credential may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// `icloud.read`.
    Read,
    /// `icloud.read` and `icloud.write`.
    ReadWrite,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "icloud.read",
            Self::ReadWrite => "icloud.read icloud.write",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "icloud.read" => Ok(Self::Read),
            "icloud.read icloud.write" => Ok(Self::ReadWrite),
            _ => Err(internal(StoreFault("stored scope is not known"))),
        }
    }
}

/// Opaque id of one OAuth grant or API key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantId([u8; 16]);

impl fmt::Debug for GrantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Authorization code that can unseal the password for 60 seconds.
#[derive(Debug)]
pub struct IssuedCode {
    /// Grant this code belongs to.
    pub grant_id: GrantId,
    /// Single-use code. The only copy of the key material.
    pub code: SecretString,
}

/// Access and refresh tokens issued together.
#[derive(Debug)]
pub struct IssuedTokens {
    /// Grant these tokens belong to.
    pub grant_id: GrantId,
    /// Opens the password for one hour.
    pub access: SecretString,
    /// Rotates the grant. Unused copies die after 90 days.
    pub refresh: SecretString,
    /// Scope chosen at sign-in.
    pub scope: Scope,
    /// Access-token lifetime.
    pub expires_in: Duration,
}

/// Password opened for the duration of one tool call.
#[derive(Debug)]
pub struct CallSecret {
    /// Grant that presented the token.
    pub grant_id: GrantId,
    /// Account the password belongs to.
    pub apple_id: AppleId,
    /// App-specific password. Zeroized on drop.
    pub secret: SecretString,
    /// Scope stored for this grant.
    pub scope: Scope,
}

/// Personal API key. The key is shown once and is the only copy of its seal key.
#[derive(Debug)]
pub struct ApiKey {
    /// Grant this key belongs to.
    pub grant_id: GrantId,
    /// Bearer token. Prefix `ibr_`.
    pub key: SecretString,
    /// Scope chosen when the key was minted.
    pub scope: Scope,
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

    /// Opens a file-backed store so several connections share one database.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the file cannot be opened or the schema fails.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(internal)?;
        apply_schema(&pool).await?;
        Ok(Self { pool })
    }

    /// Seals `asp` under a new authorization code.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the row cannot be written.
    pub async fn seal_under_code(
        &self,
        apple_id: &AppleId,
        asp: &SecretString,
        scope: Scope,
        now: SystemTime,
    ) -> Result<IssuedCode, StoreError> {
        let now = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = seal_in(&mut tx, apple_id, asp, scope, now).await;
        settle(tx, result).await
    }

    /// Exchanges a code for an access token and a refresh token, then deletes the code seal.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Expired`] after 60 seconds, and [`StoreError::InvalidToken`]
    /// when the code is unknown or already exchanged.
    pub async fn exchange_code(
        &self,
        code: &str,
        now: SystemTime,
    ) -> Result<IssuedTokens, StoreError> {
        let now = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = exchange_in(&mut tx, code, now).await;
        settle(tx, result).await
    }

    /// Opens the password for this call. The access or API-key seal stays in the database.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Expired`] after one hour for an access token,
    /// [`StoreError::InvalidGrant`] when the grant was revoked, and
    /// [`StoreError::InvalidToken`] when the token is unknown.
    pub async fn open_for_call(
        &self,
        access: &str,
        now: SystemTime,
    ) -> Result<CallSecret, StoreError> {
        let now = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = open_in(&mut tx, access, now).await;
        settle(tx, result).await
    }

    /// Rotates a refresh token. The presented token keeps opening the password for two minutes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Expired`] when a refresh token goes unused for 90 days,
    /// and [`StoreError::InvalidGrant`] when a token is presented again after its grace window.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> Result<IssuedTokens, StoreError> {
        let now = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = refresh_in(&mut tx, refresh_token, now).await;
        settle(tx, result).await
    }

    /// Records one failed login for `grant`.
    ///
    /// Three failures whose first and last are at least 15 minutes apart revoke the grant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidGrant`] when the grant does not exist, and
    /// [`StoreError::Internal`] when the row cannot be updated.
    pub async fn note_auth_failure(
        &self,
        grant: GrantId,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let now = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = record_failure(&mut tx, &grant.0, now).await;
        settle(tx, result).await
    }

    /// Clears the failure streak after a login succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidGrant`] when the grant does not exist, and
    /// [`StoreError::Internal`] when the row cannot be updated.
    pub async fn note_auth_success(
        &self,
        grant: GrantId,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let _ = unix(now)?;
        let mut tx = begin(&self.pool).await?;
        let result = record_success(&mut tx, &grant.0).await;
        settle(tx, result).await
    }

    /// Mints a personal API key after `validator` accepts the password.
    ///
    /// The key does not expire. Its seal opens only with this key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Rejected`] when no service accepts the password or
    /// validation cannot run, and [`StoreError::Internal`] when the row cannot be written.
    pub async fn mint_api_key(
        &self,
        credentials: &Credentials,
        name: &str,
        scope: Scope,
        validator: &impl Validator,
        now: SystemTime,
    ) -> Result<ApiKey, StoreError> {
        let report = match validator.validate().await {
            Ok(report) => report,
            Err(_err) => return Err(StoreError::Rejected),
        };
        if !report.any_service_ok() {
            return Err(StoreError::Rejected);
        }
        let now = unix(now)?;
        let asp = credentials.with_secret(|secret| SecretString::from(secret));
        let mut tx = begin(&self.pool).await?;
        let result = mint_key_in(&mut tx, &credentials.apple_id, &asp, name, scope, now).await;
        settle(tx, result).await
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

const CODE_TTL: i64 = 60;
const ACCESS_TTL: i64 = 3_600;
const REFRESH_TTL: i64 = 90 * 24 * 60 * 60;
const GRACE_TTL: i64 = 120;
const ACCESS_TTL_SECS: u64 = 3_600;

const PREFIX_CODE: &str = "ibc_";
const PREFIX_ACCESS: &str = "iba_";
const PREFIX_REFRESH: &str = "ibf_";
const PREFIX_API: &str = "ibr_";

const PURPOSE_CODE: &str = "code";
const PURPOSE_ACCESS: &str = "access";
const PURPOSE_API_KEY: &str = "api_key";
const PURPOSE_REFRESH: &str = "refresh";
const PURPOSE_GRACE: &str = "refresh_grace";
const PURPOSE_SPENT: &str = "refresh_spent";

const STATUS_ACTIVE: &str = "active";
const STATUS_REVOKED: &str = "revoked";
const KIND_OAUTH: &str = "oauth";
const KIND_API_KEY: &str = "api_key";
const FAILURES_TO_REVOKE: i64 = 3;
const FAILURE_WINDOW: i64 = 15 * 60;

type WriteTx = sqlx::Transaction<'static, sqlx::Sqlite>;

#[derive(Debug)]
struct StoreFault(&'static str);

impl fmt::Display for StoreFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for StoreFault {}

struct Hit {
    seal_id: i64,
    grant_id: Vec<u8>,
    purpose: String,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    expires_at: Option<i64>,
    status: String,
    scope: String,
    apple_id: String,
}

struct Outgoing<'a> {
    grant: &'a [u8; 16],
    apple_id: &'a str,
    purpose: &'a str,
    token: &'a str,
    plaintext: &'a str,
    expires_at: Option<i64>,
    now: i64,
}

async fn begin(pool: &SqlitePool) -> Result<WriteTx, StoreError> {
    pool.begin_with("BEGIN IMMEDIATE").await.map_err(internal)
}

async fn settle<T>(tx: WriteTx, result: Result<T, StoreError>) -> Result<T, StoreError> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(internal)?;
            Ok(value)
        }
        Err(err) if persists(&err) => Err(commit_err(tx, err).await),
        Err(err) => Err(err),
    }
}

fn persists(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::InvalidToken | StoreError::Expired | StoreError::InvalidGrant
    )
}

async fn commit_err(tx: WriteTx, err: StoreError) -> StoreError {
    match tx.commit().await {
        Ok(()) => err,
        Err(commit) => internal(commit),
    }
}

async fn seal_in(
    tx: &mut WriteTx,
    apple_id: &AppleId,
    asp: &SecretString,
    scope: Scope,
    now: i64,
) -> Result<IssuedCode, StoreError> {
    sweep(tx, now).await?;
    let account = upsert_account(tx, apple_id, now).await?;
    let grant = random_bytes::<16>()?;
    sqlx::query(
        "INSERT INTO grants (id, account_id, kind, name, scope, status, created_at)
         VALUES (?, ?, ?, NULL, ?, ?, ?)",
    )
    .bind(grant.as_slice())
    .bind(account)
    .bind(KIND_OAUTH)
    .bind(scope.as_str())
    .bind(STATUS_ACTIVE)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    let code = mint(PREFIX_CODE)?;
    insert_seal(
        tx,
        &Outgoing {
            grant: &grant,
            apple_id: apple_id.as_str(),
            purpose: PURPOSE_CODE,
            token: code.expose_secret(),
            plaintext: asp.expose_secret(),
            expires_at: Some(later(now, CODE_TTL)?),
            now,
        },
    )
    .await?;
    Ok(IssuedCode {
        grant_id: GrantId(grant),
        code,
    })
}

async fn mint_key_in(
    tx: &mut WriteTx,
    apple_id: &AppleId,
    asp: &SecretString,
    name: &str,
    scope: Scope,
    now: i64,
) -> Result<ApiKey, StoreError> {
    sweep(tx, now).await?;
    let account = upsert_account(tx, apple_id, now).await?;
    let grant = random_bytes::<16>()?;
    sqlx::query(
        "INSERT INTO grants (id, account_id, kind, name, scope, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(grant.as_slice())
    .bind(account)
    .bind(KIND_API_KEY)
    .bind(name)
    .bind(scope.as_str())
    .bind(STATUS_ACTIVE)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    let key = mint(PREFIX_API)?;
    insert_seal(
        tx,
        &Outgoing {
            grant: &grant,
            apple_id: apple_id.as_str(),
            purpose: PURPOSE_API_KEY,
            token: key.expose_secret(),
            plaintext: asp.expose_secret(),
            expires_at: None,
            now,
        },
    )
    .await?;
    Ok(ApiKey {
        grant_id: GrantId(grant),
        key,
        scope,
    })
}

async fn exchange_in(tx: &mut WriteTx, code: &str, now: i64) -> Result<IssuedTokens, StoreError> {
    let hit = load(tx, code, now).await?;
    if hit.purpose != PURPOSE_CODE {
        return Err(StoreError::InvalidToken);
    }
    if let Some(err) = refusal(&hit, now) {
        return Err(refuse(tx, &hit, err).await);
    }
    let grant = grant_bytes(&hit.grant_id)?;
    let plain = unseal(&hit, code)?;
    delete_seal(tx, hit.seal_id).await?;
    issue_pair(tx, &hit, &grant, plain.expose_secret(), now).await
}

async fn open_in(tx: &mut WriteTx, access: &str, now: i64) -> Result<CallSecret, StoreError> {
    let hit = load(tx, access, now).await?;
    if hit.purpose != PURPOSE_ACCESS && hit.purpose != PURPOSE_API_KEY {
        return Err(StoreError::InvalidToken);
    }
    if let Some(err) = refusal(&hit, now) {
        return Err(refuse(tx, &hit, err).await);
    }
    let grant = grant_bytes(&hit.grant_id)?;
    let secret = unseal(&hit, access)?;
    Ok(CallSecret {
        grant_id: GrantId(grant),
        apple_id: AppleId::try_from(hit.apple_id.as_str()).map_err(internal)?,
        secret,
        scope: Scope::parse(&hit.scope)?,
    })
}

async fn refresh_in(
    tx: &mut WriteTx,
    refresh_token: &str,
    now: i64,
) -> Result<IssuedTokens, StoreError> {
    let hit = load(tx, refresh_token, now).await?;
    if let Some(err) = refusal(&hit, now) {
        return Err(refuse(tx, &hit, err).await);
    }
    if hit.purpose != PURPOSE_REFRESH && hit.purpose != PURPOSE_GRACE {
        return Err(StoreError::InvalidToken);
    }
    let grant = grant_bytes(&hit.grant_id)?;
    let plain = unseal(&hit, refresh_token)?;
    if hit.purpose == PURPOSE_REFRESH {
        mark_grace(tx, hit.seal_id, later(now, GRACE_TTL)?).await?;
    }
    issue_pair(tx, &hit, &grant, plain.expose_secret(), now).await
}

async fn refuse(tx: &mut WriteTx, hit: &Hit, err: StoreError) -> StoreError {
    if matches!(err, StoreError::InvalidGrant)
        && let Err(revoke_err) = revoke(tx, &hit.grant_id).await
    {
        return revoke_err;
    }
    err
}

fn refusal(hit: &Hit, now: i64) -> Option<StoreError> {
    if hit.status == STATUS_REVOKED || hit.purpose == PURPOSE_SPENT {
        return Some(StoreError::InvalidGrant);
    }
    if hit.expires_at.is_some_and(|expires| now >= expires) {
        return Some(StoreError::Expired);
    }
    None
}

async fn load(tx: &mut WriteTx, token: &str, now: i64) -> Result<Hit, StoreError> {
    sweep(tx, now).await?;
    let mut lookup = seal::lookup(token.as_bytes());
    let row = sqlx::query(
        "SELECT seals.id AS seal_id, seals.grant_id AS grant_id, seals.purpose AS purpose,
                seals.nonce AS nonce, seals.ciphertext AS ciphertext,
                seals.expires_at AS expires_at, grants.status AS status, grants.scope AS scope,
                accounts.apple_id AS apple_id
         FROM seals
         JOIN grants ON grants.id = seals.grant_id
         JOIN accounts ON accounts.id = grants.account_id
         WHERE seals.lookup = ?",
    )
    .bind(lookup.as_slice())
    .fetch_optional(&mut **tx)
    .await;
    lookup.zeroize();
    let row = row.map_err(internal)?;
    let Some(row) = row else {
        return Err(StoreError::InvalidToken);
    };
    hit_from(&row).map_err(internal)
}

fn hit_from(row: &SqliteRow) -> Result<Hit, sqlx::Error> {
    Ok(Hit {
        seal_id: row.try_get("seal_id")?,
        grant_id: row.try_get("grant_id")?,
        purpose: row.try_get("purpose")?,
        nonce: row.try_get("nonce")?,
        ciphertext: row.try_get("ciphertext")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("status")?,
        scope: row.try_get("scope")?,
        apple_id: row.try_get("apple_id")?,
    })
}

async fn sweep(tx: &mut WriteTx, now: i64) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE seals SET ciphertext = NULL, nonce = NULL
         WHERE purpose IN (?, ?, ?) AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(PURPOSE_CODE)
    .bind(PURPOSE_ACCESS)
    .bind(PURPOSE_REFRESH)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    sqlx::query(
        "UPDATE seals SET purpose = ?, ciphertext = NULL, nonce = NULL
         WHERE purpose = ? AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(PURPOSE_SPENT)
    .bind(PURPOSE_GRACE)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    Ok(())
}

async fn upsert_account(tx: &mut WriteTx, apple_id: &AppleId, now: i64) -> Result<i64, StoreError> {
    sqlx::query_scalar(
        "INSERT INTO accounts (apple_id, created_at) VALUES (?, ?)
         ON CONFLICT (apple_id) DO UPDATE SET apple_id = excluded.apple_id
         RETURNING id",
    )
    .bind(apple_id.as_str())
    .bind(now)
    .fetch_one(&mut **tx)
    .await
    .map_err(internal)
}

async fn insert_seal(tx: &mut WriteTx, outgoing: &Outgoing<'_>) -> Result<(), StoreError> {
    let aad = associated_data(outgoing.apple_id, outgoing.grant);
    let sealed = seal::seal(
        &aad,
        outgoing.token.as_bytes(),
        outgoing.plaintext.as_bytes(),
    )
    .map_err(seal_to_store)?;
    sqlx::query(
        "INSERT INTO seals (grant_id, purpose, lookup, nonce, ciphertext, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(outgoing.grant.as_slice())
    .bind(outgoing.purpose)
    .bind(sealed.lookup.as_slice())
    .bind(sealed.nonce.as_slice())
    .bind(sealed.ciphertext.as_slice())
    .bind(outgoing.expires_at)
    .bind(outgoing.now)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    Ok(())
}

async fn issue_pair(
    tx: &mut WriteTx,
    hit: &Hit,
    grant: &[u8; 16],
    plaintext: &str,
    now: i64,
) -> Result<IssuedTokens, StoreError> {
    let access = mint(PREFIX_ACCESS)?;
    let refresh = mint(PREFIX_REFRESH)?;
    insert_seal(
        tx,
        &Outgoing {
            grant,
            apple_id: &hit.apple_id,
            purpose: PURPOSE_ACCESS,
            token: access.expose_secret(),
            plaintext,
            expires_at: Some(later(now, ACCESS_TTL)?),
            now,
        },
    )
    .await?;
    insert_seal(
        tx,
        &Outgoing {
            grant,
            apple_id: &hit.apple_id,
            purpose: PURPOSE_REFRESH,
            token: refresh.expose_secret(),
            plaintext,
            expires_at: Some(later(now, REFRESH_TTL)?),
            now,
        },
    )
    .await?;
    Ok(IssuedTokens {
        grant_id: GrantId(*grant),
        access,
        refresh,
        scope: Scope::parse(&hit.scope)?,
        expires_in: Duration::from_secs(ACCESS_TTL_SECS),
    })
}

async fn mark_grace(tx: &mut WriteTx, seal_id: i64, expires_at: i64) -> Result<(), StoreError> {
    sqlx::query("UPDATE seals SET purpose = ?, expires_at = ? WHERE id = ?")
        .bind(PURPOSE_GRACE)
        .bind(expires_at)
        .bind(seal_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

async fn delete_seal(tx: &mut WriteTx, seal_id: i64) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM seals WHERE id = ?")
        .bind(seal_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

async fn revoke(tx: &mut WriteTx, grant_id: &[u8]) -> Result<(), StoreError> {
    sqlx::query("UPDATE grants SET status = ? WHERE id = ?")
        .bind(STATUS_REVOKED)
        .bind(grant_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    sqlx::query("UPDATE seals SET ciphertext = NULL, nonce = NULL WHERE grant_id = ?")
        .bind(grant_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

async fn record_failure(tx: &mut WriteTx, grant_id: &[u8], now: i64) -> Result<(), StoreError> {
    let row =
        sqlx::query("SELECT status, failure_count, first_failure_at FROM grants WHERE id = ?")
            .bind(grant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(internal)?;
    let Some(row) = row else {
        return Err(StoreError::InvalidGrant);
    };
    let status: String = row.try_get("status").map_err(internal)?;
    if status == STATUS_REVOKED {
        return Ok(());
    }
    let count: i64 = row.try_get("failure_count").map_err(internal)?;
    let first: Option<i64> = row.try_get("first_failure_at").map_err(internal)?;
    let (count, first) = match first {
        Some(first) if count > 0 => (count.saturating_add(1), first),
        _ => (1, now),
    };
    if count >= FAILURES_TO_REVOKE && now.saturating_sub(first) >= FAILURE_WINDOW {
        return revoke(tx, grant_id).await;
    }
    sqlx::query("UPDATE grants SET failure_count = ?, first_failure_at = ? WHERE id = ?")
        .bind(count)
        .bind(first)
        .bind(grant_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(())
}

async fn record_success(tx: &mut WriteTx, grant_id: &[u8]) -> Result<(), StoreError> {
    let updated = sqlx::query(
        "UPDATE grants SET failure_count = 0, first_failure_at = NULL WHERE id = ? AND status = ?",
    )
    .bind(grant_id)
    .bind(STATUS_ACTIVE)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    if updated.rows_affected() > 0 {
        return Ok(());
    }
    let exists = sqlx::query("SELECT id FROM grants WHERE id = ?")
        .bind(grant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(internal)?;
    if exists.is_none() {
        return Err(StoreError::InvalidGrant);
    }
    Ok(())
}

fn unseal(hit: &Hit, token: &str) -> Result<SecretString, StoreError> {
    let grant = grant_bytes(&hit.grant_id)?;
    let nonce = nonce_bytes(hit.nonce.as_deref())?;
    let Some(ciphertext) = hit.ciphertext.as_deref() else {
        return Err(internal(StoreFault("seal has no ciphertext")));
    };
    let sealed = seal::Sealed {
        lookup: seal::lookup(token.as_bytes()),
        nonce,
        ciphertext: ciphertext.to_vec(),
    };
    let aad = associated_data(&hit.apple_id, &grant);
    seal::open(&aad, token.as_bytes(), &sealed).map_err(seal_to_store)
}

fn associated_data(apple_id: &str, grant: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(apple_id.len() + 1 + grant.len());
    aad.extend_from_slice(apple_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(grant);
    aad
}

fn grant_bytes(bytes: &[u8]) -> Result<[u8; 16], StoreError> {
    bytes
        .try_into()
        .map_err(|_| internal(StoreFault("grant id is not 16 bytes")))
}

fn nonce_bytes(bytes: Option<&[u8]>) -> Result<[u8; 12], StoreError> {
    let Some(bytes) = bytes else {
        return Err(internal(StoreFault("seal has no nonce")));
    };
    bytes
        .try_into()
        .map_err(|_| internal(StoreFault("nonce is not 12 bytes")))
}

fn seal_to_store(err: seal::SealError) -> StoreError {
    match err {
        seal::SealError::Random => internal(err),
        seal::SealError::Authentication | seal::SealError::Plaintext => StoreError::InvalidToken,
    }
}

fn mint(prefix: &str) -> Result<SecretString, StoreError> {
    let mut bytes = random_bytes::<32>()?;
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    Ok(SecretString::from(format!("{prefix}{body}")))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut bytes = [0u8; N];
    if let Err(err) = getrandom::fill(&mut bytes) {
        bytes.zeroize();
        return Err(internal(err));
    }
    Ok(bytes)
}

fn unix(now: SystemTime) -> Result<i64, StoreError> {
    let secs = now.duration_since(UNIX_EPOCH).map_err(internal)?.as_secs();
    i64::try_from(secs).map_err(internal)
}

fn later(now: i64, ttl: i64) -> Result<i64, StoreError> {
    now.checked_add(ttl)
        .ok_or_else(|| internal(StoreFault("expiry does not fit")))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
    use ibridge_core::AppleId;
    use secrecy::{ExposeSecret, SecretString};

    use super::{IssuedTokens, Scope, Store, StoreError};

    const ASP: &str = "abcd-efgh-ijkl-mnop";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    async fn seal_code(store: &Store, now: SystemTime) -> super::IssuedCode {
        let apple = AppleId::try_from("ada@icloud.com").unwrap();
        store
            .seal_under_code(&apple, &SecretString::from(ASP), Scope::ReadWrite, now)
            .await
            .unwrap()
    }

    async fn exchange(store: &Store, now: SystemTime) -> IssuedTokens {
        let code = seal_code(store, now).await;
        store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .unwrap()
    }

    async fn purposes(store: &Store) -> Vec<String> {
        sqlx::query_scalar("SELECT purpose FROM seals ORDER BY purpose")
            .fetch_all(&store.pool)
            .await
            .unwrap()
    }

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

    #[tokio::test]
    async fn code_seal_then_exchange_reseals_under_access_and_refresh_and_deletes_code() {
        let store = Store::memory().await.unwrap();
        let now = at(0);
        let code = seal_code(&store, now).await;
        let tokens = store
            .exchange_code(code.code.expose_secret(), now)
            .await
            .unwrap();
        let again = store.exchange_code(code.code.expose_secret(), now).await;
        assert!(
            matches!(again, Err(StoreError::InvalidToken)),
            "exchanged code must be deleted, got {again:?}"
        );
        assert_eq!(
            purposes(&store).await,
            vec!["access".to_owned(), "refresh".to_owned()],
            "only the access and refresh seals remain"
        );
        let opened = store
            .open_for_call(tokens.access.expose_secret(), now)
            .await
            .unwrap();
        assert_eq!(opened.secret.expose_secret(), ASP);
        let rotated = store
            .refresh(tokens.refresh.expose_secret(), now)
            .await
            .unwrap();
        let from_refresh = store
            .open_for_call(rotated.access.expose_secret(), now)
            .await
            .unwrap();
        assert_eq!(from_refresh.secret.expose_secret(), ASP);
    }

    #[tokio::test]
    async fn code_expires_after_60s() {
        let store = Store::memory().await.unwrap();
        let now = at(0);
        let code = seal_code(&store, now).await;
        let expired = store.exchange_code(code.code.expose_secret(), at(60)).await;
        assert!(
            matches!(expired, Err(StoreError::Expired)),
            "a code dies at 60 seconds, got {expired:?}"
        );
        let fresh = seal_code(&store, now).await;
        store
            .exchange_code(fresh.code.expose_secret(), at(59))
            .await
            .expect("a code still exchanges one second before 60");
    }

    #[tokio::test]
    async fn access_token_expires_after_1h() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        store
            .open_for_call(tokens.access.expose_secret(), at(3599))
            .await
            .expect("access token works through 3599 seconds");
        let expired = store
            .open_for_call(tokens.access.expose_secret(), at(3600))
            .await;
        assert!(
            matches!(expired, Err(StoreError::Expired)),
            "access token dies at one hour, got {expired:?}"
        );
    }

    #[tokio::test]
    async fn refresh_expires_after_90_days_unused() {
        let store = Store::memory().await.unwrap();
        let live = exchange(&store, at(0)).await;
        let ninety_days = 90 * 24 * 60 * 60;
        store
            .refresh(live.refresh.expose_secret(), at(ninety_days - 1))
            .await
            .expect("refresh works one second before 90 days");
        let stale = exchange(&store, at(0)).await;
        let expired = store
            .refresh(stale.refresh.expose_secret(), at(ninety_days))
            .await;
        assert!(
            matches!(expired, Err(StoreError::Expired)),
            "an unused refresh token dies at 90 days, got {expired:?}"
        );
    }

    #[tokio::test]
    async fn access_opens_for_call_only() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        let access = tokens.access.expose_secret();
        let first = store.open_for_call(access, at(1)).await.unwrap();
        let second = store.open_for_call(access, at(2)).await.unwrap();
        assert_eq!(first.secret.expose_secret(), ASP);
        assert_eq!(second.secret.expose_secret(), ASP);
        let blobs: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT ciphertext FROM seals WHERE ciphertext IS NOT NULL")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        assert!(
            blobs.iter().all(|blob| !blob
                .windows(ASP.len())
                .any(|window| window == ASP.as_bytes())),
            "opening for a call must not write the password into the database"
        );
        assert_eq!(
            purposes(&store)
                .await
                .into_iter()
                .filter(|purpose| purpose == "access")
                .count(),
            1,
            "opening does not consume or duplicate the access seal"
        );
    }

    #[tokio::test]
    async fn refresh_rotates_and_keeps_grace_copy_2min() {
        let store = Store::memory().await.unwrap();
        let first = exchange(&store, at(0)).await;
        let second = store
            .refresh(first.refresh.expose_secret(), at(10))
            .await
            .unwrap();
        let third = store
            .refresh(first.refresh.expose_secret(), at(10 + 119))
            .await
            .expect("the previous refresh still works inside two minutes");
        store
            .open_for_call(second.access.expose_secret(), at(10 + 119))
            .await
            .expect("the first rotation's access token still opens");
        store
            .open_for_call(third.access.expose_secret(), at(10 + 119))
            .await
            .expect("the grace rotation's access token opens");
        store
            .refresh(second.refresh.expose_secret(), at(10 + 119))
            .await
            .expect("the rotated refresh token stays valid");
    }

    #[tokio::test]
    async fn refresh_reuse_after_grace_revokes_grant() {
        let store = Store::memory().await.unwrap();
        let first = exchange(&store, at(0)).await;
        let second = store
            .refresh(first.refresh.expose_secret(), at(10))
            .await
            .unwrap();
        let reused = store
            .refresh(first.refresh.expose_secret(), at(10 + 121))
            .await;
        assert!(
            matches!(reused, Err(StoreError::InvalidGrant)),
            "reuse after the grace window revokes the grant, got {reused:?}"
        );
        let rotated = store
            .refresh(second.refresh.expose_secret(), at(10 + 121))
            .await;
        assert!(
            matches!(rotated, Err(StoreError::InvalidGrant)),
            "revocation kills the rotated refresh token too, got {rotated:?}"
        );
        let opened = store
            .open_for_call(second.access.expose_secret(), at(10 + 121))
            .await;
        assert!(
            matches!(opened, Err(StoreError::InvalidGrant)),
            "revocation kills the access token too, got {opened:?}"
        );
    }

    #[tokio::test]
    async fn concurrent_refresh_both_succeed_within_grace() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ibridge-store-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let store = Store::open(&path).await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        let refresh = tokens.refresh.expose_secret().to_owned();
        let left = store.clone();
        let right = store.clone();
        let (first, second) = tokio::join!(
            left.refresh(&refresh, at(5)),
            right.refresh(&refresh, at(5)),
        );
        let first = first.expect("one concurrent refresh succeeds");
        let second = second.expect("the other concurrent refresh succeeds");
        assert_ne!(
            first.access.expose_secret(),
            second.access.expose_secret(),
            "each refresh issues its own access token"
        );
        store
            .open_for_call(first.access.expose_secret(), at(5))
            .await
            .expect("first access token opens");
        store
            .open_for_call(second.access.expose_secret(), at(5))
            .await
            .expect("second access token opens");
        store
            .refresh(first.refresh.expose_secret(), at(6))
            .await
            .expect("first refresh token rotates");
        store
            .refresh(second.refresh.expose_secret(), at(6))
            .await
            .expect("second refresh token rotates");
        let _ = std::fs::remove_dir_all(&dir);
    }

    const FIFTEEN_MIN: u64 = 15 * 60;

    #[tokio::test]
    async fn three_auth_failures_over_15min_revoke_grant() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        let other = exchange(&store, at(0)).await;
        store
            .note_auth_failure(tokens.grant_id, at(0))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(60))
            .await
            .unwrap();
        let still = store
            .refresh(tokens.refresh.expose_secret(), at(FIFTEEN_MIN - 1))
            .await;
        assert!(
            still.is_ok(),
            "two failures do not revoke the grant, got {still:?}"
        );
        let still = still.unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(FIFTEEN_MIN))
            .await
            .unwrap();
        let revoked = store
            .refresh(still.refresh.expose_secret(), at(FIFTEEN_MIN))
            .await;
        assert!(
            matches!(revoked, Err(StoreError::InvalidGrant)),
            "the third failure at 15 minutes revokes the grant, got {revoked:?}"
        );
        let opened = store
            .open_for_call(still.access.expose_secret(), at(FIFTEEN_MIN))
            .await;
        assert!(
            matches!(opened, Err(StoreError::InvalidGrant)),
            "revocation kills the access token too, got {opened:?}"
        );
        store
            .refresh(other.refresh.expose_secret(), at(FIFTEEN_MIN))
            .await
            .expect("another grant is unaffected");
    }

    #[tokio::test]
    async fn failures_within_15min_do_not_revoke() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        store
            .note_auth_failure(tokens.grant_id, at(0))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(1))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(FIFTEEN_MIN - 1))
            .await
            .unwrap();
        store
            .refresh(tokens.refresh.expose_secret(), at(FIFTEEN_MIN - 1))
            .await
            .expect("three failures inside 15 minutes do not revoke");
    }

    #[tokio::test]
    async fn success_resets_failure_count() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        store
            .note_auth_failure(tokens.grant_id, at(0))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(60))
            .await
            .unwrap();
        store
            .note_auth_success(tokens.grant_id, at(120))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(120))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(180))
            .await
            .unwrap();
        store
            .note_auth_failure(tokens.grant_id, at(120 + FIFTEEN_MIN - 1))
            .await
            .unwrap();
        store
            .refresh(tokens.refresh.expose_secret(), at(120 + FIFTEEN_MIN - 1))
            .await
            .expect("a success starts the 15 minute span over");
    }

    #[tokio::test]
    async fn revoked_grant_refresh_invalid_grant() {
        let store = Store::memory().await.unwrap();
        let tokens = exchange(&store, at(0)).await;
        for at_secs in [0, 60, FIFTEEN_MIN] {
            store
                .note_auth_failure(tokens.grant_id, at(at_secs))
                .await
                .unwrap();
        }
        let refreshed = store
            .refresh(tokens.refresh.expose_secret(), at(FIFTEEN_MIN))
            .await;
        assert!(
            matches!(refreshed, Err(StoreError::InvalidGrant)),
            "a revoked grant's refresh token is invalid_grant, got {refreshed:?}"
        );
        let again = store
            .refresh(tokens.refresh.expose_secret(), at(FIFTEEN_MIN + 1))
            .await;
        assert!(
            matches!(again, Err(StoreError::InvalidGrant)),
            "the revoked grant stays revoked, got {again:?}"
        );
    }

    struct FixedValidator {
        result: Result<ValidationReport, AuthError>,
    }

    impl Validator for FixedValidator {
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the scripted validator returns a prepared report"
        )]
        async fn validate(&self) -> Result<ValidationReport, AuthError> {
            self.result.clone()
        }
    }

    fn accepted_report() -> ValidationReport {
        ValidationReport {
            mail: ServiceCheck::Ok,
            calendar: ServiceCheck::Failed {
                reason: "calendar is off".to_owned(),
            },
            contacts: ServiceCheck::Failed {
                reason: "contacts are off".to_owned(),
            },
        }
    }

    fn rejected_report() -> ValidationReport {
        ValidationReport {
            mail: ServiceCheck::Failed {
                reason: "mail is off".to_owned(),
            },
            calendar: ServiceCheck::Failed {
                reason: "calendar is off".to_owned(),
            },
            contacts: ServiceCheck::Failed {
                reason: "contacts are off".to_owned(),
            },
        }
    }

    async fn mint_key(store: &Store, apple: &str, asp: &str, scope: Scope) -> super::ApiKey {
        let id = AppleId::try_from(apple).unwrap();
        store
            .mint_api_key(
                &Credentials::new(id, SecretString::from(asp)),
                "laptop",
                scope,
                &FixedValidator {
                    result: Ok(accepted_report()),
                },
                at(0),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn mint_requires_validated_asp() {
        let store = Store::memory().await.unwrap();
        let ada = AppleId::try_from("ada@icloud.com").unwrap();
        let denied = store
            .mint_api_key(
                &Credentials::new(ada.clone(), SecretString::from(ASP)),
                "laptop",
                Scope::Read,
                &FixedValidator {
                    result: Ok(rejected_report()),
                },
                at(0),
            )
            .await;
        assert!(
            matches!(denied, Err(StoreError::Rejected)),
            "a password no service accepts is rejected, got {denied:?}"
        );
        let broken = store
            .mint_api_key(
                &Credentials::new(ada.clone(), SecretString::from(ASP)),
                "laptop",
                Scope::Read,
                &FixedValidator {
                    result: Err(AuthError::Validation),
                },
                at(0),
            )
            .await;
        assert!(
            matches!(broken, Err(StoreError::Rejected)),
            "a validator that cannot run is rejected, got {broken:?}"
        );
        let stored = purposes(&store).await;
        assert!(
            stored.iter().all(|purpose| purpose != "api_key"),
            "a rejected mint must not store an api key, got {stored:?}"
        );
        let minted = store
            .mint_api_key(
                &Credentials::new(ada, SecretString::from(ASP)),
                "laptop",
                Scope::ReadWrite,
                &FixedValidator {
                    result: Ok(accepted_report()),
                },
                at(0),
            )
            .await
            .expect("one accepting service is enough to mint");
        assert!(
            minted.key.expose_secret().starts_with("ibr_"),
            "api keys use the ibr_ prefix"
        );
    }

    #[tokio::test]
    async fn apikey_opens_only_its_copy() {
        let store = Store::memory().await.unwrap();
        let ada = mint_key(&store, "ada@icloud.com", ASP, Scope::ReadWrite).await;
        let bea = mint_key(
            &store,
            "bea@icloud.com",
            "zzzz-zzzz-zzzz-zzzz",
            Scope::ReadWrite,
        )
        .await;
        let first = store
            .open_for_call(ada.key.expose_secret(), at(1))
            .await
            .unwrap();
        let second = store
            .open_for_call(ada.key.expose_secret(), at(2))
            .await
            .unwrap();
        assert_eq!(first.secret.expose_secret(), ASP);
        assert_eq!(second.secret.expose_secret(), ASP);
        let other = store
            .open_for_call(bea.key.expose_secret(), at(2))
            .await
            .unwrap();
        assert_eq!(other.secret.expose_secret(), "zzzz-zzzz-zzzz-zzzz");
        let later = 90 * 24 * 60 * 60 * 2;
        store
            .open_for_call(ada.key.expose_secret(), at(later))
            .await
            .expect("an api key does not expire on its own");
    }

    #[tokio::test]
    async fn revoked_apikey_rejected() {
        let store = Store::memory().await.unwrap();
        let key = mint_key(&store, "ada@icloud.com", ASP, Scope::ReadWrite).await;
        for at_secs in [0, 60, FIFTEEN_MIN] {
            store
                .note_auth_failure(key.grant_id, at(at_secs))
                .await
                .unwrap();
        }
        let opened = store
            .open_for_call(key.key.expose_secret(), at(FIFTEEN_MIN))
            .await;
        assert!(
            matches!(opened, Err(StoreError::InvalidGrant)),
            "a revoked api key is rejected, got {opened:?}"
        );
    }

    #[tokio::test]
    async fn apikey_scope_read_only() {
        let store = Store::memory().await.unwrap();
        let key = mint_key(&store, "ada@icloud.com", ASP, Scope::Read).await;
        let opened = store
            .open_for_call(key.key.expose_secret(), at(1))
            .await
            .unwrap();
        assert_eq!(opened.scope, Scope::Read);
        assert_eq!(opened.secret.expose_secret(), ASP);
        let write = mint_key(&store, "ada@icloud.com", ASP, Scope::ReadWrite).await;
        let opened = store
            .open_for_call(write.key.expose_secret(), at(1))
            .await
            .unwrap();
        assert_eq!(opened.scope, Scope::ReadWrite);
    }
}
