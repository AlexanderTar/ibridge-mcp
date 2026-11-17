// SPDX-License-Identifier: Apache-2.0

//! Dynamic client registration, the fallback for clients without a metadata document.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

use super::cimd::display_name;
use super::client::{ClientInfo, valid_redirect_uri};
use super::{Peer, Shared};
use crate::store::{Store, StoreError, internal};

/// Registrations kept before new ones are refused.
const MAX_CLIENTS: i64 = 10_000;
/// Largest registration request.
const MAX_REQUEST: usize = 16 * 1024;
const MAX_REDIRECTS: usize = 10;
/// A registration nobody signed in through is swept after a week.
const UNUSED_TTL_SECS: i64 = 7 * 24 * 60 * 60;

const TABLE: &str = "CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT NOT NULL PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER
)";

/// Clients that registered themselves. Lives in the credential database.
#[derive(Clone, Debug)]
pub(crate) struct ClientRegistry {
    pool: SqlitePool,
}

/// Why a registration did not happen.
#[derive(Debug)]
enum RegisterError {
    /// The registry is full.
    Full,
    /// The database failed. Display text holds no secret.
    Store(StoreError),
}

impl ClientRegistry {
    pub(crate) async fn open(store: &Store) -> Result<Self, StoreError> {
        sqlx::query(TABLE)
            .execute(store.pool())
            .await
            .map_err(internal)?;
        Ok(Self {
            pool: store.pool().clone(),
        })
    }

    pub(crate) async fn get(&self, client_id: &str) -> Result<Option<ClientInfo>, StoreError> {
        let row =
            sqlx::query("SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?")
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(internal)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let name: String = row.try_get("client_name").map_err(internal)?;
        let uris: String = row.try_get("redirect_uris").map_err(internal)?;
        let redirect_uris = serde_json::from_str(&uris).map_err(internal)?;
        Ok(Some(ClientInfo {
            id: client_id.to_owned(),
            name,
            redirect_uris,
        }))
    }

    /// Drops registrations nobody signed in through after a week, and when the table is
    /// still full, the oldest unused one. Registrations that were used are never dropped,
    /// so a flood of fake ones cannot lock real clients out of registering.
    async fn make_room(&self, now: i64, max: i64) -> Result<(), RegisterError> {
        let store = |err| RegisterError::Store(internal(err));
        sqlx::query("DELETE FROM oauth_clients WHERE used_at IS NULL AND created_at < ?")
            .bind(now.saturating_sub(UNUSED_TTL_SECS))
            .execute(&self.pool)
            .await
            .map_err(store)?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
            .fetch_one(&self.pool)
            .await
            .map_err(store)?;
        if count < max {
            return Ok(());
        }
        let evicted = sqlx::query(
            "DELETE FROM oauth_clients WHERE rowid =
             (SELECT rowid FROM oauth_clients WHERE used_at IS NULL ORDER BY created_at, rowid LIMIT 1)",
        )
        .execute(&self.pool)
        .await
        .map_err(store)?;
        if evicted.rows_affected() == 0 {
            return Err(RegisterError::Full);
        }
        Ok(())
    }

    /// Notes that someone signed in through this client, which keeps it from being swept.
    pub(crate) async fn mark_used(&self, client_id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE oauth_clients SET used_at = ? WHERE client_id = ?")
            .bind(now_secs())
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn register(
        &self,
        name: &str,
        redirect_uris: Vec<String>,
    ) -> Result<ClientInfo, RegisterError> {
        let created = now_secs();
        self.make_room(created, MAX_CLIENTS).await?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|err| RegisterError::Store(internal(err)))?;
        let id = format!(
            "dcr_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        let uris = serde_json::to_string(&redirect_uris)
            .map_err(|err| RegisterError::Store(internal(err)))?;
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(uris)
        .bind(created)
        .execute(&self.pool)
        .await
        .map_err(|err| RegisterError::Store(internal(err)))?;
        Ok(ClientInfo {
            id,
            name: name.to_owned(),
            redirect_uris,
        })
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0))
}

impl From<getrandom::Error> for RegisterError {
    fn from(err: getrandom::Error) -> Self {
        Self::Store(internal(err))
    }
}

pub(super) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route("/register", post(register))
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(Arc::clone(shared))
}

fn refusal(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

/// RFC 7591 registration, limited to public clients.
async fn register(
    State(shared): State<Arc<Shared>>,
    peer: Peer,
    Json(request): Json<Value>,
) -> Response {
    if !shared.registrations.allow(&peer.0, Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let redirect_uris: Vec<String> = request
        .get("redirect_uris")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .map(|entry| entry.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .unwrap_or_default();
    if redirect_uris.is_empty()
        || redirect_uris.len() > MAX_REDIRECTS
        || !redirect_uris.iter().all(|uri| valid_redirect_uri(uri))
    {
        return refusal(
            "invalid_redirect_uri",
            "redirect_uris must list https, loopback or app-scheme URIs",
        );
    }
    let public_only = request
        .get("token_endpoint_auth_method")
        .is_none_or(|method| method == "none");
    let grants_ok = request
        .get("grant_types")
        .and_then(Value::as_array)
        .is_none_or(|grants| {
            grants
                .iter()
                .all(|grant| matches!(grant.as_str(), Some("authorization_code" | "refresh_token")))
        });
    let responses_ok = request
        .get("response_types")
        .and_then(Value::as_array)
        .is_none_or(|types| types.iter().all(|kind| kind == "code"));
    if !public_only || !grants_ok || !responses_ok {
        return refusal(
            "invalid_client_metadata",
            "only public clients using the code and refresh_token grants are supported",
        );
    }
    let name = request
        .get("client_name")
        .and_then(Value::as_str)
        .map(display_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "An MCP client".to_owned());
    match shared.registry.register(&name, redirect_uris).await {
        Ok(client) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client.id,
                "client_name": client.name,
                "redirect_uris": client.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Err(RegisterError::Full) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "temporarily_unavailable"})),
        )
            .into_response(),
        Err(RegisterError::Store(error)) => {
            tracing::error!(%error, "client registration failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::ClientRegistry;
    use crate::oauth::Access;
    use crate::oauth::test_support::{Harness, harness};

    async fn register(harness: &Harness, body: &Value) -> (StatusCode, Value) {
        let app = harness.app.clone();
        let request = Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn dcr_fallback_registers_public_client() {
        let harness = harness(Access::MultiTenant).await;
        let (status, reply) = register(
            &harness,
            &json!({
                "client_name": "Test Client",
                "redirect_uris": ["http://127.0.0.1/cb", "https://app.example/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "registered: {reply}");
        let client_id = reply["client_id"].as_str().expect("a client id");
        assert!(client_id.starts_with("dcr_"), "issued id: {client_id}");
        assert_eq!(reply["token_endpoint_auth_method"], "none");
        assert!(
            reply.get("client_secret").is_none(),
            "public clients get no secret"
        );
        assert_eq!(reply["client_name"], "Test Client");
        assert_eq!(
            reply["redirect_uris"],
            json!(["http://127.0.0.1/cb", "https://app.example/cb"])
        );

        let registry = ClientRegistry::open(&harness.store)
            .await
            .expect("registry");
        let stored = registry
            .get(client_id)
            .await
            .expect("lookup")
            .expect("the client was stored");
        assert_eq!(stored.name, "Test Client");
        assert_eq!(
            stored.redirect_uris,
            ["http://127.0.0.1/cb", "https://app.example/cb"]
        );
        assert!(
            registry.get("dcr_unknown").await.expect("lookup").is_none(),
            "an unknown id finds nothing"
        );
    }

    /// Fills the table with `count` registrations that never signed anyone in.
    async fn fill(harness: &Harness, count: i64) {
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
             INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
             SELECT 'dcr_old' || i, 'old', '[\"https://old.example/cb\"]', CAST(strftime('%s', 'now') AS INTEGER) - 100000 + i FROM n",
        )
        .bind(count)
        .execute(harness.store.pool())
        .await
        .expect("seed registrations");
    }

    #[tokio::test]
    async fn a_full_table_evicts_unused_registrations_instead_of_refusing_for_good() {
        let harness = harness(Access::MultiTenant).await;
        fill(&harness, super::MAX_CLIENTS).await;
        let (status, reply) = register(
            &harness,
            &json!({"redirect_uris": ["https://app.example/cb"]}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a flood of unused registrations must not disable DCR: {reply}"
        );
        let registry = ClientRegistry::open(&harness.store)
            .await
            .expect("registry");
        assert!(
            registry.get("dcr_old1").await.expect("lookup").is_none(),
            "the oldest unused registration made room"
        );
        assert!(
            registry.get("dcr_old2").await.expect("lookup").is_some(),
            "only one was evicted"
        );
    }

    #[tokio::test]
    async fn unused_registrations_expire_but_used_ones_stay() {
        let harness = harness(Access::MultiTenant).await;
        let registry = ClientRegistry::open(&harness.store)
            .await
            .expect("registry");
        let week = 7 * 24 * 60 * 60;
        for id in ["dcr_stale", "dcr_used", "dcr_fresh"] {
            let age = if id == "dcr_fresh" { 60 } else { week + 60 };
            sqlx::query(
                "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
                 VALUES (?, 'c', '[\"https://c.example/cb\"]', CAST(strftime('%s', 'now') AS INTEGER) - ?)",
            )
            .bind(id)
            .bind(age)
            .execute(harness.store.pool())
            .await
            .expect("seed");
        }
        registry.mark_used("dcr_used").await.expect("mark used");
        let (status, _) = register(
            &harness,
            &json!({"redirect_uris": ["https://app.example/cb"]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let present = |id: &'static str| {
            let registry = &registry;
            async move { registry.get(id).await.expect("lookup").is_some() }
        };
        assert!(!present("dcr_stale").await, "unused for over a week");
        assert!(present("dcr_used").await, "someone signed in through it");
        assert!(present("dcr_fresh").await, "still young");
    }

    #[tokio::test]
    async fn dcr_rejects_metadata_a_public_client_cannot_have() {
        let harness = harness(Access::MultiTenant).await;
        let cases = [
            (json!({"client_name": "x"}), "invalid_redirect_uri"),
            (json!({"redirect_uris": []}), "invalid_redirect_uri"),
            (
                json!({"redirect_uris": ["http://app.example/cb"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris": ["javascript:alert(1)"]}),
                "invalid_redirect_uri",
            ),
            (
                json!({"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "client_secret_basic"}),
                "invalid_client_metadata",
            ),
            (
                json!({"redirect_uris": ["https://app.example/cb"], "grant_types": ["password"]}),
                "invalid_client_metadata",
            ),
        ];
        for (body, error) in cases {
            let (status, reply) = register(&harness, &body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(reply["error"], error, "{body}");
        }
    }

    #[tokio::test]
    async fn registration_is_rate_limited_per_ip() {
        let harness = harness(Access::MultiTenant).await;
        let post = |ip: &'static str| {
            let harness = &harness;
            async move {
                let request = Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"redirect_uris": ["https://app.example/cb"]}).to_string(),
                    ))
                    .expect("request");
                harness.send(request, ip).await.status
            }
        };
        for attempt in 0..10 {
            assert_eq!(
                post("198.51.100.9").await,
                StatusCode::CREATED,
                "registration {attempt}"
            );
        }
        assert_eq!(
            post("198.51.100.9").await,
            StatusCode::TOO_MANY_REQUESTS,
            "the eleventh registration from one address in an hour"
        );
        assert_eq!(
            post("198.51.100.10").await,
            StatusCode::CREATED,
            "another address is unaffected"
        );
    }
}
