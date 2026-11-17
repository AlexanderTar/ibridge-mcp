// SPDX-License-Identifier: Apache-2.0

//! `/healthz` says the process is up. `/readyz` says it can serve: the database
//! answers and holds this build's schema. Railway restarts on `/readyz`; the
//! external uptime check watches `/healthz`.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

use crate::store::Store;

/// The two health routes. Neither needs a token and neither reads a request body.
pub(crate) fn routes(store: Store) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(ready))
        .with_state(store)
}

async fn ready(State(store): State<Store>) -> (StatusCode, String) {
    match store.ready().await {
        Ok(()) => (StatusCode::OK, "ready".to_owned()),
        Err(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("not ready: {reason}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use super::routes;
    use crate::store::Store;

    async fn get(app: &Router, path: &str) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn healthz_ok() {
        let store = Store::memory().await.expect("store");
        let app = routes(store.clone());
        assert_eq!(get(&app, "/healthz").await.0, StatusCode::OK);

        // The process is up even when the database is not: that is /readyz's question.
        store.pool().close().await;
        assert_eq!(
            get(&app, "/healthz").await.0,
            StatusCode::OK,
            "healthz does not touch the database"
        );
    }

    #[tokio::test]
    async fn readyz_checks_db_and_migrations() {
        let store = Store::memory().await.expect("store");
        let app = routes(store.clone());
        assert_eq!(get(&app, "/readyz").await.0, StatusCode::OK, "fresh store");

        // A database from a build with another schema.
        sqlx::query("PRAGMA user_version = 99")
            .execute(store.pool())
            .await
            .expect("set version");
        let (status, body) = get(&app, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "wrong schema");
        assert!(body.contains("migrations"), "names the check: {body}");

        sqlx::query("PRAGMA user_version = 2")
            .execute(store.pool())
            .await
            .expect("restore version");
        assert_eq!(
            get(&app, "/readyz").await.0,
            StatusCode::OK,
            "back to ready"
        );

        store.pool().close().await;
        let (status, body) = get(&app, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "closed database");
        assert!(body.contains("database"), "names the check: {body}");
    }
}
