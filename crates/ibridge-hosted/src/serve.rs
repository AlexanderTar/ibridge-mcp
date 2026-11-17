// SPDX-License-Identifier: Apache-2.0

//! Running the hosted server: open the database, build the router, serve until told to stop.

use std::net::SocketAddr;

use rmcp::model::ServerConfig;
use tokio::net::TcpListener;

use crate::config::HostedConfig;
use crate::oauth::SignInCheck;
use crate::provider::Backend;
use crate::store::{Store, StoreError};

/// File name of the database inside the data directory.
pub const DATABASE_FILE: &str = "ibridge.db";

/// Why the server stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The data directory or the socket could not be used.
    #[error("could not use the data directory or the socket: {0}")]
    Io(#[from] std::io::Error),
    /// The database could not be opened or the router built.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Serves the hosted router on `listener` until `shutdown` finishes.
///
/// The data directory is created if it is missing. `config` has already passed
/// [`HostedConfig::resolve`], so nothing is created for a configuration that would
/// have been refused.
///
/// # Errors
///
/// Returns [`ServeError`] when the data directory, the database or the socket fails.
pub async fn serve<B: Backend>(
    config: HostedConfig,
    listener: TcpListener,
    backend: B,
    checker: impl SignInCheck,
    info: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    tokio::fs::create_dir_all(&config.data_dir).await?;
    let store = Store::open(&config.data_dir.join(DATABASE_FILE)).await?;
    let store = match config.signup_cap {
        Some(cap) => store.with_signup_cap(cap),
        None => store,
    };
    let app = crate::app::app(config.oauth, store, backend, checker, info, &config.guards).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ibridge_auth::Credentials;
    use ibridge_testkit::http::send;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::serve;
    use crate::config::{HostedConfig, HostedOptions};
    use crate::oauth::validated_by;
    use crate::test_app::{FakeBackend, info};

    #[tokio::test]
    async fn serve_answers_health_on_a_real_socket_and_stops() {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().join("data");
        let config = HostedConfig::resolve(
            HostedOptions {
                addr: "127.0.0.1:0".parse().expect("address"),
                public_url: "https://ibridge.example".to_owned(),
                data_dir: data_dir.clone(),
                multi_tenant: true,
            },
            |_| None,
        )
        .expect("config");
        let listener = TcpListener::bind(config.addr).await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(serve(
            config,
            listener,
            FakeBackend,
            validated_by(|_: &Credentials| crate::test_app::AcceptAll),
            info(),
            async move {
                let _ = stopped.await;
            },
        ));

        let health = send("GET", &format!("{base}/healthz"), &[], "").await;
        assert_eq!(health.status, 200, "{}", health.body);
        let ready = send("GET", &format!("{base}/readyz"), &[], "").await;
        assert_eq!(ready.status, 200, "{}", ready.body);
        assert!(
            data_dir.join(super::DATABASE_FILE).exists(),
            "the database lives in the data directory"
        );

        stop.send(()).expect("server is running");
        server.await.expect("task").expect("clean stop");
    }
}
