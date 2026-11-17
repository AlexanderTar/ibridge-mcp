// SPDX-License-Identifier: Apache-2.0

//! The whole hosted router: OAuth, `/mcp` and the health routes.

use std::sync::Arc;

use axum::Router;
use rmcp::model::ServerConfig;

use crate::health;
use crate::limits::{Guards, around, limit_calls};
use crate::oauth::{OAuthConfig, SignInCheck, router};
use crate::provider::{AccountCache, Backend};
use crate::server::mcp_router;
use crate::store::{Store, StoreError};

/// Builds the hosted router for `backend`'s accounts.
///
/// `info` is what `initialize` reports. `guards` are the call, size and time limits. Serve the result with
/// `into_make_service_with_connect_info::<SocketAddr>()`, as [`router`] explains.
/// Call it inside a Tokio runtime: it starts the task that closes idle accounts.
///
/// # Errors
///
/// Returns [`StoreError`] when the client table cannot be created or the
/// system has no TLS roots to fetch client metadata with.
pub async fn app<B: Backend>(
    config: OAuthConfig,
    store: Store,
    backend: B,
    checker: impl SignInCheck,
    info: ServerConfig,
    guards: &Guards,
) -> Result<Router, StoreError> {
    let cache = Arc::new(AccountCache::new(
        backend,
        store.clone(),
        config.url("/account"),
    ));
    // The task ends when the cache, held by the handler, is dropped.
    drop(cache.spawn_sweeper());
    let mcp = limit_calls(mcp_router(cache, info, &config), guards);
    let oauth = router(config, &store, checker, mcp).await?;
    Ok(around(oauth.merge(health::routes(store)), guards))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::logging::json_subscriber;
    use crate::store::{Scope, Store};
    use crate::test_app::{SECRET_SUBJECT, app_over, call, token};

    /// Collects what the subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn json_logs_no_message_content() {
        let logs = Captured::default();
        // The most talkative level, so anything a layer would print shows up.
        let _guard = tracing::subscriber::set_default(json_subscriber(logs.clone(), Level::TRACE));
        let store = Store::memory().await.expect("store");
        let app = app_over(&store).await;
        let bearer = token(
            &store,
            "ada@icloud.com",
            "app-pass-word-1234",
            Scope::ReadWrite,
        )
        .await;

        let (status, body) = call(&app, &bearer, "mail_search", &json!({})).await;

        assert_eq!(status, StatusCode::OK, "the call works: {body}");
        assert!(
            body.contains(SECRET_SUBJECT),
            "the message reached the caller, so a log could have carried it: {body}"
        );
        let text = logs.text();
        assert!(!text.is_empty(), "the call was logged at all");
        for line in text.lines() {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("log lines are JSON ({error}): {line}"));
        }
        for secret in [
            SECRET_SUBJECT,
            "boss@example.com",
            &bearer,
            "app-pass-word-1234",
        ] {
            assert!(
                !text.contains(secret),
                "a log line carries {secret:?}:\n{text}"
            );
        }
        assert!(
            !text.to_ascii_lowercase().contains("authorization"),
            "no header is logged:\n{text}"
        );
    }
}
