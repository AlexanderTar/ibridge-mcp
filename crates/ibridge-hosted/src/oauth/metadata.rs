// SPDX-License-Identifier: Apache-2.0

//! Protected resource and authorization server metadata, and the `/mcp` challenge.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::Shared;

const PRM_PATH: &str = "/.well-known/oauth-protected-resource";
const PRM_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const AS_PATH: &str = "/.well-known/oauth-authorization-server";

pub(super) fn routes(shared: &Arc<Shared>) -> Router {
    Router::new()
        .route(PRM_PATH, get(protected_resource))
        .route(PRM_MCP_PATH, get(protected_resource))
        .route(AS_PATH, get(authorization_server))
        // ponytail: hosted MCP auth replaces this placeholder with the real
        // endpoint, which checks the access token. Until then no token passes.
        .route("/mcp", axum::routing::any(challenge))
        .with_state(Arc::clone(shared))
}

async fn protected_resource(State(shared): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({
        "resource": shared.config.url("/mcp"),
        "authorization_servers": [shared.config.issuer()],
        "scopes_supported": ["icloud.read", "icloud.write"],
        "bearer_methods_supported": ["header"],
    }))
}

async fn authorization_server(State(shared): State<Arc<Shared>>) -> Json<Value> {
    let config = &shared.config;
    Json(json!({
        "issuer": config.issuer(),
        "authorization_endpoint": config.url("/authorize"),
        "token_endpoint": config.url("/token"),
        "registration_endpoint": config.url("/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["icloud.read", "icloud.write", "offline_access"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    }))
}

async fn challenge(State(shared): State<Arc<Shared>>) -> Response {
    let value = format!(
        r#"Bearer resource_metadata="{}""#,
        shared.config.url(PRM_MCP_PATH)
    );
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::oauth::test_support::harness;

    async fn app() -> Router {
        harness(crate::oauth::Access::MultiTenant).await.app
    }

    async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let request = Request::get(path).body(Body::empty()).expect("request");
        let response = app().await.oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, headers, body)
    }

    async fn get_json(path: &str) -> Value {
        let (status, _headers, body) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path} answers 200");
        serde_json::from_slice(&body).expect("json body")
    }

    #[tokio::test]
    async fn unauthenticated_mcp_gets_401_with_resource_metadata() {
        let (status, headers, _body) = get("/mcp").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no bearer means 401");
        let challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .expect("a challenge header")
            .to_str()
            .expect("ascii challenge");
        assert_eq!(
            challenge,
            r#"Bearer resource_metadata="https://ibridge.example/.well-known/oauth-protected-resource/mcp""#,
            "the challenge names the protected resource metadata"
        );
    }

    #[tokio::test]
    async fn prm_resource_equals_public_url_mcp() {
        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ] {
            let metadata = get_json(path).await;
            assert_eq!(
                metadata["resource"], "https://ibridge.example/mcp",
                "{path}: resource is the public MCP URL"
            );
            assert_eq!(
                metadata["authorization_servers"],
                serde_json::json!(["https://ibridge.example"]),
                "{path}: this server is the only authorization server"
            );
        }
    }

    #[tokio::test]
    async fn as_metadata_advertises_cimd_none_s256_iss_offline_access() {
        let metadata = get_json("/.well-known/oauth-authorization-server").await;
        assert_eq!(metadata["issuer"], "https://ibridge.example");
        assert_eq!(
            metadata["authorization_endpoint"],
            "https://ibridge.example/authorize"
        );
        assert_eq!(metadata["token_endpoint"], "https://ibridge.example/token");
        assert_eq!(
            metadata["registration_endpoint"], "https://ibridge.example/register",
            "DCR is the fallback for clients without a metadata document"
        );
        assert_eq!(
            metadata["client_id_metadata_document_supported"], true,
            "CIMD is advertised"
        );
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            serde_json::json!(["none"])
        );
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"], true,
            "RFC 9207 iss is advertised"
        );
        let scopes = metadata["scopes_supported"].as_array().expect("scopes");
        for wanted in ["icloud.read", "icloud.write", "offline_access"] {
            assert!(
                scopes.iter().any(|scope| scope == wanted),
                "{wanted} is advertised, got {scopes:?}"
            );
        }
        assert_eq!(
            metadata["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            metadata["response_types_supported"],
            serde_json::json!(["code"])
        );
    }
}
