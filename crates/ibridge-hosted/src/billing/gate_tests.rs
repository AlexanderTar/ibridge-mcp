// SPDX-License-Identifier: Apache-2.0

//! The access gate end to end: a `tools/call` over `/mcp` with billing on.

use std::time::SystemTime;

use axum::Router;
use axum::http::StatusCode;
use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use super::{BillingConfig, TaxMode};
use crate::billing::fakes::FAKE_SECRET_KEY;
use crate::oauth::{Access as WhoMaySignIn, validated_by};
use crate::store::{Scope, Store, User, ValidatedCredentials};
use crate::test_app::{
    AcceptAll, FakeBackend, SECRET_SUBJECT, call, info, rpc_request, send, tool_request,
};

const ASP: &str = "app-pass-word-1234";
const ADA: &str = "ada@icloud.com";

fn billing() -> BillingConfig {
    BillingConfig {
        secret_key: SecretString::from(FAKE_SECRET_KEY),
        webhook_secret: SecretString::from("whsec_gate"),
        price_monthly: "price_month".to_owned(),
        price_yearly: "price_year".to_owned(),
        tax: TaxMode::Managed,
    }
}

async fn app(store: &Store, billing: Option<BillingConfig>) -> Router {
    let mut config = crate::test_app::config(WhoMaySignIn::MultiTenant);
    if let Some(billing) = billing {
        config = config.billing(billing);
    }
    crate::app::app(
        config,
        store.clone(),
        FakeBackend,
        validated_by(|_: &Credentials| AcceptAll),
        info(),
        &crate::limits::Guards::default(),
    )
    .await
    .expect("app")
}

fn ada() -> AppleId {
    AppleId::try_from(ADA).expect("apple id")
}

/// An access token whose grant is linked to `user`, or to nobody.
async fn token_for(store: &Store, user: Option<&User>) -> String {
    let now = SystemTime::now();
    let code = store
        .seal_under_code(
            &ada(),
            &SecretString::from(ASP),
            Scope::ReadWrite,
            now,
            user.map(|user| user.id),
        )
        .await
        .expect("seal");
    store
        .exchange_code(code.code.expose_secret(), now)
        .await
        .expect("exchange")
        .access
        .expose_secret()
        .to_owned()
}

async fn api_key_for(store: &Store, user: &User) -> String {
    let validated =
        ValidatedCredentials::from_check(Credentials::new(ada(), ASP.to_owned()), |_| AcceptAll)
            .await
            .expect("validated");
    store
        .mint_api_key(
            &validated,
            "key",
            Scope::ReadWrite,
            SystemTime::now(),
            Some(user.id),
        )
        .await
        .expect("key")
        .key
        .expose_secret()
        .to_owned()
}

async fn user(store: &Store) -> User {
    store
        .upsert_user("uid-1", "sub-1", None)
        .await
        .expect("user")
}

/// The JSON-RPC result in a response body that may be a bare object or one `data:` line.
fn result_of(body: &str) -> Value {
    let payload = body
        .lines()
        .find_map(|line| line.strip_prefix("data:"))
        .unwrap_or(body);
    let value: Value = serde_json::from_str(payload.trim())
        .unwrap_or_else(|error| panic!("a JSON body ({error}): {body}"));
    value.get("result").cloned().unwrap_or(value)
}

async fn search(app: &Router, bearer: &str) -> (StatusCode, String) {
    call(app, bearer, "mail_search", &json!({})).await
}

fn assert_denied(status: StatusCode, body: &str) {
    assert_eq!(
        status,
        StatusCode::OK,
        "a tool error is a normal MCP reply: {body}"
    );
    let result = result_of(body);
    assert_eq!(result["isError"], true, "{body}");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("https://ibridge.example/account"),
        "the error links to the account page: {text}"
    );
    assert!(
        !body.contains(SECRET_SUBJECT),
        "the mail was not read: {body}"
    );
}

fn assert_allowed(status: StatusCode, body: &str) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains(SECRET_SUBJECT),
        "the call reached the mailbox: {body}"
    );
}

#[tokio::test]
async fn tools_call_denied_without_access_returns_is_error_with_account_link() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    let (status, body) = search(&app, &bearer).await;
    assert_denied(status, &body);
    // Every status that is not active or past_due is the same.
    for status_text in [
        "canceled",
        "unpaid",
        "incomplete",
        "incomplete_expired",
        "paused",
    ] {
        store
            .set_subscription(linked.id, "sub_1", status_text, Some(1))
            .await
            .expect("set");
        let (status, body) = search(&app, &bearer).await;
        assert_denied(status, &body);
    }
}

#[tokio::test]
async fn tools_list_works_without_access() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    let reply = send(&app, rpc_request(&bearer, "tools/list", None, json!({}))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    let tools = result_of(&reply.text)["tools"]
        .as_array()
        .cloned()
        .expect("a tool list");
    assert!(
        tools.iter().any(|tool| tool["name"] == "mail_search"),
        "the tools are still listed: {tools:?}"
    );
    let reply = send(
        &app,
        rpc_request(&bearer, "server/discover", None, json!({})),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "server/discover works without a plan: {}",
        reply.text
    );
}

#[tokio::test]
async fn tools_call_allowed_when_active() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    let (status, body) = search(&app, &bearer).await;
    assert_denied(status, &body);
    // Paying restores access at once, with the same token.
    store
        .set_subscription(linked.id, "sub_1", "active", Some(1))
        .await
        .expect("set");
    let (status, body) = search(&app, &bearer).await;
    assert_allowed(status, &body);
}

#[tokio::test]
async fn past_due_keeps_access() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    store
        .set_subscription(linked.id, "sub_1", "past_due", Some(1))
        .await
        .expect("set");
    let (status, body) = search(&app, &bearer).await;
    assert_allowed(status, &body);
}

#[tokio::test]
async fn complimentary_user_is_allowed_without_a_subscription() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    store
        .set_complimentary(linked.id, true)
        .await
        .expect("comp");
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    let (status, body) = search(&app, &bearer).await;
    assert_allowed(status, &body);
}

#[tokio::test]
async fn api_key_follows_same_rule() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let key = api_key_for(&store, &linked).await;
    assert!(key.starts_with("ibr_"), "an API key");
    let (status, body) = search(&app, &key).await;
    assert_denied(status, &body);
    store
        .set_subscription(linked.id, "sub_1", "active", Some(1))
        .await
        .expect("set");
    let (status, body) = search(&app, &key).await;
    assert_allowed(status, &body);
}

#[tokio::test]
async fn grant_without_linked_user_denied_when_billing_on() {
    let store = Store::memory().await.expect("store");
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, None).await;
    let (status, body) = search(&app, &bearer).await;
    assert_denied(status, &body);
}

#[tokio::test]
async fn no_billing_config_never_gates() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, None).await;
    for bearer in [
        token_for(&store, None).await,
        token_for(&store, Some(&linked)).await,
    ] {
        let (status, body) = search(&app, &bearer).await;
        assert_allowed(status, &body);
    }
}

#[tokio::test]
async fn a_denied_call_is_a_tool_error_not_an_http_error_for_every_tool() {
    let store = Store::memory().await.expect("store");
    let linked = user(&store).await;
    let app = app(&store, Some(billing())).await;
    let bearer = token_for(&store, Some(&linked)).await;
    let reply = send(&app, tool_request(&bearer, "account_status", &json!({}))).await;
    assert_denied(reply.status, &reply.text);
}
