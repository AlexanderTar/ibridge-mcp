// SPDX-License-Identifier: Apache-2.0

//! Rate limits, and the size and time limits of the hosted HTTP surface.
//!
//! `/authorize` and `/account` share one [`SignInLimits`] so an attacker cannot
//! get a second budget by switching pages. `/mcp` has a per-account budget of tool
//! calls, and every route has a body limit and a timeout.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use serde_json::Value;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::middleware::CallAuth;

/// The limits on the hosted HTTP surface.
#[derive(Debug, Clone)]
pub struct Guards {
    /// Tool calls one account may make in any minute, across all its grants.
    pub calls_per_minute: usize,
    /// The largest request body any route accepts.
    pub body_bytes: usize,
    /// How long a request may take to produce its response headers.
    pub timeout: Duration,
}

impl Default for Guards {
    fn default() -> Self {
        Self {
            calls_per_minute: 60,
            body_bytes: 1 << 20,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Keys tracked before expired ones are swept out.
const SWEEP_AT: usize = 10_000;

/// At most `limit` hits per key in any `window`.
#[derive(Debug)]
pub(crate) struct Limiter {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Limiter {
    pub(crate) fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit for `key` and returns true while the key is within its limit.
    ///
    /// A refused hit is not recorded, so waiting out the window always works.
    pub(crate) fn allow(&self, key: &str, now: Instant) -> bool {
        self.allow_n(key, 1, now)
    }

    /// Records `n` hits for `key` together, or none when they would not all fit.
    pub(crate) fn allow_n(&self, key: &str, n: usize, now: Instant) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        if hits.len() >= SWEEP_AT {
            hits.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|last| now.saturating_duration_since(*last) < self.window)
            });
        }
        let times = hits.entry(key.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= self.window)
        {
            times.pop_front();
        }
        if times.len() + n > self.limit {
            return false;
        }
        times.extend(std::iter::repeat_n(now, n));
        true
    }
}

/// Puts the body limit and the timeout around every route of `app`.
pub(crate) fn around(app: Router, guards: &Guards) -> Router {
    app.layer(RequestBodyLimitLayer::new(guards.body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            guards.timeout,
        ))
}

/// The per-account budget of tool calls.
#[derive(Debug)]
pub(crate) struct CallLimit {
    limiter: Limiter,
    body_bytes: usize,
}

/// Counts the tool calls an account makes, behind the token check.
///
/// Only `tools/call` messages spend the budget, so a client can still list tools and
/// say who it is when it is out of calls. The count reads the body, so it sits behind
/// the same size limit as everything else. The key is the account's address, which is
/// lowercase, so every spelling of it shares one budget.
pub(crate) fn limit_calls(mcp: Router, guards: &Guards) -> Router {
    let limit = Arc::new(CallLimit {
        limiter: Limiter::new(guards.calls_per_minute, Duration::from_mins(1)),
        body_bytes: guards.body_bytes,
    });
    mcp.layer(middleware::from_fn_with_state(limit, count_calls))
}

async fn count_calls(
    State(limit): State<Arc<CallLimit>>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    let Some(account) = request
        .extensions()
        .get::<CallAuth>()
        .map(|call| call.apple_id().as_str().to_ascii_lowercase())
    else {
        // The token check runs first and always sets this; refuse rather than skip the limit.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, limit.body_bytes).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let calls = tool_calls_in(&bytes);
    if calls > 0 && !limit.limiter.allow_n(&account, calls, Instant::now()) {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return response;
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// How many `tools/call` messages `body` holds. Text that is not JSON-RPC counts as one call.
fn tool_calls_in(body: &[u8]) -> usize {
    let is_call =
        |message: &Value| message.get("method").and_then(Value::as_str) == Some("tools/call");
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Array(batch)) => batch.iter().filter(|message| is_call(message)).count(),
        Ok(message) => usize::from(is_call(&message)),
        Err(_) => 1,
    }
}

/// The sign-in budget: 10 attempts a minute per IP and 5 per 15 minutes per address.
#[derive(Debug)]
pub(crate) struct SignInLimits {
    per_ip: Limiter,
    per_address: Limiter,
}

impl SignInLimits {
    pub(crate) fn new() -> Self {
        Self {
            per_ip: Limiter::new(10, Duration::from_secs(60)),
            per_address: Limiter::new(5, Duration::from_mins(15)),
        }
    }

    /// Counts one sign-in attempt. An attempt refused for its IP does not use up the address's budget.
    pub(crate) fn allow(&self, ip: &str, address: Option<&str>, now: Instant) -> bool {
        self.per_ip.allow(ip, now)
            && address.is_none_or(|address| self.per_address.allow(address, now))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Limiter, SignInLimits};

    #[test]
    fn a_key_gets_its_limit_per_window_and_then_a_fresh_window() {
        let limiter = Limiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.allow("a", start));
        assert!(limiter.allow("a", start + Duration::from_secs(1)));
        assert!(
            !limiter.allow("a", start + Duration::from_secs(2)),
            "third hit in the window"
        );
        assert!(
            limiter.allow("b", start + Duration::from_secs(2)),
            "other keys are separate"
        );
        assert!(
            limiter.allow("a", start + Duration::from_secs(61)),
            "the first hit has left the window"
        );
    }

    #[test]
    fn a_batch_spends_its_calls_together_or_not_at_all() {
        let limiter = Limiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        assert!(limiter.allow_n("a", 2, now));
        assert!(!limiter.allow_n("a", 2, now), "two more do not fit in one");
        assert!(limiter.allow("a", now), "the refused batch spent nothing");
        assert!(!limiter.allow("a", now), "now the window is full");
    }

    #[test]
    fn only_tools_call_messages_count_and_junk_counts_as_one() {
        use super::tool_calls_in;
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert_eq!(tool_calls_in(call.as_bytes()), 1);
        assert_eq!(tool_calls_in(list.as_bytes()), 0);
        assert_eq!(
            tool_calls_in(format!("[{call},{list},{call}]").as_bytes()),
            2
        );
        assert_eq!(
            tool_calls_in(b"not json"),
            1,
            "unreadable bodies are not free"
        );
    }

    #[test]
    fn an_ip_refusal_does_not_spend_the_address_budget() {
        let limits = SignInLimits::new();
        let start = Instant::now();
        for _ in 0..10 {
            assert!(limits.allow("203.0.113.1", None, start));
        }
        for _ in 0..20 {
            assert!(!limits.allow("203.0.113.1", Some("ada@icloud.com"), start));
        }
        for other in 0..5 {
            assert!(
                limits.allow(
                    &format!("198.51.100.{other}"),
                    Some("ada@icloud.com"),
                    start
                ),
                "the address budget is untouched by the blocked IP"
            );
        }
    }
}

#[cfg(test)]
mod guard_tests {
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::json;

    use super::Guards;

    /// The body in 1 KiB chunks, as a client without a length would send it.
    fn futures_stream(
        body: String,
    ) -> impl futures::Stream<Item = Result<Vec<u8>, std::io::Error>> {
        let chunks: Vec<_> = body
            .into_bytes()
            .chunks(1024)
            .map(|chunk| Ok(chunk.to_vec()))
            .collect();
        futures::stream::iter(chunks)
    }
    use crate::store::{Scope, Store};
    use crate::test_app::{HANG, app_over, app_with, call, rpc_request, send, token, tool_request};

    #[tokio::test]
    async fn per_account_60_calls_per_min() {
        let store = Store::memory().await.expect("store");
        let app = app_over(&store).await;
        // Two grants of one account share one budget.
        let first = token(&store, "ada@icloud.com", "pw", Scope::ReadWrite).await;
        let second = token(&store, "ada@icloud.com", "pw", Scope::Read).await;
        let other = token(&store, "bob@icloud.com", "pw", Scope::ReadWrite).await;

        for n in 0..60 {
            let bearer = if n % 2 == 0 { &first } else { &second };
            let (status, body) = call(&app, bearer, "mail_list_mailboxes", &json!({})).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "call {n} is within the budget: {body}"
            );
        }

        let refused = send(
            &app,
            tool_request(&first, "mail_list_mailboxes", &json!({})),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::TOO_MANY_REQUESTS,
            "the 61st call"
        );
        assert_eq!(
            refused
                .headers
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60"),
            "tells the client when to come back"
        );
        let also = send(
            &app,
            tool_request(&second, "mail_list_mailboxes", &json!({})),
        )
        .await;
        assert_eq!(
            also.status,
            StatusCode::TOO_MANY_REQUESTS,
            "the other grant is out too"
        );

        let listing = send(&app, rpc_request(&first, "tools/list", None, json!({}))).await;
        assert_eq!(
            listing.status,
            StatusCode::OK,
            "only tool calls are counted: {}",
            listing.text
        );
        let (status, body) = call(&app, &other, "mail_list_mailboxes", &json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "another account has its own budget: {body}"
        );
    }

    #[tokio::test]
    async fn body_limit_and_timeout() {
        let store = Store::memory().await.expect("store");
        let guards = Guards {
            body_bytes: 2048,
            timeout: Duration::from_millis(300),
            ..Guards::default()
        };
        let app = app_with(&store, &guards).await;
        let bearer = token(&store, "ada@icloud.com", "pw", Scope::ReadWrite).await;

        let big = "x".repeat(4096);
        let oversized = send(
            &app,
            tool_request(&bearer, "mail_search", &json!({"text": big})),
        )
        .await;
        assert_eq!(
            oversized.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a big /mcp body"
        );

        let form = format!("grant_type=authorization_code&code={big}");
        let sized = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::CONTENT_LENGTH, form.len())
            .body(Body::from(form.clone()))
            .expect("request");
        assert_eq!(
            send(&app, sized).await.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a big form body with a length"
        );
        // A body of unknown length is cut off as it is read, and the route refuses it.
        let streamed = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from_stream(futures_stream(form)))
            .expect("request");
        assert!(
            send(&app, streamed).await.status.is_client_error(),
            "a big form body of unknown length"
        );

        let started = Instant::now();
        let stuck = send(
            &app,
            tool_request(&bearer, "mail_search", &json!({"text": HANG})),
        )
        .await;
        assert_eq!(
            stuck.status,
            StatusCode::GATEWAY_TIMEOUT,
            "a call that never answers"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it was cut off, not waited out"
        );

        let (status, body) = call(&app, &bearer, "mail_list_mailboxes", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "normal calls still work: {body}");
    }
}
