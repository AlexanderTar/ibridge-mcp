// SPDX-License-Identifier: Apache-2.0

//! Scripted HTTP transport for the client tests.

use std::future::Future;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use ibridge_auth::Credentials;
use ibridge_core::AppleId;

use crate::client::Transport;
use crate::error::DavError;

/// One request the guard handed to the transport.
#[derive(Clone, Debug)]
pub(crate) struct Logged {
    /// Request URI.
    pub uri: http::Uri,
    /// `Authorization` header, when the guard attached one.
    pub authorization: Option<String>,
    /// When the transport saw the request. Respects a paused tokio clock.
    pub at: tokio::time::Instant,
    /// Request body. Discovery tests read the property name from it.
    pub body: String,
    /// `If-Match`, when the guard sent one.
    pub if_match: Option<String>,
    /// `If-None-Match`, when the guard sent one.
    pub if_none_match: Option<String>,
}

type Handler = Arc<dyn Fn(&Request<String>) -> Response<Full<Bytes>> + Send + Sync>;

/// Canned responses, shared with the assertions.
#[derive(Clone)]
pub(crate) struct Script {
    log: Arc<Mutex<Vec<Logged>>>,
    handler: Handler,
}

impl Script {
    pub(crate) fn new(
        handler: impl Fn(&Request<String>) -> Response<Full<Bytes>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            handler: Arc::new(handler),
        }
    }

    pub(crate) fn requests(&self) -> Vec<Logged> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Transport for Script {
    fn dispatch(
        &self,
        request: Request<String>,
    ) -> impl Future<Output = Result<Response<Full<Bytes>>, DavError>> + Send {
        let authorization = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Logged {
                uri: request.uri().clone(),
                authorization,
                body: request.body().clone(),
                if_match: header_string(&request, http::header::IF_MATCH),
                if_none_match: header_string(&request, http::header::IF_NONE_MATCH),
                at: tokio::time::Instant::now(),
            });
        let response = (self.handler)(&request);
        async move { Ok(response) }
    }
}

fn header_string(request: &Request<String>, name: http::HeaderName) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(crate) fn credentials() -> Credentials {
    Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    )
}

pub(crate) fn expected_basic() -> String {
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "ada@icloud.com:test-secret",
    );
    format!("Basic {token}")
}
