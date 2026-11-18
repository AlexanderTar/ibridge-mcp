// SPDX-License-Identifier: Apache-2.0

//! One small HTTPS client for the Apple and Google calls.
//!
//! Redirects are not followed, every call has a deadline, and no reply is read past a size
//! limit. Hosts are fixed in code by the callers, never taken from a request.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use url::Url;

use super::IdentityError;

/// Longest a call may take, connection to last byte.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest reply read. Apple's and Google's replies are a few kilobytes.
const MAX_REPLY: usize = 256 * 1024;

type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// What a server answered.
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

/// The client. Cloning shares the connection pool.
#[derive(Clone)]
pub(crate) struct Http {
    client: Client<Connector, Full<Bytes>>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Http")
    }
}

impl Http {
    /// A client that speaks https only.
    pub(crate) fn https() -> Result<Self, IdentityError> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| IdentityError::Unreachable)?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self::over(connector))
    }

    /// A client that also speaks plain http, for the fake servers on loopback in tests.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn loopback() -> Result<Self, IdentityError> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| IdentityError::Unreachable)?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self::over(connector))
    }

    fn over(connector: Connector) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }

    pub(crate) async fn get(&self, url: &Url) -> Result<Reply, IdentityError> {
        let request = Request::get(url.as_str())
            .header(header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .map_err(|_| IdentityError::Unreachable)?;
        self.send(request).await
    }

    pub(crate) async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
    ) -> Result<Reply, IdentityError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        self.post(url, "application/x-www-form-urlencoded", body)
            .await
    }

    pub(crate) async fn post_json(
        &self,
        url: &Url,
        json: &serde_json::Value,
    ) -> Result<Reply, IdentityError> {
        self.post(url, "application/json", json.to_string()).await
    }

    async fn post(
        &self,
        url: &Url,
        content_type: &str,
        body: String,
    ) -> Result<Reply, IdentityError> {
        let request = Request::post(url.as_str())
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| IdentityError::Unreachable)?;
        self.send(request).await
    }

    async fn send(&self, request: Request<Full<Bytes>>) -> Result<Reply, IdentityError> {
        tokio::time::timeout(CALL_TIMEOUT, async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| IdentityError::Unreachable)?;
            let (parts, mut body) = response.into_parts();
            let mut collected = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| IdentityError::Unreachable)?;
                if let Some(data) = frame.data_ref() {
                    if collected.len() + data.len() > MAX_REPLY {
                        return Err(IdentityError::Unreachable);
                    }
                    collected.extend_from_slice(data);
                }
            }
            Ok(Reply {
                status: parts.status,
                headers: parts.headers,
                body: Bytes::from(collected),
            })
        })
        .await
        .map_err(|_| IdentityError::Unreachable)?
    }
}
