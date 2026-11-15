// SPDX-License-Identifier: Apache-2.0

//! A bare HTTP client for tests that talk to a server bound on loopback.

use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use http_body_util::{BodyExt as _, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// What a server answered.
#[derive(Debug)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body, read to the end as text.
    pub body: String,
}

impl Reply {
    /// The value of a response header, when it is present and text.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// Sends one request and reads the whole answer.
///
/// # Panics
///
/// Panics when the request cannot be built or sent. Tests want that to be loud.
pub async fn send(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut request = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("a valid method"))
        .uri(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("a valid request");
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let response = client.request(request).await.expect("the server answers");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("the body reads").to_bytes();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}
