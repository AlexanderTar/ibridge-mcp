// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the OAuth tests: fake clients, a scripted iCloud check and a request driver.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
use ibridge_core::AppleId;
use tower::ServiceExt;
use url::Url;

use super::check::{Combined, SignInCheck, validated_by};
use super::cimd::{BoxFuture, CimdError, ClientSource};
use super::client::ClientInfo;
use super::{Access, Evict, Features, OAuthConfig, Shared, router_with};
use crate::billing::Billing;
use crate::identity::Identity;
use crate::store::{Store, StoreError, ValidatedCredentials};

pub(crate) const PUBLIC: &str = "https://ibridge.example";
pub(crate) const CLIENT_ID: &str = "https://client.example/oauth/client.json";
pub(crate) const MARKUP_CLIENT_ID: &str = "https://markup.example/oauth/client.json";
pub(crate) const LOOPBACK_REDIRECT: &str = "http://127.0.0.1:53682/callback";
pub(crate) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub(crate) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub(crate) const ADA: &str = "ada@icloud.com";

/// Accepted by every service.
pub(crate) const ASP_ALL: &str = "aaaa-bbbb-cccc-dddd";
/// Accepted by IMAP only.
pub(crate) const ASP_MAIL_ONLY: &str = "mail-only-pass-word";
/// Accepted by `CalDAV` only: the account has no iCloud Mail.
pub(crate) const ASP_CALDAV_ONLY: &str = "caldav-only-pass-wd";

/// Two clients: a normal one and one whose name is markup.
#[derive(Debug)]
pub(crate) struct FakeClients;

impl ClientSource for FakeClients {
    fn resolve<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<ClientInfo, CimdError>> {
        let found = match client_id {
            CLIENT_ID => Some(("Claude Test", "https://client.example/cb")),
            MARKUP_CLIENT_ID => Some(("<script>alert(1)</script>", "https://markup.example/cb")),
            _ => None,
        };
        let result = found.map(|(name, https)| ClientInfo {
            id: client_id.to_owned(),
            name: name.to_owned(),
            redirect_uris: vec!["http://127.0.0.1/callback".to_owned(), https.to_owned()],
        });
        Box::pin(async move { result.ok_or(CimdError::Fetch) })
    }
}

/// Reports one service as accepted when the password is on its list.
struct Service {
    accepts: &'static [&'static str],
    password: String,
    mail: bool,
}

impl Validator for Service {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the scripted check answers at once"
    )]
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        let verdict = if self.accepts.contains(&self.password.as_str()) {
            ServiceCheck::Ok
        } else {
            ServiceCheck::Failed {
                reason: "rejected".to_owned(),
            }
        };
        let off = || ServiceCheck::Failed {
            reason: "not checked here".to_owned(),
        };
        Ok(if self.mail {
            ValidationReport {
                mail: verdict,
                calendar: off(),
                contacts: off(),
            }
        } else {
            ValidationReport {
                mail: off(),
                calendar: verdict,
                contacts: off(),
            }
        })
    }
}

/// The production shape: an IMAP validator and a DAV validator, combined.
struct CountingCheck {
    calls: Arc<AtomicUsize>,
    inner: Box<dyn SignInCheck>,
}

impl SignInCheck for CountingCheck {
    fn check(
        &self,
        credentials: Credentials,
    ) -> BoxFuture<'_, Result<ValidatedCredentials, StoreError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.check(credentials)
    }
}

pub(crate) struct Harness {
    pub(crate) app: Router,
    pub(crate) store: Store,
    /// How many times the iCloud check ran.
    pub(crate) checks: Arc<AtomicUsize>,
    /// The accounts whose pooled sessions the pages asked to close, in order.
    pub(crate) evicted: Arc<Mutex<Vec<AppleId>>>,
    /// When set, every request reaches the server through this proxy address: the
    /// socket peer is the proxy and the caller's address rides in `X-Forwarded-For`.
    pub(crate) proxy: Option<IpAddr>,
}

pub(crate) async fn harness(access: Access) -> Harness {
    harness_at(PUBLIC, access).await
}

/// A harness whose server believes it lives at `public_url`.
pub(crate) async fn harness_at(public_url: &str, access: Access) -> Harness {
    harness_over(public_url, access, Store::memory().await.expect("store")).await
}

/// A multi-tenant harness whose store takes at most `cap` accounts.
pub(crate) async fn harness_capped(cap: usize) -> Harness {
    let store = Store::memory().await.expect("store").with_signup_cap(cap);
    harness_over(PUBLIC, Access::MultiTenant, store).await
}

async fn harness_over(public_url: &str, access: Access, store: Store) -> Harness {
    let evicted = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&evicted);
    let evict: Evict = Arc::new(move |apple_id| {
        log.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(apple_id.clone());
    });
    let mcp = Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
    let mut harness = harness_with(public_url, access, store, evict, mcp).await;
    harness.evicted = evicted;
    harness
}

/// A harness over `store` whose pages evict through `evict` and whose `/mcp` is `mcp`.
pub(crate) async fn harness_with(
    public_url: &str,
    access: Access,
    store: Store,
    evict: Evict,
    mcp: Router,
) -> Harness {
    let config = OAuthConfig::new(public_url, access).expect("public url");
    harness_configured(config, store, evict, mcp).await
}

/// A harness over `store` that serves with `config`.
pub(crate) async fn harness_configured(
    config: OAuthConfig,
    store: Store,
    evict: Evict,
    mcp: Router,
) -> Harness {
    harness_built(config, store, evict, mcp, None, None).await.0
}

/// [`harness_configured`] with Sign in with Apple on, over `identity`.
///
/// Also returns the shared state, so a test can reach the stores the pages use.
pub(crate) async fn harness_identity(identity: Identity, store: Store) -> (Harness, Arc<Shared>) {
    let config = OAuthConfig::new(PUBLIC, Access::MultiTenant).expect("public url");
    let mcp = Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
    let evict: Evict = Arc::new(|_| {});
    harness_built(config, store, evict, mcp, Some(identity), None).await
}

/// [`harness_identity`] with Stripe on as well, over `billing`.
pub(crate) async fn harness_billing(
    identity: Identity,
    billing: Billing,
    store: Store,
) -> (Harness, Arc<Shared>) {
    let config = OAuthConfig::new(PUBLIC, Access::MultiTenant).expect("public url");
    let mcp = Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
    let evict: Evict = Arc::new(|_| {});
    harness_built(config, store, evict, mcp, Some(identity), Some(billing)).await
}

/// A harness with Sign in with Apple on, and Stripe when `billing` is given, for `access`.
pub(crate) async fn harness_featured(
    access: Access,
    store: Store,
    identity: Identity,
    billing: Option<Billing>,
) -> (Harness, Arc<Shared>) {
    let config = OAuthConfig::new(PUBLIC, access).expect("public url");
    let mcp = Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
    let evict: Evict = Arc::new(|_| {});
    harness_built(config, store, evict, mcp, Some(identity), billing).await
}

/// A plain harness (no Sign in with Apple) and the shared state its pages use.
pub(crate) async fn harness_with_shared() -> (Harness, Arc<Shared>) {
    let config = OAuthConfig::new(PUBLIC, Access::MultiTenant).expect("public url");
    let mcp = Router::new().route("/mcp", axum::routing::any(|| async { StatusCode::OK }));
    let store = Store::memory().await.expect("store");
    harness_built(config, store, Arc::new(|_| {}), mcp, None, None).await
}

async fn harness_built(
    config: OAuthConfig,
    store: Store,
    evict: Evict,
    mcp: Router,
    identity: Option<Identity>,
    billing: Option<Billing>,
) -> (Harness, Arc<Shared>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = validated_by(|credentials: &Credentials| {
        credentials.with_secret(|password| Combined {
            mail: Service {
                accepts: &[ASP_ALL, ASP_MAIL_ONLY],
                password: password.to_owned(),
                mail: true,
            },
            dav: Service {
                accepts: &[ASP_ALL, ASP_CALDAV_ONLY],
                password: password.to_owned(),
                mail: false,
            },
        })
    });
    let checker = CountingCheck {
        calls: Arc::clone(&calls),
        inner: Box::new(inner),
    };
    let (app, shared) = router_with(
        config,
        &store,
        Arc::new(FakeClients),
        Arc::new(checker),
        evict,
        mcp,
        Features { identity, billing },
    )
    .await
    .expect("router");
    let harness = Harness {
        app,
        store,
        checks: calls,
        evicted: Arc::new(Mutex::new(Vec::new())),
        proxy: None,
    };
    (harness, shared)
}

/// One response, read to the end.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) text: String,
}

impl Reply {
    /// `name=value` of the first `Set-Cookie`, for sending back.
    pub(crate) fn cookie_pair(&self) -> String {
        let set = self
            .headers
            .get(header::SET_COOKIE)
            .expect("a Set-Cookie header")
            .to_str()
            .expect("ascii");
        set.split(';').next().expect("a pair").to_owned()
    }

    /// The `value` of the form input called `name`.
    pub(crate) fn input(&self, name: &str) -> String {
        let marker = format!(r#"name="{name}" value=""#);
        let start = self.text.find(&marker).expect("the input is on the page") + marker.len();
        let end = self.text[start..].find('"').expect("a closing quote");
        self.text[start..start + end].to_owned()
    }

    /// The text of the page's error paragraph, if it has one.
    pub(crate) fn error_text(&self) -> Option<String> {
        let marker = r#"<p class="error" role="alert">"#;
        let start = self.text.find(marker)? + marker.len();
        let end = self.text[start..].find("</p>")?;
        Some(self.text[start..start + end].trim().to_owned())
    }

    /// The `Location` header as a URL.
    pub(crate) fn location(&self) -> Url {
        let value = self
            .headers
            .get(header::LOCATION)
            .expect("a Location header")
            .to_str()
            .expect("ascii");
        Url::parse(value).expect("a URL")
    }
}

impl Harness {
    pub(crate) async fn send(&self, mut request: Request<Body>, ip: &str) -> Reply {
        let client: IpAddr = ip.parse().expect("an ip");
        let socket_peer = match self.proxy {
            Some(proxy) => {
                request.headers_mut().insert(
                    "x-forwarded-for",
                    client.to_string().parse().expect("a header value"),
                );
                proxy
            }
            None => client,
        };
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(socket_peer, 40_000)));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("body");
        Reply {
            status,
            headers,
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    pub(crate) async fn get_path(&self, path: &str, ip: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::empty()).expect("request"), ip)
            .await
    }

    pub(crate) async fn post_path(
        &self,
        path: &str,
        ip: &str,
        cookie: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::from(body)).expect("request"), ip)
            .await
    }

    /// A GET `/authorize` URL with the usual parameters, minus `drop`, plus `extra`.
    pub(crate) fn authorize_path(drop: &[&str], extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", LOOPBACK_REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
            ("scope", "icloud.read icloud.write offline_access"),
            ("resource", "https://ibridge.example/mcp"),
        ];
        pairs.retain(|(name, _)| !drop.contains(name) && !extra.iter().any(|(n, _)| n == name));
        pairs.extend_from_slice(extra);
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        format!("/authorize?{query}")
    }

    pub(crate) async fn get_authorize(&self, path: &str, ip: &str) -> Reply {
        let request = Request::get(path).body(Body::empty()).expect("request");
        self.send(request, ip).await
    }

    /// Posts the form from a fetched page, with the cookie that page set.
    pub(crate) async fn post_form(
        &self,
        page: &Reply,
        ip: &str,
        apple_id: &str,
        password: &str,
        read_only: Option<&str>,
    ) -> Reply {
        let cookie = page.cookie_pair();
        let csrf = page.input("csrf");
        self.post_raw(
            ip,
            Some(&cookie),
            &page.form_fields(),
            &csrf,
            apple_id,
            password,
            read_only,
        )
        .await
    }

    /// Signs in as `ADA` with `ASP_ALL` and returns the authorization code.
    pub(crate) async fn sign_in_for_code(&self, ip: &str) -> String {
        let page = self
            .get_authorize(&Self::authorize_path(&[], &[]), ip)
            .await;
        let reply = self.post_form(&page, ip, ADA, ASP_ALL, None).await;
        reply
            .location()
            .query_pairs()
            .find(|(name, _)| name == "code")
            .map(|(_, value)| value.into_owned())
            .expect("a code")
    }

    /// POSTs `/token` with `pairs` as a form body.
    pub(crate) async fn post_token(&self, pairs: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("request");
        self.send(request, "203.0.113.50").await
    }

    /// The token request that redeems `code` with the usual client and redirect.
    pub(crate) fn exchange_pairs<'a>(code: &'a str, verifier: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", LOOPBACK_REDIRECT),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier),
        ]
    }

    #[expect(clippy::too_many_arguments, reason = "a test driver mirrors the form")]
    pub(crate) async fn post_raw(
        &self,
        ip: &str,
        cookie: Option<&str>,
        fields: &[(String, String)],
        csrf: &str,
        apple_id: &str,
        password: &str,
        read_only: Option<&str>,
    ) -> Reply {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.extend_pairs(
            fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        form.append_pair("csrf", csrf);
        form.append_pair("apple_id", apple_id);
        form.append_pair("password", password);
        if let Some(value) = read_only {
            form.append_pair("read_only", value);
        }
        let mut request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let request = request.body(Body::from(form.finish())).expect("request");
        self.send(request, ip).await
    }
}

impl Reply {
    /// The body as JSON.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.text).expect("a JSON body")
    }

    /// The hidden OAuth fields on the page, for posting back.
    pub(crate) fn form_fields(&self) -> Vec<(String, String)> {
        [
            "client_id",
            "redirect_uri",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
            "resource",
            "response_type",
        ]
        .iter()
        .filter(|name| self.text.contains(&format!(r#"name="{name}" value=""#)))
        .map(|name| ((*name).to_owned(), self.input(name)))
        .collect()
    }
}
