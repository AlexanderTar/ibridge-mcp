// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask live-hosted-check`: signs in to a hosted server the way a client does,
//! then asks it for `account_status`.
//!
//! The launch runs this from the public instance's datacenter with the real test
//! account, to see whether Apple accepts the sign-in from there. Nothing here prints the
//! password, a token or a code; reports and errors name the step and the HTTP status only.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, header};
use http_body_util::{BodyExt as _, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ibridge_auth::{CredentialSource as _, FileSource};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Why the check failed. Text carries a step name and a status, never a secret or a server reply.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LiveError {
    /// The account file is missing, not mode `0600`, or incomplete.
    #[error("the test account file is missing, not mode 0600, or incomplete")]
    Account,
    /// A step failed.
    #[error("{step} failed: {detail}")]
    Step { step: &'static str, detail: String },
    /// The report could not be written.
    #[error("could not write the report: {0}")]
    Report(#[from] std::io::Error),
}

fn fail(step: &'static str, detail: impl Into<String>) -> LiveError {
    LiveError::Step {
        step,
        detail: detail.into(),
    }
}

const REDIRECT: &str = "http://127.0.0.1:53682/callback";
const TIMEOUT: Duration = Duration::from_secs(30);

type Http = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self, step: &'static str) -> Result<Value, LiveError> {
        serde_json::from_str(&self.body).map_err(|_| fail(step, "the reply was not JSON"))
    }

    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }
}

fn http() -> Result<Http, LiveError> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|_| fail("tls", "the system has no root certificates"))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// Sends one request. Redirects are not followed: the sign-in step needs to read one.
async fn send(
    client: &Http,
    step: &'static str,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: String,
) -> Result<Reply, LiveError> {
    let mut request = Request::builder().method(method).uri(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| fail(step, "the request could not be built"))?;
    let exchange = async {
        let response = client.request(request).await.ok()?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.ok()?.to_bytes();
        Some(Reply {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    };
    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| fail(step, "the server could not be reached"))
}

fn expect_status(step: &'static str, reply: &Reply, wanted: u16) -> Result<(), LiveError> {
    if reply.status == wanted {
        Ok(())
    } else {
        Err(fail(
            step,
            format!("HTTP {}, expected {wanted}", reply.status),
        ))
    }
}

fn random_text(bytes: usize, step: &'static str) -> Result<String, LiveError> {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).map_err(|_| fail(step, "no random bytes"))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn text_field<'a>(value: &'a Value, name: &str, step: &'static str) -> Result<&'a str, LiveError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| fail(step, format!("the reply has no {name}")))
}

/// The `value` of the form input `name` on `page`.
fn input_value(page: &str, name: &str) -> Option<String> {
    let marker = format!(r#"name="{name}" value=""#);
    let start = page.find(&marker)? + marker.len();
    let end = page[start..].find('"')?;
    Some(page[start..start + end].to_owned())
}

/// Where the server's OAuth endpoints are.
struct Endpoints {
    issuer: String,
    authorize: String,
    token: String,
    register: String,
}

/// Runs the check against `url` with the account in `account`, writing the report to `out`.
///
/// Walks the discovery, registration, sign-in and token steps a client does, then calls
/// `account_status` with the access token.
pub(crate) async fn run(url: &str, account: &Path, out: &mut impl Write) -> Result<(), LiveError> {
    let credentials = FileSource::new(account)
        .credentials()
        .await
        .map_err(|_| LiveError::Account)?;
    let base = url.trim_end_matches('/');
    let client = http()?;
    let endpoints = discover(&client, base).await?;
    writeln!(out, "discovery: ok ({})", endpoints.issuer)?;
    let client_id = register(&client, &endpoints).await?;
    writeln!(out, "registration: ok")?;
    let (code, verifier) = sign_in(&client, &endpoints, &client_id, &credentials).await?;
    writeln!(out, "sign-in: ok as {}", credentials.apple_id.as_str())?;
    let access = exchange(&client, &endpoints, &client_id, &code, &verifier).await?;
    writeln!(out, "token: ok")?;
    let status = account_status(&client, base, &access).await?;
    writeln!(out, "account_status: ok")?;
    for service in status
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = service.get("name").and_then(Value::as_str).unwrap_or("?");
        let state = service.get("status").and_then(Value::as_str).unwrap_or("?");
        match service.get("reason").and_then(Value::as_str) {
            Some(reason) => writeln!(out, "  {name}: {state} ({reason})")?,
            None => writeln!(out, "  {name}: {state}")?,
        }
    }
    Ok(())
}

/// A client with no token is pointed at the authorization server, which names its endpoints.
async fn discover(client: &Http, base: &str) -> Result<Endpoints, LiveError> {
    let challenge = send(
        client,
        "discovery",
        Method::POST,
        &format!("{base}/mcp"),
        &[
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        "{}".to_owned(),
    )
    .await?;
    expect_status("discovery", &challenge, 401)?;
    if !challenge
        .header(header::WWW_AUTHENTICATE)
        .is_some_and(|value| value.contains("resource_metadata"))
    {
        return Err(fail(
            "discovery",
            "the 401 does not point at resource metadata",
        ));
    }
    let metadata = send(
        client,
        "discovery",
        Method::GET,
        &format!("{base}/.well-known/oauth-authorization-server"),
        &[],
        String::new(),
    )
    .await?;
    expect_status("discovery", &metadata, 200)?;
    let metadata = metadata.json("discovery")?;
    let issuer = text_field(&metadata, "issuer", "discovery")?.trim_end_matches('/');
    if issuer != base {
        return Err(fail(
            "discovery",
            "the issuer is not the URL that was checked",
        ));
    }
    Ok(Endpoints {
        issuer: issuer.to_owned(),
        authorize: text_field(&metadata, "authorization_endpoint", "discovery")?.to_owned(),
        token: text_field(&metadata, "token_endpoint", "discovery")?.to_owned(),
        register: text_field(&metadata, "registration_endpoint", "discovery")?.to_owned(),
    })
}

/// The way a client with no metadata document introduces itself.
async fn register(client: &Http, endpoints: &Endpoints) -> Result<String, LiveError> {
    let registration = send(
        client,
        "registration",
        Method::POST,
        &endpoints.register,
        &[("content-type", "application/json")],
        json!({
            "client_name": "ibridge live-hosted-check",
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })
        .to_string(),
    )
    .await?;
    expect_status("registration", &registration, 201)?;
    let registered = registration.json("registration")?;
    Ok(text_field(&registered, "client_id", "registration")?.to_owned())
}

/// The page a person would see, filled in by the program. Returns the code and the PKCE verifier.
async fn sign_in(
    client: &Http,
    endpoints: &Endpoints,
    client_id: &str,
    credentials: &ibridge_auth::Credentials,
) -> Result<(String, String), LiveError> {
    let verifier = random_text(32, "sign-in")?;
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_text(16, "sign-in")?;
    let resource = format!("{}/mcp", endpoints.issuer);
    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state.as_str()),
        ("scope", "icloud.read icloud.write"),
        ("resource", resource.as_str()),
    ];
    let page = send(
        client,
        "sign-in",
        Method::GET,
        &format!("{}?{}", endpoints.authorize, form(&params)),
        &[],
        String::new(),
    )
    .await?;
    expect_status("sign-in", &page, 200)?;
    let cookie = page
        .header(header::SET_COOKIE)
        .and_then(|value| value.split(';').next())
        .ok_or_else(|| fail("sign-in", "the sign-in page set no cookie"))?
        .to_owned();
    let csrf = input_value(&page.body, "csrf")
        .ok_or_else(|| fail("sign-in", "the sign-in page has no form token"))?;
    let submitted = credentials.with_secret(|password| {
        let mut pairs = params.to_vec();
        pairs.push(("csrf", csrf.as_str()));
        pairs.push(("apple_id", credentials.apple_id.as_str()));
        pairs.push(("password", password));
        form(&pairs)
    });
    let signed_in = send(
        client,
        "sign-in",
        Method::POST,
        &endpoints.authorize,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", cookie.as_str()),
        ],
        submitted,
    )
    .await?;
    if !(300..400).contains(&signed_in.status) {
        return Err(fail(
            "sign-in",
            format!(
                "HTTP {}; the sign-in page did not redirect",
                signed_in.status
            ),
        ));
    }
    let location = signed_in
        .header(header::LOCATION)
        .and_then(|value| url::Url::parse(value).ok())
        .ok_or_else(|| fail("sign-in", "the redirect has no usable Location"))?;
    let query = |name: &str| {
        location
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if query("state").as_deref() != Some(state.as_str()) {
        return Err(fail("sign-in", "the redirect does not carry our state"));
    }
    if query("iss").as_deref().map(|iss| iss.trim_end_matches('/')) != Some(&endpoints.issuer) {
        return Err(fail("sign-in", "the redirect does not carry the issuer"));
    }
    let code = query("code").ok_or_else(|| fail("sign-in", "the redirect has no code"))?;
    Ok((code, verifier))
}

/// The code for an access token, proving the PKCE verifier.
async fn exchange(
    client: &Http,
    endpoints: &Endpoints,
    client_id: &str,
    code: &str,
    verifier: &str,
) -> Result<String, LiveError> {
    let tokens = send(
        client,
        "token",
        Method::POST,
        &endpoints.token,
        &[("content-type", "application/x-www-form-urlencoded")],
        form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ]),
    )
    .await?;
    expect_status("token", &tokens, 200)?;
    let tokens = tokens.json("token")?;
    Ok(text_field(&tokens, "access_token", "token")?.to_owned())
}

/// Calls the tool and returns its structured result: what the account looks like to a client.
async fn account_status(client: &Http, base: &str, access: &str) -> Result<Value, LiveError> {
    let call = send(
        client,
        "account_status",
        Method::POST,
        &format!("{base}/mcp"),
        &[
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("authorization", &format!("Bearer {access}")),
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "account_status"),
        ],
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "account_status",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "ibridge-live-hosted-check", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string(),
    )
    .await?;
    expect_status("account_status", &call, 200)?;
    let message = call.json("account_status")?;
    message
        .pointer("/result/structuredContent")
        .filter(|_| message.pointer("/result/isError") != Some(&json!(true)))
        .cloned()
        .ok_or_else(|| fail("account_status", "the tool call returned an error"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use crate::fakes::{FakeImapBackend, accept_all, info};
    use ibridge_hosted::{HostedConfig, HostedOptions, serve};
    use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::{LiveError, run};

    const PASSWORD: &str = "live-check-never-print-1";

    /// A running hosted server on loopback, and the way to stop it.
    struct Instance {
        url: String,
        imap: FakeImap,
        stop: Option<oneshot::Sender<()>>,
        data: tempfile::TempDir,
    }

    impl Drop for Instance {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    /// Starts a hosted server whose IMAP is a fake. `allowed` limits who may sign in.
    async fn instance(allowed: Option<&str>) -> Instance {
        let data = tempfile::tempdir().expect("temp dir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let url = format!("http://{addr}");
        let config = HostedConfig::resolve(
            HostedOptions {
                addr,
                public_url: url.clone(),
                data_dir: data.path().join("data"),
                multi_tenant: allowed.is_none(),
                behind_proxy: false,
            },
            |name| {
                (name == ibridge_hosted::ALLOWED_APPLE_IDS)
                    .then(|| allowed.map(str::to_owned))
                    .flatten()
            },
        )
        .expect("config");
        let imap = FakeImap::spawn(FakeScript {
            accepts_password: Some(PASSWORD.to_owned()),
            ..FakeScript::default()
        });
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(serve(
            config,
            listener,
            FakeImapBackend(imap.clone()),
            accept_all(),
            info(),
            async move {
                let _ = stopped.await;
            },
        ));
        Instance {
            url,
            imap,
            stop: Some(stop),
            data,
        }
    }

    fn account_file(dir: &tempfile::TempDir, mode: u32, apple_id: &str) -> PathBuf {
        let path = dir.path().join("test-account.env");
        fs::write(
            &path,
            format!("IBRIDGE_TEST_APPLE_ID={apple_id}\nIBRIDGE_TEST_APP_PASSWORD={PASSWORD}\n"),
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mode");
        path
    }

    #[tokio::test]
    async fn live_hosted_check_reports_services() {
        let server = instance(None).await;
        let account = account_file(&server.data, 0o600, "ada@icloud.com");
        let mut report = Vec::new();

        run(&server.url, &account, &mut report)
            .await
            .expect("the check passes against a working server");

        let text = String::from_utf8(report).expect("text");
        for line in ["sign-in: ok", "mail: on", "calendar: on", "contacts: on"] {
            assert!(text.contains(line), "the report has {line:?}:\n{text}");
        }
        assert!(text.contains("ada@icloud.com"), "{text}");
        assert!(
            !text.contains(PASSWORD),
            "the password is never printed:\n{text}"
        );
        let _ = &server.imap;
    }

    #[tokio::test]
    async fn live_hosted_check_names_the_step_that_failed_without_the_password() {
        // Only someone else may sign in, so the account's sign-in is refused.
        let server = instance(Some("bob@icloud.com")).await;
        let account = account_file(&server.data, 0o600, "ada@icloud.com");
        let mut report = Vec::new();

        let error = run(&server.url, &account, &mut report)
            .await
            .expect_err("a refused sign-in fails the check");

        let shown = format!("{error} {error:?} {}", String::from_utf8_lossy(&report));
        assert!(
            matches!(&error, LiveError::Step { step, .. } if *step == "sign-in"),
            "{shown}"
        );
        assert!(
            !shown.contains(PASSWORD),
            "the password is never printed: {shown}"
        );

        let loose = account_file(&server.data, 0o644, "ada@icloud.com");
        let error = run(&server.url, &loose, &mut Vec::new())
            .await
            .expect_err("a group-readable account file is refused");
        assert!(matches!(error, LiveError::Account), "{error}");
    }
}
