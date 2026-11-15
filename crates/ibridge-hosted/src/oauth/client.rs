// SPDX-License-Identifier: Apache-2.0

//! What the server knows about an OAuth client, and which redirects it may use.

use url::{Host, Url};

/// A client that CIMD or DCR identified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    /// A metadata document URL (CIMD) or an id this server issued (DCR).
    pub(crate) id: String,
    /// Name the sign-in page shows. Never trusted as markup.
    pub(crate) name: String,
    /// Redirect URIs the client registered.
    pub(crate) redirect_uris: Vec<String>,
}

impl ClientInfo {
    /// True when `requested` is one of the registered redirects.
    #[expect(
        dead_code,
        reason = "the authorize page checks redirects in the next unit"
    )]
    pub(crate) fn allows_redirect(&self, requested: &str) -> bool {
        redirect_allowed(&self.redirect_uris, requested)
    }
}

/// Exact string match, except that a loopback redirect may use any port.
pub(crate) fn redirect_allowed(registered: &[String], requested: &str) -> bool {
    registered
        .iter()
        .any(|entry| entry == requested || same_loopback_redirect(entry, requested))
}

/// RFC 8252 section 7.3: an http loopback IP redirect matches on everything but the port.
fn same_loopback_redirect(registered: &str, requested: &str) -> bool {
    let (Ok(registered), Ok(requested)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    is_loopback_http(&registered)
        && is_loopback_http(&requested)
        && registered.host() == requested.host()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
        && requested.fragment().is_none()
}

fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        }
}

/// Schemes that run code or read files when opened, so no client may register them.
const REFUSED_SCHEMES: [&str; 9] = [
    "javascript",
    "data",
    "file",
    "vbscript",
    "blob",
    "about",
    "ftp",
    "ws",
    "wss",
];

/// True when `uri` may be registered as a redirect: https, http on a loopback IP,
/// or a private-use app scheme such as `vscode://`.
pub(crate) fn valid_redirect_uri(uri: &str) -> bool {
    // The URL parser repairs `https:///host` and `https:\\host` into a different
    // host than the text says, so only plain, unambiguous text is accepted.
    if !uri
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return false;
    }
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let authority_follows = uri
        .split_once("://")
        .is_some_and(|(_, rest)| !rest.starts_with('/'));
    if url.has_authority() && !authority_follows {
        return false;
    }
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some_and(|host| !host.is_empty()),
        "http" => is_loopback_http(&url),
        // ponytail: any other scheme is allowed unless listed above. The ceiling
        // is that an app scheme can be claimed by a second app on the device;
        // PKCE still stops that app from using a stolen code.
        scheme => !REFUSED_SCHEMES.contains(&scheme) && !scheme.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::{redirect_allowed, valid_redirect_uri};

    fn registered() -> Vec<String> {
        [
            "https://app.example/cb",
            "http://127.0.0.1/callback",
            "http://[::1]/callback",
            "http://localhost:3000/cb",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[test]
    fn redirect_exact_match_and_loopback_any_port() {
        let list = registered();
        for ok in [
            "https://app.example/cb",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:54321/callback",
            "http://127.0.0.1:1/callback",
            "http://[::1]:8080/callback",
            "http://localhost:3000/cb",
        ] {
            assert!(redirect_allowed(&list, ok), "{ok} is allowed");
        }
        for bad in [
            "https://app.example/cb/",
            "https://app.example/cb?x=1",
            "https://app.example:8443/cb",
            "https://APP.example/cb",
            "https://app.example.evil.test/cb",
            "http://app.example/cb",
            "http://127.0.0.1:54321/other",
            "http://127.0.0.1:54321/callback?x=1",
            "http://127.0.0.1:54321/callback#frag",
            "https://127.0.0.1:54321/callback",
            "http://127.0.0.2:54321/callback",
            "http://127.0.0.1:54321@evil.example/callback",
            "http://localhost:3001/cb",
            "http://localhost/cb",
            "",
        ] {
            assert!(!redirect_allowed(&list, bad), "{bad:?} is refused");
        }
    }

    #[test]
    fn registrable_redirects_are_https_loopback_or_app_schemes() {
        for ok in [
            "https://app.example/cb",
            "http://127.0.0.1:1234/cb",
            "http://[::1]/cb",
            "vscode://anthropic.claude/cb",
            "claude://callback",
        ] {
            assert!(valid_redirect_uri(ok), "{ok} may be registered");
        }
        for bad in [
            "http://app.example/cb",
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "https://app.example/cb#frag",
            "https://user@app.example/cb",
            "not a url",
            "/relative",
            "https:///cb",
            "",
        ] {
            assert!(!valid_redirect_uri(bad), "{bad:?} may not be registered");
        }
    }
}
