// SPDX-License-Identifier: Apache-2.0

//! Principal and home-set discovery, plus a `CalDAV`/`CardDAV` sign-in check.

use std::sync::{Arc, Mutex};

use http::{StatusCode, Uri};
use ibridge_auth::{AuthError, Credentials, ServiceCheck, ValidationReport, Validator};
use libdav::dav::FindPropertyHrefs;
use libdav::names::{ADDRESSBOOK_HOME_SET, CALENDAR_HOME_SET, CURRENT_USER_PRINCIPAL};
use libdav::requests::DavRequest;

use crate::client::{Transport, execute};
use crate::error::DavError;

/// Absolute URL of a calendar home or an address-book home.
///
/// The host is the account's shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionHome {
    /// Absolute `https` URL, including the shard host.
    pub url: String,
}

/// Homes already discovered for one account.
///
/// A second lookup for the same account reuses the stored URL and does not
/// ask the bootstrap host again.
#[derive(Debug, Default)]
pub(crate) struct ShardCache {
    caldav: Mutex<Option<CollectionHome>>,
    carddav: Mutex<Option<CollectionHome>>,
}

impl ShardCache {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

const CALDAV_BOOTSTRAP: &str = "https://caldav.icloud.com/";
const CARDDAV_BOOTSTRAP: &str = "https://contacts.icloud.com/";
const CARDDAV_WELL_KNOWN: &str = "/.well-known/carddav";

pub(crate) fn caldav_root() -> (Uri, &'static str) {
    (Uri::from_static(CALDAV_BOOTSTRAP), "/")
}

pub(crate) fn carddav_root() -> (Uri, &'static str) {
    (Uri::from_static(CARDDAV_BOOTSTRAP), CARDDAV_WELL_KNOWN)
}

/// Finds the calendar home, starting at `caldav.icloud.com`.
///
/// # Errors
///
/// Returns [`DavError`] when the principal or the calendar home cannot be read.
pub(crate) async fn discover_caldav(
    transport: &impl Transport,
    credentials: &Credentials,
    cache: &ShardCache,
) -> Result<CollectionHome, DavError> {
    let (base, path) = caldav_root();
    discover_caldav_from(transport, credentials, cache, &base, path).await
}

/// Finds the calendar home starting at `path` on `base`.
///
/// # Errors
///
/// Returns [`DavError`] when the principal or the calendar home cannot be read.
pub(crate) async fn discover_caldav_from(
    transport: &impl Transport,
    credentials: &Credentials,
    cache: &ShardCache,
    base: &Uri,
    path: &str,
) -> Result<CollectionHome, DavError> {
    if let Some(home) = load(&cache.caldav) {
        return Ok(home);
    }
    let (principal, landed) =
        propfind_href(transport, credentials, base, path, &CURRENT_USER_PRINCIPAL).await?;
    let principal_path = href_path(&principal)?;
    let home_base = if principal.host().is_some() {
        origin_of(&principal)?
    } else {
        origin_of(&landed)?
    };
    let (home_href, home_landed) = propfind_href(
        transport,
        credentials,
        &home_base,
        &principal_path,
        &CALENDAR_HOME_SET,
    )
    .await?;
    let home = CollectionHome {
        url: absolute_url(&home_href, &home_landed)?,
    };
    store(&cache.caldav, &home);
    Ok(home)
}

/// Finds the address-book home, starting at `/.well-known/carddav`.
///
/// # Errors
///
/// Returns [`DavError`] when the principal or the address-book home cannot be read.
pub(crate) async fn discover_carddav(
    transport: &impl Transport,
    credentials: &Credentials,
    cache: &ShardCache,
) -> Result<CollectionHome, DavError> {
    let (base, path) = carddav_root();
    discover_carddav_from(transport, credentials, cache, &base, path).await
}

/// Finds the address-book home starting at `path` on `base`.
///
/// # Errors
///
/// Returns [`DavError`] when the principal or the address-book home cannot be read.
pub(crate) async fn discover_carddav_from(
    transport: &impl Transport,
    credentials: &Credentials,
    cache: &ShardCache,
    base: &Uri,
    path: &str,
) -> Result<CollectionHome, DavError> {
    if let Some(home) = load(&cache.carddav) {
        return Ok(home);
    }
    let (principal, landed) =
        propfind_href(transport, credentials, base, path, &CURRENT_USER_PRINCIPAL).await?;
    let principal_path = href_path(&principal)?;
    let home_base = if principal.host().is_some() {
        origin_of(&principal)?
    } else {
        origin_of(&landed)?
    };
    let (home_href, home_landed) = propfind_href(
        transport,
        credentials,
        &home_base,
        &principal_path,
        &ADDRESSBOOK_HOME_SET,
    )
    .await?;
    let home = CollectionHome {
        url: absolute_url(&home_href, &home_landed)?,
    };
    store(&cache.carddav, &home);
    Ok(home)
}

async fn propfind_href(
    transport: &impl Transport,
    credentials: &Credentials,
    base: &Uri,
    path: &str,
    property: &libdav::PropertyName<'_, '_>,
) -> Result<(Uri, Uri), DavError> {
    let request = FindPropertyHrefs::new(path, property);
    let http_request = request
        .prepare_request(base.clone())
        .map_err(|_| DavError::Protocol)?;
    let exchange = execute(transport, credentials, http_request).await?;
    if !exchange.status.is_success() {
        return Err(status_error(exchange.status));
    }
    let parts = http::Response::builder()
        .status(exchange.status)
        .body(())
        .map_err(|_| DavError::Protocol)?
        .into_parts()
        .0;
    let parsed = request
        .parse_response(&parts, &exchange.body)
        .map_err(|_| DavError::Protocol)?;
    let href = parsed.hrefs.into_iter().next().ok_or(DavError::Protocol)?;
    Ok((href, exchange.url))
}

fn status_error(status: StatusCode) -> DavError {
    match status {
        StatusCode::UNAUTHORIZED => DavError::Auth,
        StatusCode::NOT_FOUND => DavError::NotFound,
        _ => DavError::Protocol,
    }
}

fn href_path(href: &Uri) -> Result<String, DavError> {
    let path = href.path();
    if path.is_empty() {
        return Err(DavError::Protocol);
    }
    Ok(path.to_owned())
}

fn origin_of(uri: &Uri) -> Result<Uri, DavError> {
    let scheme = uri.scheme_str().ok_or(DavError::Protocol)?;
    let authority = uri.authority().ok_or(DavError::Protocol)?;
    format!("{scheme}://{authority}/")
        .parse()
        .map_err(|_| DavError::Protocol)
}

fn absolute_url(href: &Uri, base: &Uri) -> Result<String, DavError> {
    if href.host().is_some() {
        return Ok(href.to_string());
    }
    let origin = origin_of(base)?;
    let path = href_path(href)?;
    let joined = format!("{}{path}", origin.to_string().trim_end_matches('/'));
    let parsed: Uri = joined.parse().map_err(|_| DavError::Protocol)?;
    Ok(parsed.to_string())
}

fn load(slot: &Mutex<Option<CollectionHome>>) -> Option<CollectionHome> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn store(slot: &Mutex<Option<CollectionHome>>, home: &CollectionHome) {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(home.clone());
}

/// Sign-in check that speaks `CalDAV` and `CardDAV` only.
///
/// Mail is reported as failed: this validator does not open an IMAP session.
/// A failed service does not fail the whole check. [`AuthError`] is reserved
/// for the case where the check cannot be run at all.
#[derive(Debug)]
pub struct DavValidator<T> {
    transport: T,
    credentials: Arc<Credentials>,
    cache: ShardCache,
}

impl<T> DavValidator<T> {
    pub(crate) fn from_transport(transport: T, credentials: Arc<Credentials>) -> Self {
        Self {
            transport,
            credentials,
            cache: ShardCache::new(),
        }
    }
}

impl DavValidator<crate::DavClient> {
    /// Builds a validator that discovers calendar and contacts for `credentials`.
    ///
    /// # Errors
    ///
    /// Returns [`DavError::Network`] when the TLS roots cannot be loaded.
    pub fn new(credentials: Credentials) -> Result<Self, DavError> {
        let credentials = Arc::new(credentials);
        Ok(Self::from_transport(
            crate::DavClient::from_shared(Arc::clone(&credentials))?,
            credentials,
        ))
    }
}

impl<T: Transport + Sync> Validator for DavValidator<T> {
    async fn validate(&self) -> Result<ValidationReport, AuthError> {
        let calendar =
            service_check(discover_caldav(&self.transport, &self.credentials, &self.cache).await);
        let contacts =
            service_check(discover_carddav(&self.transport, &self.credentials, &self.cache).await);
        Ok(ValidationReport {
            mail: ServiceCheck::Failed {
                reason: "mail is not checked by the DAV validator".to_owned(),
            },
            calendar,
            contacts,
        })
    }
}

fn service_check(result: Result<CollectionHome, DavError>) -> ServiceCheck {
    match result {
        Ok(_) => ServiceCheck::Ok,
        Err(error) => ServiceCheck::Failed {
            reason: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use ibridge_auth::{Credentials, ServiceCheck, Validator};
    use ibridge_core::AppleId;

    use super::{ShardCache, discover_caldav, discover_carddav};
    use crate::test_support::{Script, credentials, expected_basic};

    const ADA_PRINCIPAL: &str = "/184573921/principal/";
    const ADA_CALENDAR_HOME: &str = "https://p15-caldav.icloud.com/184573921/calendars/";
    const ADA_CONTACTS_HOME: &str = "https://p15-contacts.icloud.com/184573921/carddavhome/";
    const BOB_PRINCIPAL: &str = "/999/principal/";
    const BOB_CALENDAR_HOME: &str = "https://p22-caldav.icloud.com/999/calendars/";

    fn basic_for(apple_id: &str) -> String {
        let token = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{apple_id}:test-secret"),
        );
        format!("Basic {token}")
    }

    fn bob() -> Credentials {
        Credentials::new(
            AppleId::try_from("bob@icloud.com").expect("primary address"),
            "test-secret",
        )
    }

    fn multistatus(property_xml: &str) -> Response<Full<Bytes>> {
        let body = format!(
            r#"<?xml version="1.0"?>
            <multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
                <response>
                    <href>/</href>
                    <propstat>
                        <prop>{property_xml}</prop>
                        <status>HTTP/1.1 200 OK</status>
                    </propstat>
                </response>
            </multistatus>"#
        );
        Response::builder()
            .status(207)
            .body(Full::new(Bytes::from(body)))
            .expect("response")
    }

    fn redirect(location: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(302)
            .header("location", location)
            .body(Full::new(Bytes::new()))
            .expect("response")
    }

    fn empty(status: u16) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .body(Full::new(Bytes::new()))
            .expect("response")
    }

    fn caldav_server() -> Script {
        let ada = expected_basic();
        let bob_basic = basic_for("bob@icloud.com");
        Script::new(move |request| {
            let auth = request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let (principal, home) = if auth == bob_basic {
                (BOB_PRINCIPAL, BOB_CALENDAR_HOME)
            } else if auth == ada {
                (ADA_PRINCIPAL, ADA_CALENDAR_HOME)
            } else {
                return empty(401);
            };
            let body = request.body();
            if body.contains("current-user-principal") {
                return multistatus(&format!(
                    "<current-user-principal><href>{principal}</href></current-user-principal>"
                ));
            }
            if body.contains("calendar-home-set") {
                return multistatus(&format!(
                    "<C:calendar-home-set><href>{home}</href></C:calendar-home-set>"
                ));
            }
            empty(404)
        })
    }

    fn carddav_server() -> Script {
        Script::new(|request| {
            if request.uri().path() == "/.well-known/carddav" {
                return redirect("https://contacts.icloud.com/184573921/principal/");
            }
            let body = request.body();
            if body.contains("current-user-principal") {
                return multistatus(&format!(
                    "<current-user-principal><href>{ADA_PRINCIPAL}</href></current-user-principal>"
                ));
            }
            if body.contains("addressbook-home-set") {
                return multistatus(&format!(
                    "<CARD:addressbook-home-set><href>{ADA_CONTACTS_HOME}</href></CARD:addressbook-home-set>"
                ));
            }
            empty(204)
        })
    }

    #[tokio::test]
    async fn discover_caldav_principal_then_home_on_shard() {
        let script = caldav_server();
        let home = discover_caldav(&script, &credentials(), &ShardCache::new())
            .await
            .expect("principal lookup then calendar-home-set on the shard");
        assert_eq!(home.url, ADA_CALENDAR_HOME);
        let seen = script.requests();
        assert!(
            seen.len() >= 2,
            "principal and home-set are separate requests, saw {seen:?}"
        );
        assert!(
            seen[0].body.contains("current-user-principal"),
            "first request must ask for the principal, saw {seen:?}"
        );
        assert_eq!(seen[0].uri.host(), Some("caldav.icloud.com"));
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some(expected_basic().as_str())
        );
        let home_at = seen
            .iter()
            .position(|logged| logged.body.contains("calendar-home-set"))
            .expect("a calendar-home-set request");
        assert!(home_at > 0, "home-set comes after the principal");
        assert_eq!(
            seen[home_at].uri.path(),
            ADA_PRINCIPAL,
            "home-set is read from the principal URL"
        );
        assert!(
            seen.iter().all(|logged| logged.authorization.is_some()),
            "every discovery request carries Basic auth, saw {seen:?}"
        );
    }

    #[tokio::test]
    async fn discover_carddav_well_known() {
        let script = carddav_server();
        let home = discover_carddav(&script, &credentials(), &ShardCache::new())
            .await
            .expect("CardDAV discovery starts at the well-known path");
        assert_eq!(home.url, ADA_CONTACTS_HOME);
        let seen = script.requests();
        assert_eq!(seen[0].uri.host(), Some("contacts.icloud.com"));
        assert_eq!(
            seen[0].uri.path(),
            "/.well-known/carddav",
            "CardDAV starts at well-known, saw {seen:?}"
        );
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some(expected_basic().as_str())
        );
        let principal_at = seen
            .iter()
            .position(|logged| logged.body.contains("current-user-principal"))
            .expect("a principal request");
        let home_at = seen
            .iter()
            .position(|logged| logged.body.contains("addressbook-home-set"))
            .expect("an addressbook-home-set request");
        assert!(principal_at < home_at, "principal before the home set");
    }

    #[tokio::test]
    async fn shard_cached_per_account() {
        let script = caldav_server();
        let ada_cache = ShardCache::new();
        let first = discover_caldav(&script, &credentials(), &ada_cache)
            .await
            .expect("first discovery");
        assert_eq!(first.url, ADA_CALENDAR_HOME);
        let after_first = script.requests().len();
        let again = discover_caldav(&script, &credentials(), &ada_cache)
            .await
            .expect("cached discovery");
        assert_eq!(again.url, first.url);
        assert_eq!(
            script.requests().len(),
            after_first,
            "the same account must not ask the bootstrap host again"
        );

        let bob_script = caldav_server();
        let bob_home = discover_caldav(&bob_script, &bob(), &ShardCache::new())
            .await
            .expect("bob has his own shard");
        assert_eq!(bob_home.url, BOB_CALENDAR_HOME);
        assert!(
            bob_script
                .requests()
                .iter()
                .any(|logged| logged.uri.host() == Some("caldav.icloud.com")),
            "another account must discover its own shard, not reuse ada's"
        );
    }

    #[tokio::test]
    async fn dav_validator_ok_for_caldav_only_account() {
        let script = Script::new(|request| {
            let host = request.uri().host().unwrap_or("");
            if host.contains("contacts") {
                return empty(404);
            }
            let body = request.body();
            if body.contains("current-user-principal") {
                return multistatus(&format!(
                    "<current-user-principal><href>{ADA_PRINCIPAL}</href></current-user-principal>"
                ));
            }
            if body.contains("calendar-home-set") {
                return multistatus(&format!(
                    "<C:calendar-home-set><href>{ADA_CALENDAR_HOME}</href></C:calendar-home-set>"
                ));
            }
            empty(404)
        });
        let validator =
            super::DavValidator::from_transport(script.clone(), std::sync::Arc::new(credentials()));
        let report = validator
            .validate()
            .await
            .expect("a CalDAV-only account still produces a report");
        assert!(
            matches!(report.calendar, ServiceCheck::Ok),
            "calendar must validate, got {report:?}"
        );
        assert!(
            matches!(report.contacts, ServiceCheck::Failed { .. }),
            "contacts stay failed when that service is absent, got {report:?}"
        );
        assert!(
            matches!(report.mail, ServiceCheck::Failed { .. }),
            "the DAV validator does not speak IMAP, got {report:?}"
        );
        assert!(
            report.any_service_ok(),
            "sign-in succeeds when only calendar validates"
        );
    }

    #[tokio::test]
    async fn calendar_home_second_call_makes_no_request() {
        let script = caldav_server();
        let client = crate::DavClient::from_script(script.clone(), credentials());
        let first = client
            .calendar_home()
            .await
            .expect("the client discovers the calendar home");
        assert_eq!(first.url, ADA_CALENDAR_HOME);
        let after_first = script.requests().len();
        let again = client
            .calendar_home()
            .await
            .expect("the client returns the cached home");
        assert_eq!(again, first);
        assert_eq!(
            script.requests().len(),
            after_first,
            "the second calendar home lookup must not send a request"
        );
    }

    #[tokio::test]
    async fn contacts_home_second_call_makes_no_request() {
        let script = carddav_server();
        let client = crate::DavClient::from_script(script.clone(), credentials());
        let first = client
            .contacts_home()
            .await
            .expect("the client discovers the contacts home");
        assert_eq!(first.url, ADA_CONTACTS_HOME);
        let after_first = script.requests().len();
        let again = client
            .contacts_home()
            .await
            .expect("the client returns the cached home");
        assert_eq!(again, first);
        assert_eq!(
            script.requests().len(),
            after_first,
            "the second contacts home lookup must not send a request"
        );
    }
}
