// SPDX-License-Identifier: Apache-2.0

//! Wiremock helpers for `CalDAV` and `CardDAV`.
//!
//! [`FakeCalDav`] is a small in-memory `CalDAV` server on a loopback port. It
//! answers discovery, collection listing, `calendar-query` reports and
//! conditional writes, and it logs every request so tests can assert on what
//! the provider sent. [`FakeCardDav`] is the same server speaking `CardDAV`:
//! address books, `addressbook-query` reports and vCards.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError};

use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Principal path the fake answers `current-user-principal` with.
const PRINCIPAL: &str = "/principals/ada/";
/// Calendar home path, relative to the server root.
const HOME: &str = "/ada/calendars/";
/// Address-book home path, relative to the server root.
const CARD_HOME: &str = "/ada/carddavhome/";

/// Which DAV dialect the fake speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Flavor {
    #[default]
    Cal,
    Card,
}

impl Flavor {
    fn home(self) -> &'static str {
        match self {
            Self::Cal => HOME,
            Self::Card => CARD_HOME,
        }
    }
}

/// One request the fake saw.
#[derive(Clone, Debug)]
pub struct LoggedRequest {
    /// HTTP method, such as `REPORT`.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request body.
    pub body: String,
    /// `If-Match` header, when sent.
    pub if_match: Option<String>,
    /// `If-None-Match` header, when sent.
    pub if_none_match: Option<String>,
}

#[derive(Clone, Debug)]
struct Item {
    etag: String,
    body: String,
}

#[derive(Clone, Debug)]
struct Collection {
    name: String,
    components: Vec<String>,
    items: BTreeMap<String, Item>,
}

#[derive(Debug, Default)]
struct State {
    flavor: Flavor,
    collections: BTreeMap<String, Collection>,
    log: Vec<LoggedRequest>,
    counter: u64,
    fail_next_put: Option<u16>,
}

/// An in-memory `CalDAV` server. Dropping it stops the listener.
#[derive(Debug)]
pub struct FakeCalDav {
    server: MockServer,
    state: Arc<Mutex<State>>,
}

/// An in-memory `CardDAV` server. It shares the resource methods of
/// [`FakeCalDav`] (`put`, `body`, `files`, `requests`, `base_url`), where a
/// collection is an address book and a resource is a vCard.
#[derive(Debug)]
pub struct FakeCardDav(FakeCalDav);

impl FakeCardDav {
    /// Starts the fake on a free loopback port with no address books.
    pub async fn start() -> Self {
        Self(FakeCalDav::start_with(Flavor::Card).await)
    }

    /// Adds an address book under the address-book home.
    pub fn add_book(&self, slug: &str, name: &str) {
        self.0.add_collection(slug, name, &[]);
    }

    /// Address-book home path, relative to the server root.
    pub fn home_path() -> &'static str {
        CARD_HOME
    }
}

impl Deref for FakeCardDav {
    type Target = FakeCalDav;

    fn deref(&self) -> &FakeCalDav {
        &self.0
    }
}

impl FakeCalDav {
    /// Starts the fake on a free loopback port with no calendars.
    pub async fn start() -> Self {
        Self::start_with(Flavor::Cal).await
    }

    async fn start_with(flavor: Flavor) -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State {
            flavor,
            ..State::default()
        }));
        Mock::given(any())
            .respond_with(Responder {
                state: Arc::clone(&state),
            })
            .mount(&server)
            .await;
        Self { server, state }
    }

    /// Base URL with a trailing slash, for `DavClient::for_test_server`.
    pub fn base_url(&self) -> String {
        format!("{}/", self.server.uri())
    }

    /// Adds a collection under the calendar home.
    ///
    /// `components` are the supported component names, such as `VEVENT`.
    pub fn add_collection(&self, slug: &str, name: &str, components: &[&str]) {
        self.lock().collections.insert(
            slug.to_owned(),
            Collection {
                name: name.to_owned(),
                components: components.iter().map(|c| (*c).to_owned()).collect(),
                items: BTreeMap::new(),
            },
        );
    }

    /// Stores an iCalendar resource and returns its `ETag`.
    pub fn put(&self, slug: &str, file: &str, ics: &str) -> String {
        let mut state = self.lock();
        let etag = next_etag(&mut state);
        if let Some(collection) = state.collections.get_mut(slug) {
            collection.items.insert(
                file.to_owned(),
                Item {
                    etag: etag.clone(),
                    body: ics.to_owned(),
                },
            );
        }
        etag
    }

    /// Makes the next `PUT` answer `status` and store nothing, as when another
    /// client wins the race.
    pub fn fail_next_put_with(&self, status: u16) {
        self.lock().fail_next_put = Some(status);
    }

    /// Names of the resources stored in a collection.
    pub fn files(&self, slug: &str) -> Vec<String> {
        self.lock()
            .collections
            .get(slug)
            .map_or_else(Vec::new, |collection| {
                collection.items.keys().cloned().collect()
            })
    }

    /// Body of a stored resource.
    pub fn body(&self, slug: &str, file: &str) -> Option<String> {
        self.lock()
            .collections
            .get(slug)
            .and_then(|collection| collection.items.get(file))
            .map(|item| item.body.clone())
    }

    /// Every request the fake has seen, oldest first.
    pub fn requests(&self) -> Vec<LoggedRequest> {
        self.lock().log.clone()
    }

    /// Calendar home path, relative to the server root.
    pub fn home_path() -> &'static str {
        HOME
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct Responder {
    state: Arc<Mutex<State>>,
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok().map(str::to_owned))
        };
        let entry = LoggedRequest {
            method: request.method.to_string(),
            path: request.url.path().to_owned(),
            body: String::from_utf8_lossy(&request.body).into_owned(),
            if_match: header("if-match"),
            if_none_match: header("if-none-match"),
        };
        state.log.push(entry.clone());
        route(&mut state, &entry)
    }
}

fn route(state: &mut State, request: &LoggedRequest) -> ResponseTemplate {
    match request.method.as_str() {
        "PROPFIND" => propfind(state, request),
        "REPORT" => report(state, request),
        "PUT" => put_item(state, request),
        "DELETE" => delete_item(state, request),
        "GET" => get_item(state, request),
        _ => ResponseTemplate::new(405),
    }
}

/// A 207 whose `C:` prefix is the dialect's own namespace.
fn multistatus(flavor: Flavor, responses: &str) -> ResponseTemplate {
    let namespace = match flavor {
        Flavor::Cal => "urn:ietf:params:xml:ns:caldav",
        Flavor::Card => "urn:ietf:params:xml:ns:carddav",
    };
    let body = format!(
        "<?xml version=\"1.0\"?><multistatus xmlns=\"DAV:\" \
         xmlns:C=\"{namespace}\">{responses}</multistatus>"
    );
    ResponseTemplate::new(207).set_body_raw(body, "application/xml")
}

fn propfind(state: &State, request: &LoggedRequest) -> ResponseTemplate {
    if request.body.contains("current-user-principal") {
        return multistatus(
            state.flavor,
            &format!(
                "<response><href>/</href><propstat><prop><current-user-principal>\
             <href>{PRINCIPAL}</href></current-user-principal></prop>\
             <status>HTTP/1.1 200 OK</status></propstat></response>"
            ),
        );
    }
    let home = state.flavor.home();
    if request.body.contains("calendar-home-set") || request.body.contains("addressbook-home-set") {
        let tag = if state.flavor == Flavor::Card {
            "addressbook-home-set"
        } else {
            "calendar-home-set"
        };
        return multistatus(
            state.flavor,
            &format!(
                "<response><href>{PRINCIPAL}</href><propstat><prop><C:{tag}>\
             <href>{home}</href></C:{tag}></prop>\
             <status>HTTP/1.1 200 OK</status></propstat></response>"
            ),
        );
    }
    let mut responses = format!(
        "<response><href>{home}</href><propstat><prop><resourcetype><collection/></resourcetype>\
         </prop><status>HTTP/1.1 200 OK</status></propstat></response>"
    );
    for (slug, collection) in &state.collections {
        let mut components = String::new();
        for name in &collection.components {
            let _ = write!(components, "<C:comp name=\"{name}\"/>");
        }
        let (kind, set) = if state.flavor == Flavor::Card {
            ("addressbook", String::new())
        } else {
            (
                "calendar",
                format!(
                    "<C:supported-calendar-component-set>{components}\
                     </C:supported-calendar-component-set>"
                ),
            )
        };
        let _ = write!(
            responses,
            "<response><href>{home}{slug}/</href><propstat><prop>\
             <displayname>{}</displayname>\
             <resourcetype><collection/><C:{kind}/></resourcetype>{set}\
             </prop><status>HTTP/1.1 200 OK</status></propstat></response>",
            collection.name
        );
    }
    multistatus(state.flavor, &responses)
}

fn collection_slug<'a>(state: &State, path: &'a str) -> Option<(&'a str, Option<&'a str>)> {
    let rest = path.strip_prefix(state.flavor.home())?;
    let mut parts = rest.trim_end_matches('/').splitn(2, '/');
    let slug = parts.next().filter(|slug| !slug.is_empty())?;
    Some((slug, parts.next()))
}

fn report(state: &State, request: &LoggedRequest) -> ResponseTemplate {
    let Some((slug, None)) = collection_slug(state, &request.path) else {
        return ResponseTemplate::new(404);
    };
    let Some(collection) = state.collections.get(slug) else {
        return ResponseTemplate::new(404);
    };
    let mut responses = String::new();
    // A multiget names the resources it wants; a query lists everything.
    let multiget = request.body.contains("multiget");
    for (file, item) in &collection.items {
        if multiget && !request.body.contains(&format!("/{slug}/{file}<")) {
            continue;
        }
        let data = if state.flavor == Flavor::Card {
            "address-data"
        } else {
            "calendar-data"
        };
        let _ = write!(
            responses,
            "<response><href>{}{slug}/{file}</href><propstat><prop>\
             <getetag>{}</getetag><C:{data}>{}</C:{data}></prop>\
             <status>HTTP/1.1 200 OK</status></propstat></response>",
            state.flavor.home(),
            item.etag,
            xml_escape(&item.body)
        );
    }
    multistatus(state.flavor, &responses)
}

fn put_item(state: &mut State, request: &LoggedRequest) -> ResponseTemplate {
    if let Some(status) = state.fail_next_put.take() {
        return ResponseTemplate::new(status);
    }
    let Some((slug, Some(file))) = collection_slug(state, &request.path) else {
        return ResponseTemplate::new(404);
    };
    let (slug, file) = (slug.to_owned(), file.to_owned());
    let existing = state
        .collections
        .get(&slug)
        .and_then(|collection| collection.items.get(&file))
        .map(|item| item.etag.clone());
    if !state.collections.contains_key(&slug) {
        return ResponseTemplate::new(404);
    }
    if request.if_none_match.as_deref() == Some("*") && existing.is_some() {
        return ResponseTemplate::new(412);
    }
    if let Some(wanted) = &request.if_match
        && existing.as_deref() != Some(wanted.as_str())
    {
        return ResponseTemplate::new(412);
    }
    let etag = next_etag(state);
    let created = existing.is_none();
    if let Some(collection) = state.collections.get_mut(&slug) {
        collection.items.insert(
            file,
            Item {
                etag: etag.clone(),
                body: request.body.clone(),
            },
        );
    }
    ResponseTemplate::new(if created { 201 } else { 204 }).insert_header("etag", etag.as_str())
}

fn delete_item(state: &mut State, request: &LoggedRequest) -> ResponseTemplate {
    let Some((slug, Some(file))) = collection_slug(state, &request.path) else {
        return ResponseTemplate::new(404);
    };
    let Some(collection) = state.collections.get_mut(slug) else {
        return ResponseTemplate::new(404);
    };
    let Some(item) = collection.items.get(file) else {
        return ResponseTemplate::new(404);
    };
    if let Some(wanted) = &request.if_match
        && wanted != &item.etag
    {
        return ResponseTemplate::new(412);
    }
    collection.items.remove(file);
    ResponseTemplate::new(204)
}

fn get_item(state: &State, request: &LoggedRequest) -> ResponseTemplate {
    let Some((slug, Some(file))) = collection_slug(state, &request.path) else {
        return ResponseTemplate::new(404);
    };
    match state
        .collections
        .get(slug)
        .and_then(|collection| collection.items.get(file))
    {
        Some(item) => ResponseTemplate::new(200)
            .insert_header("etag", item.etag.as_str())
            .set_body_raw(
                item.body.clone(),
                if state.flavor == Flavor::Card {
                    "text/vcard"
                } else {
                    "text/calendar"
                },
            ),
        None => ResponseTemplate::new(404),
    }
}

fn next_etag(state: &mut State) -> String {
    state.counter += 1;
    format!("\"etag-{}\"", state.counter)
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
