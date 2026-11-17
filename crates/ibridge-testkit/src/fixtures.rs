// SPDX-License-Identifier: Apache-2.0

//! Loader for recorded protocol fixtures.
//!
//! The recorder (`cargo xtask record-fixtures`) writes scrubbed server
//! responses under `tests/fixtures/{imap,caldav,carddav}` at the workspace root.

use std::fs;
use std::io;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// The directory that holds one protocol's recorded files, such as `imap`.
#[must_use]
pub fn dir(protocol: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(protocol)
}

/// Reads one recorded file.
///
/// # Panics
///
/// Panics when the file is missing: a replay test cannot run without it.
#[must_use]
pub fn read(protocol: &str, file: &str) -> String {
    let path = dir(protocol).join(file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("fixture {} is unreadable: {error}", path.display()))
}

/// An IMAP server that answers from the recorded `imap` fixtures.
///
/// It sends the recorded greeting, answers `CAPABILITY` and `LIST` with the
/// recorded lines, answers `STATUS` with empty counts, and accepts `LOGIN`
/// and everything else. It speaks lines only: it does not parse literals.
#[derive(Clone, Debug)]
pub struct ReplayImap {
    greeting: String,
    capability: String,
    list: String,
}

impl ReplayImap {
    /// Loads `capability-greeting.txt`, `capability-after-login.txt` and `list.txt`.
    #[must_use]
    pub fn load() -> Self {
        Self {
            greeting: read("imap", "capability-greeting.txt"),
            capability: read("imap", "capability-after-login.txt"),
            list: read("imap", "list.txt"),
        }
    }

    /// Opens one client half of a duplex and replays the recording on the other.
    #[must_use]
    pub fn connect(&self) -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let replay = self.clone();
        tokio::spawn(async move {
            let _ = replay.serve(server).await;
        });
        client
    }

    async fn serve(self, mut stream: DuplexStream) -> io::Result<()> {
        stream.write_all(crlf(&self.greeting).as_bytes()).await?;
        let mut pending = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            while let Some(end) = pending.windows(2).position(|pair| pair == b"\r\n") {
                let line = String::from_utf8_lossy(&pending[..end]).into_owned();
                pending.drain(..end + 2);
                let reply = self.reply(&line);
                stream.write_all(reply.as_bytes()).await?;
                if reply.contains("BYE") {
                    return Ok(());
                }
            }
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&chunk[..read]);
        }
    }

    fn reply(&self, line: &str) -> String {
        let mut words = line.splitn(3, ' ');
        let tag = words.next().unwrap_or("*");
        let command = words.next().unwrap_or("").to_ascii_uppercase();
        let arguments = words.next().unwrap_or("");
        match command.as_str() {
            "CAPABILITY" => format!(
                "{}{tag} OK CAPABILITY completed\r\n",
                crlf(&self.capability)
            ),
            "LIST" => format!("{}{tag} OK LIST completed\r\n", crlf(&self.list)),
            "STATUS" => {
                let name = arguments.split(" (").next().unwrap_or("\"\"");
                format!("* STATUS {name} (MESSAGES 0 UNSEEN 0)\r\n{tag} OK STATUS completed\r\n")
            }
            "LOGOUT" => format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"),
            _ => format!("{tag} OK {command} completed\r\n"),
        }
    }
}

/// Recorded text with every line ending as CRLF and none missing at the end.
fn crlf(text: &str) -> String {
    text.lines().map(|line| format!("{line}\r\n")).collect()
}

/// A `CalDAV` server that answers from the recorded `caldav` fixtures.
///
/// It answers principal and home discovery itself, because the recorder saves
/// only what follows discovery: `propfind-home.xml` for the home listing,
/// `report-events.xml` and `report-todos.xml` for the two `calendar-query`
/// reports, and `event.ics` and `todo.ics` for the resources it seeded. A
/// A report on any other collection is empty; any other request is a 404.
#[derive(Debug)]
pub struct ReplayCalDav {
    server: wiremock::MockServer,
}

/// The recorded paths a [`ReplayCalDav`] serves.
#[derive(Clone, Debug)]
struct CalDavRoutes {
    home: String,
    events_collection: String,
    event: String,
    event_etag: String,
    todos_collection: String,
    todo: String,
    todo_etag: String,
}

impl ReplayCalDav {
    /// Starts a server on a free loopback port and loads the fixtures.
    pub async fn start() -> Self {
        let events = read("caldav", "report-events.xml");
        let todos = read("caldav", "report-todos.xml");
        let listing = read("caldav", "propfind-home.xml");
        let event = first_resource(&events);
        let todo = first_resource(&todos);
        let routes = CalDavRoutes {
            home: first_href(&listing),
            events_collection: parent(&event),
            event_etag: etag_of(&events, &event),
            event,
            todos_collection: parent(&todo),
            todo_etag: etag_of(&todos, &todo),
            todo,
        };
        let files = [
            ("propfind-home.xml", listing),
            ("report-events.xml", events),
            ("report-todos.xml", todos),
            ("event.ics", read("caldav", "event.ics")),
            ("todo.ics", read("caldav", "todo.ics")),
        ];
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(move |request: &wiremock::Request| caldav_reply(&routes, &files, request))
            .mount(&server)
            .await;
        Self { server }
    }

    /// Base URL with a trailing slash, for `DavClient::for_test_server`.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("{}/", self.server.uri())
    }

    /// Path of the recorded event calendar's home, such as `/0000000000/calendars/`.
    #[must_use]
    pub fn home_path(&self) -> String {
        first_href(&read("caldav", "propfind-home.xml"))
    }
}

fn caldav_reply(
    routes: &CalDavRoutes,
    files: &[(&str, String)],
    request: &wiremock::Request,
) -> wiremock::ResponseTemplate {
    let file = |name: &str| {
        files
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, text)| text.clone())
            .unwrap_or_default()
    };
    let xml = |status: u16, body: String| {
        wiremock::ResponseTemplate::new(status).set_body_raw(body, "application/xml")
    };
    let path = request.url.path();
    let body = String::from_utf8_lossy(&request.body);
    let principal = "/0000000000/principal/";
    match request.method.as_str() {
        "PROPFIND" if body.contains("current-user-principal") => xml(
            207,
            format!(
                "<multistatus xmlns=\"DAV:\"><response><href>/</href><propstat><prop>\
                 <current-user-principal><href>{principal}</href></current-user-principal>\
                 </prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"
            ),
        ),
        "PROPFIND" if body.contains("calendar-home-set") => xml(
            207,
            format!(
                "<multistatus xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
                 <response><href>{principal}</href><propstat><prop><C:calendar-home-set>\
                 <href>{}</href></C:calendar-home-set></prop>\
                 <status>HTTP/1.1 200 OK</status></propstat></response></multistatus>",
                routes.home
            ),
        ),
        "PROPFIND" if path == routes.home => xml(207, file("propfind-home.xml")),
        "REPORT" if path == routes.events_collection => xml(207, file("report-events.xml")),
        "REPORT" if path == routes.todos_collection => xml(207, file("report-todos.xml")),
        "REPORT" => xml(207, "<multistatus xmlns=\"DAV:\"></multistatus>".to_owned()),
        "GET" if path == routes.event => wiremock::ResponseTemplate::new(200)
            .insert_header("ETag", routes.event_etag.as_str())
            .set_body_raw(file("event.ics"), "text/calendar"),
        "GET" if path == routes.todo => wiremock::ResponseTemplate::new(200)
            .insert_header("ETag", routes.todo_etag.as_str())
            .set_body_raw(file("todo.ics"), "text/calendar"),
        _ => wiremock::ResponseTemplate::new(404),
    }
}

/// The text of the first `<href>` in a multistatus body.
fn first_href(xml: &str) -> String {
    xml.split_once("<href>")
        .and_then(|(_, rest)| rest.split_once("</href>"))
        .map(|(href, _)| href.to_owned())
        .unwrap_or_else(|| panic!("a recorded multistatus holds an href"))
}

/// The first `<href>` that names an `.ics` resource.
fn first_resource(xml: &str) -> String {
    xml.split("<href>")
        .skip(1)
        .filter_map(|part| part.split_once("</href>").map(|(href, _)| href))
        .find(|href| href.ends_with(".ics"))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("a recorded report holds an .ics resource"))
}

/// The `getetag` the report gives for `href`. A real `GET` answers with the same value.
fn etag_of(report: &str, href: &str) -> String {
    report
        .split_once(&format!("<href>{href}</href>"))
        .and_then(|(_, rest)| rest.split_once("<getetag"))
        .and_then(|(_, rest)| rest.split_once('>'))
        .and_then(|(_, rest)| rest.split_once("</getetag>"))
        .map(|(etag, _)| etag.trim().to_owned())
        .unwrap_or_else(|| panic!("a recorded report gives an ETag for its resource"))
}

/// The collection a resource path lives in, with its trailing slash.
fn parent(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(collection, _)| format!("{collection}/"))
        .unwrap_or_else(|| panic!("a recorded resource path has a collection"))
}
