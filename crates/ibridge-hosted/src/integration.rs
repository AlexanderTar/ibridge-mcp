// SPDX-License-Identifier: Apache-2.0

//! The hosted server against Radicale and `GreenMail`: calendar, contacts and send, called
//! with a token, through the production backend.

use std::future::Future;
use std::io;

use http::Request;
use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use ibridge_dav::DavClient;
use ibridge_mail::Connect;
use serde_json::{Value, json};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use tokio::net::TcpStream;

use crate::e2e::{hosted_over, send, sign_in};
use crate::icloud::IcloudBackend;
use crate::test_app::rpc_request;

#[derive(Clone, Debug)]
struct TcpConnect(u16);

impl Connect for TcpConnect {
    type Stream = TcpStream;

    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        TcpStream::connect(("127.0.0.1", self.0))
    }
}

/// One tool call through the hosted app. Fails the test when the tool reports an error.
async fn tool(app: &axum::Router, bearer: &str, name: &str, arguments: Value) -> Value {
    let reply = send(
        app,
        rpc_request(
            bearer,
            "tools/call",
            Some(name),
            json!({"name": name, "arguments": arguments}),
        ),
    )
    .await;
    let message = reply.json();
    assert!(
        message.get("error").is_none() && message["result"]["isError"] != json!(true),
        "{name} worked: {message}"
    );
    message["result"]["structuredContent"].clone()
}

async fn mkcol(raw: &DavClient, url: &str, kind: &str) {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <mkcol xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:{kind}\"><set><prop>\
         <resourcetype><collection/><C:{}/></resourcetype></prop></set></mkcol>",
        if kind == "caldav" {
            "calendar"
        } else {
            "addressbook"
        },
    );
    let created = raw
        .request(
            Request::builder()
                .method("MKCOL")
                .uri(url)
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(body)
                .expect("mkcol"),
        )
        .await
        .expect("create collection");
    assert!(
        created.status.is_success(),
        "mkcol status {}",
        created.status
    );
}

#[tokio::test]
async fn hosted_e2e_calendar_and_contacts_radicale() {
    let radicale = ibridge_testkit::containers::radicale()
        .start()
        .await
        .expect("radicale starts");
    // Setup only: a stored-credential client makes the collections the tools will use.
    let raw = DavClient::for_test_server(
        Credentials::new(AppleId::try_from("ada@icloud.com").expect("apple id"), "x"),
        radicale.base_url(),
    )
    .expect("setup client");
    let calendar_home = raw.calendar_home().await.expect("caldav home");
    mkcol(
        &raw,
        &format!("{}/events/", calendar_home.url.trim_end_matches('/')),
        "caldav",
    )
    .await;
    mkcol(
        &raw,
        &format!("{}/tasks/", calendar_home.url.trim_end_matches('/')),
        "caldav",
    )
    .await;
    let contacts_home = raw.contacts_home().await.expect("carddav home");
    mkcol(
        &raw,
        &format!("{}/card/", contacts_home.url.trim_end_matches('/')),
        "carddav",
    )
    .await;

    let backend = IcloudBackend::loopback(
        TcpConnect(1),
        radicale.base_url(),
        radicale.base_url(),
        "127.0.0.1",
        1,
    )
    .expect("backend");
    let app = hosted_over(backend).await;
    let bearer = sign_in(&app, "ada@icloud.com", "abcd-efgh-ijkl-mnop").await;

    let calendars = tool(&app, &bearer, "calendar_list_calendars", json!({})).await;
    let calendar = calendars["calendars"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a calendar, got {calendars}"))
        .to_owned();
    tool(
        &app,
        &bearer,
        "calendar_create_event",
        json!({
            "calendar": calendar,
            "summary": "Hosted standup",
            "start": "2026-11-16T09:00:00Z",
            "end": "2026-11-16T09:30:00Z",
        }),
    )
    .await;
    let events = tool(
        &app,
        &bearer,
        "calendar_list_events",
        json!({"start": "2026-11-15T00:00:00Z", "end": "2026-11-30T00:00:00Z"}),
    )
    .await;
    assert!(
        events.to_string().contains("Hosted standup"),
        "the event made through the hosted server is listed, got {events}"
    );

    let lists = tool(&app, &bearer, "reminders_list_lists", json!({})).await;
    let list = lists["lists"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a reminder list, got {lists}"))
        .to_owned();
    tool(
        &app,
        &bearer,
        "reminders_create",
        json!({"list": list, "title": "Hosted groceries"}),
    )
    .await;
    let reminders = tool(&app, &bearer, "reminders_list", json!({"list": list})).await;
    assert!(
        reminders.to_string().contains("Hosted groceries"),
        "the reminder made through the hosted server is listed, got {reminders}"
    );

    tool(
        &app,
        &bearer,
        "contacts_create",
        json!({"full_name": "Grace Hopper", "emails": ["grace@example.com"]}),
    )
    .await;
    let found = tool(&app, &bearer, "contacts_search", json!({"query": "grace"})).await;
    assert!(
        found.to_string().contains("Grace Hopper"),
        "the contact made through the hosted server is found, got {found}"
    );
}

#[tokio::test]
async fn hosted_e2e_send_greenmail() {
    let greenmail = ibridge_testkit::containers::greenmail()
        .start()
        .await
        .expect("greenmail starts");
    let imap_port = greenmail
        .get_host_port_ipv4(3143.tcp())
        .await
        .expect("imap port");
    let smtp_port = greenmail
        .get_host_port_ipv4(3025.tcp())
        .await
        .expect("smtp port");

    let backend = IcloudBackend::loopback(
        TcpConnect(imap_port),
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "127.0.0.1",
        smtp_port,
    )
    .expect("backend");
    let app = hosted_over(backend).await;
    // GreenMail's account for ada@icloud.com has this password.
    let bearer = sign_in(&app, "ada@icloud.com", "test-secret").await;

    tool(
        &app,
        &bearer,
        "mail_send",
        json!({
            "to": ["ada@icloud.com"],
            "subject": "Hosted picnic",
            "body": "Bring napkins.",
        }),
    )
    .await;
    let inbox = tool(
        &app,
        &bearer,
        "mail_search",
        json!({"subject": "Hosted picnic"}),
    )
    .await;
    assert!(
        inbox.to_string().contains("Hosted picnic"),
        "the message sent through the hosted server arrived, got {inbox}"
    );
}
