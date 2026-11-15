// SPDX-License-Identifier: Apache-2.0

//! `GreenMail` coverage for list, search and fetch.

use std::future::Future;
use std::io;

use ibridge_auth::Credentials;
use ibridge_core::{AppleId, Draft, MailSearch, MailboxPath, MailboxRole};

use crate::session::MailSession;
use crate::smtp::SmtpClient;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::pool::{Connect, ImapPool};

#[derive(Debug)]
struct TcpConnect {
    port: u16,
}

impl Connect for TcpConnect {
    type Stream = TcpStream;

    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        TcpStream::connect(("127.0.0.1", self.port))
    }
}

#[tokio::test]
async fn greenmail_list_search_fetch() {
    let container = ibridge_testkit::containers::greenmail()
        .start()
        .await
        .expect("greenmail starts");
    let port = container
        .get_host_port_ipv4(3143.tcp())
        .await
        .expect("imap port");
    append_picnic(port).await;

    let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
    let pooled = ImapPool::new(
        Credentials::new(apple_id, "test-secret"),
        TcpConnect { port },
    );
    let boxes = pooled.list_mailboxes().await.expect("list mailboxes");
    assert!(
        boxes.iter().any(|mailbox| mailbox.path.as_str() == "INBOX"),
        "INBOX is listed, got {boxes:?}"
    );
    let page = pooled
        .search(&MailSearch {
            mailbox: Some(MailboxPath::try_from("INBOX").expect("inbox")),
            role: None,
            from: None,
            to: None,
            subject: None,
            text: None,
            since: None,
            before: None,
            unread_only: false,
            flagged_only: false,
            limit: 25,
            cursor: None,
        })
        .await
        .expect("search");
    let message = page
        .messages
        .iter()
        .find(|message| message.subject.contains("picnic"))
        .expect("the appended message is in the search page");
    let fetched = pooled
        .get_message(&message.id, 0)
        .await
        .expect("fetch the message");
    assert!(
        fetched.message.body.contains("Hello from greenmail"),
        "the body is the delivered text, got {:?}",
        fetched.message.body
    );
}

async fn append_picnic(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("imap accepts a connection");
    let mut greeting = [0_u8; 256];
    let read = stream.read(&mut greeting).await.expect("greeting");
    assert!(read > 0, "the server sends a greeting");
    let login = b"A1 LOGIN ada@icloud.com test-secret\r\n";
    stream.write_all(login).await.expect("write login");
    let mut reply = [0_u8; 1024];
    let read = stream.read(&mut reply).await.expect("login reply");
    let reply = String::from_utf8_lossy(&reply[..read]);
    assert!(
        reply.contains("A1 OK"),
        "ada@icloud.com can log in, got {reply}"
    );
    let message = b"Subject: picnic\r\nFrom: ada@icloud.com\r\n\r\nHello from greenmail\r\n";
    let append = format!("A2 APPEND INBOX {{{}}}\r\n", message.len());
    stream
        .write_all(append.as_bytes())
        .await
        .expect("write append");
    let mut cont = [0_u8; 64];
    let read = stream.read(&mut cont).await.expect("append continue");
    assert!(
        cont[..read].contains(&b'+'),
        "the server asks for the literal, got {}",
        String::from_utf8_lossy(&cont[..read])
    );
    stream.write_all(message).await.expect("write message");
    stream.write_all(b"\r\n").await.expect("end literal");
    let mut done = [0_u8; 256];
    let read = stream.read(&mut done).await.expect("append result");
    let done = String::from_utf8_lossy(&done[..read]);
    assert!(done.contains("A2 OK"), "the message is stored, got {done}");
}

fn account() -> Credentials {
    let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
    Credentials::new(apple_id, "test-secret")
}

fn query(mailbox: Option<MailboxPath>, role: Option<MailboxRole>) -> MailSearch {
    MailSearch {
        mailbox,
        role,
        from: None,
        to: None,
        subject: None,
        text: None,
        since: None,
        before: None,
        unread_only: false,
        flagged_only: false,
        limit: 25,
        cursor: None,
    }
}

#[tokio::test]
async fn greenmail_send_then_find_in_inbox_and_sent() {
    let container = ibridge_testkit::containers::greenmail()
        .start()
        .await
        .expect("greenmail starts");
    let imap_port = container
        .get_host_port_ipv4(3143.tcp())
        .await
        .expect("imap port");
    let smtp_port = container
        .get_host_port_ipv4(3025.tcp())
        .await
        .expect("smtp port");
    create_mailbox(imap_port, "Sent").await;

    let session = MailSession::new(
        ImapPool::new(account(), TcpConnect { port: imap_port }),
        SmtpClient::plain(account(), "127.0.0.1", smtp_port).expect("loopback smtp"),
    );
    session
        .send(&Draft {
            to: vec!["ada@icloud.com".to_owned()],
            subject: "bridge picnic".to_owned(),
            body: "See you at the gate.".to_owned(),
            from: None,
            reply_to: None,
        })
        .await
        .expect("send");

    let reader = ImapPool::new(account(), TcpConnect { port: imap_port });
    let inbox = reader
        .search(&query(
            Some(MailboxPath::try_from("INBOX").expect("inbox")),
            None,
        ))
        .await
        .expect("inbox search");
    assert!(
        inbox
            .messages
            .iter()
            .any(|message| message.subject.contains("bridge picnic")),
        "GreenMail delivers the SMTP message to INBOX, got {inbox:?}"
    );
    let sent = reader
        .search(&query(None, Some(MailboxRole::Sent)))
        .await
        .expect("sent search");
    assert!(
        sent.messages
            .iter()
            .any(|message| message.subject.contains("bridge picnic")),
        "the send appends a copy to Sent, got {sent:?}"
    );
}

async fn create_mailbox(port: u16, name: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("imap accepts a connection");
    let mut greeting = [0_u8; 256];
    let read = stream.read(&mut greeting).await.expect("greeting");
    assert!(read > 0, "the server sends a greeting");
    stream
        .write_all(b"C1 LOGIN ada@icloud.com test-secret\r\n")
        .await
        .expect("write login");
    let mut reply = [0_u8; 1024];
    let read = stream.read(&mut reply).await.expect("login reply");
    let reply = String::from_utf8_lossy(&reply[..read]);
    assert!(reply.contains("C1 OK"), "login for create, got {reply}");
    let create = format!("C2 CREATE {name}\r\n");
    stream
        .write_all(create.as_bytes())
        .await
        .expect("write create");
    let mut done = [0_u8; 512];
    let read = stream.read(&mut done).await.expect("create result");
    let done = String::from_utf8_lossy(&done[..read]);
    assert!(
        done.contains("C2 OK"),
        "the Sent mailbox exists, got {done}"
    );
}
