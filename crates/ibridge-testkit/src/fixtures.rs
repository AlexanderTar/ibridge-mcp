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
