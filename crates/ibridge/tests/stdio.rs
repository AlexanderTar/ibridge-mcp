// SPDX-License-Identifier: Apache-2.0

//! Runs the real binary: stdout carries JSON-RPC and nothing else.

use std::io::Write as _;
use std::process::{Command, Stdio};

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const LIST_TOOLS: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

#[test]
fn serve_stdio_logs_never_to_stdout() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibridge"))
        .args(["serve", "--stdio"])
        .env("IBRIDGE_APPLE_ID", "ada@icloud.com")
        .env("IBRIDGE_APP_PASSWORD", "not-a-real-password")
        .env("IBRIDGE_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    for line in [INITIALIZE, INITIALIZED, LIST_TOOLS] {
        writeln!(stdin, "{line}").expect("write a request");
    }
    drop(stdin);
    let output = child
        .wait_with_output()
        .expect("the server exits when stdin closes");

    let stdout = String::from_utf8(output.stdout).expect("stdout is text");
    let mut saw_tools = false;
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let message: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "not a JSON-RPC message: {line}");
        saw_tools |= message["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "mail_search"));
    }
    assert!(
        saw_tools,
        "tools/list answered with the mail tools, got {stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("serving"),
        "logs go to stderr, got {stderr}"
    );
}
