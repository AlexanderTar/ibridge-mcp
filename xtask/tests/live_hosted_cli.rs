// SPDX-License-Identifier: Apache-2.0

//! Runs the real `xtask live-hosted-check` against a hosted server on loopback.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use ibridge_hosted::testing::{FakeImapBackend, accept_all, info};
use ibridge_hosted::{HostedConfig, HostedOptions, serve};
use ibridge_testkit::imap_fake::{FakeImap, FakeScript};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const PASSWORD: &str = "cli-live-check-never-print";

#[tokio::test]
async fn live_hosted_check_passes_against_a_local_instance_and_never_prints_the_password() {
    let dir = tempfile::tempdir().expect("temp dir");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let url = format!("http://{addr}");
    let config = HostedConfig::resolve(
        HostedOptions {
            addr,
            public_url: url.clone(),
            data_dir: dir.path().join("data"),
            multi_tenant: true,
        },
        |_| None,
    )
    .expect("config");
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(serve(
        config,
        listener,
        FakeImapBackend(FakeImap::spawn(FakeScript::default())),
        accept_all(),
        info(),
        async move {
            let _ = stopped.await;
        },
    ));
    let account = dir.path().join("test-account.env");
    fs::write(
        &account,
        format!("IBRIDGE_TEST_APPLE_ID=ada@icloud.com\nIBRIDGE_TEST_APP_PASSWORD={PASSWORD}\n"),
    )
    .expect("write");
    fs::set_permissions(&account, fs::Permissions::from_mode(0o600)).expect("mode");

    // The binary blocks, so it runs off the runtime that serves it.
    let output = tokio::task::spawn_blocking({
        let account = account.clone();
        move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
                .args(["live-hosted-check", "--url", &url, "--account"])
                .arg(account)
                .output()
                .expect("run xtask")
        }
    })
    .await
    .expect("join");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    for line in [
        "sign-in: ok as ada@icloud.com",
        "account_status: ok",
        "mail: on",
        "calendar: on",
        "contacts: on",
    ] {
        assert!(stdout.contains(line), "the report has {line:?}:\n{stdout}");
    }
    assert!(
        !stdout.contains(PASSWORD) && !stderr.contains(PASSWORD),
        "the password was printed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // A missing flag is a usage error, not a crash.
    let usage = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("live-hosted-check")
        .output()
        .expect("run xtask");
    assert_eq!(usage.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&usage.stderr).contains("usage:"));

    stop.send(()).expect("server is running");
    server.await.expect("task").expect("clean stop");
}
