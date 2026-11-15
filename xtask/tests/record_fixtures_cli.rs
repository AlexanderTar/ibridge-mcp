// SPDX-License-Identifier: Apache-2.0

//! Runs the real `xtask` binary and reads what it prints.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const PASSWORD: &str = "hunter2-never-print";

fn account_file(name: &str, mode: u32, apple_id: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ibridge-cli-{name}-{}", std::process::id()));
    let body = format!("IBRIDGE_TEST_APPLE_ID={apple_id}\nIBRIDGE_TEST_APP_PASSWORD={PASSWORD}\n");
    fs::write(&path, body).expect("write account file");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set mode");
    path
}

fn run(account: &PathBuf, out: &PathBuf) -> Output {
    run_kind("mail", account, out)
}

fn run_kind(kind: &str, account: &PathBuf, out: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["record-fixtures", kind, "--account"])
        .arg(account)
        .arg("--out")
        .arg(out)
        .output()
        .expect("run xtask")
}

#[test]
fn recorder_never_prints_password_from_the_binary() {
    let out = std::env::temp_dir().join(format!("ibridge-cli-out-{}", std::process::id()));
    // Both files are refused before any connection: one has a bad Apple ID, the
    // other is group-readable. A missing file is refused the same way.
    let bad_id = account_file("badid", 0o600, "not-an-apple-id");
    let loose = account_file("loose", 0o644, "ada@icloud.com");
    let missing = std::env::temp_dir().join(format!("ibridge-cli-missing-{}", std::process::id()));

    for account in [&bad_id, &loose, &missing] {
        let output = run(account, &out);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
        assert!(
            stderr.contains("record-fixtures:"),
            "the failure reaches stderr: {stderr}"
        );
        assert!(
            !stdout.contains(PASSWORD) && !stderr.contains(PASSWORD),
            "the password was printed for {}:\nstdout: {stdout}\nstderr: {stderr}",
            account.display()
        );
    }
    assert!(!out.exists(), "nothing is recorded");
    for path in [bad_id, loose] {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn calendar_recorder_refuses_bad_account_files_without_printing_the_password() {
    let out = std::env::temp_dir().join(format!("ibridge-cal-cli-out-{}", std::process::id()));
    let bad_id = account_file("cal-badid", 0o600, "not-an-apple-id");
    let loose = account_file("cal-loose", 0o644, "ada@icloud.com");
    let missing =
        std::env::temp_dir().join(format!("ibridge-cal-cli-missing-{}", std::process::id()));

    for account in [&bad_id, &loose, &missing] {
        let output = run_kind("calendar", account, &out);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
        assert!(
            stderr.contains("record-fixtures:"),
            "the failure reaches stderr: {stderr}"
        );
        assert!(
            !stdout.contains(PASSWORD) && !stderr.contains(PASSWORD),
            "the password was printed for {}:\nstdout: {stdout}\nstderr: {stderr}",
            account.display()
        );
    }
    assert!(!out.exists(), "nothing is recorded");
    for path in [bad_id, loose] {
        let _ = fs::remove_file(path);
    }
}
