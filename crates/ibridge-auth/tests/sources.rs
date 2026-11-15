// SPDX-License-Identifier: Apache-2.0

//! Credential sources.

use std::future::Future;
use std::path::PathBuf;

use ibridge_auth::{CredentialSource, EnvSource, FileSource, KeyringSource};
use ibridge_core::AppleId;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("credential source waited"),
    }
}

fn apple_id() -> AppleId {
    AppleId::try_from("ada@icloud.com").expect("primary address")
}

#[cfg(unix)]
fn write_secret_file(mode: u32, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("ibridge-auth-{mode:o}-{}", std::process::id()));
    std::fs::write(&path, body).expect("write credential file");
    let mut permissions = std::fs::metadata(&path)
        .expect("credential file metadata")
        .permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(&path, permissions).expect("set credential file mode");
    path
}

struct RemoveFile(PathBuf);

impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn file_source_requires_0600() {
    let body = "IBRIDGE_APPLE_ID=ada@icloud.com\nIBRIDGE_APP_PASSWORD=app-password-do-not-leak\n";
    let tight = RemoveFile(write_secret_file(0o600, body));
    let loose = RemoveFile(write_secret_file(0o644, body));
    let fallback = RemoveFile(write_secret_file(
        0o600,
        "IBRIDGE_TEST_APPLE_ID=ada@icloud.com\nIBRIDGE_TEST_APP_PASSWORD=app-password-do-not-leak\n",
    ));

    assert!(
        ready(FileSource::new(&loose.0).credentials()).is_err(),
        "a mode 0644 credential file must be refused"
    );
    let loaded =
        ready(FileSource::new(&tight.0).credentials()).expect("a mode 0600 file must load");
    assert_eq!(loaded.apple_id.as_str(), "ada@icloud.com");
    assert_eq!(
        loaded.with_secret(str::to_owned),
        "app-password-do-not-leak"
    );
    let from_test_names = ready(FileSource::new(&fallback.0).credentials())
        .expect("0600 file may use the test variable names");
    assert_eq!(
        from_test_names.with_secret(str::to_owned),
        "app-password-do-not-leak"
    );
}

#[test]
fn env_source_reads_vars() {
    temp_env::with_vars(
        [
            ("IBRIDGE_APPLE_ID", Some("ada@icloud.com")),
            ("IBRIDGE_APP_PASSWORD", Some("app-password-do-not-leak")),
        ],
        || {
            let loaded =
                ready(EnvSource::new().credentials()).expect("env source reads the variables");
            assert_eq!(loaded.apple_id.as_str(), "ada@icloud.com");
            assert_eq!(
                loaded.with_secret(str::to_owned),
                "app-password-do-not-leak"
            );
        },
    );
}

#[test]
fn keyring_mock_roundtrip() {
    keyring_core::set_default_store(keyring_core::mock::Store::new().expect("mock store"));
    let id = apple_id();
    let entry = keyring_core::Entry::new("ibridge", id.as_str()).expect("keychain entry");
    entry
        .set_password("app-password-do-not-leak")
        .expect("store the app password in the mock keychain");
    let loaded =
        ready(KeyringSource::new(id).credentials()).expect("keyring source reads the mock entry");
    assert_eq!(loaded.apple_id.as_str(), "ada@icloud.com");
    assert_eq!(
        loaded.with_secret(str::to_owned),
        "app-password-do-not-leak"
    );
}
