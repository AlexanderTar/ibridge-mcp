// SPDX-License-Identifier: Apache-2.0

//! Helpers the binary's tests share.

use std::sync::Once;

use tokio::sync::Mutex;

/// Tests share one in-memory keychain, so they take turns.
pub(crate) static KEYCHAIN: Mutex<()> = Mutex::const_new(());

/// Points the keyring at an in-memory store. Never touches a real keychain.
pub(crate) fn mock_keychain() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        keyring_core::set_default_store(keyring_core::mock::Store::new().expect("mock keychain"));
    });
}
