// SPDX-License-Identifier: Apache-2.0

//! macOS Keychain.

pub(super) fn install_keychain() -> anyhow::Result<()> {
    keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
    Ok(())
}
