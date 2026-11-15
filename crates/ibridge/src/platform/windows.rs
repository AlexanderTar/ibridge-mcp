// SPDX-License-Identifier: Apache-2.0

//! Windows Credential Manager.

pub(super) fn install_keychain() -> anyhow::Result<()> {
    keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
    Ok(())
}
