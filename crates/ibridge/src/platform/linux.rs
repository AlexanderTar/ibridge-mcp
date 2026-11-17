// SPDX-License-Identifier: Apache-2.0

//! Linux Secret Service.

// ponytail: a headless box with no Secret Service fails here. The spec's
// 0600-file fallback is not built yet; `IBRIDGE_APPLE_ID` and
// `IBRIDGE_APP_PASSWORD` cover that case for `serve`.
pub(super) fn install_keychain() -> anyhow::Result<()> {
    keyring_core::set_default_store(zbus_secret_service_keyring_store::Store::new()?);
    Ok(())
}
