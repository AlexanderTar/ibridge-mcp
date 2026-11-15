// SPDX-License-Identifier: Apache-2.0

//! Code that differs by operating system: the keychain and the browser opener.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Points the keyring at this operating system's credential store.
///
/// Call it once, before the first keychain read or write. Tests never call it:
/// they install the in-memory mock store instead.
///
/// # Errors
///
/// Returns an error when the credential store cannot be opened.
pub(crate) fn install_keychain() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    return macos::install_keychain();
    #[cfg(target_os = "windows")]
    return windows::install_keychain();
    #[cfg(target_os = "linux")]
    return linux::install_keychain();
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    anyhow::bail!("this operating system has no supported credential store")
}

/// Opens `url` in the default browser. Failure is ignored: the caller prints the URL too.
pub(crate) fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let spawned = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let spawned = std::process::Command::new("xdg-open").arg(url).spawn();
    if let Err(error) = spawned {
        tracing::debug!(%error, "could not open the browser");
    }
}
