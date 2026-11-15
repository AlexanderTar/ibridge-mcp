// SPDX-License-Identifier: Apache-2.0

//! Code that differs by operating system: the keychain and the browser opener.

#[cfg(feature = "http")]
pub(crate) mod launchd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(feature = "http")]
pub(crate) mod systemd;
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

/// Finishes when the process is asked to stop: Ctrl-C, or SIGTERM from launchd and systemd.
#[cfg(feature = "http")]
pub(crate) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The service manager that runs the daemon on this operating system.
#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    /// A launchd `LaunchAgent` (macOS).
    Launchd,
    /// A systemd `--user` unit (Linux).
    Systemd,
}

#[cfg(feature = "http")]
impl Service {
    /// The manager here, or `None` on an operating system without one.
    pub(crate) const fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::Launchd)
        } else if cfg!(target_os = "linux") {
            Some(Self::Systemd)
        } else {
            None
        }
    }
}
