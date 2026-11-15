// SPDX-License-Identifier: Apache-2.0

//! A launchd `LaunchAgent` for the daemon.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::daemon::{Runner, Spec, Status};

/// The agent's label.
pub(crate) const LABEL: &str = "fyi.ibridge.daemon";

/// Where the agent's plist lives.
pub(crate) fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

fn log_path(home: &Path) -> PathBuf {
    home.join("Library/Logs/ibridge/daemon.log")
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The plist text.
///
/// The agent starts at login and restarts after a failure, but stays down after a clean exit.
pub(crate) fn plist(spec: &Spec, home: &Path) -> String {
    let arguments = std::iter::once(spec.exe.to_string_lossy().into_owned())
        .chain(spec.args())
        .fold(String::new(), |mut lines, argument| {
            let _ = writeln!(lines, "        <string>{}</string>", escape(&argument));
            lines
        });
    let log = escape(&log_path(home).to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{arguments}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#
    )
}

/// The user's numeric id, which names the `gui/<uid>` launchd domain.
fn domain(run: &dyn Runner) -> anyhow::Result<String> {
    let id = run.run("id", &["-u"])?;
    let uid = id.stdout.trim();
    anyhow::ensure!(
        id.success && !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()),
        "could not read the user id"
    );
    Ok(format!("gui/{uid}"))
}

/// Writes the plist and loads the agent. An agent that is already loaded is replaced.
pub(crate) fn install(spec: &Spec, home: &Path, run: &dyn Runner) -> anyhow::Result<()> {
    let domain = domain(run)?;
    let path = plist_path(home);
    for dir in [path.parent(), log_path(home).parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    std::fs::write(&path, plist(spec, home))
        .with_context(|| format!("could not write {}", path.display()))?;
    // A first install has nothing to unload, so a failure here is fine.
    run.run("launchctl", &["bootout", &format!("{domain}/{LABEL}")])?;
    let path_text = path.to_string_lossy();
    let loaded = run.run("launchctl", &["bootstrap", &domain, &path_text])?;
    anyhow::ensure!(loaded.success, "launchctl could not load the agent");
    Ok(())
}

/// Unloads the agent and removes the plist.
pub(crate) fn uninstall(home: &Path, run: &dyn Runner) -> anyhow::Result<()> {
    let domain = domain(run)?;
    // An agent that is not loaded is already stopped.
    run.run("launchctl", &["bootout", &format!("{domain}/{LABEL}")])?;
    match std::fs::remove_file(plist_path(home)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("could not remove the plist"),
    }
}

/// Whether the agent is loaded and running.
pub(crate) fn status(_home: &Path, run: &dyn Runner) -> anyhow::Result<Status> {
    let domain = domain(run)?;
    let printed = run.run("launchctl", &["print", &format!("{domain}/{LABEL}")])?;
    Ok(if !printed.success {
        Status::NotInstalled
    } else if printed.stdout.contains("state = running") {
        Status::Running
    } else {
        Status::Stopped
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::plist;
    use crate::daemon::Spec;
    use crate::serve::Access;

    fn spec(access: Access) -> Spec {
        Spec {
            exe: PathBuf::from("/usr/local/bin/ibridge"),
            addr: "127.0.0.1:8765".parse().expect("address"),
            access,
        }
    }

    #[test]
    fn launchd_plist_snapshot() {
        let home = Path::new("/Users/ada");
        insta::assert_snapshot!("plist", plist(&spec(Access::ReadWrite), home));
        insta::assert_snapshot!("plist_read_only", plist(&spec(Access::ReadOnly), home));
    }

    #[test]
    fn plist_escapes_xml_in_the_binary_path() {
        let odd = Spec {
            exe: PathBuf::from("/Users/a&b/<bin>/ibridge"),
            ..spec(Access::ReadWrite)
        };
        let text = plist(&odd, Path::new("/Users/ada"));
        assert!(
            text.contains("/Users/a&amp;b/&lt;bin&gt;/ibridge"),
            "the path is XML-escaped, got {text}"
        );
    }
}
