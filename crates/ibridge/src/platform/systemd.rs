// SPDX-License-Identifier: Apache-2.0

//! A systemd `--user` unit for the daemon.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::daemon::{Runner, Spec, Status};

/// The unit's name.
pub(crate) const UNIT: &str = "ibridge.service";

/// Where the unit file lives.
pub(crate) fn unit_path(home: &Path) -> PathBuf {
    home.join(".config/systemd/user").join(UNIT)
}

/// Quotes one word for `ExecStart=`: systemd expands `%` specifiers and `$` variables inside it.
fn quote(word: &str) -> String {
    let escaped = word
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{escaped}\"")
}

/// The unit text.
pub(crate) fn unit(spec: &Spec) -> String {
    let exe = quote(&spec.exe.to_string_lossy());
    let args = spec.args().join(" ");
    format!(
        "[Unit]
Description=ibridge MCP server on loopback
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={exe} {args}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"
    )
}

fn systemctl(run: &dyn Runner, args: &[&str]) -> anyhow::Result<crate::daemon::Outcome> {
    let mut full = vec!["--user"];
    full.extend_from_slice(args);
    run.run("systemctl", &full)
}

/// Writes the unit, then enables and starts it.
pub(crate) fn install(spec: &Spec, home: &Path, run: &dyn Runner) -> anyhow::Result<()> {
    let path = unit_path(home);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    std::fs::write(&path, unit(spec))
        .with_context(|| format!("could not write {}", path.display()))?;
    anyhow::ensure!(
        systemctl(run, &["daemon-reload"])?.success,
        "systemctl could not reload its units"
    );
    anyhow::ensure!(
        systemctl(run, &["enable", "--now", UNIT])?.success,
        "systemctl could not start {UNIT}"
    );
    Ok(())
}

/// Stops and disables the unit, then removes it.
pub(crate) fn uninstall(home: &Path, run: &dyn Runner) -> anyhow::Result<()> {
    // A unit that is not enabled is already stopped.
    systemctl(run, &["disable", "--now", UNIT])?;
    match std::fs::remove_file(unit_path(home)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("could not remove the unit file"),
    }
    systemctl(run, &["daemon-reload"])?;
    Ok(())
}

/// Whether the unit is installed and active.
pub(crate) fn status(home: &Path, run: &dyn Runner) -> anyhow::Result<Status> {
    if !unit_path(home).is_file() {
        return Ok(Status::NotInstalled);
    }
    let active = systemctl(run, &["is-active", UNIT])?;
    Ok(if active.stdout.trim() == "active" {
        Status::Running
    } else {
        Status::Stopped
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::unit;
    use crate::daemon::Spec;
    use crate::serve::Access;

    fn spec(exe: &str, access: Access) -> Spec {
        Spec {
            exe: PathBuf::from(exe),
            addr: "127.0.0.1:8765".parse().expect("address"),
            access,
        }
    }

    #[test]
    fn systemd_unit_snapshot() {
        insta::assert_snapshot!(
            "unit",
            unit(&spec("/usr/local/bin/ibridge", Access::ReadWrite))
        );
        insta::assert_snapshot!(
            "unit_read_only",
            unit(&spec("/usr/local/bin/ibridge", Access::ReadOnly))
        );
    }

    #[test]
    fn unit_quotes_a_binary_path_with_spaces_and_specifiers() {
        let text = unit(&spec("/opt/my apps/100%/ibridge", Access::ReadWrite));
        assert!(
            text.contains(r#"ExecStart="/opt/my apps/100%%/ibridge" serve --http 127.0.0.1:8765"#),
            "spaces are quoted and % is doubled, got {text}"
        );
    }
}
