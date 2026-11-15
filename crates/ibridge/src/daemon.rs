// SPDX-License-Identifier: Apache-2.0

//! `ibridge daemon install`, `uninstall` and `status`.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::platform::{Service, launchd, systemd};
use crate::serve::Access;
use crate::token::DaemonToken;

/// The port the daemon listens on unless `--port` says otherwise.
pub(crate) const DEFAULT_PORT: u16 = 8765;

/// What the daemon runs as.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    /// The `ibridge` binary the service starts.
    pub(crate) exe: PathBuf,
    /// The loopback address it listens on.
    pub(crate) addr: SocketAddr,
    /// Whether it hides write tools.
    pub(crate) access: Access,
}

impl Spec {
    /// The arguments after the binary path.
    pub(crate) fn args(&self) -> Vec<String> {
        let mut args = vec![
            "serve".to_owned(),
            "--http".to_owned(),
            self.addr.to_string(),
        ];
        if self.access == Access::ReadOnly {
            args.push("--read-only".to_owned());
        }
        args
    }

    /// The URL clients connect to.
    fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }
}

/// The result of one command run by a [`Runner`].
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    /// Whether it exited with status 0.
    pub(crate) success: bool,
    /// What it printed on stdout.
    pub(crate) stdout: String,
}

/// Runs `launchctl`, `systemctl` and `id`. Tests inject a fake: they never touch the real service manager.
pub(crate) trait Runner {
    /// Runs `program` with `args` and waits for it.
    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<Outcome>;
}

/// Whether the daemon is installed and up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// No service definition is installed.
    NotInstalled,
    /// Installed, but not running.
    Stopped,
    /// Installed and running.
    Running,
}

/// Installs and starts the daemon, then prints the Claude Code setup line.
///
/// # Errors
///
/// Returns an error when the service manager refuses, a file cannot be written, or the keychain fails.
pub(crate) fn install(
    service: Service,
    spec: &Spec,
    home: &Path,
    run: &dyn Runner,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let token = DaemonToken::get_or_create()?;
    let manager = match service {
        Service::Launchd => {
            launchd::install(spec, home, run)?;
            "launchd"
        }
        Service::Systemd => {
            systemd::install(spec, home, run)?;
            "systemd"
        }
    };
    let url = spec.url();
    writeln!(
        out,
        "Installed the ibridge daemon with {manager}. It listens on {url}."
    )?;
    token.with_secret(|secret| {
        writeln!(
            out,
            "\nAdd it to Claude Code:\n  claude mcp add --transport http ibridge {url} --header \"Authorization: Bearer {secret}\""
        )
    })?;
    Ok(())
}

/// Stops the daemon and removes its service definition.
///
/// # Errors
///
/// Returns an error when the service definition cannot be removed.
pub(crate) fn uninstall(service: Service, home: &Path, run: &dyn Runner) -> anyhow::Result<()> {
    match service {
        Service::Launchd => launchd::uninstall(home, run),
        Service::Systemd => systemd::uninstall(home, run),
    }
}

/// Whether the daemon is installed and running.
///
/// # Errors
///
/// Returns an error when the service manager cannot be asked.
pub(crate) fn status(service: Service, home: &Path, run: &dyn Runner) -> anyhow::Result<Status> {
    match service {
        Service::Launchd => launchd::status(home, run),
        Service::Systemd => systemd::status(home, run),
    }
}

/// Runs real commands.
#[derive(Debug)]
struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<Outcome> {
        let output = std::process::Command::new(program)
            .args(args)
            .stderr(std::process::Stdio::inherit())
            .output()
            .with_context(|| format!("could not run {program}"))?;
        Ok(Outcome {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        })
    }
}

fn environment() -> anyhow::Result<(Service, PathBuf)> {
    let service = Service::current()
        .context("the daemon is supported on macOS (launchd) and Linux (systemd) only")?;
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok((service, PathBuf::from(home)))
}

/// `ibridge daemon install`.
pub(crate) fn run_install(port: u16, access: Access) -> anyhow::Result<()> {
    let (service, home) = environment()?;
    crate::platform::install_keychain()?;
    let spec = Spec {
        exe: std::env::current_exe().context("cannot find this program's path")?,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        access,
    };
    install(
        service,
        &spec,
        &home,
        &SystemRunner,
        &mut std::io::stdout().lock(),
    )
}

/// `ibridge daemon uninstall`.
pub(crate) fn run_uninstall() -> anyhow::Result<()> {
    let (service, home) = environment()?;
    uninstall(service, &home, &SystemRunner)?;
    writeln!(
        std::io::stdout().lock(),
        "The ibridge daemon is uninstalled."
    )?;
    Ok(())
}

/// `ibridge daemon status`.
pub(crate) fn run_status() -> anyhow::Result<()> {
    let (service, home) = environment()?;
    let text = match status(service, &home, &SystemRunner)? {
        Status::NotInstalled => "not installed",
        Status::Stopped => "installed, not running",
        Status::Running => "running",
    };
    writeln!(std::io::stdout().lock(), "ibridge daemon: {text}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use keyring_core::Entry;

    use super::{Outcome, Runner, Spec, Status, install};
    use crate::account::KEYCHAIN_SERVICE;
    use crate::platform::{Service, launchd, systemd};
    use crate::serve::Access;
    use crate::testing::{KEYCHAIN, mock_keychain};

    /// Records every command and answers from a script. Nothing real runs.
    struct Fake {
        calls: RefCell<Vec<String>>,
        answers: Vec<(&'static str, Outcome)>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                answers: Vec::new(),
            }
        }

        fn answering(mut self, command: &'static str, outcome: Outcome) -> Self {
            self.answers.push((command, outcome));
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<Outcome> {
            let command = format!("{program} {}", args.join(" "));
            self.calls.borrow_mut().push(command.clone());
            Ok(self
                .answers
                .iter()
                .find(|(prefix, _)| command.starts_with(prefix))
                .map_or_else(
                    || Outcome {
                        success: true,
                        stdout: String::new(),
                    },
                    |(_, outcome)| outcome.clone(),
                ))
        }
    }

    fn ok(stdout: &str) -> Outcome {
        Outcome {
            success: true,
            stdout: stdout.to_owned(),
        }
    }

    fn failed() -> Outcome {
        Outcome {
            success: false,
            stdout: String::new(),
        }
    }

    fn spec(access: Access) -> Spec {
        Spec {
            exe: PathBuf::from("/usr/local/bin/ibridge"),
            addr: "127.0.0.1:8765".parse().expect("address"),
            access,
        }
    }

    fn token() -> String {
        Entry::new(KEYCHAIN_SERVICE, "daemon-token")
            .expect("entry")
            .get_password()
            .expect("the daemon token is in the keychain")
    }

    fn written(service: Service, home: &Path) -> PathBuf {
        match service {
            Service::Launchd => launchd::plist_path(home),
            Service::Systemd => systemd::unit_path(home),
        }
    }

    #[tokio::test]
    async fn install_prints_claude_add_with_header() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        for service in [Service::Launchd, Service::Systemd] {
            let home = tempfile::tempdir().expect("temp home");
            let run = Fake::new().answering("id -u", ok("501\n"));
            let mut out = Vec::new();
            install(
                service,
                &spec(Access::ReadWrite),
                home.path(),
                &run,
                &mut out,
            )
            .expect("installs");
            let printed = String::from_utf8(out).expect("text");
            let expected = format!(
                "claude mcp add --transport http ibridge http://127.0.0.1:8765/mcp --header \"Authorization: Bearer {}\"",
                token()
            );
            assert!(
                printed.lines().any(|line| line.trim() == expected),
                "{service:?}: the setup line with the bearer header is printed, got:\n{printed}"
            );
            assert!(
                written(service, home.path()).is_file(),
                "{service:?}: the service definition is written"
            );
            let calls = run.calls();
            let started = match service {
                Service::Launchd => "launchctl bootstrap",
                Service::Systemd => "systemctl --user enable --now ibridge.service",
            };
            assert!(
                calls.iter().any(|call| call.starts_with(started)),
                "{service:?}: the service is started with `{started}`, got {calls:?}"
            );
        }
    }

    #[tokio::test]
    async fn install_twice_keeps_one_token() {
        let _turn = KEYCHAIN.lock().await;
        mock_keychain();
        let home = tempfile::tempdir().expect("temp home");
        let run = Fake::new().answering("id -u", ok("501\n"));
        install(
            Service::Systemd,
            &spec(Access::ReadWrite),
            home.path(),
            &run,
            &mut Vec::new(),
        )
        .expect("first install");
        let first = token();
        install(
            Service::Systemd,
            &spec(Access::ReadWrite),
            home.path(),
            &run,
            &mut Vec::new(),
        )
        .expect("second install");
        assert_eq!(token(), first, "a second install reuses the token");
    }

    #[tokio::test]
    async fn uninstall_removes_the_definition_and_stops_the_service() {
        for service in [Service::Launchd, Service::Systemd] {
            let home = tempfile::tempdir().expect("temp home");
            let run = Fake::new().answering("id -u", ok("501\n"));
            let path = written(service, home.path());
            std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
            std::fs::write(&path, "x").expect("definition");
            match service {
                Service::Launchd => launchd::uninstall(home.path(), &run),
                Service::Systemd => systemd::uninstall(home.path(), &run),
            }
            .expect("uninstalls");
            assert!(!path.exists(), "{service:?}: the definition is removed");
            let stopped = match service {
                Service::Launchd => "launchctl bootout",
                Service::Systemd => "systemctl --user disable --now ibridge.service",
            };
            assert!(
                run.calls().iter().any(|call| call.starts_with(stopped)),
                "{service:?}: the service is stopped with `{stopped}`, got {:?}",
                run.calls()
            );
        }
    }

    #[tokio::test]
    async fn status_tells_running_stopped_and_missing_apart() {
        let home = tempfile::tempdir().expect("temp home");
        let missing = Fake::new()
            .answering("id -u", ok("501\n"))
            .answering("launchctl print", failed());
        assert_eq!(
            launchd::status(home.path(), &missing).expect("status"),
            Status::NotInstalled,
            "launchd does not know the agent"
        );
        let stopped = Fake::new()
            .answering("id -u", ok("501\n"))
            .answering("launchctl print", ok("state = waiting"));
        assert_eq!(
            launchd::status(home.path(), &stopped).expect("status"),
            Status::Stopped,
            "launchd knows the agent but it is not running"
        );
        let running = Fake::new()
            .answering("id -u", ok("501\n"))
            .answering("launchctl print", ok("state = running"));
        assert_eq!(
            launchd::status(home.path(), &running).expect("status"),
            Status::Running,
            "launchd says it is running"
        );

        let unit = systemd::unit_path(home.path());
        assert_eq!(
            systemd::status(home.path(), &Fake::new()).expect("status"),
            Status::NotInstalled,
            "no unit file"
        );
        std::fs::create_dir_all(unit.parent().expect("parent")).expect("dirs");
        std::fs::write(&unit, "x").expect("unit");
        assert_eq!(
            systemd::status(
                home.path(),
                &Fake::new().answering("systemctl --user is-active", ok("inactive\n"))
            )
            .expect("status"),
            Status::Stopped,
            "a unit file with an inactive service"
        );
        assert_eq!(
            systemd::status(
                home.path(),
                &Fake::new().answering("systemctl --user is-active", ok("active\n"))
            )
            .expect("status"),
            Status::Running,
            "an active service"
        );
    }
}
