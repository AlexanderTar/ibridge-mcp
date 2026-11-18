// SPDX-License-Identifier: Apache-2.0

//! Workspace maintenance tasks.

mod docs;
mod live_hosted;
mod mcpb;
mod record_calendar;
mod record_contacts;
mod record_fixtures;
mod registry;
mod scrub;

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const SPDX_HEADER: &str = "// SPDX-License-Identifier: Apache-2.0";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("check-headers") => report(check_headers(&headers_root())),
        Some("record-fixtures") => run_record_fixtures(args),
        Some("mcpb") => match mcpb::run(&headers_root(), args) {
            Ok(bundles) => report_paths(&bundles),
            Err(error) => fail(&format!("mcpb: {error}")),
        },
        Some("check-docs") => match docs::check(&headers_root()) {
            Ok(problems) if problems.is_empty() => report_message("docs ok"),
            Ok(problems) => fail(&problems.join("\n")),
            Err(error) => fail(&format!("check-docs: {error}")),
        },
        Some("registry") => match registry::run(&headers_root(), args) {
            Ok(message) => report_message(&message),
            Err(error) => fail(&format!("registry: {error}")),
        },
        Some("live-hosted-check") => run_live_hosted_check(args),
        Some("schema-snapshot") => ExitCode::from(2),
        Some(command) => fail(&format!("unknown command: {command}")),
        None => fail(
            "usage: cargo xtask <check-headers|check-docs|record-fixtures|schema-snapshot|mcpb|registry|live-hosted-check>",
        ),
    }
}

/// `live-hosted-check --url URL [--account FILE]`.
///
/// Signs in to the hosted server at `URL` with the test account the way a client does,
/// then calls `account_status`, and prints one line per step. The account file defaults
/// to `~/.config/ibridge/test-account.env`. The password is never printed.
fn run_live_hosted_check(mut args: impl Iterator<Item = String>) -> ExitCode {
    const USAGE: &str =
        "usage: cargo xtask live-hosted-check --url <https://host> [--account FILE]";
    let mut url = None;
    let mut account = env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/ibridge/test-account.env"));
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            ("--url", Some(value)) => url = Some(value),
            ("--account", Some(value)) => account = Some(PathBuf::from(value)),
            _ => return fail(USAGE),
        }
    }
    let (Some(url), Some(account)) = (url, account) else {
        return fail(USAGE);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(&format!("live-hosted-check: {error}")),
    };
    match runtime.block_on(live_hosted::run(&url, &account, &mut io::stdout())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("live-hosted-check: {error}")),
    }
}

/// `record-fixtures mail|calendar|contacts [--account FILE] [--out DIR] [--check]`.
///
/// The account file defaults to `~/.config/ibridge/test-account.env`. Output goes
/// to `tests/fixtures/imap`, `tests/fixtures/caldav` or `tests/fixtures/carddav`,
/// where the user reviews the diff before committing. `--check` is for `calendar`
/// only: it lists the `ibridge-test` calendar and list and writes nothing.
/// `contacts` creates one marker contact, records it and deletes it again.
fn run_record_fixtures(mut args: impl Iterator<Item = String>) -> ExitCode {
    const USAGE: &str = "usage: cargo xtask record-fixtures <mail|calendar|contacts> [--account FILE] [--out DIR] [--check]";
    let mut kind = match args.next().as_deref() {
        Some("mail") => Kind::Mail,
        Some("calendar") => Kind::Calendar,
        Some("contacts") => Kind::Contacts,
        _ => return fail(USAGE),
    };
    let mut account = env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/ibridge/test-account.env"));
    let mut out = headers_root().join(match kind {
        Kind::Mail => "tests/fixtures/imap",
        Kind::Calendar | Kind::CalendarCheck => "tests/fixtures/caldav",
        Kind::Contacts => "tests/fixtures/carddav",
    });
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--account" => match args.next() {
                Some(path) => account = Some(PathBuf::from(path)),
                None => return fail(USAGE),
            },
            "--out" => match args.next() {
                Some(path) => out = PathBuf::from(path),
                None => return fail(USAGE),
            },
            "--check" if kind == Kind::Calendar => kind = Kind::CalendarCheck,
            _ => return fail(USAGE),
        }
    }
    let Some(account) = account else {
        return fail("record-fixtures: HOME is not set; pass --account FILE");
    };
    let mut random = [0_u8; 8];
    if let Err(error) = getrandom::fill(&mut random) {
        return fail(&format!("record-fixtures: no random bytes: {error}"));
    }
    let nonce = format!("{:016x}", u64::from_le_bytes(random));
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(&format!("record-fixtures: {error}")),
    };
    let result = match kind {
        Kind::Mail => record_mail(&runtime, &account, &out, &nonce),
        Kind::Calendar => record_calendar(&runtime, &account, &out, &nonce),
        Kind::CalendarCheck => check_calendar(&runtime, &account),
        Kind::Contacts => record_contacts(&runtime, &account, &out, &nonce),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("record-fixtures: {error}")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Mail,
    Calendar,
    Contacts,
    /// Lists the test calendar and list and writes nothing.
    CalendarCheck,
}

fn record_mail(
    runtime: &tokio::runtime::Runtime,
    account: &Path,
    out: &Path,
    nonce: &str,
) -> Result<(), record_fixtures::RecordError> {
    let connector =
        ibridge_mail::IcloudConnect::new().map_err(|_| record_fixtures::RecordError::Connect)?;
    let wait = record_fixtures::Wait {
        attempts: 12,
        delay: Duration::from_secs(5),
    };
    runtime.block_on(record_fixtures::run_mail(
        account,
        &connector,
        record_fixtures::SmtpSender::new,
        out,
        wait,
        nonce,
        &mut io::stdout(),
    ))
}

/// A client for one account. `CalendarCheck` and `Calendar` each build their own.
fn dav_client(
    credentials: &ibridge_auth::Credentials,
) -> Result<ibridge_dav::DavClient, ibridge_dav::DavError> {
    ibridge_dav::DavClient::new(credentials.duplicate())
}

fn record_calendar(
    runtime: &tokio::runtime::Runtime,
    account: &Path,
    out: &Path,
    nonce: &str,
) -> Result<(), record_fixtures::RecordError> {
    runtime.block_on(record_calendar::run_calendar(
        account,
        dav_client,
        out,
        nonce,
        &mut io::stdout(),
    ))
}

fn record_contacts(
    runtime: &tokio::runtime::Runtime,
    account: &Path,
    out: &Path,
    nonce: &str,
) -> Result<(), record_fixtures::RecordError> {
    runtime.block_on(record_contacts::run_contacts(
        account,
        dav_client,
        out,
        nonce,
        &mut io::stdout(),
    ))
}

fn check_calendar(
    runtime: &tokio::runtime::Runtime,
    account: &Path,
) -> Result<(), record_fixtures::RecordError> {
    runtime.block_on(record_calendar::check_calendar(
        account,
        dav_client,
        &mut io::stdout(),
    ))
}

#[expect(
    clippy::print_stderr,
    reason = "xtask lists the files it wrote on stderr"
)]
fn report_paths(paths: &[PathBuf]) -> ExitCode {
    for path in paths {
        eprintln!("{}", path.display());
    }
    ExitCode::SUCCESS
}

#[expect(
    clippy::print_stderr,
    reason = "xtask reports the outcome of a check on stderr"
)]
fn report_message(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::SUCCESS
}

#[expect(
    clippy::print_stderr,
    reason = "xtask reports header failures and command errors on stderr"
)]
fn fail(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(2)
}

#[expect(
    clippy::print_stderr,
    reason = "xtask reports header failures and command errors on stderr"
)]
fn report(result: io::Result<Vec<PathBuf>>) -> ExitCode {
    match result {
        Ok(missing) if missing.is_empty() => ExitCode::SUCCESS,
        Ok(missing) => {
            for path in &missing {
                eprintln!("{}", path.display());
            }
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("check-headers: {error}");
            ExitCode::from(1)
        }
    }
}

fn headers_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member")
        .to_path_buf()
}

fn check_headers(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "target" || name == ".git" {
                continue;
            }
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                dirs.push(path);
                continue;
            }
            let is_rust = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
            if is_rust && !has_header(&path)? {
                missing.push(path);
            }
        }
    }
    missing.sort();
    Ok(missing)
}

fn has_header(path: &Path) -> io::Result<bool> {
    let text = fs::read_to_string(path)?;
    Ok(text.lines().next() == Some(SPDX_HEADER))
}

#[cfg(test)]
mod tests {
    use super::{check_headers, headers_root};
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn missing_spdx_header_is_reported() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ibridge-headers-{nanos}"));
        let _guard = RemoveDir(root.clone());
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("bare.rs"), "fn bare() {}\n").unwrap();
        fs::write(
            root.join("ok.rs"),
            "// SPDX-License-Identifier: Apache-2.0\n\nfn ok() {}\n",
        )
        .unwrap();

        let missing = check_headers(&root).unwrap();

        assert_eq!(missing, vec![root.join("nested").join("bare.rs")]);
    }

    #[test]
    fn header_scan_root_is_the_workspace_from_a_child_directory() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap();
        let _restore = Restore(env::current_dir().unwrap());
        env::set_current_dir(workspace.join("crates")).unwrap();

        let root = headers_root().canonicalize().unwrap();

        assert_eq!(root, workspace);
    }

    struct Restore(PathBuf);

    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.0);
        }
    }

    struct RemoveDir(PathBuf);

    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
