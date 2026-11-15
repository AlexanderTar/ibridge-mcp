// SPDX-License-Identifier: Apache-2.0

//! Workspace maintenance tasks.

mod record_fixtures;
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
        Some("schema-snapshot" | "mcpb") => ExitCode::from(2),
        Some(command) => fail(&format!("unknown command: {command}")),
        None => fail("usage: cargo xtask <check-headers|record-fixtures|schema-snapshot|mcpb>"),
    }
}

/// `record-fixtures mail [--account FILE] [--out DIR]`.
///
/// The account file defaults to `~/.config/ibridge/test-account.env`. Output goes
/// to `tests/fixtures/imap`, where the user reviews the diff before committing.
fn run_record_fixtures(mut args: impl Iterator<Item = String>) -> ExitCode {
    const USAGE: &str = "usage: cargo xtask record-fixtures mail [--account FILE] [--out DIR]";
    if args.next().as_deref() != Some("mail") {
        return fail(USAGE);
    }
    let mut account = env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/ibridge/test-account.env"));
    let mut out = headers_root().join("tests/fixtures/imap");
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            ("--account", Some(path)) => account = Some(PathBuf::from(path)),
            ("--out", Some(path)) => out = PathBuf::from(path),
            _ => return fail(USAGE),
        }
    }
    let Some(account) = account else {
        return fail("record-fixtures: HOME is not set; pass --account FILE");
    };
    let connector = match ibridge_mail::IcloudConnect::new() {
        Ok(connector) => connector,
        Err(error) => return fail(&format!("record-fixtures: {error}")),
    };
    let wait = record_fixtures::Wait {
        attempts: 12,
        delay: Duration::from_secs(5),
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
    let result = runtime.block_on(record_fixtures::run_mail(
        &account,
        &connector,
        record_fixtures::SmtpSender::new,
        &out,
        wait,
        &nonce,
        &mut io::stdout(),
    ));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("record-fixtures: {error}")),
    }
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
