// SPDX-License-Identifier: Apache-2.0

//! Workspace maintenance tasks.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const SPDX_HEADER: &str = "// SPDX-License-Identifier: Apache-2.0";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("check-headers") => report(check_headers(Path::new("."))),
        Some("record-fixtures" | "schema-snapshot" | "mcpb") => ExitCode::from(2),
        Some(command) => fail(&format!("unknown command: {command}")),
        None => fail("usage: cargo xtask <check-headers|record-fixtures|schema-snapshot|mcpb>"),
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
    use super::check_headers;
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

    struct RemoveDir(PathBuf);

    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
