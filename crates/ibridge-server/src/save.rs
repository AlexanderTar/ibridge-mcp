// SPDX-License-Identifier: Apache-2.0

//! Writing a saved attachment into the download folder.

use std::io::Write as _;
use std::path::{Path, PathBuf};

const MAX_NAME_CHARS: usize = 120;
const MAX_EXTENSION_CHARS: usize = 16;
/// Names Windows will not create as files, whatever their extension.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A file name that is safe to create in the download folder.
///
/// The name comes from a message, so it is untrusted: it may carry a path, control
/// characters, a leading dot or a name Windows reserves. Only the last path part
/// is kept. An empty result becomes `attachment-<part>`.
pub(crate) fn safe_name(name: &str, part: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let replaced: String = last
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = replaced
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' ']);
    let mut kept = shorten(trimmed);
    if kept.is_empty() {
        let id: String = part.chars().filter(char::is_ascii_alphanumeric).collect();
        return format!("attachment-{id}");
    }
    let stem = kept.split('.').next().unwrap_or_default();
    if RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        kept.insert(0, '_');
    }
    kept
}

/// `name` cut to [`MAX_NAME_CHARS`], cutting the part before the extension.
fn shorten(name: &str) -> String {
    if name.chars().count() <= MAX_NAME_CHARS {
        return name.to_owned();
    }
    match name.rfind('.') {
        Some(dot) if dot > 0 && name[dot..].chars().count() <= MAX_EXTENSION_CHARS => {
            let extension = &name[dot..];
            let room = MAX_NAME_CHARS - extension.chars().count();
            let stem: String = name[..dot].chars().take(room).collect();
            format!("{stem}{extension}")
        }
        _ => name.chars().take(MAX_NAME_CHARS).collect(),
    }
}

/// Writes `bytes` to a new file named `name` in `dir`, creating `dir` first.
///
/// An existing file is never replaced: the name gets ` (1)`, ` (2)` and so on
/// before its extension.
pub(crate) fn save_unique(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    for number in 0_u32..1000 {
        let candidate = if number == 0 {
            name.to_owned()
        } else {
            format!("{stem} ({number}){extension}")
        };
        let path = dir.join(candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "too many files with that name",
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{safe_name, save_unique};

    #[test]
    fn safe_name_keeps_only_a_plain_file_name() {
        for (given, expected) in [
            ("report.pdf", "report.pdf"),
            ("../../evil name.txt", "evil name.txt"),
            ("C:\\Users\\ada\\notes.txt", "notes.txt"),
            ("/etc/passwd", "passwd"),
            (".bashrc", "bashrc"),
            ("  spaced.txt  ", "spaced.txt"),
            ("a<b>:c\"d|e?f*g.txt", "a_b__c_d_e_f_g.txt"),
            ("tab\there\u{0}.txt", "tab_here_.txt"),
            ("CON", "_CON"),
            ("nul.txt", "_nul.txt"),
            ("trailing. .", "trailing"),
            ("", "attachment-3"),
            ("..", "attachment-3"),
            ("dir/", "attachment-3"),
            ("héllo wörld.txt", "héllo wörld.txt"),
        ] {
            assert_eq!(safe_name(given, "3"), expected, "for {given:?}");
        }
        let long = format!("{}.txt", "a".repeat(300));
        let cut = safe_name(&long, "3");
        assert!(
            cut.chars().count() <= 120
                && Path::new(&cut).extension().is_some_and(|ext| ext == "txt"),
            "a long name is shortened and keeps its extension, got {cut:?}"
        );
    }

    #[test]
    fn save_unique_numbers_a_name_that_is_taken() {
        let dir = tempfile::tempdir().expect("temp dir");
        let nested = dir.path().join("a").join("b");
        let first =
            save_unique(&nested, "x.tar.gz", b"one").expect("first save creates the folder");
        let second = save_unique(&nested, "x.tar.gz", b"two").expect("second save");
        let bare = save_unique(&nested, "noext", b"1").expect("no extension");
        let bare_again = save_unique(&nested, "noext", b"2").expect("no extension again");
        let names: Vec<_> = [&first, &second, &bare, &bare_again]
            .iter()
            .map(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .expect("name")
                    .to_owned()
            })
            .collect();
        assert_eq!(names, ["x.tar.gz", "x.tar (1).gz", "noext", "noext (1)"]);
        assert_eq!(std::fs::read(&first).expect("first"), b"one");
        assert_eq!(std::fs::read(&second).expect("second"), b"two");
    }
}
