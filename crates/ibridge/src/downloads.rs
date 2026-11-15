// SPDX-License-Identifier: Apache-2.0

//! Where `mail_save_attachment` puts files.

use std::ffi::OsString;
use std::path::PathBuf;

/// The download folder: `IBRIDGE_DOWNLOAD_DIR` when set, else `~/Downloads/ibridge`.
///
/// `None` when neither the variable nor a home folder is known. Then the tool is not offered.
pub(crate) fn dir() -> Option<PathBuf> {
    resolve(
        std::env::var_os("IBRIDGE_DOWNLOAD_DIR"),
        std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")),
    )
}

fn resolve(configured: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let present = |value: Option<OsString>| value.filter(|value| !value.is_empty());
    match (present(configured), present(home)) {
        (Some(dir), _) => Some(PathBuf::from(dir)),
        (None, Some(home)) => Some(PathBuf::from(home).join("Downloads").join("ibridge")),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::resolve;

    #[test]
    fn download_dir_follows_the_setting_then_the_home_folder() {
        assert_eq!(
            resolve(Some("/data/files".into()), Some("/home/ada".into())),
            Some(PathBuf::from("/data/files")),
            "the setting wins"
        );
        assert_eq!(
            resolve(None, Some("/home/ada".into())),
            Some(PathBuf::from("/home/ada/Downloads/ibridge")),
            "the default is under Downloads"
        );
        assert_eq!(
            resolve(Some("".into()), Some("/home/ada".into())),
            Some(PathBuf::from("/home/ada/Downloads/ibridge")),
            "an empty setting is no setting"
        );
        assert_eq!(resolve(None, None), None, "no home, no folder");
        assert_eq!(
            resolve(None, Some("".into())),
            None,
            "an empty home is no home"
        );
    }
}
