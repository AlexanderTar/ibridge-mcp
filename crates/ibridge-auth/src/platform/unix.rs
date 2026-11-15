// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

/// Owner read/write only. Other bits, including group and world, are refused.
pub(crate) fn is_mode_0600(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.permissions().mode() & 0o777 == 0o600
}
