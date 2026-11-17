// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

/// Windows has no `0600` mode, so a credential file is never accepted.
pub(crate) fn is_mode_0600(path: &Path) -> bool {
    let _ = path;
    false
}
