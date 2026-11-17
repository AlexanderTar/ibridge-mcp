// SPDX-License-Identifier: Apache-2.0

//! Operating-system checks for credential files.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::is_mode_0600;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::is_mode_0600;
