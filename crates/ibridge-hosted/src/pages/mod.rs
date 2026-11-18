// SPDX-License-Identifier: Apache-2.0

//! The pages people read and use: the account page, and the landing, privacy and terms pages.

pub(crate) mod account;
#[cfg(test)]
mod account_apple_tests;
#[cfg(test)]
mod account_delete_tests;
mod delete;
pub(crate) mod landing;
pub(crate) mod signin;
#[cfg(test)]
pub(crate) mod test_rig;
