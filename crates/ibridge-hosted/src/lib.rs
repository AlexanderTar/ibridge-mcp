// SPDX-License-Identifier: Apache-2.0

//! Hosted OAuth server and token-sealed credential store.

mod store;

pub use store::{RedactingFields, Store, StoreError, ValidatedCredentials, redact};
