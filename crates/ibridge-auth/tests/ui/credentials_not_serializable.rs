// SPDX-License-Identifier: Apache-2.0

//! `Credentials` must not implement `Serialize`.

use ibridge_auth::Credentials;
use serde::Serialize;

fn assert_serialize<T: Serialize>() {}

fn main() {
    assert_serialize::<Credentials>();
}
