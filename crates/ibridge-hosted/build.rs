// SPDX-License-Identifier: Apache-2.0

//! Turns on `cfg(apple_logo)` when `assets/apple-logo.svg` exists.
//!
//! Apple's Sign in with Apple logo is licensed artwork, so the repository does not ship it.
//! Adding the file is the only step that gives the button its logo; without it the button is
//! text-only.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(apple_logo)");
    println!("cargo::rerun-if-changed=assets");
    if std::path::Path::new("assets/apple-logo.svg").exists() {
        println!("cargo::rustc-cfg=apple_logo");
    }
}
