// SPDX-License-Identifier: Apache-2.0

//! Turns on `cfg(apple_logo)` when both Sign in with Apple logo files exist.
//!
//! Apple's logo is Apple's own artwork (not under the project's licence; see `assets/NOTICE`)
//! and is committed unmodified from Apple's logo-only set: `assets/apple-logo-white.svg` (for
//! the black button) and `assets/apple-logo-black.svg` (for the white one). A self-hoster may
//! delete them; without both, the button is text-only.

const LOGO_FILES: [&str; 2] = ["assets/apple-logo-white.svg", "assets/apple-logo-black.svg"];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(apple_logo)");
    println!("cargo::rerun-if-changed=assets");
    if LOGO_FILES.iter().all(|f| std::path::Path::new(f).exists()) {
        println!("cargo::rustc-cfg=apple_logo");
    }
}
