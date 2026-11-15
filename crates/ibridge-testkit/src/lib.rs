// SPDX-License-Identifier: Apache-2.0

//! Scripted protocol fakes, fixtures and test containers.

pub mod containers;
pub mod dav_mock;
pub mod fixtures;
pub mod imap_fake;

#[cfg(test)]
mod tests {
    #[test]
    fn container_stubs_are_callable() {
        crate::containers::greenmail();
        crate::containers::radicale();
    }
}
