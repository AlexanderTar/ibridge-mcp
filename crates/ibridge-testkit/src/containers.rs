// SPDX-License-Identifier: Apache-2.0

//! Testcontainer wrappers for the Docker-backed suites.

/// Start a `GreenMail` container. The image wiring lands with the mail tests.
#[expect(
    clippy::missing_const_for_fn,
    reason = "starts a container once the image wiring lands"
)]
pub fn greenmail() {}

/// Start a Radicale container. The image wiring lands with the calendar tests.
#[expect(
    clippy::missing_const_for_fn,
    reason = "starts a container once the image wiring lands"
)]
pub fn radicale() {}
