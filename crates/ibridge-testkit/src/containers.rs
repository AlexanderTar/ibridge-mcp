// SPDX-License-Identifier: Apache-2.0

//! Testcontainer wrappers for the Docker-backed suites.

/// Start a `GreenMail` container. The image wiring lands with the mail tests.
pub fn greenmail() {}

/// Start a Radicale container. The image wiring lands with the calendar tests.
pub fn radicale() {}
