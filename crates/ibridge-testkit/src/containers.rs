// SPDX-License-Identifier: Apache-2.0

//! Testcontainer wrappers for the Docker-backed suites.

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::{ContainerRequest, GenericImage, ImageExt};

/// `GreenMail` on IMAP port 3143 for `ada@icloud.com`. Building the request does not start Docker.
pub fn greenmail() -> ContainerRequest<GenericImage> {
    GenericImage::new("greenmail/standalone", "2.1.15")
        .with_exposed_port(3143.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Starting GreenMail API server"))
        .with_env_var(
            "GREENMAIL_OPTS",
            "-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=ada:test-secret@icloud.com -Dgreenmail.users.login=email",
        )
}

/// Start a Radicale container. The image wiring lands with the calendar tests.
pub fn radicale() {}
