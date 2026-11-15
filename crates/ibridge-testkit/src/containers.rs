// SPDX-License-Identifier: Apache-2.0

//! Testcontainer wrappers for the Docker-backed suites.

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ContainerRequest, GenericImage, ImageExt};

/// Host port Radicale listens on inside the container.
const RADICALE_PORT: u16 = 5232;

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

/// A Radicale container that stays stopped until [`Radicale::start`].
#[derive(Debug)]
pub struct Radicale;

/// A running Radicale. Dropping it stops the container.
pub struct RunningRadicale {
    url: String,
    /// Keeps the container running until this value is dropped.
    _container: ContainerAsync<GenericImage>,
}

impl std::fmt::Debug for RunningRadicale {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningRadicale")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl Radicale {
    /// Launch Radicale and return its base URL.
    ///
    /// The image allows any username and does not check the password. The
    /// caller still sends its own credentials; Radicale uses the username as
    /// the collection owner.
    ///
    /// # Errors
    ///
    /// Returns an error when Docker cannot start the container or it does not
    /// become ready.
    pub async fn start(self) -> Result<RunningRadicale, String> {
        let _ = self;
        let container = GenericImage::new("tomsquest/docker-radicale", "3.9.1.1")
            .with_exposed_port(RADICALE_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stderr("Radicale server ready"))
            .start()
            .await
            .map_err(|error| error.to_string())?;
        let port = container
            .get_host_port_ipv4(RADICALE_PORT)
            .await
            .map_err(|error| error.to_string())?;
        Ok(RunningRadicale {
            url: format!("http://127.0.0.1:{port}/"),
            _container: container,
        })
    }
}

impl RunningRadicale {
    /// Base URL, including the mapped host port, with a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.url
    }
}

/// Build a Radicale container. Calling this does not start Docker.
pub fn radicale() -> Radicale {
    Radicale
}
