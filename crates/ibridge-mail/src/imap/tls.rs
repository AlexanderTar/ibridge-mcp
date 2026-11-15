// SPDX-License-Identifier: Apache-2.0

//! TLS connector for `imap.mail.me.com:993`.

use std::future::Future;
use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::pool::Connect;

const HOST: &str = "imap.mail.me.com";
const PORT: u16 = 993;

/// Implicit-TLS connection to iCloud IMAP.
///
/// The host is fixed, so the app-specific password can only reach
/// `imap.mail.me.com`. Certificates are checked against the system roots.
#[derive(Clone)]
pub struct IcloudConnect {
    tls: TlsConnector,
}

impl std::fmt::Debug for IcloudConnect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IcloudConnect")
            .finish_non_exhaustive()
    }
}

impl IcloudConnect {
    /// Loads the system root certificates.
    ///
    /// # Errors
    ///
    /// Returns an error when no usable root certificate is installed.
    pub fn new() -> io::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(io::Error::other("no system root certificates"));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
        })
    }
}

impl Connect for IcloudConnect {
    type Stream = TlsStream<TcpStream>;

    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        let tls = self.tls.clone();
        async move {
            let tcp = TcpStream::connect((HOST, PORT)).await?;
            let name = ServerName::try_from(HOST).map_err(io::Error::other)?;
            tls.connect(name, tcp).await
        }
    }
}
