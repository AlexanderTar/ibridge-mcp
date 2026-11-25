// SPDX-License-Identifier: Apache-2.0

//! A TLS server on loopback with a throwaway certificate authority, for clients that must
//! check a certificate against a host name.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// What the fake does after it has read a request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum TlsReply {
    /// Writes these bytes, then closes.
    Bytes(Vec<u8>),
    /// Reads the request and never answers.
    Hang,
}

/// A TLS server on `127.0.0.1` that records the raw bytes of each request.
#[derive(Debug)]
pub struct TlsFake {
    addr: SocketAddr,
    root: Vec<u8>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<Mutex<usize>>,
}

impl TlsFake {
    /// Starts a server whose certificate is valid for `host` only and signed by a
    /// certificate authority that exists only in this fake.
    ///
    /// # Panics
    ///
    /// Panics when the certificate cannot be made or the port cannot be bound.
    pub async fn start(host: &str, reply: TlsReply) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca certificate");
        let ca_der = ca.der().to_vec();
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::new(vec![host.to_owned()])
            .expect("leaf params")
            .signed_by(&leaf_key, &Issuer::new(ca_params, ca_key))
            .expect("leaf certificate");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(0));
        let (seen, counted) = (Arc::clone(&requests), Arc::clone(&connections));
        tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                *counted.lock().expect("connections lock") += 1;
                let (acceptor, reply, seen) = (acceptor.clone(), reply.clone(), Arc::clone(&seen));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let request = read_request(&mut tls).await;
                    seen.lock().expect("requests lock").push(request);
                    match reply {
                        TlsReply::Bytes(bytes) => {
                            let _ = tls.write_all(&bytes).await;
                            let _ = tls.shutdown().await;
                        }
                        TlsReply::Hang => std::future::pending::<()>().await,
                    }
                });
            }
        });
        Self {
            addr,
            root: ca_der,
            requests,
            connections,
        }
    }

    /// The port the fake listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The DER bytes of the certificate authority a client must trust.
    #[must_use]
    pub fn root_der(&self) -> Vec<u8> {
        self.root.clone()
    }

    /// The raw bytes of every request read so far, headers and body.
    ///
    /// # Panics
    ///
    /// Panics when the lock is poisoned.
    #[must_use]
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("requests lock").clone()
    }

    /// How many TCP connections the fake accepted, including ones that failed the handshake.
    ///
    /// # Panics
    ///
    /// Panics when the lock is poisoned.
    #[must_use]
    pub fn connections(&self) -> usize {
        *self.connections.lock().expect("connections lock")
    }
}

/// Reads the head and as much body as `Content-Length` announces.
async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let Ok(read) = stream.read(&mut chunk).await else {
            return bytes;
        };
        if read == 0 {
            return bytes;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return bytes;
            }
        }
    }
}
