//! TLS support for the management API (HTTPS) and encrypted DNS upstreams
//! (DNS-over-TLS, RFC 7858).
//!
//! Rustls uses the `ring` provider. Management TLS is all-or-nothing: the API
//! listener is either plain HTTP (for a reverse proxy) or HTTPS with the
//! configured certificate, never a silent downgrade. DoT upstreams validate
//! the configured `tls_server_name` against the bundled WebPKI roots or an
//! explicit operator CA bundle.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Bound the TLS handshake so slow clients cannot pin listener resources.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Load a PEM certificate chain and private key into a rustls server config.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("open TLS certificate {}", cert_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .with_context(|| format!("parse TLS certificate {}", cert_path.display()))?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        return Err(anyhow!(
            "TLS certificate file {} contains no certificates",
            cert_path.display()
        ));
    }

    let key_file = File::open(key_path)
        .with_context(|| format!("open TLS private key {}", key_path.display()))?;
    let key = read_private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("parse TLS private key {}", key_path.display()))?
        .ok_or_else(|| {
            anyhow!(
                "TLS private key file {} contains no supported private key",
                key_path.display()
            )
        })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and private key do not form a valid TLS identity")?;
    Ok(Arc::new(config))
}

fn read_private_key(
    reader: &mut dyn std::io::BufRead,
) -> std::io::Result<Option<PrivateKeyDer<'static>>> {
    loop {
        match rustls_pemfile::read_one(reader)? {
            None => return Ok(None),
            Some(rustls_pemfile::Item::RSAKey(key)) => {
                return Ok(Some(PrivateKeyDer::Pkcs1(key.into())))
            }
            Some(rustls_pemfile::Item::PKCS8Key(key)) => {
                return Ok(Some(PrivateKeyDer::Pkcs8(key.into())))
            }
            Some(rustls_pemfile::Item::ECKey(key)) => {
                return Ok(Some(PrivateKeyDer::Sec1(key.into())))
            }
            Some(_) => continue,
        }
    }
}

/// Load the trust anchors for a DoT upstream. `ca_file` is an operator PEM
/// bundle; `None` uses the bundled public roots. An empty bundle is an error,
/// never an implicit "trust everything".
pub fn upstream_roots(ca_file: Option<&Path>) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let file = File::open(path)
                .with_context(|| format!("open TLS CA bundle {}", path.display()))?;
            let certs = rustls_pemfile::certs(&mut BufReader::new(file))
                .with_context(|| format!("parse TLS CA bundle {}", path.display()))?;
            if certs.is_empty() {
                return Err(anyhow!(
                    "TLS CA bundle {} contains no certificates",
                    path.display()
                ));
            }
            for cert in certs {
                roots
                    .add(CertificateDer::from(cert))
                    .with_context(|| format!("invalid CA certificate in {}", path.display()))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(roots)
}

/// Build a client config that trusts exactly `ca_file` (or the public roots)
/// and performs normal hostname/IP certificate verification.
pub fn upstream_client_config(ca_file: Option<&Path>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let roots = upstream_roots(ca_file)?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Axum listener that accepts TCP and completes a server-side TLS handshake
/// before yielding the stream. Failed/timeout handshakes are dropped and the
/// accept loop continues (the `Listener` contract forbids returning errors).
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner,
            acceptor: TlsAcceptor::from(config),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(event = "tls_accept_error", error = %e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return (tls, addr),
                Ok(Err(e)) => {
                    tracing::debug!(event = "tls_handshake_failed", client = %addr, error = %e);
                }
                Err(_) => {
                    tracing::debug!(event = "tls_handshake_timeout", client = %addr);
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
