use super::tls_proxy::auto_stream;
use super::to_socket_addr;
use super::Error;
use super::HttpsTransport;
use super::TlsTransport;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))]
fn stream_nativetls(
    domain: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<native_tls::TlsStream<TcpStream>, Error> {
    let connector = native_tls::TlsConnector::new()?;
    let stream = auto_stream(domain, port, timeout)?;

    Ok(connector.connect(domain, stream)?)
}

#[cfg(feature = "with_rustls")]
fn stream_rustls(
    domain: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
    use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};
    use rustls_pki_types;
    use std::{convert::TryFrom, sync::Arc};

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: provider::DEFAULT_CIPHER_SUITES.to_vec(),
            ..provider::default_provider()
        }
        .into(),
    )
    .with_protocol_versions(&rustls::DEFAULT_VERSIONS.to_vec())
    .expect("inconsistent cipher-suite/versions selected")
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let dns_name = rustls_pki_types::ServerName::try_from(domain.to_string())?;

    let conn = rustls::ClientConnection::new(Arc::new(config), dns_name)?;

    let sock_addr = to_socket_addr(domain, port)?;
    let sock = match timeout {
        None => TcpStream::connect(&sock_addr)?,
        Some(t) => TcpStream::connect_timeout(&sock_addr, t)?,
    };
    let tls = rustls::StreamOwned::new(conn, sock);

    Ok(tls)
}

pub trait TlsStream<S: std::io::Read + std::io::Write> {
    fn stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<S, Error>;
}

#[cfg(any(feature = "with_tls", feature = "with_https"))]
cfg_if::cfg_if! {
    if #[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))] {

        impl TlsStream<native_tls::TlsStream<TcpStream>> for HttpsTransport {
            fn stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<native_tls::TlsStream<TcpStream>, Error> {
                stream_nativetls(domain, port, timeout)
            }
        }

        impl TlsStream<native_tls::TlsStream<TcpStream>> for TlsTransport {
            fn stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<native_tls::TlsStream<TcpStream>, Error> {
                stream_nativetls(domain, port, timeout)
            }
        }

    } else if #[cfg(feature = "with_rustls")] {

        impl TlsStream<rustls::StreamOwned<rustls::ClientConnection,TcpStream>> for HttpsTransport {
            fn stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<rustls::StreamOwned<rustls::ClientConnection,TcpStream>, Error> {
                stream_rustls(domain, port, timeout)
            }
        }

        impl TlsStream<rustls::StreamOwned<rustls::ClientConnection,TcpStream>> for TlsTransport {
            fn stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<rustls::StreamOwned<rustls::ClientConnection,TcpStream>, Error> {
                stream_rustls(domain, port, timeout)
            }
        }

    } else {
        unreachable!("tls/https enabled but no tls implementation provided")
    }
}
