#![cfg_attr(not(feature = "with_https"), allow(unused))]

use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};

/// The **HTTPS transport**, which sends DNS wire data inside HTTP packets
/// encrypted with TLS, using TCP.
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL.
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl Transport for HttpsTransport {

    #[cfg(any(feature = "with_https"))]
    fn send(&self, request: &Request, timeout: Option<Duration>) -> Result<Response, Error> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()?;

        debug!("Connected");

        let request_bytes = request.to_bytes().expect("failed to serialise request");
        let response = client.post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .header("User-Agent", USER_AGENT)
            .body(request_bytes)
            .send()?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::WrongHttpStatus(status.as_u16(), Some(status.to_string())));
        }

        let headers = response.headers();
        let content_length = headers.get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);

        debug!("HTTP body has {} bytes", content_length);

        let response = Response::from_bytes(&response.bytes()?)?;
        Ok(response)
    }

    #[cfg(not(feature = "with_https"))]
    fn send(&self, request: &Request, timeout: Option<Duration>) -> Result<Response, Error> {
        unreachable!("HTTPS feature disabled")
    }
}

/// The User-Agent header sent with HTTPS requests.
static USER_AGENT: &str = concat!("dog/", env!("CARGO_PKG_VERSION"));

