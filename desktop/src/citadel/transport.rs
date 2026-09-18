//! [`HttpKerkeseTransport`]: a real, HTTP-backed
//! `citadel_kerkese_core::KerkeseTransport` for `desktop`'s CITADEL/MARSHAL
//! user-space proxy — the same "Option 2" instantiation
//! `citadel-kerkese-core`'s `examples/async_proxy_sketch.rs` sketches, made
//! real for this repo: `desktop` already runs on a hosted, `std` platform
//! (unlike `kernel/`), so pulling in Tokio + `reqwest` here is fine.
//!
//! # This is standalone, not wired into a real decision path
//!
//! Nothing in this module is called from any authorization/gating code
//! path in Runix today. It's a self-contained, independently testable
//! component — connecting it to something that actually gates a privileged
//! action is later, separate work (see the parent module's doc comment).
//!
//! # The endpoint is configuration, never a hardcoded default
//!
//! [`HttpKerkeseTransport::from_env`] reads the CITADEL endpoint URL from
//! the `RUNIX_CITADEL_URL` environment variable. If it isn't set (or a
//! caller constructs [`HttpKerkeseTransport`] with `url: None` directly),
//! [`HttpKerkeseTransport::submit`] fails closed with
//! `TransportError::Unreachable` rather than silently no-op'ing or falling
//! back to a guessed production URL — an unconfigured transport must never
//! look like a working one.

use citadel_kerkese_core::{KerkeseTransport, TransportError};
use tokio::runtime::Runtime;

/// Environment variable holding the CITADEL MARSHAL Kerkese-submission
/// endpoint URL. Deliberately not a compiled-in default — see this
/// module's doc comment.
pub const RUNIX_CITADEL_URL_ENV: &str = "RUNIX_CITADEL_URL";

/// An HTTP-backed [`KerkeseTransport`] for a hosted (desktop/mobile)
/// CITADEL proxy process.
///
/// Bridges `KerkeseTransport::submit`'s synchronous signature to
/// `reqwest`'s async client via a dedicated single-threaded Tokio runtime,
/// following `citadel-kerkese-core`'s `examples/async_proxy_sketch.rs`
/// pattern.
pub struct HttpKerkeseTransport {
    client: reqwest::Client,
    /// The CITADEL endpoint to POST Kerkese envelopes to. `None` means
    /// "not configured" — `submit` fails closed in that case rather than
    /// guessing a URL. See [`HttpKerkeseTransport::from_env`].
    url: Option<String>,
    /// Dedicated runtime used only to drive `submit`'s internal `reqwest`
    /// call to completion. See `async_proxy_sketch.rs`'s doc comment for
    /// why this owns a private runtime rather than reusing a caller's.
    runtime: Runtime,
}

impl HttpKerkeseTransport {
    /// Builds a transport pointed at `url`. `url: None` means "not
    /// configured" — every [`HttpKerkeseTransport::submit`] call will fail
    /// closed with `TransportError::Unreachable` until a caller supplies a
    /// real endpoint.
    pub fn new(url: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build Tokio runtime for HttpKerkeseTransport"),
        }
    }

    /// Builds a transport from the `RUNIX_CITADEL_URL` environment
    /// variable. If it's unset (or empty), the returned transport is
    /// "not configured" — see [`HttpKerkeseTransport::new`].
    pub fn from_env() -> Self {
        let url = std::env::var(RUNIX_CITADEL_URL_ENV)
            .ok()
            .filter(|s| !s.is_empty());
        Self::new(url)
    }

    /// The actual async submission logic — kept separate from `submit` so
    /// the sync/async boundary is a single, visually obvious `block_on`
    /// call.
    async fn submit_async(
        &self,
        url: &str,
        envelope_bytes: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(envelope_bytes.to_vec())
            .send()
            .await
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::BadResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TransportError::BadResponse(e.to_string()))
    }
}

impl KerkeseTransport for HttpKerkeseTransport {
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        let Some(url) = self.url.as_deref() else {
            return Err(TransportError::Unreachable(format!(
                "{RUNIX_CITADEL_URL_ENV} not configured — refusing to guess a CITADEL endpoint"
            )));
        };
        // This is the sync/async bridge: `submit` itself is sync (required
        // by `KerkeseTransport`), but the only I/O primitive available here
        // is `reqwest`'s async client. `block_on` drives the future to
        // completion on this thread, blocking it for the duration of the
        // HTTP round-trip.
        self.runtime
            .block_on(self.submit_async(url, envelope_bytes))
    }
}

#[cfg(test)]
mod tests {
    //! Tests exercise [`HttpKerkeseTransport`] against a lightweight,
    //! hand-rolled, in-process, `127.0.0.1`-only HTTP mock — never a live
    //! CITADEL endpoint. The mock lives entirely in this `#[cfg(test)]`
    //! module (it's `std::net`-only, gated out of any real build), returns
    //! only canned fixture responses, and has no relationship to any real
    //! MARSHAL/CITADEL connection — nothing a real caller could mistake for
    //! a working integration.

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Starts a one-shot mock HTTP server on `127.0.0.1` that accepts a
    /// single connection, reads one HTTP/1.1 request (headers + body per
    /// `Content-Length`), and writes back `response`. Returns the bound
    /// URL to POST to.
    ///
    /// This is deliberately not a general-purpose HTTP server — it's the
    /// minimum needed to prove `HttpKerkeseTransport` sends bytes over the
    /// wire and parses a response correctly, nothing more.
    fn spawn_mock_server(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                read_http_request(&mut stream);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        format!("http://{addr}/marshal/kerkese")
    }

    /// Reads a full HTTP/1.1 request (headers, then `Content-Length` body
    /// bytes) off `stream` and returns the body. Good enough for a test
    /// double talking to `reqwest`, not a real HTTP parser.
    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        let header_end = loop {
            let n = stream.read(&mut chunk).expect("read request");
            if n == 0 {
                break None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break Some(pos + 4);
            }
        };
        let Some(header_end) = header_end else {
            return buf;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let content_length: usize = headers
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().to_string())
            })
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        while buf.len() < header_end + content_length {
            let n = stream.read(&mut chunk).expect("read body");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        buf[header_end..].to_vec()
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    const CANNED_DECISION_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 96\r\nConnection: close\r\n\r\n{\"execution_id\":\"00000000-0000-0000-0000-000000000000\",\"outcome\":\"EXECUTE\",\"gates\":[],\"reasons\":[],\"ts_utc\":\"2026-07-26T12:00:01Z\"}";

    #[test]
    fn submit_round_trips_through_mock_server() {
        let url = spawn_mock_server(CANNED_DECISION_RESPONSE);
        let transport = HttpKerkeseTransport::new(Some(url));

        let result = transport
            .submit(b"{\"fake\":\"kerkese\"}")
            .expect("submit should succeed");
        let body = String::from_utf8(result).expect("utf8 response");
        assert!(body.contains("\"outcome\":\"EXECUTE\""));
    }

    #[test]
    fn submit_fails_closed_when_not_configured() {
        let transport = HttpKerkeseTransport::new(None);
        let err = transport.submit(b"{}").unwrap_err();
        match err {
            TransportError::Unreachable(msg) => {
                assert!(msg.contains(RUNIX_CITADEL_URL_ENV));
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn submit_surfaces_bad_response_on_non_2xx_status() {
        let response =
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let url = spawn_mock_server(response);
        let transport = HttpKerkeseTransport::new(Some(url));

        let err = transport.submit(b"{}").unwrap_err();
        match err {
            TransportError::BadResponse(msg) => assert!(msg.contains("500")),
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn submit_surfaces_unreachable_on_connection_refused() {
        // Bind then immediately drop the listener to get a port nothing is
        // listening on, so the connection is refused rather than merely
        // slow.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let transport = HttpKerkeseTransport::new(Some(format!("http://{addr}/marshal/kerkese")));
        let err = transport.submit(b"{}").unwrap_err();
        assert!(matches!(err, TransportError::Unreachable(_)));
    }
}
