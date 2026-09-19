//! `citadel_proxy`: the real TCP-facing half of the desktop CITADEL/MARSHAL
//! user-space proxy — accepts `runix_ipc::marshal::MarshalRequest`s over a
//! plain TCP connection (the wire format `kernel::marshal_client`'s
//! socket-based transport speaks, and the exact framing
//! `kernel/tests/support/marshal_proof_listener.py` answers as a stand-in
//! today — see that script's doc comment for the wire format this module
//! must match byte-for-byte), forwards the carried `kerkese_json` to
//! [`HttpKerkeseTransport`], and writes back a `MarshalResponse` encoding
//! either the real Decision or a translated [`MarshalError`].
//!
//! This module owns the TCP/decode/encode plumbing (the part that's worth
//! unit-testing against a mock CITADEL HTTP endpoint, see this module's
//! `#[cfg(test)]`); `src/bin/citadel_proxy.rs` is a thin `main` that reads
//! configuration and calls [`serve`].
//!
//! # Why parse the real `Decision` type rather than hand-scraping `outcome`
//!
//! `desktop` already depends on `citadel-kerkese-core` (for
//! [`HttpKerkeseTransport`]/[`citadel_kerkese_core::KerkeseTransport`]), and
//! that crate already declares `serde`+`serde_json` as dependencies for its
//! own `decision` module (see `citadel_kerkese_core::decision::Decision`).
//! Depending on `serde_json` directly here and parsing the real `Decision`
//! struct is therefore no heavier than a hand-rolled `"outcome":\s*"..."`
//! string scrape, and is strictly more correct: it rejects a response that
//! merely *contains* the substring `"outcome":"EXECUTE"` somewhere without
//! actually being a well-formed Decision (translated to
//! `MarshalError::BadResponse`, never silently defaulting to `Execute`).
//!
//! # One connection at a time
//!
//! [`serve`] is a sequential accept loop — not a production concurrent
//! server, just a real, correctly-functioning one, matching this task's
//! scope. A later concurrency upgrade (thread-per-connection or async) is
//! separate work.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use citadel_kerkese_core::decision::{Decision, Outcome};
use citadel_kerkese_core::{KerkeseTransport, TransportError};
use runix_ipc::marshal::{MarshalError, MarshalOutcome, MarshalRequest, MarshalResponse};

use super::HttpKerkeseTransport;

/// Environment variable holding the TCP address this proxy listens on.
/// Deliberately not hardcoded in `main` so ops/test setups can point it at
/// whatever address a given QEMU `guestfwd` bridge (or plain local testing)
/// expects.
pub const LISTEN_ADDR_ENV: &str = "CITADEL_PROXY_LISTEN_ADDR";

/// Default listen address: `127.0.0.1:9000`, matching the port
/// `net_driver_tcp`/`net_driver_sockets`'s existing `guestfwd` routes
/// already forward guest connections to for other services (see e.g.
/// `kernel/tests/net_driver_tcp.rs`), so this binary can later slot into
/// that same bridge once the kernel side reaches it over a real socket —
/// wiring that end-to-end integration is separate work.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9000";

/// Upper bound on how many bytes [`read_marshal_request`] will buffer
/// before giving up, independent of [`MarshalRequest::decode`]'s own
/// internal bound check. `decode` returns `None` both for "not enough
/// bytes yet" and for "the declared length exceeds
/// `runix_ipc::marshal::MAX_JSON_LEN`" — this cap stops a connection that
/// claims an oversized/bogus length from making this accept loop buffer an
/// unbounded amount of attacker-controlled data while waiting for a
/// `decode` that can never succeed.
const MAX_REQUEST_BYTES: usize = runix_ipc::marshal::MAX_JSON_LEN + 4;

/// Reads bytes off `stream` until a full [`MarshalRequest`] can be decoded,
/// handling partial reads correctly: a real TCP stream may deliver the
/// request across multiple `read()` calls, so this keeps appending to a
/// growing buffer and retrying [`MarshalRequest::decode`] rather than
/// assuming one `read()` call is enough.
fn read_marshal_request(stream: &mut impl Read) -> std::io::Result<MarshalRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((request, _consumed)) = MarshalRequest::decode(&buf) {
            return Ok(request);
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MarshalRequest exceeds the maximum wire size without decoding",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before a full MarshalRequest was received",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn to_marshal_outcome(outcome: Outcome) -> MarshalOutcome {
    match outcome {
        Outcome::Execute => MarshalOutcome::Execute,
        Outcome::Refuse => MarshalOutcome::Refuse,
        Outcome::HardStop => MarshalOutcome::HardStop,
    }
}

/// Truncates `s` to at most [`runix_ipc::marshal::MAX_MESSAGE_LEN`] bytes on
/// a UTF-8 boundary. [`MarshalError`]'s string fields are wire-encoded with
/// a `u16` length prefix computed from the raw byte length
/// (`ipc::marshal`'s private `encode_string` helper) with no bound check of
/// its own — a message this proxy forwards verbatim from a transport error
/// (e.g. a full HTTP error body) could otherwise silently corrupt that
/// length prefix if it happened to exceed `u16::MAX`, or simply get
/// rejected by the receiving `decode`'s own `MAX_MESSAGE_LEN` check. Truncate
/// here so encode is always well-formed.
fn truncate_message(s: String) -> String {
    if s.len() <= runix_ipc::marshal::MAX_MESSAGE_LEN {
        return s;
    }
    let mut end = runix_ipc::marshal::MAX_MESSAGE_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Submits `kerkese_json` via `transport` and builds the [`MarshalResponse`]
/// to send back: a `Decision` (with `outcome` pulled out of the real,
/// parsed `Decision` JSON) on success, or a translated [`MarshalError`] on
/// any transport/parse failure. Never panics on a malformed or hostile
/// response body — a bad decision JSON becomes `MarshalError::BadResponse`,
/// never a default/guessed outcome.
fn build_response(transport: &HttpKerkeseTransport, kerkese_json: &[u8]) -> MarshalResponse {
    let decision_json = match transport.submit(kerkese_json) {
        Ok(bytes) => bytes,
        Err(TransportError::Unreachable(msg)) => {
            return MarshalResponse::Error(MarshalError::Unreachable(truncate_message(msg)));
        }
        Err(TransportError::Timeout) => return MarshalResponse::Error(MarshalError::Timeout),
        Err(TransportError::BadResponse(msg)) => {
            return MarshalResponse::Error(MarshalError::BadResponse(truncate_message(msg)));
        }
        Err(TransportError::Other(msg)) => {
            return MarshalResponse::Error(MarshalError::Other(truncate_message(msg)));
        }
    };

    match serde_json::from_slice::<Decision>(&decision_json) {
        Ok(decision) => MarshalResponse::Decision {
            outcome: to_marshal_outcome(decision.outcome),
            decision_json,
        },
        Err(e) => MarshalResponse::Error(MarshalError::BadResponse(truncate_message(format!(
            "response body was not a well-formed Decision: {e}"
        )))),
    }
}

/// Handles exactly one already-accepted connection: reads a full
/// `MarshalRequest`, submits it, and writes back the encoded
/// `MarshalResponse`. Returns an `Err` only for I/O-level failures (a
/// request that decodes but whose submission fails is still a *successful*
/// handling of the connection — the failure is reported to the peer as a
/// `MarshalResponse::Error`, not by dropping the connection).
pub fn handle_connection(
    stream: &mut TcpStream,
    transport: &HttpKerkeseTransport,
) -> std::io::Result<()> {
    let request = read_marshal_request(stream)?;
    let response = build_response(transport, &request.kerkese_json);
    stream.write_all(&response.encode())?;
    stream.flush()
}

/// Accepts and handles exactly one connection off `listener`. Exposed
/// separately from [`serve`] so tests can drive a single request/response
/// cycle deterministically instead of spawning (and having to tear down) a
/// forever-looping server thread.
pub fn serve_one(listener: &TcpListener, transport: &HttpKerkeseTransport) -> std::io::Result<()> {
    let (mut stream, _addr) = listener.accept()?;
    handle_connection(&mut stream, transport)
}

/// Binds `listen_addr` and serves connections one at a time, forever.
/// Never returns on success; returns `Err` only if binding the listener
/// itself fails. A per-connection failure (bad request, transport error,
/// I/O error mid-handling) is logged to stderr and the loop moves on to the
/// next connection rather than tearing down the whole server.
pub fn serve(listen_addr: &str, transport: HttpKerkeseTransport) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(e) = handle_connection(&mut stream, &transport) {
                    eprintln!("citadel_proxy: connection error: {e}");
                }
            }
            Err(e) => eprintln!("citadel_proxy: accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Exercises this module's TCP/decode/encode plumbing end to end
    //! (real `TcpStream`s, real `MarshalRequest`/`MarshalResponse`
    //! encode/decode) against a hand-rolled mock CITADEL HTTP endpoint —
    //! same pattern as `transport.rs`'s own tests, never a live network
    //! call.

    use super::*;
    use std::net::TcpListener as StdTcpListener;

    /// Same minimal one-shot mock HTTP server `transport.rs`'s tests use —
    /// duplicated rather than shared across a test/non-test boundary, same
    /// reasoning `ipc`'s wire modules give for not sharing private helpers
    /// across modules.
    fn spawn_mock_server(response: &'static str) -> String {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
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

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
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

    // Content-Length (131) is the actual byte length of the JSON body below
    // — unlike `transport.rs`'s otherwise-identical fixture (whose
    // `Content-Length: 96` under-counts it), this test needs the full,
    // valid Decision JSON to reach `serde_json::from_slice`, not just a
    // truncated prefix containing the `outcome` substring.
    const CANNED_EXECUTE_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 131\r\nConnection: close\r\n\r\n{\"execution_id\":\"00000000-0000-0000-0000-000000000000\",\"outcome\":\"EXECUTE\",\"gates\":[],\"reasons\":[],\"ts_utc\":\"2026-07-26T12:00:01Z\"}";

    /// A TCP client's half of one `MarshalRequest`/`MarshalResponse`
    /// round-trip against a proxy `TcpListener` — sends `req`'s encoding
    /// split across multiple `write`/short `sleep`-free chunks (proving the
    /// server-side partial-read handling actually works, not just "happens
    /// to work when the whole message arrives in one read"), and decodes
    /// whatever comes back.
    fn round_trip(proxy_addr: std::net::SocketAddr, req: &MarshalRequest) -> MarshalResponse {
        let mut client = TcpStream::connect(proxy_addr).expect("connect to proxy");
        let encoded = req.encode();
        // Split into two writes to exercise the partial-read path on the
        // server side rather than delivering the whole message in one
        // `read()`.
        let mid = encoded.len() / 2;
        client.write_all(&encoded[..mid]).expect("write first half");
        client
            .write_all(&encoded[mid..])
            .expect("write second half");

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((resp, _)) = MarshalResponse::decode(&buf) {
                return resp;
            }
            let n = client.read(&mut chunk).expect("read response");
            assert_ne!(n, 0, "proxy closed connection before a full response");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    #[test]
    fn round_trips_execute_decision_over_real_tcp() {
        let http_url = spawn_mock_server(CANNED_EXECUTE_RESPONSE);
        let transport = HttpKerkeseTransport::new(Some(http_url));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

        let handle = std::thread::spawn(move || serve_one(&proxy_listener, &transport));

        let req = MarshalRequest {
            kerkese_json: br#"{"kerkese_version":"1.0"}"#.to_vec(),
        };
        let response = round_trip(proxy_addr, &req);

        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");

        match response {
            MarshalResponse::Decision {
                outcome,
                decision_json,
            } => {
                assert_eq!(outcome, MarshalOutcome::Execute);
                let body = String::from_utf8(decision_json).expect("utf8 decision json");
                assert!(body.contains("\"outcome\":\"EXECUTE\""));
            }
            other => panic!("expected Decision, got {other:?}"),
        }
    }

    #[test]
    fn translates_transport_unreachable_into_marshal_error() {
        // Bind then drop, so the transport's HTTP POST is refused.
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_addr = listener.local_addr().expect("addr");
        drop(listener);

        let transport =
            HttpKerkeseTransport::new(Some(format!("http://{dead_addr}/marshal/kerkese")));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

        let handle = std::thread::spawn(move || serve_one(&proxy_listener, &transport));

        let req = MarshalRequest {
            kerkese_json: br#"{"kerkese_version":"1.0"}"#.to_vec(),
        };
        let response = round_trip(proxy_addr, &req);

        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");

        match response {
            MarshalResponse::Error(MarshalError::Unreachable(_)) => {}
            other => panic!("expected Error(Unreachable), got {other:?}"),
        }
    }

    #[test]
    fn translates_non_decision_body_into_bad_response() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\nnot json body";
        let http_url = spawn_mock_server(response);
        let transport = HttpKerkeseTransport::new(Some(http_url));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

        let handle = std::thread::spawn(move || serve_one(&proxy_listener, &transport));

        let req = MarshalRequest {
            kerkese_json: br#"{"kerkese_version":"1.0"}"#.to_vec(),
        };
        let response = round_trip(proxy_addr, &req);

        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");

        match response {
            MarshalResponse::Error(MarshalError::BadResponse(_)) => {}
            other => panic!("expected Error(BadResponse), got {other:?}"),
        }
    }
}
