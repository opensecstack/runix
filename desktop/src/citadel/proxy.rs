//! `citadel_proxy`: the real TCP-facing half of the desktop CITADEL/MARSHAL
//! user-space proxy — accepts `runix_ipc::marshal::MarshalRequest`s over a
//! plain TCP connection (the wire format `kernel::marshal_client`'s
//! socket-based transport speaks, and the exact framing
//! `kernel/tests/support/marshal_proof_listener.py` answers as a stand-in
//! today — see that script's doc comment for the wire format this module
//! must match byte-for-byte), and forwards to CITADEL.
//!
//! # No longer a dumb byte-forwarder
//!
//! Per `docs/RFC-VERIFIER-IDENTITY.md`'s Option A, this module used to
//! forward the carried `kerkese_json` to [`HttpKerkeseTransport`] verbatim,
//! unparsed. It now does three things, in order, for every request:
//!
//! 1. **Parses** the kernel's minimal envelope
//!    ([`super::policy::KernelMinimalEnvelope`] — only `kerkese_version`,
//!    `dry_run`, `action`, `actor`, `execution_id`; deliberately not the
//!    full `Kerkese` shape, see that type's own doc comment for why the
//!    kernel only ever asserts `actor`). A request that fails to parse (or
//!    is missing `dry_run` — required, no `#[serde(default)]`, see
//!    [`super::policy`]'s doc comment point 3) is refused before any policy
//!    check even runs.
//! 2. **Runs [`super::policy::check`]** — this proxy's own local policy
//!    decision (action-type recognition, identifier well-formedness, no
//!    kernel-asserted `verifier`). A refusal here means this proxy never
//!    attaches its identity and never forwards to CITADEL at all — the
//!    request is answered with a translated [`MarshalError`] describing
//!    which policy check failed.
//! 3. Only once that check passes: **builds the real, enriched
//!    [`super::identity::Kerkese`] envelope** (real `KerkeseActor`/
//!    `KerkeseVerifier`/`KerkeseSoD`, a fresh `execution_id` UUID, a real
//!    UTC timestamp, and this proxy's own `sig_verifier` — see
//!    [`build_enriched_envelope`]) and forwards *that* — never the
//!    kernel's original minimal envelope — to [`HttpKerkeseTransport`].
//!
//! This module owns the TCP/decode/encode plumbing plus this
//! parse/check/enrich pipeline (the part that's worth unit-testing against
//! a mock CITADEL HTTP endpoint, see this module's `#[cfg(test)]`);
//! `src/bin/citadel_proxy.rs` is a thin `main` that reads configuration and
//! calls [`serve`].
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
use ed25519_dalek::SigningKey;
use runix_ipc::marshal::{MarshalError, MarshalOutcome, MarshalRequest, MarshalResponse};

use super::identity::{
    self, Kerkese, KerkeseAction, KerkeseActor, KerkeseEvidence, KerkeseSoD, KerkeseVerifier,
};
use super::policy::{self, KernelMinimalEnvelope, PolicyError};
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

/// Parses `kerkese_json` as [`KernelMinimalEnvelope`]. A `serde_json` parse
/// failure (including a missing `dry_run` field, since that field has no
/// `#[serde(default)]` — see [`super::policy`]'s doc comment point 3)
/// becomes `MarshalError::BadResponse`: not a CITADEL transport failure,
/// but the same "this proxy could not produce a Decision" contract
/// [`MarshalResponse::Error`] already covers, so callers don't need a new
/// error case to distinguish "parse failed" from "CITADEL response was
/// malformed" — both mean "no usable Decision came back."
fn parse_kernel_envelope(kerkese_json: &[u8]) -> Result<KernelMinimalEnvelope, MarshalResponse> {
    serde_json::from_slice::<KernelMinimalEnvelope>(kerkese_json).map_err(|e| {
        MarshalResponse::Error(MarshalError::BadResponse(truncate_message(format!(
            "kerkese_json was not a well-formed minimal envelope: {e}"
        ))))
    })
}

/// Translates a [`PolicyError`] into the [`MarshalResponse`] sent back to
/// the kernel caller when this proxy refuses to vouch for a request —
/// `MarshalError::Other`, since a policy refusal is neither a transport
/// failure nor a malformed-response condition, the two cases
/// [`MarshalError`]'s other variants exist for.
fn policy_error_response(err: PolicyError) -> MarshalResponse {
    MarshalResponse::Error(MarshalError::Other(truncate_message(err.to_string())))
}

/// Builds the real, enriched [`Kerkese`] envelope this proxy forwards to
/// CITADEL, from an already policy-checked `envelope` — never called
/// before [`policy::check`] has already returned `Ok`. See this module's
/// doc comment (point 3) and [`super::identity`]'s doc comment for what's
/// real here (envelope shape, identity separation, a genuine Ed25519
/// signature under this proxy's own key) and what's still scoped down
/// (registering that key with a live CITADEL deployment).
fn build_enriched_envelope(envelope: &KernelMinimalEnvelope, signing_key: &SigningKey) -> Kerkese {
    let execution_id = uuid::Uuid::new_v4().to_string();
    let ts_utc = identity::format_rfc3339_utc(identity::now_unix_secs());

    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "module_id".to_string(),
        envelope.action.module_id.clone(),
    );
    extra.insert(
        "instance_id".to_string(),
        envelope.action.instance_id.clone(),
    );
    if !envelope.execution_id.is_empty() {
        // The kernel's own `execution_id` (today, its `instance_id` reused
        // — see `grid_sandbox.rs`) isn't a valid UUID, so it can't fill
        // `Kerkese.execution_id` (a Go `uuid.UUID` — see that field's doc
        // comment), but it's still worth carrying as evidence linking this
        // enriched envelope back to the kernel's original request.
        extra.insert(
            "kernel_execution_id".to_string(),
            envelope.execution_id.clone(),
        );
    }

    let actor = KerkeseActor {
        user_id: envelope.actor.user_id.clone(),
        role: envelope.actor.role.clone(),
        email: None,
    };
    let verifier = KerkeseVerifier::this_proxy();
    let sod = KerkeseSoD {
        operator_user_id: actor.user_id.clone(),
        verifier_user_id: verifier.user_id.clone(),
    };

    let mut kerkese = Kerkese {
        kerkese_version: if envelope.kerkese_version.is_empty() {
            "1.0".to_string()
        } else {
            envelope.kerkese_version.clone()
        },
        ts_utc,
        project_id: "runix".to_string(),
        execution_id,
        action: KerkeseAction {
            action_type: envelope.action.action_type.clone(),
            description: format!(
                "grid_sandbox.spawn_instance module_id={} instance_id={}",
                envelope.action.module_id, envelope.action.instance_id
            ),
        },
        actor,
        verifier,
        evidence: KerkeseEvidence { extra },
        sod,
        dry_run: envelope.dry_run,
        sig_verifier: String::new(),
    };

    let payload = identity::canonical_payload(&kerkese);
    kerkese.sig_verifier = identity::sign_verifier_payload(&payload, signing_key);
    kerkese
}

/// Submits `kerkese_json` via `transport` and builds the [`MarshalResponse`]
/// to send back: a `Decision` (with `outcome` pulled out of the real,
/// parsed `Decision` JSON) on success, or a translated [`MarshalError`] on
/// any transport/parse failure. Never panics on a malformed or hostile
/// response body — a bad decision JSON becomes `MarshalError::BadResponse`,
/// never a default/guessed outcome.
fn submit_and_translate(transport: &HttpKerkeseTransport, kerkese_json: &[u8]) -> MarshalResponse {
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

/// Runs this module's full parse -> policy check -> enrich -> forward
/// pipeline (see this module's own doc comment) against one already-decoded
/// `kerkese_json` payload and returns the [`MarshalResponse`] to send back.
/// Never forwards anything to `transport` unless [`policy::check`] passed.
fn build_response(
    transport: &HttpKerkeseTransport,
    signing_key: &SigningKey,
    kerkese_json: &[u8],
) -> MarshalResponse {
    let envelope = match parse_kernel_envelope(kerkese_json) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    if let Err(err) = policy::check(&envelope) {
        return policy_error_response(err);
    }

    let enriched = build_enriched_envelope(&envelope, signing_key);
    let enriched_json = match serde_json::to_vec(&enriched) {
        Ok(bytes) => bytes,
        Err(e) => {
            return MarshalResponse::Error(MarshalError::Other(truncate_message(format!(
                "failed to serialize enriched Kerkese envelope: {e}"
            ))));
        }
    };

    submit_and_translate(transport, &enriched_json)
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
    signing_key: &SigningKey,
) -> std::io::Result<()> {
    let request = read_marshal_request(stream)?;
    let response = build_response(transport, signing_key, &request.kerkese_json);
    stream.write_all(&response.encode())?;
    stream.flush()
}

/// Accepts and handles exactly one connection off `listener`. Exposed
/// separately from [`serve`] so tests can drive a single request/response
/// cycle deterministically instead of spawning (and having to tear down) a
/// forever-looping server thread.
pub fn serve_one(
    listener: &TcpListener,
    transport: &HttpKerkeseTransport,
    signing_key: &SigningKey,
) -> std::io::Result<()> {
    let (mut stream, _addr) = listener.accept()?;
    handle_connection(&mut stream, transport, signing_key)
}

/// Binds `listen_addr` and serves connections one at a time, forever, using
/// this proxy's own demo Verifier signing key
/// ([`super::identity::proxy_signing_key`]). Never returns on success;
/// returns `Err` only if binding the listener itself fails. A
/// per-connection failure (bad request, policy refusal, transport error,
/// I/O error mid-handling) is logged to stderr and the loop moves on to the
/// next connection rather than tearing down the whole server.
pub fn serve(listen_addr: &str, transport: HttpKerkeseTransport) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    let signing_key = identity::proxy_signing_key();
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(e) = handle_connection(&mut stream, &transport, &signing_key) {
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

    /// The real minimal envelope shape `kernel/src/grid_sandbox.rs`'s
    /// `shadow_marshal_evaluate` sends post-RFC (see `policy.rs`'s own test
    /// with the same fixture) — used everywhere these tests need a request
    /// this proxy's parse + policy check actually accepts.
    fn minimal_envelope_json() -> Vec<u8> {
        br#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"grid_sandbox.spawn_instance","module_id":"grid-sandbox-host","instance_id":"app-1"},"actor":{"user_id":"kernel:grid_sandbox","role":"operator"},"execution_id":"app-1"}"#.to_vec()
    }

    fn test_signing_key() -> SigningKey {
        identity::proxy_signing_key()
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

        let signing_key = test_signing_key();
        let handle =
            std::thread::spawn(move || serve_one(&proxy_listener, &transport, &signing_key));

        let req = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
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

        let signing_key = test_signing_key();
        let handle =
            std::thread::spawn(move || serve_one(&proxy_listener, &transport, &signing_key));

        let req = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
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

        let signing_key = test_signing_key();
        let handle =
            std::thread::spawn(move || serve_one(&proxy_listener, &transport, &signing_key));

        let req = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
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

    /// Proves the new enrichment logic actually runs before forwarding, not
    /// just that the old byte-forwarder still works: captures the exact
    /// bytes this proxy POSTs to CITADEL (rather than canning a response
    /// upfront) and asserts they decode as a real [`Kerkese`] envelope with
    /// `sod.operator_user_id != sod.verifier_user_id`, the proxy's own
    /// `verifier.user_id`/`role`, and a `sig_verifier` that verifies under
    /// this proxy's own key over [`identity::canonical_payload`] — i.e. the
    /// exact SoD-fix claim `docs/RFC-VERIFIER-IDENTITY.md` exists to prove,
    /// checked against what this proxy *actually sent*, not a hand-built
    /// fixture.
    #[test]
    fn enriches_envelope_with_a_distinct_signed_verifier_identity_before_forwarding() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let mock_addr = listener.local_addr().expect("local_addr");
        let captured: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_clone = captured.clone();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let body = read_http_request(&mut stream);
                *captured_clone.lock().unwrap() = Some(body);
                let _ = stream.write_all(CANNED_EXECUTE_RESPONSE.as_bytes());
                let _ = stream.flush();
            }
        });
        let transport = HttpKerkeseTransport::new(Some(format!(
            "http://{mock_addr}/marshal/kerkese"
        )));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let signing_key = test_signing_key();
        let handle =
            std::thread::spawn(move || serve_one(&proxy_listener, &transport, &signing_key));

        let req = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
        };
        let response = round_trip(proxy_addr, &req);
        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");
        assert!(matches!(response, MarshalResponse::Decision { .. }));

        let forwarded_bytes = captured.lock().unwrap().take().expect("body captured");
        let forwarded: Kerkese =
            serde_json::from_slice(&forwarded_bytes).expect("forwarded body is a real Kerkese");

        // The exact SoD-fix claim: operator and verifier are different
        // principals, not the same identity twice.
        assert_ne!(forwarded.sod.operator_user_id, forwarded.sod.verifier_user_id);
        assert_eq!(forwarded.sod.operator_user_id, "kernel:grid_sandbox");
        assert_eq!(
            forwarded.sod.verifier_user_id,
            identity::PROXY_VERIFIER_USER_ID
        );
        assert_eq!(forwarded.verifier.role, identity::PROXY_VERIFIER_ROLE);
        // ...and the role groups actually differ too (gate3NDS's second,
        // independent same-*group* check) — "operator" -> "privileged",
        // "auditor" -> "oversight" in CITADEL's real `roleGroupMap`.
        assert_ne!(forwarded.actor.role, forwarded.verifier.role);

        // The kernel's original (non-UUID) execution_id never leaked into
        // the field that must be a real UUID — it's carried as evidence
        // instead.
        assert!(uuid::Uuid::parse_str(&forwarded.execution_id).is_ok());
        assert_eq!(
            forwarded.evidence.extra.get("kernel_execution_id"),
            Some(&"app-1".to_string())
        );
        assert_eq!(
            forwarded.evidence.extra.get("module_id"),
            Some(&"grid-sandbox-host".to_string())
        );

        // A real signature, not a placeholder: verifies under this proxy's
        // own key over the exact canonical payload CITADEL's Gate
        // 1/3 would recompute.
        let payload = identity::canonical_payload(&forwarded);
        let sig_bytes = hex::decode(&forwarded.sig_verifier).expect("hex signature");
        let sig_array: [u8; 64] = sig_bytes.try_into().expect("64-byte signature");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        use ed25519_dalek::Verifier as _;
        assert!(identity::proxy_verifying_key()
            .verify(payload.as_bytes(), &signature)
            .is_ok());
    }

    /// Proves the policy check actually gates forwarding: a request this
    /// proxy's policy refuses (unrecognized action type) never reaches
    /// CITADEL at all — the mock server here would panic if it received a
    /// connection, since nothing should ever connect to it.
    #[test]
    fn policy_refusal_never_forwards_to_citadel() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let mock_addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if listener.accept().is_ok() {
                panic!("citadel_proxy forwarded a policy-refused request to CITADEL");
            }
        });
        let transport =
            HttpKerkeseTransport::new(Some(format!("http://{mock_addr}/marshal/kerkese")));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let signing_key = test_signing_key();
        let handle =
            std::thread::spawn(move || serve_one(&proxy_listener, &transport, &signing_key));

        let bad_json = br#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"not_a_recognized_action","module_id":"m","instance_id":"i"},"actor":{"user_id":"kernel:grid_sandbox","role":"operator"},"execution_id":"i"}"#.to_vec();
        let req = MarshalRequest {
            kerkese_json: bad_json,
        };
        let response = round_trip(proxy_addr, &req);
        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");

        match response {
            MarshalResponse::Error(MarshalError::Other(msg)) => {
                assert!(msg.contains("POLICY_REFUSE"));
            }
            other => panic!("expected Error(Other) carrying a policy refusal, got {other:?}"),
        }

        // Give the (should-never-connect) mock server thread a moment; if
        // it *did* receive a connection, its `panic!` above would have
        // already fired by the time `handle.join()` above returned, since
        // `serve_one` only returns after `submit`/refusal completes
        // synchronously on the same thread that would have connected.
    }
}
