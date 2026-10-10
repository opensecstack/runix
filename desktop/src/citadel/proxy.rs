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
//!    which policy check failed. Either way, this decision — allow or
//!    refuse — is itself recorded to a [`WormLog`] via
//!    [`WormLog::record_proxy_verification`] before the pipeline continues:
//!    this proxy's own verification act is evidence, not just the kernel
//!    spawn it's gating (`docs/RFC-VERIFIER-IDENTITY.md`'s "two principals,
//!    two log entries" goal).
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
use std::sync::Mutex;

use citadel_kerkese_core::decision::{Decision, Outcome};
use citadel_kerkese_core::{KerkeseTransport, TransportError};
use ed25519_dalek::SigningKey;
use runix_citadel_integration::WormLog;
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

/// Appends one [`WormLog::record_proxy_verification`] entry — the thin
/// lock-and-record wrapper [`build_response`] calls on both the allow and
/// refuse paths. A poisoned lock (a prior panic while holding it) falls back
/// to recovering the inner log rather than propagating the poison and
/// dropping the connection: recording this proxy's own verification
/// decision must never itself become a reason a request fails.
fn record_proxy_verification(
    worm_log: &Mutex<WormLog>,
    module_id: &str,
    instance_id: &str,
    authorized: bool,
    reason: Option<String>,
) {
    let mut log = worm_log
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    log.record_proxy_verification(module_id, instance_id, authorized, reason);
}

/// Translates a [`PolicyError`] into the [`MarshalResponse`] sent back to
/// the kernel caller when this proxy refuses to vouch for a request —
/// `MarshalError::PolicyRefused`: a definite negative answer from this
/// proxy's own policy layer. It is deliberately distinct from every
/// transport/malformed-response variant, because kernel callers treat those
/// as "MARSHAL unavailable" (fail-open) but must treat a refusal as a refusal.
fn policy_error_response(err: PolicyError) -> MarshalResponse {
    MarshalResponse::Error(MarshalError::PolicyRefused(truncate_message(
        err.to_string(),
    )))
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
    let description = if policy::is_data_action(&envelope.action.action_type) {
        // `policy::check` guarantees `account` for `data.reset_usage`.
        let account = envelope.action.account.unwrap_or_default();
        extra.insert("account".to_string(), account.to_string());
        format!("{} account={account}", envelope.action.action_type)
    } else if policy::is_mvno_action(&envelope.action.action_type) {
        // `policy::check` guarantees `account` (and, for bind, slot/profile).
        let account = envelope.action.account.unwrap_or_default();
        extra.insert("account".to_string(), account.to_string());
        if envelope.action.action_type == policy::MVNO_BIND_PROFILE_ACTION {
            let slot = envelope.action.slot.unwrap_or_default();
            let profile = envelope.action.profile.unwrap_or_default();
            extra.insert("slot".to_string(), slot.to_string());
            extra.insert("profile".to_string(), profile.to_string());
            format!(
                "{} account={account} slot={slot} profile={profile}",
                envelope.action.action_type
            )
        } else {
            format!("{} account={account}", envelope.action.action_type)
        }
    } else if policy::is_esim_action(&envelope.action.action_type) {
        // `policy::check` guarantees both are present for eSIM actions.
        let slot = envelope.action.slot.unwrap_or_default();
        let profile = envelope.action.profile.unwrap_or_default();
        extra.insert("slot".to_string(), slot.to_string());
        extra.insert("profile".to_string(), profile.to_string());
        format!(
            "{} slot={slot} profile={profile}",
            envelope.action.action_type
        )
    } else {
        extra.insert("module_id".to_string(), envelope.action.module_id.clone());
        extra.insert(
            "instance_id".to_string(),
            envelope.action.instance_id.clone(),
        );
        format!(
            "grid_sandbox.spawn_instance module_id={} instance_id={}",
            envelope.action.module_id, envelope.action.instance_id
        )
    };
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
            description,
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
///
/// Records this proxy's own verification decision to `worm_log` immediately
/// after [`policy::check`] runs — allow or refuse, both recorded, before the
/// pipeline continues on to enrichment/forwarding (allow case) or returns
/// (refuse case). A `kerkese_json` that fails to parse at all
/// ([`parse_kernel_envelope`]) never reaches [`policy::check`], so nothing
/// is recorded for it — there is no `(module_id, instance_id)` to attribute
/// the decision to.
fn build_response(
    transport: &HttpKerkeseTransport,
    signing_key: &SigningKey,
    worm_log: &Mutex<WormLog>,
    kerkese_json: &[u8],
) -> MarshalResponse {
    let envelope = match parse_kernel_envelope(kerkese_json) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    let (module_id, instance_id) = envelope.action.audit_ids();

    if let Err(err) = policy::check(&envelope) {
        record_proxy_verification(
            worm_log,
            &module_id,
            &instance_id,
            false,
            Some(err.to_string()),
        );
        return policy_error_response(err);
    }
    record_proxy_verification(worm_log, &module_id, &instance_id, true, None);

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
    worm_log: &Mutex<WormLog>,
) -> std::io::Result<()> {
    let request = read_marshal_request(stream)?;
    let response = build_response(transport, signing_key, worm_log, &request.kerkese_json);
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
    worm_log: &Mutex<WormLog>,
) -> std::io::Result<()> {
    let (mut stream, _addr) = listener.accept()?;
    handle_connection(&mut stream, transport, signing_key, worm_log)
}

/// Binds `listen_addr` and serves connections one at a time, forever, using
/// this proxy's own demo Verifier signing key
/// ([`super::identity::proxy_signing_key`]) and a fresh, process-lifetime
/// [`WormLog`] recording every verification decision this proxy makes (see
/// [`build_response`]). Never returns on success; returns `Err` only if
/// binding the listener itself fails. A per-connection failure (bad
/// request, policy refusal, transport error, I/O error mid-handling) is
/// logged to stderr and the loop moves on to the next connection rather than
/// tearing down the whole server.
pub fn serve(listen_addr: &str, transport: HttpKerkeseTransport) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    let signing_key = identity::proxy_signing_key();
    let worm_log = Mutex::new(WormLog::default());
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(e) = handle_connection(&mut stream, &transport, &signing_key, &worm_log)
                {
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
        let worm_log = Mutex::new(WormLog::default());
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log)
        });

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
        let worm_log = Mutex::new(WormLog::default());
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log)
        });

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
        let worm_log = Mutex::new(WormLog::default());
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log)
        });

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
        let transport =
            HttpKerkeseTransport::new(Some(format!("http://{mock_addr}/marshal/kerkese")));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let signing_key = test_signing_key();
        let worm_log = std::sync::Arc::new(Mutex::new(WormLog::default()));
        let worm_log_clone = worm_log.clone();
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log_clone)
        });

        let req = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
        };
        let response = round_trip(proxy_addr, &req);
        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");
        assert!(matches!(response, MarshalResponse::Decision { .. }));

        // The proxy's own verification decision — allowing this request —
        // was itself recorded to WORM, distinct from the CITADEL Decision
        // being gated: exactly `docs/RFC-VERIFIER-IDENTITY.md`'s "two
        // principals, two log entries" goal.
        {
            let log = worm_log.lock().unwrap();
            let entries = log.entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].module_id, "grid-sandbox-host");
            assert_eq!(entries[0].instance_id.as_deref(), Some("app-1"));
            assert!(entries[0].authorized);
            assert!(entries[0].reason.is_none());
            assert!(log.verify_chain());
        }

        let forwarded_bytes = captured.lock().unwrap().take().expect("body captured");
        let forwarded: Kerkese =
            serde_json::from_slice(&forwarded_bytes).expect("forwarded body is a real Kerkese");

        // The exact SoD-fix claim: operator and verifier are different
        // principals, not the same identity twice.
        assert_ne!(
            forwarded.sod.operator_user_id,
            forwarded.sod.verifier_user_id
        );
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

    /// The eSIM path end to end: the exact envelope shape
    /// `kernel-arm/src/marshal_transport.rs` sends is accepted, forwarded as
    /// a real enriched `Kerkese` with the `esim.enable` action type and
    /// slot/profile evidence, and recorded to WORM under the synthetic
    /// `esim` / `slot-S-profile-P` identifiers.
    #[test]
    fn forwards_esim_enable_as_an_enriched_envelope() {
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
        let transport =
            HttpKerkeseTransport::new(Some(format!("http://{mock_addr}/marshal/kerkese")));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let signing_key = test_signing_key();
        let worm_log = std::sync::Arc::new(Mutex::new(WormLog::default()));
        let worm_log_clone = worm_log.clone();
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log_clone)
        });

        let req = MarshalRequest {
            kerkese_json: br#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"esim.enable","slot":0,"profile":2},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"esim-enable-0-2"}"#.to_vec(),
        };
        let response = round_trip(proxy_addr, &req);
        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");
        assert!(matches!(
            response,
            MarshalResponse::Decision {
                outcome: MarshalOutcome::Execute,
                ..
            }
        ));

        {
            let log = worm_log.lock().unwrap();
            let entries = log.entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].module_id, "esim");
            assert_eq!(entries[0].instance_id.as_deref(), Some("slot-0-profile-2"));
            assert!(entries[0].authorized);
        }

        let forwarded: Kerkese =
            serde_json::from_slice(&captured.lock().unwrap().take().expect("body captured"))
                .expect("forwarded body is a real Kerkese");
        assert_eq!(forwarded.action.action_type, "esim.enable");
        assert_eq!(forwarded.action.description, "esim.enable slot=0 profile=2");
        assert_eq!(forwarded.evidence.extra.get("slot"), Some(&"0".to_string()));
        assert_eq!(
            forwarded.evidence.extra.get("profile"),
            Some(&"2".to_string())
        );
        assert!(!forwarded.evidence.extra.contains_key("module_id"));
        assert_eq!(forwarded.sod.operator_user_id, "el0:arm-demo");
        assert_ne!(
            forwarded.sod.operator_user_id,
            forwarded.sod.verifier_user_id
        );
    }

    /// Drives one kernel-shaped MVNO request through the proxy against a
    /// capturing mock CITADEL; returns the response, the WORM (module,
    /// instance) pair and the forwarded `Kerkese`.
    fn mvno_round_trip(json: &str) -> (MarshalResponse, (String, String), Kerkese) {
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
        let transport =
            HttpKerkeseTransport::new(Some(format!("http://{mock_addr}/marshal/kerkese")));

        let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let signing_key = test_signing_key();
        let worm_log = std::sync::Arc::new(Mutex::new(WormLog::default()));
        let worm_log_clone = worm_log.clone();
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log_clone)
        });

        let req = MarshalRequest {
            kerkese_json: json.as_bytes().to_vec(),
        };
        let response = round_trip(proxy_addr, &req);
        handle
            .join()
            .expect("proxy thread panicked")
            .expect("serve_one");

        let ids = {
            let log = worm_log.lock().unwrap();
            let entries = log.entries();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].authorized);
            (
                entries[0].module_id.clone(),
                entries[0].instance_id.clone().unwrap_or_default(),
            )
        };
        let forwarded: Kerkese =
            serde_json::from_slice(&captured.lock().unwrap().take().expect("body captured"))
                .expect("forwarded body is a real Kerkese");
        (response, ids, forwarded)
    }

    fn assert_execute(response: &MarshalResponse) {
        assert!(matches!(
            response,
            MarshalResponse::Decision {
                outcome: MarshalOutcome::Execute,
                ..
            }
        ));
    }

    #[test]
    fn forwards_mvno_bind_profile_as_an_enriched_envelope() {
        let (response, ids, forwarded) = mvno_round_trip(
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.bind_profile","account":3,"slot":0,"profile":2},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-bind-3-0-2"}"#,
        );
        assert_execute(&response);
        assert_eq!(
            ids,
            ("mvno".to_string(), "account-3-slot-0-profile-2".to_string())
        );
        assert_eq!(forwarded.action.action_type, "mvno.bind_profile");
        assert_eq!(
            forwarded.action.description,
            "mvno.bind_profile account=3 slot=0 profile=2"
        );
        let extra = &forwarded.evidence.extra;
        assert_eq!(extra.get("account"), Some(&"3".to_string()));
        assert_eq!(extra.get("slot"), Some(&"0".to_string()));
        assert_eq!(extra.get("profile"), Some(&"2".to_string()));
        assert!(!extra.contains_key("module_id"));
        assert_eq!(
            extra.get("kernel_execution_id"),
            Some(&"mvno-bind-3-0-2".to_string())
        );
        assert_eq!(forwarded.sod.operator_user_id, "el0:arm-demo");
        assert_ne!(
            forwarded.sod.operator_user_id,
            forwarded.sod.verifier_user_id
        );
    }

    #[test]
    fn forwards_mvno_suspend_and_reactivate_as_enriched_envelopes() {
        for verb in ["suspend", "reactivate"] {
            let json = format!(
                r#"{{"kerkese_version":"1.0","dry_run":true,"action":{{"type":"mvno.{verb}_account","account":5}},"actor":{{"user_id":"el0:arm-demo","role":"operator"}},"execution_id":"mvno-{verb}-5"}}"#
            );
            let (response, ids, forwarded) = mvno_round_trip(&json);
            assert_execute(&response);
            assert_eq!(ids, ("mvno".to_string(), "account-5".to_string()), "{verb}");
            assert_eq!(forwarded.action.action_type, format!("mvno.{verb}_account"));
            assert_eq!(
                forwarded.action.description,
                format!("mvno.{verb}_account account=5")
            );
            let extra = &forwarded.evidence.extra;
            assert_eq!(extra.get("account"), Some(&"5".to_string()));
            assert!(!extra.contains_key("slot"));
            assert!(!extra.contains_key("profile"));
            assert!(!extra.contains_key("module_id"));
            assert_eq!(forwarded.sod.operator_user_id, "el0:arm-demo");
            assert_ne!(
                forwarded.sod.operator_user_id,
                forwarded.sod.verifier_user_id
            );
        }
    }

    #[test]
    fn forwards_data_reset_usage_as_an_enriched_envelope() {
        let (response, ids, forwarded) = mvno_round_trip(
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"data.reset_usage","account":6},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"data-reset-6"}"#,
        );
        assert_execute(&response);
        assert_eq!(ids, ("data".to_string(), "account-6".to_string()));
        assert_eq!(forwarded.action.action_type, "data.reset_usage");
        assert_eq!(forwarded.action.description, "data.reset_usage account=6");
        let extra = &forwarded.evidence.extra;
        assert_eq!(extra.get("account"), Some(&"6".to_string()));
        assert!(!extra.contains_key("slot"));
        assert!(!extra.contains_key("profile"));
        assert!(!extra.contains_key("module_id"));
        assert_eq!(
            extra.get("kernel_execution_id"),
            Some(&"data-reset-6".to_string())
        );
        assert_eq!(forwarded.sod.operator_user_id, "el0:arm-demo");
        assert_ne!(
            forwarded.sod.operator_user_id,
            forwarded.sod.verifier_user_id
        );
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
        let worm_log = std::sync::Arc::new(Mutex::new(WormLog::default()));
        let worm_log_clone = worm_log.clone();
        let handle = std::thread::spawn(move || {
            serve_one(&proxy_listener, &transport, &signing_key, &worm_log_clone)
        });

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
            MarshalResponse::Error(MarshalError::PolicyRefused(msg)) => {
                assert!(msg.contains("POLICY_REFUSE"));
            }
            other => panic!("expected Error(PolicyRefused), got {other:?}"),
        }

        // A policy refusal is a verification decision too — recorded as
        // `authorized: false` with the policy reason, not silently dropped
        // just because CITADEL was never reached.
        {
            let log = worm_log.lock().unwrap();
            let entries = log.entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].module_id, "m");
            assert_eq!(entries[0].instance_id.as_deref(), Some("i"));
            assert!(!entries[0].authorized);
            assert!(entries[0]
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("POLICY_REFUSE"));
        }

        // Give the (should-never-connect) mock server thread a moment; if
        // it *did* receive a connection, its `panic!` above would have
        // already fired by the time `handle.join()` above returned, since
        // `serve_one` only returns after `submit`/refusal completes
        // synchronously on the same thread that would have connected.
    }
}
