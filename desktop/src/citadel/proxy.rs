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
//! # Bounded concurrency and per-connection deadlines
//!
//! The kernel reads "no answer from the proxy" as MARSHAL-unavailable, which
//! is fail-open for some actions. So a client that can merely open a TCP
//! connection must not be able to stall legitimate requests. [`serve`]
//! therefore (a) handles each connection on its own thread, up to
//! [`ProxyLimits::max_connections`] at once (excess connections are closed
//! immediately, never queued behind a stuck one), and (b) bounds every
//! connection's lifetime: the first byte must arrive within
//! [`ProxyLimits::first_byte_timeout`] (generous: a QEMU `guestfwd` bridge
//! connects here before the guest has sent anything) and the rest of the
//! request within [`ProxyLimits::frame_deadline`] (a total deadline, not a
//! per-read one, so a slow-loris trickling bytes is dropped too), and writing
//! the response is bounded by [`ProxyLimits::write_timeout`]. The CITADEL
//! leg is bounded by `HttpKerkeseTransport`'s own connect/total timeouts.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Timeouts and concurrency cap for [`serve`].
///
/// # Why these numbers
///
/// The kernel's own wait is a bounded *poll-iteration* budget, not a
/// wall-clock one (`kernel/src/grid_sandbox.rs`'s `SHADOW_MARSHAL_MAX_ITERS`
/// = 2000 recv polls; `kernel-arm/src/marshal_transport.rs`'s 64-yield
/// budget), so there is no exact millisecond figure to stay under.
///
/// The read side has two phases, because the two failure modes differ:
///
/// * **Before the first byte** the proxy cannot tell a slow legitimate peer
///   from an idle one. QEMU `guestfwd` (`-netdev ...,guestfwd=tcp:...-cmd:nc
///   host port`) starts `nc`, which connects to this proxy, as soon as the
///   guest's SYN arrives, but the guest (under TCG on a loaded CI runner) can
///   take whole seconds between completing the handshake and actually
///   sending the request bytes. A 1 s total deadline counted from accept
///   (the first hardening attempt) dropped such connections with no reply,
///   which the kernel reads as "no answer" and then waits out its entire
///   poll budget. So this phase is generous ([`Self::first_byte_timeout`]);
///   an idle client only costs one of [`Self::max_connections`] slots.
/// * **After the first byte** the whole rest of the frame must arrive within
///   [`Self::frame_deadline`], a *total* (not per-read) bound, so a
///   slow-loris trickling one byte at a time is cut off. A request is one
///   small `Send` (milliseconds on loopback), so this can stay short.
///
/// CITADEL gets connect 1 s / total 3 s (see `transport.rs`).
#[derive(Debug, Clone, Copy)]
pub struct ProxyLimits {
    /// Max idle time from accept until the first request byte arrives.
    pub first_byte_timeout: Duration,
    /// Total time allowed, once the first byte has arrived, for the rest of
    /// the request frame.
    pub frame_deadline: Duration,
    /// Time allowed for any single write of the response.
    pub write_timeout: Duration,
    /// Max connections handled concurrently; extra ones are closed at once.
    pub max_connections: usize,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            first_byte_timeout: Duration::from_secs(20),
            frame_deadline: Duration::from_secs(3),
            write_timeout: Duration::from_millis(2000),
            max_connections: 8,
        }
    }
}

/// Reads bytes off `stream` until a full [`MarshalRequest`] can be decoded,
/// handling partial reads correctly: a real TCP stream may deliver the
/// request across multiple `read()` calls, so this keeps appending to a
/// growing buffer and retrying [`MarshalRequest::decode`] rather than
/// assuming one `read()` call is enough.
///
/// Until the first byte arrives the read is bounded by `first_byte_timeout`
/// (counted from now); from the first byte on, the rest of the frame must
/// arrive within `frame_deadline` in total (each `read` gets only the
/// remaining time as its timeout). A declared length over `MAX_JSON_LEN` is
/// rejected as soon as the 4-byte prefix is in, before any body is buffered.
fn read_marshal_request(
    stream: &mut TcpStream,
    first_byte_timeout: Duration,
    frame_deadline: Duration,
) -> std::io::Result<MarshalRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut deadline = Instant::now() + first_byte_timeout;
    loop {
        if let Some((request, _consumed)) = MarshalRequest::decode(&buf) {
            return Ok(request);
        }
        if buf.len() >= 4 {
            let declared = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if declared > runix_ipc::marshal::MAX_JSON_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MarshalRequest declared length exceeds MAX_JSON_LEN",
                ));
            }
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MarshalRequest exceeds the maximum wire size without decoding",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "deadline reached before a full MarshalRequest was received",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before a full MarshalRequest was received",
            ));
        }
        if buf.is_empty() {
            // First byte: switch from the idle bound to the total frame bound.
            deadline = Instant::now() + frame_deadline;
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
    handle_connection_with(
        stream,
        transport,
        signing_key,
        worm_log,
        &ProxyLimits::default(),
    )
}

/// [`handle_connection`] with explicit [`ProxyLimits`].
pub fn handle_connection_with(
    stream: &mut TcpStream,
    transport: &HttpKerkeseTransport,
    signing_key: &SigningKey,
    worm_log: &Mutex<WormLog>,
    limits: &ProxyLimits,
) -> std::io::Result<()> {
    let request = read_marshal_request(stream, limits.first_byte_timeout, limits.frame_deadline)?;
    let response = build_response(transport, signing_key, worm_log, &request.kerkese_json);
    stream.set_write_timeout(Some(limits.write_timeout))?;
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

/// Binds `listen_addr` and serves connections forever with
/// [`ProxyLimits::default`]; see [`serve_listener`].
pub fn serve(listen_addr: &str, transport: HttpKerkeseTransport) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    serve_listener(listener, transport, ProxyLimits::default())
}

/// Serves connections off `listener` forever, using this proxy's own demo
/// Verifier signing key ([`super::identity::proxy_signing_key`]) and a fresh,
/// process-lifetime [`WormLog`] recording every verification decision this
/// proxy makes (see [`build_response`]).
///
/// Each accepted connection runs on its own thread (per-request state is
/// local to that thread; only the transport, key and WORM log are shared,
/// the log behind its `Mutex`). At most `limits.max_connections` run at
/// once: when that many are active, a new connection is closed immediately
/// (the kernel sees an EOF with no response, i.e. the same "proxy
/// unavailable" it would see from any dead proxy) rather than queued behind
/// a stuck one. Never returns; per-connection failures are logged to
/// stderr.
pub fn serve_listener(
    listener: TcpListener,
    transport: HttpKerkeseTransport,
    limits: ProxyLimits,
) -> std::io::Result<()> {
    let shared = Arc::new((
        transport,
        identity::proxy_signing_key(),
        Mutex::new(WormLog::default()),
    ));
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                eprintln!("citadel_proxy: accept error: {e}");
                continue;
            }
        };
        if active.fetch_add(1, Ordering::AcqRel) >= limits.max_connections {
            active.fetch_sub(1, Ordering::AcqRel);
            eprintln!("citadel_proxy: at connection cap, refusing a connection");
            continue; // dropping `stream` closes it
        }
        let shared = Arc::clone(&shared);
        let active_for_thread = Arc::clone(&active);
        let spawned = std::thread::Builder::new()
            .name("citadel_proxy-conn".to_string())
            .spawn(move || {
                let (transport, key, worm_log) = &*shared;
                if let Err(e) =
                    handle_connection_with(&mut stream, transport, key, worm_log, &limits)
                {
                    eprintln!("citadel_proxy: connection error: {e}");
                }
                active_for_thread.fetch_sub(1, Ordering::AcqRel);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::AcqRel);
            eprintln!("citadel_proxy: failed to spawn connection thread: {e}");
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

        // Long connect timeout: Windows retries SYNs to a closed port for
        // ~2 s before reporting refusal, which a short timeout would
        // (correctly) report as Timeout instead.
        let transport = HttpKerkeseTransport::with_timeouts(
            Some(format!("http://{dead_addr}/marshal/kerkese")),
            Duration::from_secs(10),
            Duration::from_secs(10),
        );

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

    // --- Real CITADEL answers REFUSE / HARD_STOP with HTTP 403 + the full
    // Decision body (handlers/marshal.go); 200 only for EXECUTE. ---

    fn decision_body(outcome: &str) -> String {
        format!(
            "{{\"execution_id\":\"00000000-0000-0000-0000-000000000000\",\"outcome\":\"{outcome}\",\"gates\":[],\"reasons\":[],\"ts_utc\":\"2026-07-26T12:00:01Z\"}}"
        )
    }

    fn http_response(status_line: &str, body: &str) -> &'static str {
        let s = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        Box::leak(s.into_boxed_str())
    }

    /// Runs one minimal envelope through the proxy against a mock CITADEL
    /// that replies with `response`.
    fn proxy_against(response: &'static str) -> MarshalResponse {
        let transport = HttpKerkeseTransport::new(Some(spawn_mock_server(response)));
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
        response
    }

    #[test]
    fn http_403_refuse_decision_becomes_refuse() {
        let r = proxy_against(http_response("403 Forbidden", &decision_body("REFUSE")));
        match r {
            MarshalResponse::Decision { outcome, .. } => {
                assert_eq!(outcome, MarshalOutcome::Refuse)
            }
            other => panic!("expected Decision Refuse, got {other:?}"),
        }
    }

    #[test]
    fn http_403_hard_stop_decision_becomes_hard_stop() {
        let r = proxy_against(http_response("403 Forbidden", &decision_body("HARD_STOP")));
        match r {
            MarshalResponse::Decision { outcome, .. } => {
                assert_eq!(outcome, MarshalOutcome::HardStop)
            }
            other => panic!("expected Decision HardStop, got {other:?}"),
        }
    }

    #[test]
    fn http_403_garbage_body_stays_bad_response() {
        let r = proxy_against(http_response("403 Forbidden", "not json"));
        assert!(matches!(
            r,
            MarshalResponse::Error(MarshalError::BadResponse(_))
        ));
    }

    #[test]
    fn http_403_with_execute_decision_never_becomes_execute() {
        let r = proxy_against(http_response("403 Forbidden", &decision_body("EXECUTE")));
        assert!(matches!(
            r,
            MarshalResponse::Error(MarshalError::BadResponse(_))
        ));
    }

    #[test]
    fn http_200_execute_decision_unchanged() {
        let r = proxy_against(http_response("200 OK", &decision_body("EXECUTE")));
        match r {
            MarshalResponse::Decision { outcome, .. } => {
                assert_eq!(outcome, MarshalOutcome::Execute)
            }
            other => panic!("expected Decision Execute, got {other:?}"),
        }
    }

    #[test]
    fn http_500_and_400_stay_bad_response() {
        for status in ["500 Internal Server Error", "400 Bad Request"] {
            // Even with a blocked-Decision-shaped body, only 403 is trusted.
            let r = proxy_against(http_response(status, &decision_body("REFUSE")));
            assert!(
                matches!(r, MarshalResponse::Error(MarshalError::BadResponse(_))),
                "{status}: {r:?}"
            );
        }
    }

    // ---- Hardening: idle / slow / oversized clients, concurrency cap ----

    /// Starts `serve_listener` on a background thread (it never returns; the
    /// thread dies with the test process) and returns its address.
    fn start_proxy(transport: HttpKerkeseTransport, limits: ProxyLimits) -> std::net::SocketAddr {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let addr = listener.local_addr().expect("proxy addr");
        std::thread::spawn(move || {
            let _ = serve_listener(listener, transport, limits);
        });
        addr
    }

    /// Asserts the peer closes `client` (EOF or reset) within `within`,
    /// without sending any response bytes.
    fn expect_closed(client: &mut TcpStream, within: Duration) {
        client.set_read_timeout(Some(within)).expect("set timeout");
        let mut b = [0u8; 16];
        match client.read(&mut b) {
            Ok(0) => {}
            Ok(n) => panic!("expected a close, got {n} bytes"),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            Err(e) => panic!("connection not closed within {within:?}: {e}"),
        }
    }

    fn assert_execute_response(r: MarshalResponse) {
        match r {
            MarshalResponse::Decision { outcome, .. } => {
                assert_eq!(outcome, MarshalOutcome::Execute)
            }
            other => panic!("expected Decision Execute, got {other:?}"),
        }
    }

    fn legit_request(addr: std::net::SocketAddr) -> MarshalResponse {
        round_trip(
            addr,
            &MarshalRequest {
                kerkese_json: minimal_envelope_json(),
            },
        )
    }

    #[test]
    fn idle_client_does_not_block_a_legitimate_request() {
        // A serial server would hold the legitimate request behind the idle
        // client for the whole 5 s first-byte timeout.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(5),
            ..ProxyLimits::default()
        };
        let transport = HttpKerkeseTransport::new(Some(spawn_mock_server(CANNED_EXECUTE_RESPONSE)));
        let addr = start_proxy(transport, limits);

        let _idle = TcpStream::connect(addr).expect("idle connect");
        let start = Instant::now();
        assert_execute_response(legit_request(addr));
        assert!(
            start.elapsed() < Duration::from_millis(3500),
            "legitimate request was delayed by an idle client: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn slow_loris_client_is_dropped_within_the_deadline() {
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(30),
            frame_deadline: Duration::from_millis(500),
            ..ProxyLimits::default()
        };
        let transport = HttpKerkeseTransport::new(None);
        let addr = start_proxy(transport, limits);

        let mut loris = TcpStream::connect(addr).expect("connect");
        loris.write_all(&[0x10]).expect("one byte");
        let start = Instant::now();
        expect_closed(&mut loris, Duration::from_secs(8));
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn trickling_bytes_cannot_extend_the_total_deadline() {
        // One byte every 200 ms would keep a per-read timeout alive forever;
        // the total deadline (600 ms) must still cut it off.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(30),
            frame_deadline: Duration::from_millis(600),
            ..ProxyLimits::default()
        };
        let addr = start_proxy(HttpKerkeseTransport::new(None), limits);
        let mut loris = TcpStream::connect(addr).expect("connect");
        let start = Instant::now();
        loris.write_all(&[0x40]).expect("first byte"); // declares 64 bytes (low byte)
        let mut closed = false;
        for _ in 0..25 {
            std::thread::sleep(Duration::from_millis(200));
            if loris.write_all(&[0x00]).is_err() {
                closed = true;
                break;
            }
        }
        if !closed {
            expect_closed(&mut loris, Duration::from_secs(5));
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn slow_start_before_the_first_byte_is_still_served() {
        // Regression for the CI hang: QEMU guestfwd's `nc` connects here
        // before the (TCG-slow) guest has sent anything. A delay longer than
        // `frame_deadline` but shorter than `first_byte_timeout` must be
        // tolerated, then the request answered normally.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(10),
            frame_deadline: Duration::from_millis(300),
            ..ProxyLimits::default()
        };
        let transport = HttpKerkeseTransport::new(Some(spawn_mock_server(CANNED_EXECUTE_RESPONSE)));
        let addr = start_proxy(transport, limits);

        let mut client = TcpStream::connect(addr).expect("connect");
        std::thread::sleep(Duration::from_millis(1200)); // 4x frame_deadline
        let encoded = MarshalRequest {
            kerkese_json: minimal_envelope_json(),
        }
        .encode();
        client.write_all(&encoded).expect("write request");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let response = loop {
            if let Some((resp, _)) = MarshalResponse::decode(&buf) {
                break resp;
            }
            let n = client.read(&mut chunk).expect("read response");
            assert_ne!(n, 0, "proxy dropped a slow-starting but legitimate client");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_execute_response(response);
    }

    #[test]
    fn fully_idle_client_is_dropped_at_the_first_byte_timeout() {
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_millis(600),
            ..ProxyLimits::default()
        };
        let addr = start_proxy(HttpKerkeseTransport::new(None), limits);
        let mut idle = TcpStream::connect(addr).expect("connect");
        let start = Instant::now();
        expect_closed(&mut idle, Duration::from_secs(8));
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");
    }

    #[test]
    fn slow_start_then_loris_is_cut_off_by_the_frame_deadline() {
        // The long idle allowance must not extend the frame bound: after the
        // first byte the clock restarts at `frame_deadline`, not at the
        // first-byte timeout's remainder.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(30),
            frame_deadline: Duration::from_millis(500),
            ..ProxyLimits::default()
        };
        let addr = start_proxy(HttpKerkeseTransport::new(None), limits);
        let mut c = TcpStream::connect(addr).expect("connect");
        std::thread::sleep(Duration::from_millis(400));
        c.write_all(&[0x10]).expect("one byte");
        let start = Instant::now();
        expect_closed(&mut c, Duration::from_secs(8));
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");
    }

    #[test]
    fn oversized_declared_length_is_rejected_without_waiting() {
        // Long deadline: rejection must come from the length check, not the
        // timeout.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_secs(30),
            ..ProxyLimits::default()
        };
        let addr = start_proxy(HttpKerkeseTransport::new(None), limits);
        let mut c = TcpStream::connect(addr).expect("connect");
        let declared = (runix_ipc::marshal::MAX_JSON_LEN as u32 + 1).to_le_bytes();
        c.write_all(&declared).expect("write prefix");
        let start = Instant::now();
        expect_closed(&mut c, Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn connections_beyond_the_cap_are_refused_not_queued() {
        // Documented behaviour: with `max_connections` idle clients holding
        // every slot, an extra connection is closed immediately (no
        // response, no queueing); once the idle ones hit the first-byte timeout
        // and are dropped, legitimate traffic is served again.
        let limits = ProxyLimits {
            first_byte_timeout: Duration::from_millis(1500),
            max_connections: 2,
            ..ProxyLimits::default()
        };
        let transport = HttpKerkeseTransport::new(Some(spawn_mock_server(CANNED_EXECUTE_RESPONSE)));
        let addr = start_proxy(transport, limits);

        let mut idle: Vec<TcpStream> = (0..2)
            .map(|_| TcpStream::connect(addr).expect("idle connect"))
            .collect();
        // Let the acceptor register both idle connections.
        std::thread::sleep(Duration::from_millis(300));

        let mut extra = TcpStream::connect(addr).expect("extra connect");
        let _ = extra.write_all(
            &MarshalRequest {
                kerkese_json: minimal_envelope_json(),
            }
            .encode(),
        );
        expect_closed(&mut extra, Duration::from_millis(1200));

        // The idle clients are themselves dropped at the deadline...
        for c in &mut idle {
            expect_closed(c, Duration::from_secs(8));
        }
        // ...after which the slots are free and a legitimate request works.
        assert_execute_response(legit_request(addr));
    }

    #[test]
    fn never_answering_citadel_yields_marshal_timeout_within_bound() {
        let silent = StdTcpListener::bind("127.0.0.1:0").expect("bind silent citadel");
        let silent_addr = silent.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = silent.accept() {
                read_http_request(&mut s);
                std::thread::sleep(Duration::from_secs(30));
            }
        });
        let transport = HttpKerkeseTransport::with_timeouts(
            Some(format!("http://{silent_addr}/marshal/kerkese")),
            Duration::from_millis(500),
            Duration::from_millis(500),
        );
        let addr = start_proxy(transport, ProxyLimits::default());
        let start = Instant::now();
        let r = legit_request(addr);
        assert!(
            matches!(r, MarshalResponse::Error(MarshalError::Timeout)),
            "{r:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }
}
