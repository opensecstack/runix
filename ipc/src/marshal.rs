//! MARSHAL evaluation IPC surface: typed request/response wire types for
//! asking a user-space MARSHAL proxy (a `desktop` process holding the real
//! HTTP transport to CITADEL — see `citadel-integration::KerkeseTransport`'s
//! doc comment for why that transport lives in user-space, not the kernel)
//! "evaluate this Kerkese-shaped action, tell me the Decision", over Runix's
//! own IPC rather than a live network round-trip from kernel code.
//!
//! **This module carries no governance logic of its own.** It is wire
//! plumbing only — a typed way to move a Kerkese-shaped request out of the
//! kernel and a Decision-shaped response back in. It is also not wired into
//! any real authorization path today (see `kernel/src/marshal_client.rs`'s
//! doc comment for exactly what does and doesn't call through it yet).
//!
//! # Mirrors `citadel-kerkese-core`, does not depend on it
//!
//! [`MarshalRequest::kerkese_json`] is meant to carry the same JSON shape as
//! `opensecstack/sdk/rust`'s `citadel-kerkese-core::kerkese::Kerkese` (see
//! that crate's `src/kerkese.rs`) — `kerkese_version`, `ts_utc`,
//! `project_id`, `execution_id`, `action`, `actor`, `verifier`, `evidence`,
//! `sod`, and the rest of that struct's fields — and [`MarshalOutcome`]
//! mirrors that crate's `decision::Outcome` (`Execute`/`Refuse`/`HardStop`)
//! field-for-field. Neither this crate nor `kernel/` depends on
//! `citadel-kerkese-core` directly: that crate isn't published yet (see
//! `citadel-integration`'s module doc comment, "still blocked on
//! `opensecstack/sdk/rust`"), and both `ipc` and `kernel` need to stay
//! dependency-light/no_std-safe without pulling in a new crate (and a JSON
//! library — this crate has no `serde_json` outside its `std`-gated
//! `envelope` module, see `lib.rs`) just for this. `kerkese_json` is
//! therefore carried as an opaque, already-JSON-encoded byte blob this
//! module never parses or validates — whatever constructs it (a future,
//! carefully-reviewed kernel call site, once `opensecstack/sdk/rust` lands)
//! owns getting that shape right; whatever receives it (the user-space
//! MARSHAL proxy) owns actually parsing it before forwarding to a real Gate.
//!
//! # Transport
//!
//! Same transport constraint [`crate::sockets`]/[`crate::fs`] document
//! (`SYS_IPC_SEND`/`SYS_IPC_RECV` move one byte at a time, no blocking
//! receive), and the same reason encoding is a tag byte plus
//! length-prefixed fields rather than `serde`:
//! [`MarshalRequest::decode`]/[`MarshalResponse::decode`] are fed a growing
//! buffer and return `None` ("not enough bytes yet") without discarding
//! what's already accumulated, so a caller just keeps appending bytes as
//! they arrive and retries decoding.

use alloc::string::String;
use alloc::vec::Vec;

/// Wire-format sanity bound on [`MarshalRequest::kerkese_json`]/
/// [`MarshalResponse::Decision::decision_json`] — generous enough for a
/// real Kerkese/Decision JSON envelope (which can carry evidence artifacts,
/// gate results, etc.), but still a bound, so a corrupt/adversarial length
/// header can't be misread as "wait for gigabytes more before deciding this
/// message is bogus" — same reasoning as [`crate::sockets::MAX_PAYLOAD_LEN`]/
/// [`crate::fs::MAX_DATA_LEN`].
pub const MAX_JSON_LEN: usize = 16384;

/// Wire-format sanity bound on [`MarshalError`]'s message fields — same
/// reasoning as [`crate::fs::MAX_TOKEN_FIELD_LEN`], generous headroom for a
/// short human-readable diagnostic without accepting an unbounded field.
pub const MAX_MESSAGE_LEN: usize = 256;

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// `Some((bytes, bytes_consumed))`, or `None` if `buf` doesn't yet hold a
/// complete length-prefixed blob, or the declared length exceeds
/// [`MAX_JSON_LEN`].
fn decode_bytes(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_JSON_LEN {
        return None;
    }
    if buf.len() < 4 + len {
        return None;
    }
    Some((buf[4..4 + len].to_vec(), 4 + len))
}

fn encode_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Same "`None` means not enough bytes yet, never panics" contract as
/// [`crate::fs`]'s identically-named private helper — duplicated rather
/// than shared across modules, same as `fs`/`sockets` never share their own
/// tag-byte conventions with each other.
fn decode_string(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len > MAX_MESSAGE_LEN {
        return None;
    }
    if buf.len() < 2 + len {
        return None;
    }
    let s = core::str::from_utf8(&buf[2..2 + len]).ok()?;
    Some((String::from(s), 2 + len))
}

/// Kernel client -> MARSHAL proxy, over a fixed request port (still
/// capability-gated at the port level, same "port proves you may talk to
/// this service at all" posture [`crate::fs`]'s own doc comment describes
/// for its request port).
///
/// A struct, not an enum, because there is exactly one request shape today:
/// "evaluate this Kerkese envelope." A future second request kind (e.g. a
/// health check) would need a tag byte the way [`MarshalResponse`] already
/// has one; not added preemptively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarshalRequest {
    /// Opaque, already-JSON-encoded bytes meant to carry the same shape as
    /// `citadel-kerkese-core::kerkese::Kerkese` — see this module's own doc
    /// comment for exactly what "meant to carry" does and doesn't mean.
    pub kerkese_json: Vec<u8>,
}

impl MarshalRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, &self.kerkese_json);
        out
    }

    /// `Some((request, bytes_consumed))` once `buf` holds a full message,
    /// `None` if more bytes are needed yet. Never panics on malformed or
    /// truncated input — same untrusted-input posture every other wire
    /// parser in this crate applies (see [`crate::sockets::SocketRequest::decode`]'s
    /// doc comment).
    pub fn decode(buf: &[u8]) -> Option<(MarshalRequest, usize)> {
        let (kerkese_json, consumed) = decode_bytes(buf)?;
        Some((MarshalRequest { kerkese_json }, consumed))
    }
}

/// `outcome` field of a [`MarshalResponse::Decision`] — matches
/// `citadel-kerkese-core::decision::Outcome` field-for-field (`Execute`/
/// `Refuse`/`HardStop`), not an independent design. See this module's own
/// doc comment for why this crate mirrors that shape without depending on
/// the crate that defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarshalOutcome {
    Execute,
    Refuse,
    HardStop,
}

impl MarshalOutcome {
    /// `true` for [`MarshalOutcome::Refuse`] and [`MarshalOutcome::HardStop`]
    /// — mirrors `citadel-kerkese-core::decision::Outcome::is_blocked`.
    pub fn is_blocked(&self) -> bool {
        !matches!(self, MarshalOutcome::Execute)
    }

    fn to_byte(self) -> u8 {
        match self {
            MarshalOutcome::Execute => 0,
            MarshalOutcome::Refuse => 1,
            MarshalOutcome::HardStop => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<MarshalOutcome> {
        match byte {
            0 => Some(MarshalOutcome::Execute),
            1 => Some(MarshalOutcome::Refuse),
            2 => Some(MarshalOutcome::HardStop),
            _ => None,
        }
    }
}

/// Why the MARSHAL proxy could not answer with a real [`MarshalOutcome`] —
/// matches `runix_citadel_integration::TransportError`'s shape (itself
/// matching `citadel-kerkese-core::transport::TransportError`, see that
/// type's own doc comment), mirrored rather than reused directly: `ipc`
/// does not depend on `citadel-integration` (this crate is shared by the
/// kernel *and* user-space services with no other reason to pull in CITADEL
/// signature-verification code), so a MARSHAL-proxy-side caller translates
/// its own `TransportError` into this wire-level equivalent before
/// replying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarshalError {
    /// The proxy could not reach MARSHAL at all.
    Unreachable(String),
    /// The proxy reached MARSHAL but got no usable response in time.
    Timeout,
    /// The proxy got a response, but it wasn't a well-formed Decision.
    BadResponse(String),
    /// Anything else.
    Other(String),
}

impl MarshalError {
    fn tag(&self) -> u8 {
        match self {
            MarshalError::Unreachable(_) => 0,
            MarshalError::Timeout => 1,
            MarshalError::BadResponse(_) => 2,
            MarshalError::Other(_) => 3,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            MarshalError::Unreachable(msg)
            | MarshalError::BadResponse(msg)
            | MarshalError::Other(msg) => encode_string(out, msg),
            MarshalError::Timeout => {}
        }
    }

    fn decode(buf: &[u8]) -> Option<(MarshalError, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => {
                let (msg, n) = decode_string(buf.get(1..)?)?;
                Some((MarshalError::Unreachable(msg), 1 + n))
            }
            1 => Some((MarshalError::Timeout, 1)),
            2 => {
                let (msg, n) = decode_string(buf.get(1..)?)?;
                Some((MarshalError::BadResponse(msg), 1 + n))
            }
            3 => {
                let (msg, n) = decode_string(buf.get(1..)?)?;
                Some((MarshalError::Other(msg), 1 + n))
            }
            _ => None,
        }
    }
}

/// MARSHAL proxy -> kernel client, over a fixed response port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarshalResponse {
    /// The proxy got a real Decision back from MARSHAL. `decision_json` is
    /// the same "opaque, meant to mirror `citadel-kerkese-core::decision::Decision`,
    /// never parsed by this crate" carrier [`MarshalRequest::kerkese_json`]
    /// is for the request side — `outcome` is pulled out and carried
    /// structurally alongside it purely so a caller can act on `EXECUTE`/
    /// `REFUSE`/`HARD_STOP` without having to parse JSON it may have no
    /// `no_std` way to parse at all.
    Decision {
        outcome: MarshalOutcome,
        decision_json: Vec<u8>,
    },
    /// The proxy could not produce a Decision at all — see [`MarshalError`].
    Error(MarshalError),
}

impl MarshalResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            MarshalResponse::Decision {
                outcome,
                decision_json,
            } => {
                out.push(0);
                out.push(outcome.to_byte());
                encode_bytes(&mut out, decision_json);
            }
            MarshalResponse::Error(err) => {
                out.push(1);
                err.encode(&mut out);
            }
        }
        out
    }

    /// Same "`None` means not enough bytes yet, never panics" contract as
    /// [`MarshalRequest::decode`].
    pub fn decode(buf: &[u8]) -> Option<(MarshalResponse, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => {
                let &outcome_byte = buf.get(1)?;
                let outcome = MarshalOutcome::from_byte(outcome_byte)?;
                let (decision_json, n) = decode_bytes(buf.get(2..)?)?;
                Some((
                    MarshalResponse::Decision {
                        outcome,
                        decision_json,
                    },
                    2 + n,
                ))
            }
            1 => {
                let (err, n) = MarshalError::decode(buf.get(1..)?)?;
                Some((MarshalResponse::Error(err), 1 + n))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn request_round_trips() {
        let req = MarshalRequest {
            kerkese_json: br#"{"kerkese_version":"1.0"}"#.to_vec(),
        };
        let bytes = req.encode();
        assert_eq!(MarshalRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn empty_request_round_trips() {
        let req = MarshalRequest {
            kerkese_json: Vec::new(),
        };
        let bytes = req.encode();
        assert_eq!(MarshalRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn truncated_request_asks_for_more_not_garbage() {
        let full = MarshalRequest {
            kerkese_json: alloc::vec![1, 2, 3, 4, 5],
        }
        .encode();
        for cut in 0..full.len() {
            assert_eq!(MarshalRequest::decode(&full[..cut]), None);
        }
    }

    #[test]
    fn decision_response_round_trips() {
        for outcome in [
            MarshalOutcome::Execute,
            MarshalOutcome::Refuse,
            MarshalOutcome::HardStop,
        ] {
            let resp = MarshalResponse::Decision {
                outcome,
                decision_json: br#"{"outcome":"EXECUTE"}"#.to_vec(),
            };
            let bytes = resp.encode();
            assert_eq!(MarshalResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }

    #[test]
    fn error_responses_round_trip() {
        for err in [
            MarshalError::Unreachable(String::from("no route")),
            MarshalError::Timeout,
            MarshalError::BadResponse(String::from("not json")),
            MarshalError::Other(String::from("???")),
        ] {
            let resp = MarshalResponse::Error(err);
            let bytes = resp.encode();
            assert_eq!(MarshalResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }

    #[test]
    fn is_blocked_matches_execute_only() {
        assert!(!MarshalOutcome::Execute.is_blocked());
        assert!(MarshalOutcome::Refuse.is_blocked());
        assert!(MarshalOutcome::HardStop.is_blocked());
    }

    #[test]
    fn truncated_decision_response_asks_for_more_not_garbage() {
        let full = MarshalResponse::Decision {
            outcome: MarshalOutcome::HardStop,
            decision_json: alloc::vec![9, 9, 9],
        }
        .encode();
        for cut in 0..full.len() {
            assert_eq!(MarshalResponse::decode(&full[..cut]), None);
        }
    }

    proptest! {
        // Same regression class [`crate::sockets`]'s own proptests exist to
        // prevent: no byte sequence, however malformed or truncated, may
        // make either `decode` panic — this wire format is read from a byte
        // channel a (possibly compromised) MARSHAL proxy or client writes
        // to.
        #[test]
        fn marshal_request_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = MarshalRequest::decode(&buf);
        }

        #[test]
        fn marshal_response_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = MarshalResponse::decode(&buf);
        }

        #[test]
        fn request_round_trips_for_any_payload(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let req = MarshalRequest { kerkese_json: data };
            let bytes = req.encode();
            prop_assert_eq!(MarshalRequest::decode(&bytes), Some((req, bytes.len())));
        }
    }
}
