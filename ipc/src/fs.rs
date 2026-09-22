//! Filesystem IPC wire format: `blk-driver-host`'s Phase 8 surface (one
//! fixed port per file, no filename in the payload, no per-request
//! authorization — see `docs/STATUS.md`'s filesystem-driver Phase 8
//! section and `docs/THREAT_MODEL.md`'s revisit trigger for exactly what
//! this closes) generalized into a real, typed request/response pair that
//! carries an arbitrary filename *and* a per-file
//! [`runix_capability_manager::CapabilityToken`] on every request, instead
//! of relying on capability scoping decided once at process-spawn time.
//!
//! Same transport constraint [`crate::sockets`] documents (`SYS_IPC_SEND`/
//! `SYS_IPC_RECV` move one byte at a time, no blocking receive) and the
//! same reason encoding is a tag byte plus length-prefixed fields rather
//! than `serde`: [`FsRequest::decode`]/[`FsResponse::decode`] are fed a
//! growing buffer and return `None` ("not enough bytes yet") without
//! discarding what's already accumulated, so a caller just keeps
//! appending bytes as they arrive and retries decoding.
//!
//! **The actual authorization model this closes**: the destination port
//! (`FS_REQUEST_PORT`/`FS_WRITE_REQUEST_PORT`, both still capability-gated
//! by the *kernel's* existing `port:<n>` convention, unchanged) only
//! proves a caller is allowed to talk to the filesystem service at all —
//! a coarse, shareable "client of this service" grant. Which *file* that
//! talking is allowed to touch is authorized separately, per request, by
//! `blk-driver-host` itself verifying the embedded [`CapabilityToken`]
//! against a resource string scoped to the requested name (see
//! `blk-driver-host/src/main.rs`'s `file_resource`/`verify_file_token`) —
//! the two-layer split `docs/STATUS.md`'s Phase 8 section named as the
//! next trigger ("a real path-scoped capability convention"), now
//! implemented by reusing `capability-manager`'s existing token model
//! rather than inventing a parallel one.

use alloc::string::String;
use alloc::vec::Vec;
use runix_capability_manager::CapabilityToken;

/// Wire-format sanity bound on the filename field — well past any real
/// filename this codebase's fixtures use, purely so a corrupt/adversarial
/// length header can't be misread as "wait for gigabytes more," same
/// reasoning as [`crate::sockets::MAX_PAYLOAD_LEN`].
pub const MAX_NAME_LEN: usize = 64;
/// Same bound, applied to each of a [`CapabilityToken`]'s own string
/// fields (`subject`/`resource`/`key_id`/`signature`) — a hex-encoded
/// Ed25519 signature is 128 characters; this leaves generous headroom
/// without accepting an unbounded field.
pub const MAX_TOKEN_FIELD_LEN: usize = 256;
/// Matches `blk-driver-host`'s own `SECTOR_SIZE`-based write bound in
/// spirit, generalized: a write payload larger than this is rejected
/// outright by [`FsRequest::decode`], not truncated.
pub const MAX_DATA_LEN: usize = 4096;

/// Doubling the per-request encoded size, roughly: every [`FsRequest`]
/// variant now embeds a *second* [`CapabilityToken`]
/// (`response_token`, scoped to `port:<response_port>`) alongside the
/// existing per-file one -- `docs/RFC-IPC-RESPONSE-CAPABILITY.md`'s Option A,
/// the fix for the shared-response-port confidentiality leak
/// `docs/THREAT_MODEL.md` names. Not a new size bound in itself (each
/// token's own fields are still checked against [`MAX_TOKEN_FIELD_LEN`]
/// exactly as before) -- called out here because a token is already well
/// over a kilobyte encoded and this genuinely doubles the bytes
/// `blk-driver-host`'s `FS_MAX_PENDING_BYTES` and the underlying 32-byte
/// `kernel::ipc::Channel` have to shepherd through one byte at a time per
/// request, the cost the RFC's own Open Questions section flags against
/// T1's <300ms MARSHAL budget.
const _RESPONSE_TOKEN_DOUBLES_REQUEST_SIZE: () = ();

fn encode_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `Some((string, bytes_consumed))`, or `None` if `buf` doesn't yet hold a
/// complete length-prefixed string, the length exceeds
/// [`MAX_TOKEN_FIELD_LEN`], or the bytes aren't valid UTF-8 (every field
/// this decodes is ASCII in practice, but this never assumes that of
/// untrusted input rather than checking).
fn decode_string(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len > MAX_TOKEN_FIELD_LEN {
        return None;
    }
    if buf.len() < 2 + len {
        return None;
    }
    let s = core::str::from_utf8(&buf[2..2 + len]).ok()?;
    Some((String::from(s), 2 + len))
}

fn encode_token(out: &mut Vec<u8>, token: &CapabilityToken) {
    encode_string(out, &token.subject);
    encode_string(out, &token.resource);
    out.extend_from_slice(&token.issued_at.to_le_bytes());
    out.extend_from_slice(&token.expires_at.to_le_bytes());
    encode_string(out, &token.key_id);
    encode_string(out, &token.signature);
}

fn decode_token(buf: &[u8]) -> Option<(CapabilityToken, usize)> {
    let mut off = 0;
    let (subject, n) = decode_string(&buf[off..])?;
    off += n;
    let (resource, n) = decode_string(buf.get(off..)?)?;
    off += n;
    if buf.len() < off + 16 {
        return None;
    }
    let issued_at = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let expires_at = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let (key_id, n) = decode_string(buf.get(off..)?)?;
    off += n;
    let (signature, n) = decode_string(buf.get(off..)?)?;
    off += n;
    Some((
        CapabilityToken {
            subject,
            resource,
            issued_at,
            expires_at,
            key_id,
            signature,
        },
        off,
    ))
}

/// Client -> `blk-driver-host`, over a fixed request port (still
/// capability-gated at the port level — see this module's own doc
/// comment for what that layer proves vs. what `token` here proves).
///
/// **`response_port`/`response_token`** — `docs/RFC-IPC-RESPONSE-CAPABILITY.md`
/// Option A: which port `blk-driver-host` should send the [`FsResponse`]
/// back on, plus a [`CapabilityToken`] scoped to `port:<response_port>`
/// proving the caller actually holds (i.e. was spawned with, or otherwise
/// granted) the authorization to receive there. Before this existed, every
/// client answered on one fixed, shared response port — any process that
/// could issue `SYS_IPC_RECV` on it could drain *another* client's file
/// contents regardless of whether it ever held a `file:<name>` token for
/// that content. `blk-driver-host` verifies `response_token` itself
/// (`verify_response_token`) before ever sending a byte; a request whose
/// response token fails to verify is dropped, not answered on the port it
/// claims, since replying there is exactly the leak this closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsRequest {
    /// Read `name`'s full contents. Answered with [`FsResponse::Data`] or
    /// [`FsResponse::Error`], sent to `response_port`.
    Read {
        name: String,
        token: CapabilityToken,
        response_port: u16,
        response_token: CapabilityToken,
    },
    /// Overwrite `name`'s contents with `data`. Answered with
    /// [`FsResponse::Ok`] or [`FsResponse::Error`] — same single-sector,
    /// no-resize restriction `blk-driver-host`'s own write path already
    /// documents (see `handle_write_ipc_request`'s doc comment); this
    /// wire format itself allows up to [`MAX_DATA_LEN`], the driver
    /// enforces the tighter bound.
    Write {
        name: String,
        token: CapabilityToken,
        data: Vec<u8>,
        response_port: u16,
        response_token: CapabilityToken,
    },
}

impl FsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            FsRequest::Read {
                name,
                token,
                response_port,
                response_token,
            } => {
                out.push(0);
                encode_string(&mut out, name);
                encode_token(&mut out, token);
                out.extend_from_slice(&response_port.to_le_bytes());
                encode_token(&mut out, response_token);
            }
            FsRequest::Write {
                name,
                token,
                data,
                response_port,
                response_token,
            } => {
                out.push(1);
                encode_string(&mut out, name);
                encode_token(&mut out, token);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
                out.extend_from_slice(&response_port.to_le_bytes());
                encode_token(&mut out, response_token);
            }
        }
        out
    }

    /// Same "`None` means not enough bytes yet, never panics" contract as
    /// [`crate::sockets::SocketRequest::decode`].
    pub fn decode(buf: &[u8]) -> Option<(FsRequest, usize)> {
        let &tag = buf.first()?;
        let mut off = 1;
        let (name, n) = decode_string(buf.get(off..)?)?;
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        off += n;
        let (token, n) = decode_token(buf.get(off..)?)?;
        off += n;
        match tag {
            0 => {
                let rest = buf.get(off..)?;
                if rest.len() < 2 {
                    return None;
                }
                let response_port = u16::from_le_bytes([rest[0], rest[1]]);
                off += 2;
                let (response_token, n) = decode_token(buf.get(off..)?)?;
                off += n;
                Some((
                    FsRequest::Read {
                        name,
                        token,
                        response_port,
                        response_token,
                    },
                    off,
                ))
            }
            1 => {
                let rest = buf.get(off..)?;
                if rest.len() < 2 {
                    return None;
                }
                let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
                if len > MAX_DATA_LEN {
                    return None;
                }
                if rest.len() < 2 + len {
                    return None;
                }
                let data = rest[2..2 + len].to_vec();
                off += 2 + len;
                let rest = buf.get(off..)?;
                if rest.len() < 2 {
                    return None;
                }
                let response_port = u16::from_le_bytes([rest[0], rest[1]]);
                off += 2;
                let (response_token, n) = decode_token(buf.get(off..)?)?;
                off += n;
                Some((
                    FsRequest::Write {
                        name,
                        token,
                        data,
                        response_port,
                        response_token,
                    },
                    off,
                ))
            }
            _ => None,
        }
    }
}

/// `blk-driver-host` -> client, over a fixed response port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsResponse {
    Data(Vec<u8>),
    Ok,
    Error(FsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// The embedded token didn't verify (bad signature, expired, or
    /// scoped to a different resource than `file:<name>`) — the whole
    /// point of this module, see its own doc comment.
    Unauthorized,
    NotFound,
    /// A length field, or a write whose length isn't exactly what the
    /// target file's single-sector write path requires, didn't fit this
    /// wire format's or the driver's own bounds.
    BadRequest,
    DeviceFailed,
}

impl FsError {
    fn to_byte(self) -> u8 {
        match self {
            FsError::Unauthorized => 0,
            FsError::NotFound => 1,
            FsError::BadRequest => 2,
            FsError::DeviceFailed => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<FsError> {
        match byte {
            0 => Some(FsError::Unauthorized),
            1 => Some(FsError::NotFound),
            2 => Some(FsError::BadRequest),
            3 => Some(FsError::DeviceFailed),
            _ => None,
        }
    }
}

impl FsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            FsResponse::Data(data) => {
                out.push(0);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            FsResponse::Ok => out.push(1),
            FsResponse::Error(err) => {
                out.push(2);
                out.push(err.to_byte());
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<(FsResponse, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => {
                if buf.len() < 3 {
                    return None;
                }
                let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                if len > MAX_DATA_LEN {
                    return None;
                }
                if buf.len() < 3 + len {
                    return None;
                }
                Some((FsResponse::Data(buf[3..3 + len].to_vec()), 3 + len))
            }
            1 => Some((FsResponse::Ok, 1)),
            2 => {
                let &err_byte = buf.get(1)?;
                let err = FsError::from_byte(err_byte)?;
                Some((FsResponse::Error(err), 2))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_token(resource: &str) -> CapabilityToken {
        CapabilityToken {
            subject: String::from("test-subject"),
            resource: String::from(resource),
            issued_at: 10,
            expires_at: 20,
            key_id: String::from("demo-key"),
            signature: String::from("deadbeef"),
        }
    }

    #[test]
    fn read_request_round_trips() {
        let req = FsRequest::Read {
            name: String::from("HELLO.TXT"),
            token: dummy_token("file:HELLO.TXT"),
            response_port: 4,
            response_token: dummy_token("port:4"),
        };
        let bytes = req.encode();
        assert_eq!(FsRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn write_request_round_trips() {
        let req = FsRequest::Write {
            name: String::from("WRITE.TXT"),
            token: dummy_token("file:WRITE.TXT"),
            data: alloc::vec![1, 2, 3, 4, 5],
            response_port: 5,
            response_token: dummy_token("port:5"),
        };
        let bytes = req.encode();
        assert_eq!(FsRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn data_response_round_trips() {
        let resp = FsResponse::Data(alloc::vec![9, 8, 7]);
        let bytes = resp.encode();
        assert_eq!(FsResponse::decode(&bytes), Some((resp, bytes.len())));
    }

    #[test]
    fn ok_and_error_responses_round_trip() {
        let ok = FsResponse::Ok;
        assert_eq!(FsResponse::decode(&ok.encode()), Some((ok, 1)));
        for err in [
            FsError::Unauthorized,
            FsError::NotFound,
            FsError::BadRequest,
            FsError::DeviceFailed,
        ] {
            let resp = FsResponse::Error(err);
            let bytes = resp.encode();
            assert_eq!(FsResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }

    #[test]
    fn truncated_read_request_asks_for_more_not_garbage() {
        let full = FsRequest::Read {
            name: String::from("HELLO.TXT"),
            token: dummy_token("file:HELLO.TXT"),
            response_port: 4,
            response_token: dummy_token("port:4"),
        }
        .encode();
        for cut in 0..full.len() {
            assert_eq!(FsRequest::decode(&full[..cut]), None);
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn fs_request_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..128)) {
                let _ = FsRequest::decode(&buf);
            }

            #[test]
            fn fs_response_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..128)) {
                let _ = FsResponse::decode(&buf);
            }
        }
    }
}
