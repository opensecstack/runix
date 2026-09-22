//! Sockets IPC surface: typed request/response wire types for the TCP
//! connections `net-driver-host` exposes over its `smoltcp` stack (see
//! `docs/STATUS.md`'s network-stack section — "a sockets API/IPC surface
//! for other ring 3 processes to use this stack" is exactly the gap this
//! module closes). `no_std` + `alloc` (this crate's default; see `lib.rs`'s
//! doc comment), so `net-driver-host` — a freestanding ring 3 binary with
//! no `std` — can depend on this crate directly instead of hand-rolling its
//! own byte layout.
//!
//! The underlying transport (`kernel/src/syscall.rs`'s
//! `SYS_IPC_SEND`/`SYS_IPC_RECV`, `kernel/src/ipc.rs`'s fixed-count byte
//! channels — see `blk-driver-host/src/main.rs`'s Phase 8 filesystem IPC
//! surface for the established precedent this mirrors) moves exactly one
//! byte per syscall and has no blocking receive. That's why encoding is a
//! plain tag byte plus fixed/length-prefixed fields rather than `serde`:
//! [`SocketRequest::decode`]/[`SocketResponse::decode`] are written to be
//! fed a growing buffer one byte at a time and return `None` ("not enough
//! bytes yet") without discarding what's already been accumulated, so a
//! caller can just keep appending bytes as they arrive off the channel and
//! retry decoding.
//!
//! Concurrent sockets: [`SocketRequest::Open`] allocates one of a small,
//! fixed number of socket handles (`net-driver-host`'s own `SocketSet`
//! capacity — see that process's `main.rs`) — answered with
//! [`SocketResponse::Opened`]'s `handle`, or [`SocketResponse::OpenFailed`]
//! with [`SocketError::TooManyOpen`] if none are free. Every other request
//! (`Connect`/`Send`/`Recv`/`Close`) names the handle it applies to, so two
//! open connections never clobber each other's state — `net-driver-host`
//! rejects any request naming a handle that was never opened (or already
//! closed) with [`SocketError::InvalidHandle`], the same "no ambient
//! authority" posture this codebase's capability model applies everywhere
//! else: naming a handle is not the same as being entitled to it, though
//! this wire format alone can't distinguish *which caller* opened a given
//! handle when multiple processes share the same fixed request/response
//! ports — see `net-driver-host/src/main.rs`'s `run_socket_ipc_server` doc
//! comment for that scoping caveat and why the capability gate is on the
//! *port*, not the handle.
//!
//! **Updated by `docs/RFC-IPC-RESPONSE-CAPABILITY.md` (Option A):** the
//! port-level capability gate is now two-way — `SYS_IPC_RECV` checks the
//! same `port:<n>` resource `SYS_IPC_SEND` always has, so a process with no
//! token for [`SOCK_RESPONSE_PORT`... see `net-driver-host/src/main.rs`]
//! can no longer drain it just by asking. That closes ambient *receive*
//! access to the response port, full stop. It does **not** close the gap
//! this doc comment already named: sockets still share one fixed
//! request/response port pair across every caller, and a handle is still
//! nameable by anyone holding the port-level token, with no per-handle
//! owner check behind it — the RFC deliberately scoped that out as
//! `net-driver-host`'s own follow-up work, not part of Option A. Do not
//! read the recv-side gate landing as this gap having closed too; it has
//! not.
//!
//! DHCP is out of scope for this module: [`SocketRequest::Connect`] takes
//! an already-resolved remote address, not a hostname, and address
//! acquisition for the interface itself is `net-driver-host`'s own
//! boot-time concern (`NetBootInfo::use_dhcp`), unrelated to this
//! already-up-and-running sockets surface.

use alloc::vec::Vec;

/// Number of concurrently open socket handles `net-driver-host` supports —
/// must match that process's own `SocketSet` capacity
/// (`main.rs::MAX_SOCKETS`). Purely a wire-format sanity bound (valid handle
/// values are `0..MAX_SOCKETS`), not renegotiated in-band.
pub const MAX_SOCKETS: u8 = 4;

/// Client -> `net-driver-host`, over a fixed request port (see that
/// process's own doc comment for the exact port numbers this codebase
/// uses, same "fixed port per purpose, decided at spawn time" convention
/// `blk-driver-host`'s filesystem IPC surface already established).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketRequest {
    /// Allocate a new socket handle. Answered with
    /// [`SocketResponse::Opened`] or [`SocketResponse::OpenFailed`] with
    /// [`SocketError::TooManyOpen`] if every handle is already in use. Must
    /// precede any [`SocketRequest::Connect`] naming the returned handle.
    Open,
    /// Open a TCP connection on `handle` (already allocated by
    /// [`SocketRequest::Open`]). Answered with
    /// [`SocketResponse::Connected`] or [`SocketResponse::ConnectFailed`] —
    /// the latter with [`SocketError::AlreadyOpen`] if `handle` already has
    /// a connection, or [`SocketError::InvalidHandle`] if `handle` was
    /// never opened.
    Connect {
        handle: u8,
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
    },
    /// Send `data` on `handle`'s open connection. Answered with
    /// [`SocketResponse::Sent`] (the number of bytes actually queued —
    /// may be less than `data.len()` if the socket's send buffer is
    /// nearly full) or [`SocketResponse::SendFailed`].
    Send { handle: u8, data: Vec<u8> },
    /// Ask for up to `max_len` bytes currently buffered for receipt on
    /// `handle`. Never blocks waiting for more to arrive — see
    /// [`SocketResponse::Data`]'s doc comment — so a caller polling for a
    /// reply may need to retry.
    Recv { handle: u8, max_len: u16 },
    /// Close `handle`'s connection and free the handle itself for reuse by
    /// a future [`SocketRequest::Open`]. Answered with
    /// [`SocketResponse::Closed`] unconditionally for a handle that was
    /// ever opened — closing an already-closed connection is not an error,
    /// matching `smoltcp::socket::tcp::Socket::close`'s own idempotent
    /// behavior — or [`SocketResponse::Error`] with
    /// [`SocketError::InvalidHandle`] if `handle` was never opened.
    Close { handle: u8 },
}

/// `net-driver-host` -> client, over a fixed response port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketResponse {
    /// Answers a [`SocketRequest::Connect`] that succeeded.
    Connected {
        handle: u8,
    },
    /// Answers a [`SocketRequest::Open`] that failed (before any handle
    /// exists to report) — currently only [`SocketError::TooManyOpen`].
    OpenFailed(SocketError),
    /// Answers a [`SocketRequest::Connect`] that failed.
    ConnectFailed {
        handle: u8,
        error: SocketError,
    },
    Sent {
        handle: u8,
        len: u16,
    },
    SendFailed {
        handle: u8,
        error: SocketError,
    },
    /// Zero or more bytes actually available right now on `handle`. Empty
    /// is a normal, non-error result ("nothing arrived yet"), not
    /// [`SocketResponse::Error`] — matching `net-driver-host`'s own
    /// non-blocking poll loop (there is no blocking-receive syscall in this
    /// codebase; see `blk-driver-host/src/main.rs`'s `poll_recv_byte` doc
    /// comment for the same constraint on the transport this rides over).
    Data {
        handle: u8,
        data: Vec<u8>,
    },
    /// Answers a successful [`SocketRequest::Open`] with the newly
    /// allocated handle.
    Opened {
        handle: u8,
    },
    Closed {
        handle: u8,
    },
    Error {
        handle: u8,
        error: SocketError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// [`SocketRequest::Connect`] on a handle that already has a
    /// connection open.
    AlreadyOpen,
    /// [`SocketRequest::Send`]/[`SocketRequest::Recv`] on a handle with no
    /// connection open.
    NotOpen,
    /// A length field (e.g. [`SocketRequest::Send`]'s payload) didn't fit
    /// this wire format's bounds.
    InvalidLength,
    /// The connect attempt itself failed (refused, timed out, or the
    /// underlying device reported a failure) — distinct from `NotOpen`,
    /// which means no attempt is in flight at all.
    ConnectFailed,
    /// [`SocketRequest::Open`] with every handle already in use — see
    /// [`MAX_SOCKETS`].
    TooManyOpen,
    /// A request named a handle that was never opened (or has already
    /// been [`SocketRequest::Close`]d) — never ambient authority just
    /// because a number happens to be in range.
    InvalidHandle,
}

impl SocketError {
    fn to_byte(self) -> u8 {
        match self {
            SocketError::AlreadyOpen => 0,
            SocketError::NotOpen => 1,
            SocketError::InvalidLength => 2,
            SocketError::ConnectFailed => 3,
            SocketError::TooManyOpen => 4,
            SocketError::InvalidHandle => 5,
        }
    }

    fn from_byte(byte: u8) -> Option<SocketError> {
        match byte {
            0 => Some(SocketError::AlreadyOpen),
            1 => Some(SocketError::NotOpen),
            2 => Some(SocketError::InvalidLength),
            3 => Some(SocketError::ConnectFailed),
            4 => Some(SocketError::TooManyOpen),
            5 => Some(SocketError::InvalidHandle),
            _ => None,
        }
    }
}

/// Maximum payload this wire format accepts in one [`SocketRequest::Send`]/
/// [`SocketResponse::Data`] message — well past any single-message size
/// `net-driver-host`'s fixed-size TCP socket buffers
/// (`smoltcp_device`/`main.rs`'s 256-byte `tcp::SocketBuffer`s) could ever
/// actually hold in one round, purely a wire-format sanity bound so a
/// corrupt/adversarial length header can't be misread as "wait for
/// gigabytes more before deciding this message is bogus."
pub const MAX_PAYLOAD_LEN: usize = 4096;

impl SocketRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SocketRequest::Connect {
                handle,
                remote_ip,
                remote_port,
                local_port,
            } => {
                out.push(0);
                out.push(*handle);
                out.extend_from_slice(remote_ip);
                out.extend_from_slice(&remote_port.to_le_bytes());
                out.extend_from_slice(&local_port.to_le_bytes());
            }
            SocketRequest::Send { handle, data } => {
                out.push(1);
                out.push(*handle);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            SocketRequest::Recv { handle, max_len } => {
                out.push(2);
                out.push(*handle);
                out.extend_from_slice(&max_len.to_le_bytes());
            }
            SocketRequest::Close { handle } => {
                out.push(3);
                out.push(*handle);
            }
            SocketRequest::Open => out.push(4),
        }
        out
    }

    /// `Some((request, bytes_consumed))` once `buf` holds a full message,
    /// `None` if more bytes are needed yet. Never panics on malformed or
    /// truncated input — untrusted the same way every other wire parser in
    /// this codebase treats its input (see `net-driver-host/src/lib.rs`'s
    /// own doc comment on that convention) — a caller's job is to keep
    /// accumulating bytes (or, for a length header well past
    /// [`MAX_PAYLOAD_LEN`], to drop the connection) rather than trust a
    /// partial/hostile buffer.
    pub fn decode(buf: &[u8]) -> Option<(SocketRequest, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => {
                if buf.len() < 10 {
                    return None;
                }
                let handle = buf[1];
                let remote_ip = [buf[2], buf[3], buf[4], buf[5]];
                let remote_port = u16::from_le_bytes([buf[6], buf[7]]);
                let local_port = u16::from_le_bytes([buf[8], buf[9]]);
                Some((
                    SocketRequest::Connect {
                        handle,
                        remote_ip,
                        remote_port,
                        local_port,
                    },
                    10,
                ))
            }
            1 => {
                if buf.len() < 4 {
                    return None;
                }
                let handle = buf[1];
                let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                if len > MAX_PAYLOAD_LEN {
                    return None;
                }
                if buf.len() < 4 + len {
                    return None;
                }
                Some((
                    SocketRequest::Send {
                        handle,
                        data: buf[4..4 + len].to_vec(),
                    },
                    4 + len,
                ))
            }
            2 => {
                if buf.len() < 4 {
                    return None;
                }
                let handle = buf[1];
                let max_len = u16::from_le_bytes([buf[2], buf[3]]);
                Some((SocketRequest::Recv { handle, max_len }, 4))
            }
            3 => {
                if buf.len() < 2 {
                    return None;
                }
                Some((SocketRequest::Close { handle: buf[1] }, 2))
            }
            4 => Some((SocketRequest::Open, 1)),
            _ => None,
        }
    }
}

impl SocketResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SocketResponse::Connected { handle } => {
                out.push(0);
                out.push(*handle);
            }
            SocketResponse::OpenFailed(err) => {
                out.push(1);
                out.push(err.to_byte());
            }
            SocketResponse::Sent { handle, len } => {
                out.push(2);
                out.push(*handle);
                out.extend_from_slice(&len.to_le_bytes());
            }
            SocketResponse::SendFailed { handle, error } => {
                out.push(3);
                out.push(*handle);
                out.push(error.to_byte());
            }
            SocketResponse::Data { handle, data } => {
                out.push(4);
                out.push(*handle);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            SocketResponse::Closed { handle } => {
                out.push(5);
                out.push(*handle);
            }
            SocketResponse::Error { handle, error } => {
                out.push(6);
                out.push(*handle);
                out.push(error.to_byte());
            }
            SocketResponse::Opened { handle } => {
                out.push(7);
                out.push(*handle);
            }
            SocketResponse::ConnectFailed { handle, error } => {
                out.push(8);
                out.push(*handle);
                out.push(error.to_byte());
            }
        }
        out
    }

    /// Same "`None` means not enough bytes yet, never panics" contract as
    /// [`SocketRequest::decode`].
    pub fn decode(buf: &[u8]) -> Option<(SocketResponse, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => {
                let &handle = buf.get(1)?;
                Some((SocketResponse::Connected { handle }, 2))
            }
            1 => {
                let &err_byte = buf.get(1)?;
                let err = SocketError::from_byte(err_byte)?;
                Some((SocketResponse::OpenFailed(err), 2))
            }
            2 => {
                if buf.len() < 4 {
                    return None;
                }
                let handle = buf[1];
                let len = u16::from_le_bytes([buf[2], buf[3]]);
                Some((SocketResponse::Sent { handle, len }, 4))
            }
            3 => {
                if buf.len() < 3 {
                    return None;
                }
                let handle = buf[1];
                let error = SocketError::from_byte(buf[2])?;
                Some((SocketResponse::SendFailed { handle, error }, 3))
            }
            4 => {
                if buf.len() < 4 {
                    return None;
                }
                let handle = buf[1];
                let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                if len > MAX_PAYLOAD_LEN {
                    return None;
                }
                if buf.len() < 4 + len {
                    return None;
                }
                Some((
                    SocketResponse::Data {
                        handle,
                        data: buf[4..4 + len].to_vec(),
                    },
                    4 + len,
                ))
            }
            5 => {
                let &handle = buf.get(1)?;
                Some((SocketResponse::Closed { handle }, 2))
            }
            6 => {
                if buf.len() < 3 {
                    return None;
                }
                let handle = buf[1];
                let error = SocketError::from_byte(buf[2])?;
                Some((SocketResponse::Error { handle, error }, 3))
            }
            7 => {
                let &handle = buf.get(1)?;
                Some((SocketResponse::Opened { handle }, 2))
            }
            8 => {
                if buf.len() < 3 {
                    return None;
                }
                let handle = buf[1];
                let error = SocketError::from_byte(buf[2])?;
                Some((SocketResponse::ConnectFailed { handle, error }, 3))
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
    fn open_round_trips() {
        let bytes = SocketRequest::Open.encode();
        assert_eq!(
            SocketRequest::decode(&bytes),
            Some((SocketRequest::Open, bytes.len()))
        );
    }

    #[test]
    fn connect_round_trips() {
        let req = SocketRequest::Connect {
            handle: 2,
            remote_ip: [10, 0, 2, 100],
            remote_port: 9000,
            local_port: 49152,
        };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn send_round_trips() {
        let req = SocketRequest::Send {
            handle: 1,
            data: alloc::vec![1, 2, 3, 4, 5],
        };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn recv_round_trips() {
        let req = SocketRequest::Recv {
            handle: 3,
            max_len: 256,
        };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn close_round_trips() {
        let req = SocketRequest::Close { handle: 0 };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn truncated_send_request_asks_for_more_not_garbage() {
        let full = SocketRequest::Send {
            handle: 0,
            data: alloc::vec![9, 9, 9],
        }
        .encode();
        for cut in 0..full.len() {
            assert_eq!(SocketRequest::decode(&full[..cut]), None);
        }
    }

    #[test]
    fn data_response_round_trips() {
        let resp = SocketResponse::Data {
            handle: 1,
            data: alloc::vec![7, 8, 9],
        };
        let bytes = resp.encode();
        assert_eq!(SocketResponse::decode(&bytes), Some((resp, bytes.len())));
    }

    #[test]
    fn error_responses_round_trip() {
        for err in [
            SocketError::AlreadyOpen,
            SocketError::NotOpen,
            SocketError::InvalidLength,
            SocketError::ConnectFailed,
            SocketError::TooManyOpen,
            SocketError::InvalidHandle,
        ] {
            let resp = SocketResponse::OpenFailed(err);
            let bytes = resp.encode();
            assert_eq!(SocketResponse::decode(&bytes), Some((resp, bytes.len())));

            let resp = SocketResponse::ConnectFailed {
                handle: 2,
                error: err,
            };
            let bytes = resp.encode();
            assert_eq!(SocketResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }

    proptest! {
        // The regression class this module exists to prevent: no byte
        // sequence, however malformed or truncated, may make either
        // `decode` panic — this wire format is read from a byte channel
        // another (possibly compromised) ring 3 process writes to, the
        // same untrusted-input posture `net-driver-host`'s own
        // `validate_rx_completion`/`is_arp_reply` already apply to
        // device-controlled bytes.
        #[test]
        fn socket_request_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = SocketRequest::decode(&buf);
        }

        #[test]
        fn socket_response_decode_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = SocketResponse::decode(&buf);
        }

        // Every request this module can encode must decode back to itself
        // exactly, consuming exactly the bytes it produced — the actual
        // property "the wire format is lossless," not just "doesn't crash."
        #[test]
        fn send_request_round_trips_for_any_payload(handle in any::<u8>(), data in proptest::collection::vec(any::<u8>(), 0..MAX_PAYLOAD_LEN)) {
            let req = SocketRequest::Send { handle, data };
            let bytes = req.encode();
            prop_assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
        }

        #[test]
        fn data_response_round_trips_for_any_payload(handle in any::<u8>(), data in proptest::collection::vec(any::<u8>(), 0..MAX_PAYLOAD_LEN)) {
            let resp = SocketResponse::Data { handle, data };
            let bytes = resp.encode();
            prop_assert_eq!(SocketResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }
}
