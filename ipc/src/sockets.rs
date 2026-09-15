//! Sockets IPC surface: typed request/response wire types for the single,
//! at-a-time TCP connection `net-driver-host` exposes over its `smoltcp`
//! stack (see `docs/STATUS.md`'s network-stack section — "a sockets
//! API/IPC surface for other ring 3 processes to use this stack" is
//! exactly the gap this module closes). `no_std` + `alloc` (this crate's
//! default; see `lib.rs`'s doc comment), so `net-driver-host` — a
//! freestanding ring 3 binary with no `std` — can depend on this crate
//! directly instead of hand-rolling its own byte layout.
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
//! Single connection at a time, matching `net-driver-host`'s own current
//! shape (one `smoltcp::socket::tcp::Socket`) — concurrent sockets are a
//! separate, explicitly deferred gap (see `docs/STATUS.md`/`docs/ROADMAP.md`),
//! not solved here. DHCP is likewise out of scope: [`SocketRequest::Connect`]
//! takes an already-resolved remote address, not a hostname.

use alloc::vec::Vec;

/// Client -> `net-driver-host`, over a fixed request port (see that
/// process's own doc comment for the exact port numbers this codebase
/// uses, same "fixed port per purpose, decided at spawn time" convention
/// `blk-driver-host`'s filesystem IPC surface already established).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketRequest {
    /// Open the one connection this driver can hold at a time. Answered
    /// with [`SocketResponse::Connected`] or
    /// [`SocketResponse::OpenFailed`] — the latter with
    /// [`SocketError::AlreadyOpen`] if a connection is already open, since
    /// this surface has no concurrent-socket support to hand back a second
    /// handle instead (see this module's doc comment).
    Connect {
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
    },
    /// Send `data` on the open connection. Answered with
    /// [`SocketResponse::Sent`] (the number of bytes actually queued —
    /// may be less than `data.len()` if the socket's send buffer is
    /// nearly full) or [`SocketResponse::SendFailed`].
    Send(Vec<u8>),
    /// Ask for up to `max_len` bytes currently buffered for receipt.
    /// Never blocks waiting for more to arrive — see
    /// [`SocketResponse::Data`]'s doc comment — so a caller polling for a
    /// reply may need to retry.
    Recv { max_len: u16 },
    /// Close the open connection. Answered with [`SocketResponse::Closed`]
    /// unconditionally — closing an already-closed/never-opened connection
    /// is not an error, matching `smoltcp::socket::tcp::Socket::close`'s
    /// own idempotent behavior.
    Close,
}

/// `net-driver-host` -> client, over a fixed response port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketResponse {
    Connected,
    OpenFailed(SocketError),
    Sent {
        len: u16,
    },
    SendFailed(SocketError),
    /// Zero or more bytes actually available right now. Empty is a normal,
    /// non-error result ("nothing arrived yet"), not
    /// [`SocketResponse::Error`] — matching `net-driver-host`'s own
    /// non-blocking poll loop (there is no blocking-receive syscall in this
    /// codebase; see `blk-driver-host/src/main.rs`'s `poll_recv_byte` doc
    /// comment for the same constraint on the transport this rides over).
    Data(Vec<u8>),
    Closed,
    Error(SocketError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// [`SocketRequest::Connect`] while a connection is already open.
    AlreadyOpen,
    /// [`SocketRequest::Send`]/[`SocketRequest::Recv`] with no connection
    /// open.
    NotOpen,
    /// A length field (e.g. [`SocketRequest::Send`]'s payload) didn't fit
    /// this wire format's bounds.
    InvalidLength,
    /// The connect attempt itself failed (refused, timed out, or the
    /// underlying device reported a failure) — distinct from `NotOpen`,
    /// which means no attempt is in flight at all.
    ConnectFailed,
}

impl SocketError {
    fn to_byte(self) -> u8 {
        match self {
            SocketError::AlreadyOpen => 0,
            SocketError::NotOpen => 1,
            SocketError::InvalidLength => 2,
            SocketError::ConnectFailed => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<SocketError> {
        match byte {
            0 => Some(SocketError::AlreadyOpen),
            1 => Some(SocketError::NotOpen),
            2 => Some(SocketError::InvalidLength),
            3 => Some(SocketError::ConnectFailed),
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
                remote_ip,
                remote_port,
                local_port,
            } => {
                out.push(0);
                out.extend_from_slice(remote_ip);
                out.extend_from_slice(&remote_port.to_le_bytes());
                out.extend_from_slice(&local_port.to_le_bytes());
            }
            SocketRequest::Send(data) => {
                out.push(1);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            SocketRequest::Recv { max_len } => {
                out.push(2);
                out.extend_from_slice(&max_len.to_le_bytes());
            }
            SocketRequest::Close => out.push(3),
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
                if buf.len() < 9 {
                    return None;
                }
                let remote_ip = [buf[1], buf[2], buf[3], buf[4]];
                let remote_port = u16::from_le_bytes([buf[5], buf[6]]);
                let local_port = u16::from_le_bytes([buf[7], buf[8]]);
                Some((
                    SocketRequest::Connect {
                        remote_ip,
                        remote_port,
                        local_port,
                    },
                    9,
                ))
            }
            1 => {
                if buf.len() < 3 {
                    return None;
                }
                let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                if len > MAX_PAYLOAD_LEN {
                    return None;
                }
                if buf.len() < 3 + len {
                    return None;
                }
                Some((SocketRequest::Send(buf[3..3 + len].to_vec()), 3 + len))
            }
            2 => {
                if buf.len() < 3 {
                    return None;
                }
                let max_len = u16::from_le_bytes([buf[1], buf[2]]);
                Some((SocketRequest::Recv { max_len }, 3))
            }
            3 => Some((SocketRequest::Close, 1)),
            _ => None,
        }
    }
}

impl SocketResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SocketResponse::Connected => out.push(0),
            SocketResponse::OpenFailed(err) => {
                out.push(1);
                out.push(err.to_byte());
            }
            SocketResponse::Sent { len } => {
                out.push(2);
                out.extend_from_slice(&len.to_le_bytes());
            }
            SocketResponse::SendFailed(err) => {
                out.push(3);
                out.push(err.to_byte());
            }
            SocketResponse::Data(data) => {
                out.push(4);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            SocketResponse::Closed => out.push(5),
            SocketResponse::Error(err) => {
                out.push(6);
                out.push(err.to_byte());
            }
        }
        out
    }

    /// Same "`None` means not enough bytes yet, never panics" contract as
    /// [`SocketRequest::decode`].
    pub fn decode(buf: &[u8]) -> Option<(SocketResponse, usize)> {
        let &tag = buf.first()?;
        match tag {
            0 => Some((SocketResponse::Connected, 1)),
            1 => {
                let &err_byte = buf.get(1)?;
                let err = SocketError::from_byte(err_byte)?;
                Some((SocketResponse::OpenFailed(err), 2))
            }
            2 => {
                if buf.len() < 3 {
                    return None;
                }
                let len = u16::from_le_bytes([buf[1], buf[2]]);
                Some((SocketResponse::Sent { len }, 3))
            }
            3 => {
                let &err_byte = buf.get(1)?;
                let err = SocketError::from_byte(err_byte)?;
                Some((SocketResponse::SendFailed(err), 2))
            }
            4 => {
                if buf.len() < 3 {
                    return None;
                }
                let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                if len > MAX_PAYLOAD_LEN {
                    return None;
                }
                if buf.len() < 3 + len {
                    return None;
                }
                Some((SocketResponse::Data(buf[3..3 + len].to_vec()), 3 + len))
            }
            5 => Some((SocketResponse::Closed, 1)),
            6 => {
                let &err_byte = buf.get(1)?;
                let err = SocketError::from_byte(err_byte)?;
                Some((SocketResponse::Error(err), 2))
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
    fn connect_round_trips() {
        let req = SocketRequest::Connect {
            remote_ip: [10, 0, 2, 100],
            remote_port: 9000,
            local_port: 49152,
        };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn send_round_trips() {
        let req = SocketRequest::Send(alloc::vec![1, 2, 3, 4, 5]);
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn recv_round_trips() {
        let req = SocketRequest::Recv { max_len: 256 };
        let bytes = req.encode();
        assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
    }

    #[test]
    fn close_round_trips() {
        let bytes = SocketRequest::Close.encode();
        assert_eq!(
            SocketRequest::decode(&bytes),
            Some((SocketRequest::Close, bytes.len()))
        );
    }

    #[test]
    fn truncated_send_request_asks_for_more_not_garbage() {
        let full = SocketRequest::Send(alloc::vec![9, 9, 9]).encode();
        for cut in 0..full.len() {
            assert_eq!(SocketRequest::decode(&full[..cut]), None);
        }
    }

    #[test]
    fn data_response_round_trips() {
        let resp = SocketResponse::Data(alloc::vec![7, 8, 9]);
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
        ] {
            let resp = SocketResponse::OpenFailed(err);
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
        fn send_request_round_trips_for_any_payload(data in proptest::collection::vec(any::<u8>(), 0..MAX_PAYLOAD_LEN)) {
            let req = SocketRequest::Send(data);
            let bytes = req.encode();
            prop_assert_eq!(SocketRequest::decode(&bytes), Some((req, bytes.len())));
        }

        #[test]
        fn data_response_round_trips_for_any_payload(data in proptest::collection::vec(any::<u8>(), 0..MAX_PAYLOAD_LEN)) {
            let resp = SocketResponse::Data(data);
            let bytes = resp.encode();
            prop_assert_eq!(SocketResponse::decode(&bytes), Some((resp, bytes.len())));
        }
    }
}
