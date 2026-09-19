//! Kernel-side client for the MARSHAL evaluation surface
//! (`runix_ipc::marshal`): sends a [`runix_ipc::marshal::MarshalRequest`] to
//! a MARSHAL proxy and receives the answering
//! [`runix_ipc::marshal::MarshalResponse`] over a real TCP connection,
//! carried through the sockets IPC surface (`runix_ipc::sockets`,
//! `net-driver-host`'s `run_socket_ipc_server`) instead of Runix's own
//! internal port-channel `SYS_IPC_SEND`/`SYS_IPC_RECV` mechanism.
//!
//! # Why sockets, not a port channel
//!
//! An earlier version of this module sent/received `MarshalRequest`/
//! `MarshalResponse` bytes directly on fixed ports 13/14, the same
//! `SYS_IPC_SEND`/`SYS_IPC_RECV` mechanism `blk-driver-host`'s filesystem
//! IPC and `net-driver-host`'s sockets IPC *also* ride over as their own
//! transport. That works for talking to another ring-3 process the kernel
//! itself loaded inside the same boot image — it cannot reach a real,
//! separate host machine process.
//!
//! The actual MARSHAL proxy is a genuine `std` binary using
//! `reqwest`/`tokio` (`desktop::citadel::transport::HttpKerkeseTransport`),
//! and Runix has no capability today to run a `std` binary as a ring-3
//! process inside its own kernel — so the proxy is only reachable over a
//! real network connection. This module gets there by riding on top of the
//! sockets IPC surface `net-driver-host` already exposes
//! ([`runix_ipc::sockets`]): open a handle, connect it to the proxy's
//! `remote_ip`/`remote_port`, send the encoded [`MarshalRequest`] as one or
//! more [`SocketRequest::Send`]s, poll [`SocketRequest::Recv`] for the
//! answering bytes and decode them with [`MarshalResponse::decode`] (this
//! decoder is already resumable/streaming-safe — TCP delivering the
//! response across multiple reads is the same kind of partial-data problem
//! it was built to handle), then close the handle.
//!
//! **Not called from anywhere in a real boot/authorization path.** This is
//! infrastructure a future, carefully-reviewed change would wire into one
//! of the three candidate Gate-evaluation call sites already documented
//! (`kernel/src/syscall.rs`'s `SYS_IPC_SEND`/`SYS_PORT_IN`/`SYS_PORT_OUT`,
//! or `kernel/src/grid_sandbox.rs`'s `spawn_instance`) — this module adds
//! the client function those call sites would use, without changing any of
//! their actual behavior. See `kernel/tests/marshal_tcp_roundtrip.rs` for a
//! proof this plumbing works, against a test-only Python listener standing
//! in for the real proxy, not a real MARSHAL/desktop integration (which
//! needs the desktop-side HTTP transport a separate, parallel change is
//! building).
//!
//! # Sockets IPC ports
//!
//! [`SOCK_REQUEST_PORT`]/[`SOCK_RESPONSE_PORT`] must match
//! `net-driver-host/src/main.rs`'s own `SOCK_REQUEST_PORT`/
//! `SOCK_RESPONSE_PORT` constants exactly — the same fixed-port convention
//! every client of that surface in this codebase already follows (see
//! `kernel/tests/net_driver_sockets.rs`). A real deployment would still need
//! to decide who is authorized to hold the capability for each port; this
//! module doesn't make that policy decision, it only names the ports and
//! issues the syscalls — an unauthorized caller's send is silently denied
//! at the syscall gate the same way any other unauthorized `SYS_IPC_SEND`
//! is.

use alloc::vec::Vec;
use runix_ipc::marshal::{MarshalRequest, MarshalResponse};
use runix_ipc::sockets::{SocketRequest, SocketResponse, MAX_PAYLOAD_LEN};

/// Fixed sockets IPC request port — see this module's own doc comment for
/// why it must match `net-driver-host`'s constant of the same name.
pub const SOCK_REQUEST_PORT: usize = 11;
/// Fixed sockets IPC response port — see [`SOCK_REQUEST_PORT`]'s doc
/// comment.
pub const SOCK_RESPONSE_PORT: usize = 12;

/// Sends `request`'s encoded bytes, one byte per
/// [`crate::syscall::SYS_IPC_SEND`], on [`SOCK_REQUEST_PORT`] — the caller
/// must already hold a capability authorizing `SYS_IPC_SEND` on that port,
/// same posture every function in this module has toward capability
/// checks: none of them perform one themselves, they rely on the syscall
/// gate.
fn send_socket_request(request: &SocketRequest) {
    for byte in request.encode() {
        unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_SEND,
                SOCK_REQUEST_PORT as u64,
                byte as u64,
                0,
            );
        }
    }
}

/// Polls [`SOCK_RESPONSE_PORT`] for one full [`SocketResponse`], decoding
/// with [`SocketResponse::decode`] — same "accumulate bytes, retry decode"
/// pattern `kernel/tests/net_driver_sockets.rs`'s own `recv_response`
/// already uses, and the same "no blocking receive in this codebase" reason
/// (`blk-driver-host/src/main.rs`'s `poll_recv_byte` doc comment) that
/// pattern exists at all. `None` if nothing decodable arrives within
/// `max_iters` polls.
fn recv_socket_response(max_iters: u32) -> Option<SocketResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..max_iters {
        let ret = unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_RECV,
                SOCK_RESPONSE_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            buf.push(ret as u8);
            if let Some((response, _consumed)) = SocketResponse::decode(&buf) {
                return Some(response);
            }
        }
        if i % 64 == 0 {
            crate::scheduler::yield_now();
        }
    }
    None
}

/// Allocates a new socket handle via [`SocketRequest::Open`]. `None` if
/// `net-driver-host` refused (every handle already in use) or didn't answer
/// within `max_iters` polls.
pub fn open_socket(max_iters: u32) -> Option<u8> {
    send_socket_request(&SocketRequest::Open);
    match recv_socket_response(max_iters) {
        Some(SocketResponse::Opened { handle }) => Some(handle),
        _ => None,
    }
}

/// Connects `handle` (already allocated by [`open_socket`]) to
/// `remote_ip`:`remote_port`, bound locally to `local_port`. `true` only on
/// a confirmed [`SocketResponse::Connected`] naming this same `handle`.
pub fn connect_socket(
    handle: u8,
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    max_iters: u32,
) -> bool {
    send_socket_request(&SocketRequest::Connect {
        handle,
        remote_ip,
        remote_port,
        local_port,
    });
    matches!(
        recv_socket_response(max_iters),
        Some(SocketResponse::Connected { handle: h }) if h == handle
    )
}

/// Sends `bytes` on `handle`'s open connection, splitting into
/// [`MAX_PAYLOAD_LEN`]-sized chunks as needed (a [`MarshalRequest`]'s
/// encoded `kerkese_json` may be up to `runix_ipc::marshal::MAX_JSON_LEN`
/// — larger than one [`SocketRequest::Send`] can carry). `false` if any
/// chunk isn't fully acknowledged by a matching [`SocketResponse::Sent`].
fn send_bytes(handle: u8, bytes: &[u8], max_iters: u32) -> bool {
    for chunk in bytes.chunks(MAX_PAYLOAD_LEN) {
        send_socket_request(&SocketRequest::Send {
            handle,
            data: chunk.to_vec(),
        });
        match recv_socket_response(max_iters) {
            Some(SocketResponse::Sent { handle: h, len })
                if h == handle && len as usize == chunk.len() => {}
            _ => return false,
        }
    }
    true
}

/// Closes `handle`, freeing it for reuse. Best-effort: doesn't report
/// failure, since a caller reaching this point is already tearing down
/// (either after a successful evaluation, or after giving up on a failed
/// one) and has nothing useful left to do with a close failure.
fn close_socket(handle: u8, max_iters: u32) {
    send_socket_request(&SocketRequest::Close { handle });
    let _ = recv_socket_response(max_iters);
}

/// Polls `handle` for one full [`MarshalResponse`], issuing
/// [`SocketRequest::Recv`] repeatedly (it never blocks — see
/// [`runix_ipc::sockets::SocketResponse::Data`]'s doc comment) and
/// accumulating the returned bytes into a growing buffer decoded with
/// [`MarshalResponse::decode`] — resumable across however many
/// [`SocketRequest::Recv`] rounds (and however many underlying TCP
/// segments) the response actually arrives in, exactly the partial-data
/// problem that decoder was built to handle. `None` if nothing decodable
/// arrives within `max_polls` rounds.
pub fn recv_marshal_response(handle: u8, max_polls: u32) -> Option<MarshalResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..max_polls {
        send_socket_request(&SocketRequest::Recv {
            handle,
            max_len: MAX_PAYLOAD_LEN as u16,
        });
        if let Some(SocketResponse::Data { handle: h, data }) = recv_socket_response(2000) {
            if h == handle {
                buf.extend_from_slice(&data);
                if let Some((response, _consumed)) = MarshalResponse::decode(&buf) {
                    return Some(response);
                }
            }
        }
        if i % 16 == 0 {
            crate::scheduler::yield_now();
        }
    }
    None
}

/// Full round trip: opens a socket, connects it to `remote_ip`:`remote_port`
/// (bound locally to `local_port`), sends `request`'s encoded bytes, polls
/// for the answering [`MarshalResponse`], and closes the socket — the
/// two-step "ask the MARSHAL proxy, wait for its Decision" operation a
/// future Gate-evaluation call site would actually want, now over a real
/// TCP connection to a proxy process outside this boot image, rather than
/// this codebase's internal port-channel IPC.
///
/// `None` if any step (open/connect/send/receive) fails or times out —
/// there is no blocking-receive syscall in this codebase, so a caller
/// either treats `None` as "not answered yet" and retries the whole
/// evaluation, or (for a real Gate-evaluation call site) as a fail-closed
/// timeout.
pub fn evaluate(
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    request: &MarshalRequest,
    max_iters: u32,
) -> Option<MarshalResponse> {
    let handle = open_socket(max_iters)?;
    if !connect_socket(handle, remote_ip, remote_port, local_port, max_iters) {
        close_socket(handle, max_iters);
        return None;
    }
    if !send_bytes(handle, &request.encode(), max_iters) {
        close_socket(handle, max_iters);
        return None;
    }
    let response = recv_marshal_response(handle, max_iters);
    close_socket(handle, max_iters);
    response
}
