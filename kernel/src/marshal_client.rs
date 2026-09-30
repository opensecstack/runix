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
//! # Transport: one session per [`evaluate`] call
//!
//! This module used to ride the fixed-port `SYS_IPC_SEND`/`SYS_IPC_RECV`
//! transport (`SOCK_REQUEST_PORT`/`SOCK_RESPONSE_PORT`, 11/12) every other
//! sockets-IPC client in this codebase still used at the time — see this
//! module's now-stale git history for that version's own doc comment on the
//! attribution gap that model had: a shared response port meant any two
//! concurrent callers of [`evaluate`] would race to receive each other's
//! bytes, with no way for either side to tell whose response was whose.
//!
//! A syscall-cost benchmark (`kernel/tests/syscall_cost.rs`) also measured
//! the old fixed-port transport at roughly 228x the per-syscall cost of the
//! session primitive below (~11,633 us vs. ~51 us per round trip) — for a
//! real TLS handshake (thousands of syscalls, 1500-3000 bytes) that
//! difference is the gap between "fits inside the 300ms T1 real-time
//! budget" and "exceeds it by 100x+."
//!
//! Both gaps close by riding [`SYS_IPC_SESSION_OPEN`](crate::syscall::SYS_IPC_SESSION_OPEN)
//! and its companion syscalls instead: [`evaluate`] opens exactly one
//! session per call against [`SOCKETS_SERVER_PORT`], and every request/
//! response for that call's socket lifecycle (open/connect/send/recv/close)
//! rides that same session id. A session has at most two participants (this
//! call's own thread, and whichever `net-driver-host` server thread
//! accepted it) — two concurrent [`evaluate`] calls get two independent
//! sessions, each with its own private byte channel, so there is no shared
//! response port left to race on. See `kernel/tests/ipc_session.rs` for the
//! primitive's own isolation/capability-denial/teardown proof, and
//! `docs/RFC-IPC-RESPONSE-CAPABILITY.md` for the full design.
//!
//! [`SOCKETS_SERVER_PORT`] must match `net-driver-host/src/main.rs`'s own
//! `SOCKETS_SERVER_PORT` constant exactly — the same fixed-port convention
//! every client of that surface in this codebase already follows for
//! *opening* a session (see `kernel/tests/net_driver_sockets.rs`). A caller
//! of [`evaluate`] needs a capability authorizing that one port to open a
//! session at all (`SYS_IPC_SESSION_OPEN`'s own capability check); once the
//! session exists, every further operation on it is gated by session
//! participation (owner-or-accepted-server identity), not a fresh port
//! capability check per call — see `kernel::ipc`'s `is_participant`.

use alloc::vec::Vec;
use runix_ipc::marshal::{MarshalRequest, MarshalResponse};
use runix_ipc::sockets::{SocketRequest, SocketResponse, MAX_PAYLOAD_LEN};

/// Fixed sockets IPC server port — see this module's own doc comment for
/// why it must match `net-driver-host`'s constant of the same name. Only
/// used to *open* a session ([`SYS_IPC_SESSION_OPEN`](crate::syscall::SYS_IPC_SESSION_OPEN));
/// every subsequent operation for that session addresses it by session id,
/// not this port.
pub const SOCKETS_SERVER_PORT: usize = 11;

/// Opens a new session against [`SOCKETS_SERVER_PORT`], bounded-retrying
/// (same "bounded poll, not an unbounded blocking wait" discipline every
/// wait loop in this codebase uses) up to `max_iters` times — a session
/// table momentarily at capacity (`ipc::MAX_LIVE_SESSIONS`/
/// `MAX_SESSIONS_PER_OWNER`) is worth a retry; a caller with no capability
/// for the port never succeeds no matter how many times this retries, same
/// as every other capability-gated syscall in this codebase. `None` if
/// nothing succeeded within `max_iters`.
fn open_session(max_iters: u32) -> Option<u64> {
    for i in 0..max_iters {
        let ret = unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_SESSION_OPEN,
                SOCKETS_SERVER_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            return Some(ret);
        }
        if i % 64 == 0 {
            crate::scheduler::yield_now();
        }
    }
    None
}

/// Sends `request`'s encoded bytes, one byte per
/// [`crate::syscall::SYS_IPC_SESSION_SEND`], on `session_id`, wrapped in
/// [`crate::syscall::SYS_IPC_SESSION_SEND_LOCK`]/`_UNLOCK` — a session has
/// at most two participants, but nothing stops both from calling
/// `SYS_IPC_SESSION_SEND` for the same logical message concurrently without
/// this, same interleaving hazard `kernel::ipc`'s module doc comment
/// describes for the fixed-port transport this module used to ride. `false`
/// if the lock, or any byte send, is denied (`session_id` doesn't exist, or
/// this thread isn't a participant) — every function in this module relies
/// entirely on the session syscalls' own participant check, same posture
/// toward capability/identity checks this module always had.
fn send_socket_request(session_id: u64, request: &SocketRequest) -> bool {
    let locked = unsafe {
        crate::syscall::syscall(crate::syscall::SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0)
    };
    if locked == u64::MAX {
        return false;
    }
    let mut ok = true;
    for byte in request.encode() {
        let ret = unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_SESSION_SEND,
                session_id,
                byte as u64,
                0,
            )
        };
        if ret == u64::MAX {
            ok = false;
            break;
        }
    }
    unsafe {
        crate::syscall::syscall(crate::syscall::SYS_IPC_SESSION_SEND_UNLOCK, session_id, 0, 0);
    }
    ok
}

/// Polls `session_id` for one full [`SocketResponse`] via
/// [`crate::syscall::SYS_IPC_SESSION_RECV`], decoding with
/// [`SocketResponse::decode`] — same "accumulate bytes, retry decode"
/// pattern `kernel/tests/net_driver_sockets.rs`'s own `recv_response`
/// already uses, and the same "no blocking receive in this codebase" reason
/// (`blk-driver-host/src/main.rs`'s `poll_recv_byte` doc comment) that
/// pattern exists at all. `None` if nothing decodable arrives within
/// `max_iters` polls.
fn recv_socket_response(session_id: u64, max_iters: u32) -> Option<SocketResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..max_iters {
        let ret = unsafe {
            crate::syscall::syscall(crate::syscall::SYS_IPC_SESSION_RECV, session_id, 0, 0)
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

/// Allocates a new socket handle via [`SocketRequest::Open`] on `session_id`.
/// `None` if `net-driver-host` refused (every handle already in use) or
/// didn't answer within `max_iters` polls.
fn open_socket(session_id: u64, max_iters: u32) -> Option<u8> {
    if !send_socket_request(session_id, &SocketRequest::Open) {
        return None;
    }
    match recv_socket_response(session_id, max_iters) {
        Some(SocketResponse::Opened { handle }) => Some(handle),
        _ => None,
    }
}

/// Connects `handle` (already allocated by [`open_socket`]) to
/// `remote_ip`:`remote_port`, bound locally to `local_port`, over
/// `session_id`. `true` only on a confirmed [`SocketResponse::Connected`]
/// naming this same `handle`.
fn connect_socket(
    session_id: u64,
    handle: u8,
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    max_iters: u32,
) -> bool {
    if !send_socket_request(
        session_id,
        &SocketRequest::Connect {
            handle,
            remote_ip,
            remote_port,
            local_port,
        },
    ) {
        return false;
    }
    matches!(
        recv_socket_response(session_id, max_iters),
        Some(SocketResponse::Connected { handle: h }) if h == handle
    )
}

/// Sends `bytes` on `handle`'s open connection over `session_id`, splitting
/// into [`MAX_PAYLOAD_LEN`]-sized chunks as needed (a [`MarshalRequest`]'s
/// encoded `kerkese_json` may be up to `runix_ipc::marshal::MAX_JSON_LEN`
/// — larger than one [`SocketRequest::Send`] can carry). `false` if any
/// chunk isn't fully acknowledged by a matching [`SocketResponse::Sent`].
fn send_bytes(session_id: u64, handle: u8, bytes: &[u8], max_iters: u32) -> bool {
    for chunk in bytes.chunks(MAX_PAYLOAD_LEN) {
        if !send_socket_request(
            session_id,
            &SocketRequest::Send {
                handle,
                data: chunk.to_vec(),
            },
        ) {
            return false;
        }
        match recv_socket_response(session_id, max_iters) {
            Some(SocketResponse::Sent { handle: h, len })
                if h == handle && len as usize == chunk.len() => {}
            _ => return false,
        }
    }
    true
}

/// Closes `handle` over `session_id`, freeing it for reuse. Best-effort:
/// doesn't report failure, since a caller reaching this point is already
/// tearing down (either after a successful evaluation, or after giving up
/// on a failed one) and has nothing useful left to do with a close failure.
fn close_socket(session_id: u64, handle: u8, max_iters: u32) {
    let _ = send_socket_request(session_id, &SocketRequest::Close { handle });
    let _ = recv_socket_response(session_id, max_iters);
}

/// Polls `handle` for one full [`MarshalResponse`] over `session_id`,
/// issuing [`SocketRequest::Recv`] repeatedly (it never blocks — see
/// [`runix_ipc::sockets::SocketResponse::Data`]'s doc comment) and
/// accumulating the returned bytes into a growing buffer decoded with
/// [`MarshalResponse::decode`] — resumable across however many
/// [`SocketRequest::Recv`] rounds (and however many underlying TCP
/// segments) the response actually arrives in, exactly the partial-data
/// problem that decoder was built to handle. `None` if nothing decodable
/// arrives within `max_polls` rounds.
fn recv_marshal_response(session_id: u64, handle: u8, max_polls: u32) -> Option<MarshalResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..max_polls {
        if !send_socket_request(
            session_id,
            &SocketRequest::Recv {
                handle,
                max_len: MAX_PAYLOAD_LEN as u16,
            },
        ) {
            return None;
        }
        if let Some(SocketResponse::Data { handle: h, data }) =
            recv_socket_response(session_id, 2000)
        {
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

/// Full round trip: opens a session against [`SOCKETS_SERVER_PORT`], opens
/// a socket handle on it, connects it to `remote_ip`:`remote_port` (bound
/// locally to `local_port`), sends `request`'s encoded bytes, polls for the
/// answering [`MarshalResponse`], and closes the socket — the two-step "ask
/// the MARSHAL proxy, wait for its Decision" operation a future
/// Gate-evaluation call site would actually want, now over a real TCP
/// connection to a proxy process outside this boot image, rather than this
/// codebase's internal port-channel IPC.
///
/// One session per call, not a session reused across calls — see this
/// module's own doc comment on why that's the natural lifetime boundary
/// (it maps exactly to one socket-open-through-close lifecycle) and what it
/// buys over the old shared-port transport.
///
/// `None` if any step (session open/socket open/connect/send/receive)
/// fails or times out — there is no blocking-receive syscall in this
/// codebase, so a caller either treats `None` as "not answered yet" and
/// retries the whole evaluation, or (for a real Gate-evaluation call site)
/// as a fail-closed timeout.
pub fn evaluate(
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    request: &MarshalRequest,
    max_iters: u32,
) -> Option<MarshalResponse> {
    let session_id = open_session(max_iters)?;
    let handle = open_socket(session_id, max_iters)?;
    if !connect_socket(session_id, handle, remote_ip, remote_port, local_port, max_iters) {
        close_socket(session_id, handle, max_iters);
        return None;
    }
    if !send_bytes(session_id, handle, &request.encode(), max_iters) {
        close_socket(session_id, handle, max_iters);
        return None;
    }
    let response = recv_marshal_response(session_id, handle, max_iters);
    close_socket(session_id, handle, max_iters);
    response
}
