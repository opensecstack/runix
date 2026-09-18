//! Kernel-side client for the MARSHAL evaluation IPC surface
//! (`runix_ipc::marshal`): sends a [`runix_ipc::marshal::MarshalRequest`] to
//! a user-space MARSHAL proxy over capability-gated
//! `SYS_IPC_SEND`/`SYS_IPC_RECV`, and polls for the
//! [`runix_ipc::marshal::MarshalResponse`] it answers with — the kernel-side
//! half of the design described in `citadel-integration`'s
//! [`runix_citadel_integration::KerkeseTransport`] doc comment: a `desktop`
//! process holds the real network transport to CITADEL, and kernel code
//! reaches it over Runix's own IPC rather than a live HTTP round-trip from
//! inside the kernel.
//!
//! **Not called from anywhere in a real boot/authorization path.** This is
//! infrastructure a future, carefully-reviewed change would wire into one
//! of the three candidate Gate-evaluation call sites already documented
//! (`kernel/src/syscall.rs`'s `SYS_IPC_SEND`/`SYS_PORT_IN`/`SYS_PORT_OUT`,
//! or `kernel/src/grid_sandbox.rs`'s `spawn_instance`) — this module adds
//! the client function those call sites would use, without changing any of
//! their actual behavior. See `kernel/tests/marshal_ipc_roundtrip.rs` for a
//! proof this plumbing works, against a test-only fake proxy thread, not a
//! real MARSHAL/desktop integration (which needs the desktop-side HTTP
//! transport a separate, parallel change is building).
//!
//! # Ports
//!
//! [`MARSHAL_REQUEST_PORT`]/[`MARSHAL_RESPONSE_PORT`] are this surface's own
//! fixed ports, picked from the unused range above `blk-driver-host`'s and
//! `net-driver-host`'s existing ports (`8`..`12`, see those hosts' own
//! `main.rs` constants) — same "fixed port per purpose, decided ahead of
//! time" convention every other IPC surface in this codebase already uses.
//! A real deployment would still need to decide who is authorized to hold
//! the capability for each (the MARSHAL proxy process for the response
//! port, whichever kernel-side caller is allowed to request an evaluation
//! for the request port) — this module doesn't make that policy decision,
//! it only names the ports.

use alloc::vec::Vec;
use runix_ipc::marshal::{MarshalRequest, MarshalResponse};

/// Fixed port a MARSHAL evaluation request is sent on. See this module's
/// own doc comment for why `13`/`14`.
pub const MARSHAL_REQUEST_PORT: usize = 13;
/// Fixed port a MARSHAL evaluation response is received on.
pub const MARSHAL_RESPONSE_PORT: usize = 14;

/// Sends `request`'s encoded bytes, one byte per [`crate::syscall::SYS_IPC_SEND`],
/// on [`MARSHAL_REQUEST_PORT`] — wrapped in
/// [`crate::syscall::SYS_IPC_SEND_LOCK`]/[`crate::syscall::SYS_IPC_SEND_UNLOCK`]
/// across the whole multi-byte send, the calling convention `kernel::ipc`'s
/// own doc comment requires of every real (non-single-byte) sender in this
/// codebase, so a concurrent second sender on the same port can't interleave
/// its own bytes into the middle of this message.
///
/// The caller must already hold a capability authorizing
/// `SYS_IPC_SEND`/`SYS_IPC_SEND_LOCK`/`SYS_IPC_SEND_UNLOCK` on
/// [`MARSHAL_REQUEST_PORT`] (the current thread's own capability or one of
/// its `extra_capabilities`, see `syscall::authorized_for_port`) — this
/// function does not check that itself, it just issues the syscalls; an
/// unauthorized caller's bytes are silently denied at the syscall gate the
/// same way any other unauthorized `SYS_IPC_SEND` is.
pub fn send_request(request: &MarshalRequest) {
    let bytes = request.encode();
    let lock_denied = unsafe {
        crate::syscall::syscall(
            crate::syscall::SYS_IPC_SEND_LOCK,
            MARSHAL_REQUEST_PORT as u64,
            0,
            0,
        )
    } == u64::MAX;
    if lock_denied {
        return;
    }
    for byte in bytes {
        unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_SEND,
                MARSHAL_REQUEST_PORT as u64,
                byte as u64,
                0,
            );
        }
    }
    unsafe {
        crate::syscall::syscall(
            crate::syscall::SYS_IPC_SEND_UNLOCK,
            MARSHAL_REQUEST_PORT as u64,
            0,
            0,
        );
    }
}

/// Polls [`MARSHAL_RESPONSE_PORT`] for one full [`MarshalResponse`],
/// decoding with [`MarshalResponse::decode`] (the same typed wire-format
/// function the proxy on the other end uses to encode) rather than a
/// hand-rolled parser here. Yields between polls via
/// [`crate::scheduler::yield_now`] so this doesn't spin a whole time slice
/// away from every other thread while waiting.
///
/// `None` if nothing decodable arrives within `max_iters` polls — there is
/// no blocking-receive syscall in this codebase (see
/// `blk-driver-host/src/main.rs`'s `poll_recv_byte` doc comment for the
/// same constraint on the transport this rides over), so a caller either
/// treats `None` as "not answered yet" and polls again, or (for a real
/// Gate-evaluation call site) as a fail-closed timeout.
pub fn recv_response(max_iters: u32) -> Option<MarshalResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..max_iters {
        let ret = unsafe {
            crate::syscall::syscall(
                crate::syscall::SYS_IPC_RECV,
                MARSHAL_RESPONSE_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            buf.push(ret as u8);
            if let Some((response, _consumed)) = MarshalResponse::decode(&buf) {
                return Some(response);
            }
        }
        if i % 64 == 0 {
            crate::scheduler::yield_now();
        }
    }
    None
}

/// Convenience wrapper: sends `request`, then polls for the answering
/// [`MarshalResponse`] — the two-step "ask the MARSHAL proxy, wait for its
/// Decision" round trip a future Gate-evaluation call site would actually
/// want, rather than driving [`send_request`]/[`recv_response`] separately.
pub fn evaluate(request: &MarshalRequest, max_iters: u32) -> Option<MarshalResponse> {
    send_request(request);
    recv_response(max_iters)
}
