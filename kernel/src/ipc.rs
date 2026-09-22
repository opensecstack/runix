//! Inter-process communication primitives (Alpha: "Basic IPC") — fixed-count
//! byte channels addressed by small integer port ids. `send`/`recv` block by
//! spin-yielding through the cooperative scheduler rather than blocking a
//! CPU outright; a real wait/wake queue (so a blocked thread isn't burning
//! its turn just to check "still empty?") is a later refinement once the
//! scheduler is timer-preemptive.
//!
//! **Per-port send locks — the fix for a real, concrete corruption hazard**
//! (see `blk-driver-host/src/main.rs`'s `run_fs_ipc_server`'s own doc
//! comment, which named this exact gap before it was closed): a caller
//! sending a multi-byte message (e.g. a `runix_ipc::fs::FsRequest`) does so
//! one byte per `SYS_IPC_SEND` syscall, with no message framing at this
//! layer — `send`'s own byte-at-a-time queue has no notion of "this byte
//! belongs to that message." A real FAT32 filesystem request already
//! exceeds [`CHANNEL_CAPACITY`] on its own (an `FsRequest`'s embedded
//! `CapabilityToken` alone is over a kilobyte once encoded — see
//! `runix_ipc::fs`'s own size constants), so a *single* sender's message
//! routinely needs [`send`] to block (spin-yield) partway through — the
//! cooperative scheduler's only chance to switch to another thread while
//! that message is still incomplete. If a *second* sender is also mid-send
//! to the *same* port at that exact moment, its bytes land in the channel
//! interleaved with the first sender's still-unfinished message: the
//! receiver then decodes a franken-message built from both senders' bytes,
//! not a corrupted-looking one it could safely reject — nothing in the
//! wire format can detect this after the fact, since the resulting byte
//! stream can still parse as some *other*, wrong, but perfectly
//! well-formed request. [`begin_send`]/[`end_send`] close this by giving
//! each port an advisory mutual-exclusion lock a sender holds for the
//! entire duration of one logical message: a second sender's
//! [`begin_send`] on the same port blocks (spin-yields) until the first
//! calls [`end_send`], so two senders' byte streams can never interleave
//! into each other, only ever land back-to-back, in full.

use alloc::collections::VecDeque;
use lazy_static::lazy_static;
use spin::Mutex;

const PORT_COUNT: usize = 16;
const CHANNEL_CAPACITY: usize = 32;

struct Channel {
    queue: VecDeque<u8>,
}

lazy_static! {
    static ref CHANNELS: [Mutex<Channel>; PORT_COUNT] =
        core::array::from_fn(|_| Mutex::new(Channel {
            queue: VecDeque::new()
        }));
    /// `true` while some sender is mid-message on that port — see this
    /// module's own doc comment. A plain `bool` behind a `spin::Mutex`, not
    /// an atomic flag: correctness here only needs "one holder at a time,"
    /// which a lock already gives for free, and every other piece of
    /// shared state in this file is already a `spin::Mutex` — no reason for
    /// this one gap to be the sole exception.
    static ref SEND_LOCKS: [Mutex<bool>; PORT_COUNT] = core::array::from_fn(|_| Mutex::new(false));
}

/// Blocks (spin-yielding) until `port`'s send lock is free, then claims it.
/// Every caller that sends more than one logically-related byte to the same
/// port — i.e. every real, multi-byte wire message — must call this before
/// its first [`send`] and [`end_send`] after its last, or its message is not
/// protected against interleaving with a concurrent sender on the same
/// port. See this module's own doc comment for the exact hazard this
/// closes.
pub fn begin_send(port: usize) {
    loop {
        {
            let mut locked = SEND_LOCKS[port].lock();
            if !*locked {
                *locked = true;
                return;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// Releases `port`'s send lock, claimed by an earlier [`begin_send`] on the
/// same port from the same thread — this module trusts the caller to pair
/// these correctly (the same cooperative-scheduling trust model every other
/// syscall in this kernel already places on its caller; a caller that never
/// calls this permanently starves every other sender on that port, a
/// liveness bug for that caller to avoid, not a memory-safety one).
pub fn end_send(port: usize) {
    *SEND_LOCKS[port].lock() = false;
}

/// Blocks (spin-yielding) until there's room, then enqueues `byte` on `port`.
pub fn send(port: usize, byte: u8) {
    loop {
        {
            let mut channel = CHANNELS[port].lock();
            if channel.queue.len() < CHANNEL_CAPACITY {
                channel.queue.push_back(byte);
                return;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// Non-blocking: `None` if `port` currently has nothing queued.
pub fn try_recv(port: usize) -> Option<u8> {
    CHANNELS[port].lock().queue.pop_front()
}

/// Peeks whether `port` currently has anything queued, without popping —
/// `syscall.rs`'s `SYS_IPC_RECV` arm checks this *before* paying for
/// `authorized_for_port`'s real Ed25519 verification, so a busy-poll loop
/// spinning on an empty port (this codebase's universal `SYS_IPC_RECV`
/// calling convention — see e.g. `net_driver_sockets.rs`'s `recv_response`,
/// `blk-driver-host`'s `run_fs_ipc_server`) pays the old, cheap
/// lock-and-check cost on every empty iteration instead of a full
/// signature verification on every single one. Confirmed as a real,
/// measured problem, not a guess: with the check unconditional, a single
/// `net_driver_sockets.rs` run took long enough under QEMU/TCG that it
/// looked indistinguishable from a hang (minutes to cross a few tens of
/// thousands of otherwise-empty polls) before this fix.
pub fn is_empty(port: usize) -> bool {
    CHANNELS[port].lock().queue.is_empty()
}

/// Blocks (spin-yielding) until a byte is available on `port`.
pub fn recv(port: usize) -> u8 {
    loop {
        if let Some(byte) = try_recv(port) {
            return byte;
        }
        crate::scheduler::yield_now();
    }
}
