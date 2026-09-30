//! This binary's own `int 0x80` stub — a separate implementation from
//! `kernel::syscall::syscall`, not a shared one, same as
//! `net-driver-host/src/syscall.rs`'s copy: this is a standalone-linked
//! ring 3 program, compiled and linked entirely independently of the
//! kernel. The syscall *ABI* (number in RAX, args in RDI/RSI/RDX) is the
//! only thing connecting them.

const SYS_YIELD: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_PORT_IN: u64 = 4;
const SYS_PORT_OUT: u64 = 5;
const SYS_TICKS: u64 = 6;
// `SYS_IPC_SESSION_OPEN` (10) is deliberately not listed/wrapped here —
// this process is always the *server* side of the filesystem session
// (`SYS_IPC_SESSION_ACCEPT`), never the client that opens one, matching
// `kernel/src/syscall.rs`'s own doc comment split between "OPEN" and
// "ACCEPT" callers.
const SYS_IPC_SESSION_ACCEPT: u64 = 11;
const SYS_IPC_SESSION_SEND: u64 = 12;
const SYS_IPC_SESSION_RECV: u64 = 13;
const SYS_IPC_SESSION_SEND_LOCK: u64 = 14;
const SYS_IPC_SESSION_SEND_UNLOCK: u64 = 15;

/// # Safety
/// Whatever `num`'s own contract requires.
unsafe fn syscall(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") num => ret,
            // `inout(reg) x => _`, not `in(reg) x` — see
            // `net-driver-host/src/syscall.rs`'s much longer account of the
            // real bug this prevents (two back-to-back `port_out` calls
            // with the same literal `width` argument had the second one
            // silently corrupted because the compiler cached the value in
            // a register `syscall::entry`'s remapping shim unconditionally
            // overwrites on every trip through `int 0x80`). Copied here
            // alongside the code it protects, not re-derived.
            inout("rdi") arg1 => _,
            inout("rsi") arg2 => _,
            inout("rdx") arg3 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
        );
    }
    ret
}

pub fn write_byte(byte: u8) {
    unsafe {
        syscall(SYS_WRITE, byte as u64, 0, 0);
    }
}

pub fn write_all(bytes: &[u8]) {
    for &byte in bytes {
        write_byte(byte);
    }
}

pub fn yield_now() {
    unsafe {
        syscall(SYS_YIELD, 0, 0, 0);
    }
}

/// Reads `width` (1/2/4) bytes from I/O `port`, gated by whatever capability
/// this process was spawned with (see `kernel/src/capabilities.rs`'s
/// `authorized_for_ioport`). Returns `None` if denied.
pub fn port_in(port: u16, width: u8) -> Option<u32> {
    let ret = unsafe { syscall(SYS_PORT_IN, port as u64, width as u64, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as u32)
    }
}

/// Writes `value`'s low `width` bytes to I/O `port`. Returns `false` if
/// denied, same conditions as [`port_in`].
pub fn port_out(port: u16, width: u8, value: u32) -> bool {
    let ret = unsafe { syscall(SYS_PORT_OUT, port as u64, width as u64, value as u64) };
    ret != u64::MAX
}

/// PIT ticks since boot -- see `kernel/src/syscall.rs`'s `SYS_TICKS` doc
/// comment for why this driver needs it (per-request capability-token
/// expiry checking, `main.rs`'s `verify_file_token`).
pub fn ticks() -> u64 {
    unsafe { syscall(SYS_TICKS, 0, 0, 0) }
}

/// `SYS_IPC_SESSION_ACCEPT` — non-blocking: claims the oldest session
/// opened (via `SYS_IPC_SESSION_OPEN`) against `server_port` but not yet
/// accepted, or `None` if nothing is pending *or* this process holds no
/// `port:<server_port>` capability (same `authorized_for_port` gate
/// `SYS_IPC_SEND`/`SYS_IPC_RECV` already use, per `kernel/src/syscall.rs`'s
/// own doc comment) — indistinguishable, same fail-closed convention as
/// every other gated syscall in this ABI. `main.rs`'s `run_fs_ipc_server`
/// polls this once per loop iteration against `FS_SERVER_PORT` to pick up
/// newly opened client sessions.
pub fn session_try_accept(server_port: usize) -> Option<u64> {
    let ret = unsafe { syscall(SYS_IPC_SESSION_ACCEPT, server_port as u64, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}

/// `SYS_IPC_SESSION_RECV` — non-blocking: one byte off `session_id`'s
/// queue, or `None` if it's currently empty *or* this process isn't a
/// participant (owner or accepted server) of that session — see
/// `kernel/src/ipc.rs`'s `is_participant` doc comment for why that's an
/// O(1) identity check rather than a re-verified capability token on every
/// call.
pub fn session_try_recv(session_id: u64) -> Option<u8> {
    let ret = unsafe { syscall(SYS_IPC_SESSION_RECV, session_id, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as u8)
    }
}

/// `SYS_IPC_SESSION_SEND` — sends one byte on `session_id`, blocking
/// (spin-yielding) if its queue is momentarily full. Returns `false` if
/// the session doesn't exist or this process isn't a participant.
pub fn session_send(session_id: u64, byte: u8) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND, session_id, byte as u64, 0) };
    ret != u64::MAX
}

/// `SYS_IPC_SESSION_SEND_LOCK` — claims `session_id`'s advisory send lock
/// for the duration of a multi-byte message, same reasoning
/// `kernel/src/syscall.rs`'s `SYS_IPC_SEND_LOCK` doc comment gives for
/// fixed ports: a session has at most two participants, but nothing stops
/// both from calling `session_send` for the same logical message
/// concurrently without this. Returns `false` if this process isn't a
/// participant.
pub fn session_send_lock(session_id: u64) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0) };
    ret != u64::MAX
}

/// `SYS_IPC_SESSION_SEND_UNLOCK` — releases a lock claimed by
/// [`session_send_lock`] on the same session from the same thread.
pub fn session_send_unlock(session_id: u64) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND_UNLOCK, session_id, 0, 0) };
    ret != u64::MAX
}
