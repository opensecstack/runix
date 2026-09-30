//! This binary's own `int 0x80` stub — a separate implementation from
//! `kernel::syscall::syscall`, not a shared one, same as
//! `grid-sandbox-host/src/syscall.rs`'s copy: this is a standalone-linked
//! ring 3 program, compiled and linked entirely independently of the
//! kernel. The syscall *ABI* (number in RAX, args in RDI/RSI/RDX) is the
//! only thing connecting them.

const SYS_YIELD: u64 = 0;
const SYS_WRITE: u64 = 1;
// Fixed-port `SYS_IPC_SEND`/`SYS_IPC_RECV` (2/3) are unused by this binary
// as of the sockets IPC surface's migration to the session primitive
// (`main.rs`'s `run_socket_ipc_server` doc comment) — kept here, not
// deleted, so this file's own syscall-number table stays a complete,
// contiguous record of the ABI this binary's `int 0x80` stub speaks, the
// same reasoning `session_open`'s own doc comment gives for keeping an
// unused-today wrapper.
#[allow(dead_code)]
const SYS_IPC_SEND: u64 = 2;
#[allow(dead_code)]
const SYS_IPC_RECV: u64 = 3;
const SYS_PORT_IN: u64 = 4;
const SYS_PORT_OUT: u64 = 5;
const SYS_RANDOM: u64 = 9;
const SYS_IPC_SESSION_OPEN: u64 = 10;
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
            // `inout(reg) x => _`, not `in(reg) x`: a plain `in` operand only
            // tells the compiler what value the register holds *going in* —
            // it does NOT mark the register clobbered afterward, so the
            // compiler is free to keep relying on that same physical
            // register still holding `arg1`/`arg2`/`arg3` after this block,
            // if it decides to cache one of those values across two nearby
            // calls sharing a literal argument. `entry`'s own remapping shim
            // (`mov rcx, rdx; mov rdx, rsi; mov rsi, rdi; mov rdi, rax`)
            // overwrites RDI/RSI/RDX unconditionally on every trip through
            // `int 0x80`, and `dispatch` (an ordinary SysV function) is free
            // to clobber them further — genuinely undefined after this call,
            // not just "usually fine." Confirmed as a real bug, not a
            // theoretical one: two back-to-back `port_out` calls in
            // `virtio.rs::VirtioNet::probe`, both passing the literal `1`
            // for `width` (mapped to RSI here), had the second call
            // observed with `width=0` at the kernel's own dispatch — the
            // compiler had cached `1` in a register `entry`'s shim silently
            // overwrote on the first call's round trip. `=> _` (discard the
            // output) is the correct way to tell `asm!` "this register's
            // value after the block is unspecified," matching the same
            // clobber-declaration discipline this codebase already applies
            // to RCX/R8-R11 for the exact same reason.
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
/// `authorized_for_ioport`). Returns `None` if denied — no capability, a
/// port outside the granted range, or an invalid width all collapse to the
/// same `u64::MAX` signal at the syscall boundary, same fail-closed
/// convention as every other capability-gated syscall in this kernel.
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

/// Opens a new session against `server_port`, gated by whatever capability
/// this process was spawned with for that port (same
/// `Thread::extra_capabilities` shape `blk-driver-host/src/syscall.rs`'s
/// `ipc_send` documented for the old fixed-port transport this session
/// primitive replaces as this file's own sockets IPC transport — see
/// `main.rs`'s `run_socket_ipc_server` doc comment for the migration and
/// why port-based `SYS_IPC_SEND`/`SYS_IPC_RECV` are no longer used by that
/// server at all). Not currently called anywhere in this binary
/// (`net-driver-host` is only ever the *server* side of the sockets
/// surface, never a client of another session-based server) — kept anyway,
/// same "the six session syscalls are a matched set" reasoning
/// [`session_accept`]/[`session_send`]/[`session_recv`] below already
/// justify wrapping even though only some of them are on this binary's own
/// hot path. See [`session_try_recv`]/[`session_send`] below.
#[allow(dead_code)]
pub fn session_open(server_port: usize) -> Option<u64> {
    let ret = unsafe { syscall(SYS_IPC_SESSION_OPEN, server_port as u64, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}

/// Non-blocking accept of a pending session opened against `server_port`
/// (see `kernel::ipc`'s `session_accept`) — gated by whatever capability
/// this process was spawned with for that port. `None` if denied or
/// nothing is currently pending.
pub fn session_accept(server_port: usize) -> Option<u64> {
    let ret = unsafe { syscall(SYS_IPC_SESSION_ACCEPT, server_port as u64, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}

/// Non-blocking read of one byte off `session_id`, gated by this thread
/// being a participant (owner or accepted server) of that session — no
/// separate port capability check, see `kernel::ipc`'s `is_participant`.
/// `None` if empty *or* this thread isn't a participant, indistinguishable
/// by design — same fail-closed "denied and empty look the same" convention
/// every other gated receive syscall in this codebase has.
pub fn session_try_recv(session_id: u64) -> Option<u8> {
    let ret = unsafe { syscall(SYS_IPC_SESSION_RECV, session_id, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as u8)
    }
}

/// Sends one byte on `session_id`. Returns `false` if `session_id` doesn't
/// exist or this thread isn't a participant.
pub fn session_send(session_id: u64, byte: u8) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND, session_id, byte as u64, 0) };
    ret != u64::MAX
}

/// Acquires `session_id`'s send lock — see `kernel::syscall::SYS_IPC_SESSION_SEND_LOCK`'s
/// own doc comment for why a session-scoped message needs one at all
/// (interleaving hazard between the session's two participants). Returns
/// `false` if `session_id` doesn't exist or this thread isn't a
/// participant.
pub fn session_send_lock(session_id: u64) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0) };
    ret != u64::MAX
}

/// Releases `session_id`'s send lock acquired by [`session_send_lock`].
pub fn session_send_unlock(session_id: u64) -> bool {
    let ret = unsafe { syscall(SYS_IPC_SESSION_SEND_UNLOCK, session_id, 0, 0) };
    ret != u64::MAX
}

/// One `u64` of RDRAND-backed hardware randomness from the kernel (see
/// `kernel/src/entropy.rs`), gated on this process holding a `"random"`
/// capability. `None` if denied *or* the kernel's RDRAND read failed — both
/// collapse to `u64::MAX` at the syscall boundary, same fail-closed
/// convention as every other gated syscall this process calls.
pub fn random_u64() -> Option<u64> {
    let ret = unsafe { syscall(SYS_RANDOM, 0, 0, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}
