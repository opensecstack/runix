//! Syscall ABI: `int 0x80`, syscall number in RAX, up to 3 args in
//! RDI/RSI/RDX, return value in RAX — the classic x86 `int 0x80` calling
//! convention (over `syscall`/`sysret`, which needs EFER.SCE + STAR/LSTAR/
//! FMASK MSR setup for comparatively little benefit at this stage: no
//! ring 3 exists yet to make `syscall`'s speed advantage matter, and this
//! reuses the IDT/gate infrastructure `interrupts.rs` already has).
//!
//! The ABI itself doesn't care which ring issues `int 0x80` — only the IDT
//! gate's DPL controls who's *allowed* to. It's callable from kernel code
//! today (there's no ring 3 yet, that's stage 8), which is enough to prove
//! the whole path — gate, register capture, dispatch, return — end to end.

use crate::ipc;
use crate::serial_print;
use core::arch::naked_asm;
use x86_64::instructions::port::Port;

pub const SYS_YIELD: u64 = 0;
pub const SYS_WRITE: u64 = 1; // rdi = byte to write to serial
pub const SYS_IPC_SEND: u64 = 2; // rdi = port, rsi = byte
pub const SYS_IPC_RECV: u64 = 3; // rdi = port -> byte in rax, or u64::MAX if empty
pub const SYS_PORT_IN: u64 = 4; // rdi = I/O port, rsi = width (1/2/4) -> value in rax, or u64::MAX if denied/bad width
pub const SYS_PORT_OUT: u64 = 5; // rdi = I/O port, rsi = width (1/2/4), rdx = value -> 0 ok, u64::MAX if denied/bad width
/// Returns `interrupts::ticks()` (PIT ticks since boot) in rax — no
/// capability gate, same reasoning `SYS_YIELD` has none: a monotonic tick
/// count isn't privileged data on its own, and a ring 3 process holding a
/// [`runix_capability_manager::CapabilityToken`] that embeds an
/// `expires_at` in the same tick units (e.g. `blk-driver-host`'s
/// per-request file-capability check, `ipc::fs`'s doc comment) has no
/// other way to learn "now" to check it against — it never gets raw PIT
/// port I/O privilege the way the kernel itself does.
pub const SYS_TICKS: u64 = 6;
/// rdi = port -> blocks (spin-yielding) until no other sender is mid-message
/// on `port`, then claims it. Capability-gated identically to
/// [`SYS_IPC_SEND`] (same `port:<n>` resource) — this is part of *sending*
/// to a port, not a separate privilege. See `kernel::ipc`'s own doc comment
/// for the exact interleaving hazard this pair of syscalls closes: a
/// multi-byte message routinely exceeds the channel's own capacity, so a
/// caller sending one without holding this lock across the whole send loop
/// can have its bytes interleaved with a second, concurrent sender's on the
/// same port.
pub const SYS_IPC_SEND_LOCK: u64 = 7;
/// rdi = port -> releases the lock claimed by an earlier [`SYS_IPC_SEND_LOCK`]
/// on the same port from the same thread. Capability-gated identically to
/// [`SYS_IPC_SEND_LOCK`]/[`SYS_IPC_SEND`] — not a symmetry nicety: without
/// this check, a caller with *no* capability for the port could still
/// release a lock it never held, letting some other, legitimately
/// authorized sender start mid-message while the actual lock holder isn't
/// done yet, reopening the interleaving hazard this whole mechanism exists
/// to close via an unauthenticated caller instead of a race between two
/// authorized ones. An unpaired unlock from a caller that *is* authorized
/// is still just a caller bug, not further distinguished — same
/// "no distinguishable failure" posture the rest of this ABI already has.
pub const SYS_IPC_SEND_UNLOCK: u64 = 8;

pub const VECTOR: u8 = 0x80;

/// Entry point installed at IDT vector [`VECTOR`]. Naked, not
/// `extern "x86-interrupt"`: the interrupt-calling-convention ABI only
/// exposes the fixed [`InterruptStackFrame`](x86_64::structures::idt::InterruptStackFrame)
/// fields (RIP/CS/RFLAGS/RSP/SS) to the handler body, not the
/// general-purpose registers a syscall's arguments actually arrive in — we
/// have to capture RAX/RDI/RSI/RDX ourselves, before anything else touches
/// them, then hand off to a normal Rust function.
///
/// # Safety
/// Never call this directly — it's a raw interrupt-gate entry point, not a
/// normal function. It assumes it was reached via `int 0x80` (so `iretq`
/// has a matching CPU-pushed frame to consume) and is only ever invoked
/// that way, via the IDT registration in `interrupts.rs`.
#[unsafe(naked)]
pub unsafe extern "C" fn entry() {
    naked_asm!(
        // Remap syscall convention (num=rax, arg1=rdi, arg2=rsi, arg3=rdx)
        // onto the System V argument registers `dispatch` expects
        // (rdi, rsi, rdx, rcx) — in an order where each `mov` reads its
        // source before any earlier `mov` has overwritten it.
        "mov rcx, rdx",
        "mov rdx, rsi",
        "mov rsi, rdi",
        "mov rdi, rax",
        "call {dispatch}",
        // `dispatch`'s return value is already in RAX (SysV return
        // convention) — exactly where the caller expects the syscall's
        // result to land, no extra move needed.
        "iretq",
        dispatch = sym dispatch,
    );
}

/// Shared by [`SYS_IPC_SEND`] and [`SYS_IPC_SEND_LOCK`] — locking a port's
/// send lock is part of the act of sending to it, not a separate privilege,
/// so both check the exact same `port:<n>` capability [`SYS_IPC_SEND`]
/// always has. Pulled out once both syscalls needed it, rather than a
/// second hand-copied version of the same check.
fn authorized_for_port(port: usize) -> bool {
    let resource = crate::capabilities::port_resource(port);
    let now = crate::interrupts::ticks();
    let token_authorizes = |token: &runix_capability_manager::CapabilityToken| {
        !crate::capabilities::is_revoked(token)
            && crate::capabilities::check(token, &resource, now).is_ok()
    };
    // Most threads carry exactly one capability (`current_capability()`) —
    // `current_extra_capabilities()` is only ever non-empty for a thread
    // spawned via `spawn_ring3_process_with_capabilities` (e.g.
    // `blk-driver-host`, authorized for both its own device I/O *and* the
    // reply port it serves filesystem requests over), so checking it is a
    // no-op allocation-and-empty-scan for every other thread in this
    // kernel.
    crate::scheduler::current_capability().is_some_and(|token| token_authorizes(&token))
        || crate::scheduler::current_extra_capabilities()
            .iter()
            .any(token_authorizes)
}

extern "C" fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    match num {
        SYS_YIELD => {
            crate::scheduler::yield_now();
            0
        }
        SYS_WRITE => {
            serial_print!("{}", arg1 as u8 as char);
            0
        }
        SYS_IPC_SEND => {
            let port = arg1 as usize;
            if !authorized_for_port(port) {
                // Denied: the send never reaches the channel — a thread
                // with no (or an invalid/expired/wrong-resource) capability
                // gets the same "nothing happened" signal as any other
                // syscall failure, not a distinguishable error a hostile
                // caller could use to probe why it failed.
                return u64::MAX;
            }
            ipc::send(port, arg2 as u8);
            0
        }
        SYS_IPC_SEND_LOCK => {
            let port = arg1 as usize;
            if !authorized_for_port(port) {
                return u64::MAX;
            }
            ipc::begin_send(port);
            0
        }
        SYS_IPC_SEND_UNLOCK => {
            let port = arg1 as usize;
            // Same capability check as `SYS_IPC_SEND_LOCK`, and for a
            // sharper reason than symmetry: an *unauthorized* caller could
            // otherwise release a lock it never held, letting a second,
            // legitimate sender start mid-message while the thread that
            // actually holds the lock still isn't done — reopening the
            // exact interleaving hazard this pair of syscalls exists to
            // close, just through a different, unauthenticated caller
            // instead of a race between two authorized ones.
            if !authorized_for_port(port) {
                return u64::MAX;
            }
            ipc::end_send(port);
            0
        }
        SYS_IPC_RECV => ipc::try_recv(arg1 as usize).map_or(u64::MAX, u64::from),
        SYS_TICKS => crate::interrupts::ticks(),
        SYS_PORT_IN => {
            let port = arg1 as u16;
            let width = arg2 as u8;
            if !crate::capabilities::authorized_for_ioport(port, crate::interrupts::ticks()) {
                return u64::MAX;
            }
            // Same fail-closed convention as an unauthorized caller: a bad
            // width is indistinguishable from "denied" to whoever called
            // this, not a separate error a hostile caller could use to
            // probe which check failed.
            unsafe {
                match width {
                    1 => u64::from(Port::<u8>::new(port).read()),
                    2 => u64::from(Port::<u16>::new(port).read()),
                    4 => u64::from(Port::<u32>::new(port).read()),
                    _ => u64::MAX,
                }
            }
        }
        SYS_PORT_OUT => {
            let port = arg1 as u16;
            let width = arg2 as u8;
            let value = arg3;
            if !crate::capabilities::authorized_for_ioport(port, crate::interrupts::ticks()) {
                return u64::MAX;
            }
            unsafe {
                match width {
                    1 => Port::<u8>::new(port).write(value as u8),
                    2 => Port::<u16>::new(port).write(value as u16),
                    4 => Port::<u32>::new(port).write(value as u32),
                    _ => return u64::MAX,
                }
            }
            0
        }
        _ => u64::MAX,
    }
}

/// Issue a syscall from kernel code. Once ring 3 exists (stage 8), user-mode
/// code will do the equivalent with a bare `int 0x80` — this wrapper is
/// exactly that instruction plus the register plumbing.
///
/// # Safety
/// Whatever the syscall number's own contract requires — e.g. `SYS_IPC_SEND`
/// requires `arg1` to be a valid port index (< 16 today), same as calling
/// [`ipc::send`] directly.
pub unsafe fn syscall(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") num => ret,
            // `inout(reg) x => _`, not `in(reg) x`, for RDI/RSI/RDX: a plain
            // `in` operand tells the compiler what value the register holds
            // *going in*, but not that it's clobbered afterward — leaving
            // the compiler free to assume a value cached in one of these
            // survives to a *later*, unrelated call. Confirmed as a real
            // bug, not a theoretical one: `net-driver-host/src/syscall.rs`'s
            // copy of this exact wrapper (no shared code between kernel and
            // a separately-linked ring 3 binary — see its own doc comment)
            // had this same gap, and two back-to-back syscalls sharing a
            // literal argument value had the second one silently corrupted,
            // because `entry`'s own remapping shim (below) unconditionally
            // overwrites RDI/RSI/RDX on every trip through `int 0x80`. This
            // kernel-side caller hasn't hit it yet only because nothing here
            // happens to keep a cached value in one of these across two
            // nearby calls — fixed defensively anyway, same reasoning as the
            // RCX/R8-R11 fix below.
            inout("rdi") arg1 => _,
            inout("rsi") arg2 => _,
            inout("rdx") arg3 => _,
            // `entry`'s own remapping shim above does `mov rcx, rdx` before
            // `call dispatch` — RCX is clobbered on every trip through this,
            // and `dispatch` is an ordinary SysV `extern "C"` function free
            // to use R8-R11 as scratch too. Undeclared here, the compiler
            // could keep a live value in any of these across the call and
            // have it silently overwritten — confirmed as a real bug, not a
            // theoretical one: `grid-sandbox-host/src/main.rs`'s copy of
            // this exact wrapper (no shared code between kernel and a
            // separately-linked ring 3 binary — see its own doc comment)
            // had this same gap and it corrupted a live pointer across a
            // `write_all` loop's second syscall, page-faulting on
            // `kernel/tests/grid_sandbox_wasm.rs`. This kernel-side caller
            // hasn't hit it yet only because nothing here happens to keep a
            // live value in one of these registers across the call.
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
        );
    }
    ret
}
