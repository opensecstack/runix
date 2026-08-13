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

pub const SYS_YIELD: u64 = 0;
pub const SYS_WRITE: u64 = 1; // rdi = byte to write to serial
pub const SYS_IPC_SEND: u64 = 2; // rdi = port, rsi = byte
pub const SYS_IPC_RECV: u64 = 3; // rdi = port -> byte in rax, or u64::MAX if empty

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

extern "C" fn dispatch(num: u64, arg1: u64, arg2: u64, _arg3: u64) -> u64 {
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
            let authorized = crate::scheduler::current_capability().is_some_and(|token| {
                let resource = crate::capabilities::port_resource(port);
                !crate::capabilities::is_revoked(&token)
                    && crate::capabilities::check(&token, &resource, crate::interrupts::ticks())
                        .is_ok()
            });
            if !authorized {
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
        SYS_IPC_RECV => ipc::try_recv(arg1 as usize).map_or(u64::MAX, u64::from),
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
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
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
