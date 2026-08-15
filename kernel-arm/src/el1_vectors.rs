//! EL1's own AArch64 exception vector table -- the direct EL1 analogue of
//! `vectors.rs`'s EL3 table (see that module's doc comment for the shared
//! background: table layout, why "current EL, SPx" is the group that
//! fires for anything EL1 code here does to itself, why each vector stub
//! is a tiny `save x0 / load vector index / branch to shared handler`
//! stub rather than 16 full handlers).
//!
//! # Why this exists before `mmu.rs` is fully trusted
//!
//! `el1_entry` (`nonsecure.rs`) had no exception vector table at all until
//! this module -- `VBAR_EL1` defaults to `0` at reset, so any fault
//! (in particular, a translation fault from a wrong `mmu::install` page
//! table entry) jumped the CPU into whatever raw bytes happen to sit at
//! physical address `0x200` (the "current EL, SPx, Synchronous" vector
//! offset from a zero base), with no diagnostic of any kind -- confirmed
//! the hard way: `mmu::install`'s first real attempt did exactly this,
//! silently, and the only way to even see *that* a fault happened (versus
//! a hang) was attaching GDB and noticing `$pc` had moved to `0x200`.
//! Installing this table before calling `mmu::install` turns that class of
//! failure back into a normal, diagnosable "EXCEPTION: ... ESR_EL1=...
//! FAR_EL1=..." report, the same as `vectors.rs` already does for EL3.
//!
//! # `SVC` resume, added once `el0.rs` needed it
//!
//! Vector 8 ("Synchronous, lower EL, AArch64") is where `el0.rs`'s `SVC
//! #0` calls land. Unlike every other vector here (diagnose and halt
//! forever), an `SVC` needs to *resume EL0*, with a real return value in
//! `x0` -- so `el1_vector_common`'s epilogue restores every saved
//! register from `x1` onward, but deliberately does *not* restore the
//! stub's saved `x0`: `el1_exception_handler`'s own return value (in `x0`
//! already, per the standard call return convention, right after `bl`)
//! becomes EL0's new `x0` instead. This only works because
//! `el1_exception_handler` never actually returns for any *other* vector
//! (every other case loops `wfe` forever internally) -- the epilogue is
//! unreachable except by the one path that's supposed to reach it.

use crate::serial_println;
use core::arch::naked_asm;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn el1_exception_vectors() {
    naked_asm!(
        ".balign 0x800",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #0",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #1",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #2",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #3",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #4",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #5",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #6",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #7",  "b {c}",
        // Vector 8: Synchronous, lower EL, AArch64 -- SVC lands here.
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #8",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #9",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #10", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #11", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #12", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #13", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #14", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #15", "b {c}",
        c = sym el1_vector_common,
    );
}

/// Save-context-then-call-Rust trampoline, same reasoning as
/// `vectors.rs`'s `vector_common`. After the stub's `str x0` and this
/// function's own 10 `stp`s, the saved context sits on the stack (from
/// current `sp` at the `bl`, ascending): `x29,x30` at `+0`/`+8`, ...,
/// `x1,x2` at `+144`/`+152`, the stub's original `x0` at `+160`. `x1`
/// (`+144`, EL0's original `x1` -- `SVC`'s `arg1`) and the stub's `x0`
/// (`+160`, EL0's original `x0` -- `SVC`'s syscall number) are loaded
/// into `x1`/`x2` *before* the `bl`, landing exactly where
/// `el1_exception_handler(vector, num, arg1)`'s AAPCS64 argument
/// registers expect them -- no register shuffling needed beyond the two
/// loads.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn el1_vector_common() {
    naked_asm!(
        "stp x1, x2, [sp, #-16]!",
        "stp x3, x4, [sp, #-16]!",
        "stp x5, x6, [sp, #-16]!",
        "stp x7, x8, [sp, #-16]!",
        "stp x9, x10, [sp, #-16]!",
        "stp x11, x12, [sp, #-16]!",
        "stp x13, x14, [sp, #-16]!",
        "stp x15, x16, [sp, #-16]!",
        "stp x17, x18, [sp, #-16]!",
        "stp x29, x30, [sp, #-16]!",
        "ldr x1, [sp, #160]", // EL0's original x0 (syscall number) -> handler's arg 2 (x1)
        "ldr x2, [sp, #144]", // EL0's original x1 (arg1) -> handler's arg 3 (x2)
        "bl {h}",
        // Only reached if el1_exception_handler actually returned (the
        // SVC-resume case -- every other vector loops wfe forever inside
        // the handler instead). x0 already holds the handler's return
        // value (the SysV return-value register, unchanged since `bl`) --
        // restore x1 upward as normal, then *discard* (not restore) the
        // stub's saved x0 so the handler's return value reaches EL0.
        "ldp x29, x30, [sp], #16",
        "ldp x17, x18, [sp], #16",
        "ldp x15, x16, [sp], #16",
        "ldp x13, x14, [sp], #16",
        "ldp x11, x12, [sp], #16",
        "ldp x9, x10, [sp], #16",
        "ldp x7, x8, [sp], #16",
        "ldp x5, x6, [sp], #16",
        "ldp x3, x4, [sp], #16",
        "ldp x1, x2, [sp], #16",
        "add sp, sp, #16", // discard the stub's saved x0, not restore it
        "eret",
        h = sym el1_exception_handler,
    );
}

fn vector_name(vector: u64) -> &'static str {
    match vector {
        0 => "Synchronous (current EL, SP0)",
        1 => "IRQ (current EL, SP0)",
        2 => "FIQ (current EL, SP0)",
        3 => "SError (current EL, SP0)",
        4 => "Synchronous (current EL, SPx)",
        5 => "IRQ (current EL, SPx)",
        6 => "FIQ (current EL, SPx)",
        7 => "SError (current EL, SPx)",
        8 => "Synchronous (lower EL, AArch64)",
        9 => "IRQ (lower EL, AArch64)",
        10 => "FIQ (lower EL, AArch64)",
        11 => "SError (lower EL, AArch64)",
        _ => "unknown/AArch32",
    }
}

/// `ESR_EL1.EC` value for "SVC instruction execution in AArch64 state".
const ESR_EC_SVC64: u64 = 0x15;

/// Vector 8 (Synchronous, lower EL AArch64), specifically an `SVC`: routes
/// to `svc::dispatch` and *returns* its result -- the one case this
/// handler resumes instead of halting. Every other vector (including
/// vector 8 for a non-`SVC` synchronous exception, e.g. a real EL0 data
/// abort once anything can trigger one) reports and halts, same as
/// before -- this handler doesn't yet know what a safe resume means for
/// anything else.
#[unsafe(no_mangle)]
extern "C" fn el1_exception_handler(vector: u64, syscall_num: u64, arg1: u64) -> u64 {
    let esr_el1: u64;
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr_el1);
    }
    let ec = (esr_el1 >> 26) & 0x3F;

    if vector == 8 && ec == ESR_EC_SVC64 {
        return crate::svc::dispatch(syscall_num, arg1);
    }

    let far_el1: u64;
    let elr_el1: u64;
    unsafe {
        core::arch::asm!("mrs {}, FAR_EL1", out(reg) far_el1);
        core::arch::asm!("mrs {}, ELR_EL1", out(reg) elr_el1);
    }
    serial_println!(
        "EL1 EXCEPTION: vector {} ({}), ELR_EL1={:#x}, ESR_EL1={:#x} (EC={:#x}), FAR_EL1={:#x}",
        vector,
        vector_name(vector),
        elr_el1,
        esr_el1,
        ec,
        far_el1
    );
    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}

/// Points `VBAR_EL1` at [`el1_exception_vectors`] -- see this module's doc
/// comment for what leaving `VBAR_EL1` at its reset value (`0`) actually
/// does to a fault.
pub fn install() {
    unsafe {
        core::arch::asm!(
            "adrp x0, {v}",
            "add x0, x0, :lo12:{v}",
            "msr VBAR_EL1, x0",
            v = sym el1_exception_vectors,
            out("x0") _,
        );
    }
}
