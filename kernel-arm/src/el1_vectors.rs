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
/// `vectors.rs`'s `vector_common`. Unlike EL3's version, this one never
/// resumes (no case here needs it yet -- Alpha's EL1 fault handling is
/// diagnose-and-halt, not catch-and-continue) so there's no epilogue to
/// restore registers before an `eret`; `el1_exception_handler` simply
/// never returns.
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
        "bl {h}",
        "1:",
        "wfe",
        "b 1b",
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

/// Reports the fault and halts. `FAR_EL1` (Fault Address Register) is what
/// makes this actually useful for diagnosing a bad translation-table
/// entry -- `ESR_EL1` says *what kind* of fault (translation, permission,
/// access-flag, ...), `FAR_EL1` says *which address* triggered it, which
/// `mmu.rs`'s two 1 GiB block descriptors alone don't reveal at a glance.
#[unsafe(no_mangle)]
extern "C" fn el1_exception_handler(vector: u64) -> ! {
    let esr_el1: u64;
    let far_el1: u64;
    let elr_el1: u64;
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr_el1);
        core::arch::asm!("mrs {}, FAR_EL1", out(reg) far_el1);
        core::arch::asm!("mrs {}, ELR_EL1", out(reg) elr_el1);
    }
    let ec = (esr_el1 >> 26) & 0x3F;
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
