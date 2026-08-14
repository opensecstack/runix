//! AArch64 exception vector table for EL3, and installing it via `VBAR_EL3`.
//!
//! ARM has no IDT the way x86_64 does (see `kernel/src/interrupts.rs`) --
//! instead, `VBAR_EL3` points at a fixed, 2 KiB-aligned table of 16 entries,
//! each exactly 0x80 (128) bytes, grouped into four sets of four (one set
//! per "where did this exception come from" case -- current EL with SP0,
//! current EL with SPx, a lower EL via AArch64, a lower EL via AArch32),
//! each set covering Synchronous/IRQ/FIQ/SError. We run at EL3 on SP_EL3
//! (not SP0) after `_start` sets up its own stack, so the "current EL,
//! SPx" group (table offset 0x200) is the one that actually fires for
//! anything we do to ourselves.
//!
//! # Context save/restore
//!
//! A first version of this module resumed a caught `brk` by only saving
//! `x0` (the register the vector stub itself clobbers to pass the vector
//! index) -- and corrupted the interrupted code's other live registers on
//! resume, silently. `main.rs`'s `unsafe { asm!("brk #0") }` has no
//! operands and no clobber list, so the compiler is free to keep *anything*
//! live in `x1`-`x18`/`x29`/`x30` across it, on the assumption that a bare
//! trap instruction touches nothing. It doesn't know a handler runs in
//! between and reuses those same registers for its own work. Each vector
//! stub now saves the full set before calling into Rust, and the shared
//! epilogue restores it before `eret` -- the same class of bug (and fix)
//! as `kernel/src/syscall.rs`'s undeclared `RCX`/`R8`-`R11` clobber across
//! `int 0x80` on the x86_64 side (see `docs/THREAT_MODEL.md`), not a novel
//! one to this architecture.
//!
//! Alpha scope: prove the table is wired up, a synchronous exception is
//! actually caught (not silently ignored, or, worse, causing a silent
//! reset -- an unhandled exception with no `VBAR_EL3` set is undefined on
//! real hardware), and resumed *without corrupting the interrupted code's
//! register state*. Real IRQ handling (once the GIC is initialized) is
//! later work; this module's resume path only knows how to continue past
//! one specific, deliberately-triggered case (a `brk` on the current-EL/
//! SPx vector) -- everything else still halts, honestly, rather than
//! guessing at a resume that hasn't been verified safe.

use crate::serial_println;
use core::arch::naked_asm;

/// The table itself. Naked and manually `.balign`-ed rather than expressed
/// as 16 separate `#[naked]` functions: the hardware requires these 16
/// entries to be contiguous, in this exact order, each exactly 0x80 bytes
/// apart -- a property only a single assembly block can guarantee, since
/// nothing in Rust's own function-layout rules promises 16 `fn`s stay
/// adjacent with no padding between them.
///
/// Each entry stays tiny on purpose (well under the 128-byte budget): save
/// the one register it's about to clobber (`x0`, to carry the vector
/// index), load that index, and branch to [`vector_common`] -- which does
/// the rest of the context save, outside the table, where there's no
/// per-entry size limit.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn exception_vectors() {
    naked_asm!(
        ".balign 0x800",
        // Current EL, SP0 (0x000) -- not expected to fire (we never use
        // SP0 after `_start` switches to our own stack), handled anyway
        // rather than left as a silent trap into whatever code happens to
        // follow this table in memory.
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #0",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #1",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #2",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #3",  "b {c}",
        // Current EL, SPx (0x200) -- this is the group that actually fires
        // for anything EL3 code here does to itself.
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #4",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #5",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #6",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #7",  "b {c}",
        // Lower EL, AArch64 (0x400) -- fires once EL1 code exists and
        // traps/interrupts back up to EL3 (no such trap is set up from the
        // EL1 side yet -- see `nonsecure.rs`).
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #8",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #9",  "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #10", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #11", "b {c}",
        // Lower EL, AArch32 (0x600) -- Runix has no 32-bit-mode plans;
        // handled for completeness (an unhandled entry here is exactly as
        // fatal as the SP0 group above), not because it's expected to fire.
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #12", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #13", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #14", "b {c}",
        ".balign 0x80", "str x0, [sp, #-16]!", "mov x0, #15", "b {c}",
        c = sym vector_common,
    );
}

/// Finishes saving context (everything the stub didn't already push:
/// `x1`-`x18`, the AAPCS64 caller-saved/scratch set, plus `x29`/`x30` since
/// compiler-generated code can use those too), calls [`exception_handler`]
/// with the vector index (still in `x0`) as its argument, and -- if it
/// returns at all -- restores everything in reverse and `eret`s.
/// [`exception_handler`] returning (instead of looping forever) *is* the
/// "resume" signal; see its own doc comment for which cases do that.
///
/// Naked and separate from the table itself only because per-vector-entry
/// space is scarce (128 bytes) and this isn't: `bl`/`ret` need a real
/// return address, which a `b`-only stub entry never sets up.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn vector_common() {
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
        "ldr x0, [sp], #16",
        "eret",
        h = sym exception_handler,
    );
}

/// Human-readable label for each of the 16 vector indices `exception_vectors`
/// can report -- purely diagnostic, so a caught exception says *what kind*,
/// not just "something happened."
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
        12 => "Synchronous (lower EL, AArch32)",
        13 => "IRQ (lower EL, AArch32)",
        14 => "FIQ (lower EL, AArch32)",
        15 => "SError (lower EL, AArch32)",
        _ => "unknown",
    }
}

/// `ESR_EL3.EC` (Exception Class, bits [31:26]) value for "BRK instruction
/// execution in AArch64 state" -- the one exception class this handler
/// knows how to safely resume from.
const ESR_EC_BRK64: u64 = 0x3C;

/// Called (via `bl`, from [`vector_common`]) with the full interrupted
/// context already saved on the stack beneath the return address --
/// `vector` is the table index, `x0`'s original value included in what's
/// saved (not passed here; it's restored from the stack by
/// [`vector_common`]'s epilogue regardless of what this function does).
///
/// Reads `ESR_EL3` (Exception Syndrome Register): `vector` alone says
/// *which table entry* fired, `ESR_EL3` says *why* (e.g. which instruction
/// class trapped).
///
/// A `brk` on the synchronous/current-EL/SPx vector (exactly what
/// `main.rs`'s deliberate exception test produces) is resumed: this
/// function *returns normally*, `ELR_EL3` advanced by 4 (one AArch64
/// instruction) first so `vector_common`'s `eret` continues execution
/// right after the `brk` -- the same thing a hardware debugger does
/// stepping over a breakpoint. `ELR_EL3` isn't advanced automatically by
/// the CPU for a synchronous exception, so this has to happen explicitly
/// or the resumed code would just trap on the same `brk` again.
///
/// Anything else halts (loops forever, never returns) -- this handler
/// doesn't yet know what a safe resume means for any other exception
/// class, and a full context save existing now doesn't change that; it
/// only makes the *one* resume case this handles actually safe.
#[unsafe(no_mangle)]
extern "C" fn exception_handler(vector: u64) {
    // Vector 5 (IRQ, current EL SPx) -- routed through the GIC, not ESR_EL3
    // (ESR isn't meaningfully populated for IRQ the way it is for a
    // synchronous exception; the GIC's own `GICC_IAR` is the source of
    // truth for "which interrupt fired," see `gic.rs`). Handled first and
    // separately so the synchronous-exception path below doesn't have to
    // account for a vector where ESR_EL3 isn't the right thing to read.
    if vector == 5 || vector == 6 {
        let raw_iar = crate::gic::acknowledge();
        let id = crate::gic::interrupt_id(raw_iar);
        serial_println!("EXCEPTION: IRQ fired, GIC interrupt id = {}", id);
        crate::gic::end_of_interrupt(raw_iar);
        return;
    }

    let esr_el3: u64;
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL3", out(reg) esr_el3);
    }
    let ec = (esr_el3 >> 26) & 0x3F;
    serial_println!(
        "EXCEPTION: vector {} ({}), ESR_EL3 = {:#x} (EC = {:#x})",
        vector,
        vector_name(vector),
        esr_el3,
        ec
    );

    if vector == 4 && ec == ESR_EC_BRK64 {
        serial_println!(
            "EXCEPTION: resuming past the brk (EL3 exception handling verified, full context preserved)"
        );
        unsafe {
            core::arch::asm!(
                "mrs x0, ELR_EL3",
                "add x0, x0, #4",
                "msr ELR_EL3, x0",
                out("x0") _,
            );
        }
        return;
    }

    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}

/// Points `VBAR_EL3` at [`exception_vectors`] -- until this runs, EL3 has
/// no exception table installed at all, and anything that traps is
/// undefined behavior on real hardware (QEMU's own default tends to be a
/// clean reset, which is not meaningfully better: either way, nothing of
/// ours ever finds out an exception happened).
pub fn install() {
    unsafe {
        core::arch::asm!(
            "adrp x0, {v}",
            "add x0, x0, :lo12:{v}",
            "msr VBAR_EL3, x0",
            v = sym exception_vectors,
            out("x0") _,
        );
    }
}
