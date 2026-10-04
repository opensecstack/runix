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
//! #0` calls land. EL0's `x0` carries the syscall number and `x1`/`x2`/`x3`
//! its three arguments -- three, not the two this gate originally carried,
//! because the eSIM lifecycle syscalls (`svc.rs`'s `SYS_SIM_INSTALL`) need
//! `slot`, `profile_id`, *and* `identity` at once. Widening the ABI by one
//! register was chosen over bit-packing `slot`/`profile_id` into a single
//! argument: packed fields need an agreed-on encoding duplicated on both
//! sides of the boundary (`svc.rs` and `el0.rs`), whereas one more register
//! is free -- AAPCS64 has eight argument registers and
//! `el1_exception_handler` was using four. See
//! [`el1_vector_common`]'s doc comment for the stack-offset derivation that
//! widening required. Unlike every other vector here (diagnose and halt
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
/// `vectors.rs`'s `vector_common`. Every push below is a pre-decrement
/// (`[sp, #-16]!`), so the *last* push sits lowest and each earlier push
/// sits 16 bytes higher. Counting back from `sp` as it stands at the `bl`
/// (the stub's `str x0` plus this function's own 10 `stp`s = 11 pushes =
/// 176 bytes below where the stub was entered), the saved context is, in
/// ascending order:
///
/// ```text
/// +0  /+8    x29,x30   (10th/last stp -- pushed lowest)
/// +16 /+24   x17,x18
/// +32 /+40   x15,x16
/// +48 /+56   x13,x14
/// +64 /+72   x11,x12
/// +80 /+88   x9,x10
/// +96 /+104  x7,x8
/// +112/+120  x5,x6
/// +128/+136  x3,x4     (2nd stp)
/// +144/+152  x1,x2     (1st stp -- pushed highest of the ten)
/// +160       x0        (the vector stub's own `str x0`, highest of all)
/// ```
///
/// EL0's original `x0`/`x1`/`x2`/`x3` (`SVC`'s syscall number, `arg1`,
/// `arg2`, `arg3`) therefore live at `+160`/`+144`/`+152`/`+128`
/// respectively -- note `+128` for `x3` comes from the *second* `stp`'s
/// first register, which is why the third argument's slot sits *below*
/// the first two rather than continuing upward past them. They are loaded
/// into `x1`/`x2`/`x3`/`x4` *before* the `bl`, landing exactly where
/// `el1_exception_handler(vector, num, arg1, arg2, arg3)`'s AAPCS64
/// argument registers expect them -- no register shuffling needed beyond
/// the four loads.
///
/// Clobbering `x1`..`x4` with those loads is safe precisely because this
/// function already pushed all four (`x1,x2` at `+144`/`+152`, `x3,x4` at
/// `+128`/`+136`) -- the epilogue restores them from the stack, not from
/// whatever the loads left behind, so the argument registers are free
/// scratch space between the `stp`s and the `ldp`s.
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
        "ldr x3, [sp, #152]", // EL0's original x2 (arg2) -> handler's arg 4 (x3)
        "ldr x4, [sp, #128]", // EL0's original x3 (arg3) -> handler's arg 5 (x4)
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
/// anything else, with one narrow exception documented inline below (an EL0
/// fault taken during `el0_proof.rs`'s one-shot EL0 excursion, which is the
/// one other case with a real EL1 continuation to resume *to*).
#[unsafe(no_mangle)]
extern "C" fn el1_exception_handler(
    vector: u64,
    syscall_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> u64 {
    let esr_el1: u64;
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr_el1);
    }
    let ec = (esr_el1 >> 26) & 0x3F;

    if vector == 8 && ec == ESR_EC_SVC64 {
        return crate::svc::dispatch(syscall_num, arg1, arg2, arg3);
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

    // One narrow escape from "print and halt forever", for exactly one
    // situation: a synchronous exception from a lower EL (vector 8) that is
    // not an `SVC`, taken while `el0_proof.rs` has an EL1 continuation in
    // flight -- i.e. its EL0 process faulted instead of finishing. The
    // diagnostic above has already been printed, so nothing is lost; what
    // this buys is that the *only* thread able to report the proof's result
    // (the one suspended inside `el0_proof::enter_el0`) gets resumed to
    // print a `FAILED` line, instead of the whole boot hanging here with no
    // verdict. Deliberately not generalized to other vectors or to the
    // no-continuation case: with no continuation live this condition is
    // false and the behaviour below is unchanged, which is what keeps
    // `el0.rs`'s `el0_demo` -- which runs later, with no continuation --
    // exactly as it was.
    // `tcp_proof.rs`'s own continuation is checked *first* and is the only
    // one of the two that can actually tell whether it is live: it ANDs
    // `el0_exec::continuation_live()` with a flag of its own (see
    // `tcp_proof::TCP_PROOF_ACTIVE`'s doc comment), whereas
    // `el0_proof::continuation_live()` below is simply
    // `el0_exec::continuation_live()` unconditionally -- correct only when
    // `tcp_proof.rs`'s excursion is not the one in flight. Checking
    // `tcp_proof` first means a fault during *its* excursion is never
    // misrouted into `el0_proof`'s own `OBSERVED`, which nothing would ever
    // read.
    if vector == 8 && crate::tcp_proof::continuation_live() {
        // SAFETY: `continuation_live()` is true, which is this function's
        // stated precondition; see `abort_from_fault`'s own doc comment for
        // the stack reasoning.
        unsafe { crate::tcp_proof::abort_from_fault(vector, esr_el1, far_el1, elr_el1) };
    }

    // `marshal_transport.rs`'s own continuation, checked next for the same
    // reason `tcp_proof`'s is checked before `el0_proof`'s below: three
    // modules now share `el0_exec`'s single continuation slot, and each
    // one's own `*_ACTIVE`-gated `continuation_live()` is the only way to
    // tell *whose* excursion is actually live (see
    // `marshal_transport::MARSHAL_ACTIVE`'s doc comment). A fault during
    // this module's excursion must never be misrouted into `tcp_proof`'s or
    // `el0_proof`'s own `OBSERVED`, which would otherwise record a fault
    // that wasn't theirs and leave this module's own bounded wait to time
    // out with no diagnostic.
    if vector == 8 && crate::marshal_transport::continuation_live() {
        // SAFETY: `continuation_live()` is true, which is this function's
        // stated precondition; see `abort_from_fault`'s own doc comment for
        // the stack reasoning.
        unsafe { crate::marshal_transport::abort_from_fault(vector, esr_el1, far_el1, elr_el1) };
    }

    if vector == 8 && crate::el0_proof::continuation_live() {
        // SAFETY: `continuation_live()` is true, which is this function's
        // stated precondition; see `abort_from_fault`'s own doc comment for
        // the stack reasoning.
        unsafe { crate::el0_proof::abort_from_fault(vector, esr_el1, far_el1, elr_el1) };
    }

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
