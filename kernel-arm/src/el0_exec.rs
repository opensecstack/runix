//! The generic one-shot EL1-to-EL0 continuation: save an EL1 thread's
//! context, `eret` into an EL0 image, and resume that exact EL1 call site
//! once EL0 reports back through a single `SVC` (or faults). Extracted from
//! `el0_proof.rs`, which was this mechanism's first caller and is now a
//! user of it rather than its only home -- a second caller (a future
//! "Stage 3" TCP proof, per `docs/BETA_MOBILE_PROGRESS.md`) needs the exact
//! same `eret`-out/`SVC`-back shape with a different payload and different
//! observations, and duplicating `enter_el0`/`resume_el1` for it would mean
//! two copies of a naked-asm stack layout that must stay byte-for-byte
//! identical to `scheduler::switch_to`'s.
//!
//! # The return-to-EL1 mechanism, and why it is honest rather than a
//! shortcut
//!
//! The x86_64 side's second scheduling slice gave each ring 3 thread a
//! *separate kernel-entry stack* and a general `SYS_YIELD`. Neither is here,
//! and neither is faked. What this module builds instead is a **one-shot
//! EL1 continuation**:
//!
//! [`enter_el0`] saves the EL1 thread's AAPCS64 callee-saved registers onto
//! that thread's own kernel stack -- the same block `scheduler::switch_to`
//! saves, in the same layout -- records the resulting `sp` in
//! [`EL0_CONTINUATION`], and then `eret`s to EL0. The payload runs, issues
//! one `SVC`, and the caller -- reached from whichever `svc.rs` arm owns
//! that syscall number -- calls [`take_continuation`] and then
//! [`resume_el1`], which restores that block and `ret`s -- so `enter_el0`
//! *returns to its caller*, at EL1, on the same stack, with the same
//! address space still active. The EL0 payload is a coroutine that yields
//! exactly once, by finishing.
//!
//! **Why no separate kernel-entry stack is needed for this, specifically.**
//! `eret` from EL1h to EL0t does not touch `SP_EL1`; EL0 runs on `SP_EL0`.
//! So at the moment the `SVC` is taken, `SP_EL1` is bit-for-bit what it was
//! at the `eret` instruction -- which is this thread's own scheduler-
//! allocated kernel stack, immediately below the saved continuation block.
//! The vector stub, `el1_vector_common`'s ten `stp`s and
//! `el1_exception_handler`'s frames therefore all land *below* the
//! continuation and cannot touch it, and when the caller sets `sp` back to
//! the continuation (via [`resume_el1`]) it abandons exactly those frames,
//! which nothing will ever return to. The EL0 thread's kernel-entry stack is
//! its own kernel stack, and that is sound here rather than merely
//! convenient.
//!
//! **What that costs, stated plainly, because it is exactly what the second
//! slice would buy:** at most one thread may be mid-`eret` at a time
//! ([`EL0_CONTINUATION`] is a single slot), and an EL0 thread may not yield
//! *while at EL0* -- only by finishing. A general process model needs both,
//! which is why a general `SYS_YIELD` and a per-thread EL1 stack are a
//! future slice and not smuggled into this one.

use core::sync::atomic::{AtomicUsize, Ordering};

/// `SPSR_EL1` for the `eret` to EL0: `M[3:0] = 0b0000` (EL0t) with
/// Debug/SError/IRQ/FIQ masked, identical to `el0.rs`'s `SPSR_EL0T_MASKED`
/// and for the same reasons -- in particular that masking `DAIF` does not
/// affect `SVC`, which is synchronous and never maskable.
const SPSR_EL0T_MASKED: u64 = 0b1111 << 6;

/// `M[3:0]` of a `SPSR_EL1` value, i.e. the exception level and stack the
/// interrupted context was using. `0b0000` is EL0t and nothing else is.
pub const SPSR_MODE_MASK: u64 = 0b1111;
pub const SPSR_MODE_EL0T: u64 = 0b0000;

/// The saved `sp` of the one in-flight EL1 continuation, or 0 for "no EL0
/// excursion is running." Written by [`enter_el0`]'s assembly through
/// [`AtomicUsize::as_ptr`] and consumed by [`take_continuation`].
///
/// A single slot, not a per-thread field: see this module's doc comment on
/// what that deliberately does not support.
static EL0_CONTINUATION: AtomicUsize = AtomicUsize::new(0);

/// [`scheduler::Context`](crate::scheduler)'s size, duplicated here for the
/// same reason `scheduler.rs` duplicates it: a naked function's stack
/// offsets must be assembly-time constants. The two blocks are the same
/// layout on purpose -- same registers, same order, same size -- because
/// [`enter_el0`] saves what `switch_to` saves and [`resume_el1`] restores it
/// the same way; the assertion in `scheduler.rs` pins the number itself.
pub const CONTINUATION_SIZE: usize = 160;
const _: () = assert!(CONTINUATION_SIZE == crate::scheduler::CONTEXT_SIZE);

/// Saves the calling EL1 thread's callee-saved context on its own kernel
/// stack, records it in `*slot`, and `eret`s to `entry` at EL0 with
/// `SP_EL0 = sp_el0`.
///
/// Returns -- from [`resume_el1`]'s `ret`, once the caller has reclaimed the
/// continuation via [`take_continuation`] -- with `sp` and every
/// callee-saved register exactly as they were. Caller-saved registers are
/// clobbered, which is what the `extern "C"` boundary already licenses.
///
/// # Safety
/// `entry` must be a mapped, EL0-executable VA in the currently active
/// address space and `sp_el0` a mapped, EL0-writable, 16-byte-aligned stack
/// top in it; `slot` must point at a writable `usize` that outlives the EL0
/// excursion. The code at `entry` must reach EL1 again only through an `SVC`
/// whose handler calls [`take_continuation`] then [`resume_el1`] -- anything
/// else either halts in `el1_vectors.rs` or, for a synchronous fault, is
/// converted to a caller-defined failure by [`abort_from_fault`].
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn enter_el0(entry: u64, sp_el0: u64, slot: *mut usize) {
    core::arch::naked_asm!(
        // Byte-for-byte `scheduler::switch_to`'s save half: same registers,
        // same offsets, same 160-byte block, so this restore and
        // `switch_to`'s restore are interchangeable views of one layout.
        "sub sp, sp, #160",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]",
        "stp d8, d9, [sp, #96]",
        "stp d10, d11, [sp, #112]",
        "stp d12, d13, [sp, #128]",
        "stp d14, d15, [sp, #144]",
        // *slot = sp. x3 onward are caller-saved and dead here.
        "mov x3, sp",
        "str x3, [x2]",
        // Everything the SVC/exception path will use lands *below* this sp,
        // so the block just saved survives the whole EL0 excursion -- see
        // this module's doc comment.
        "movz x3, {spsr}",
        "msr SPSR_EL1, x3",
        "msr ELR_EL1, x0",
        "msr SP_EL0, x1",
        "eret",
        spsr = const SPSR_EL0T_MASKED,
    );
}

/// Restores a continuation saved by [`enter_el0`] and `ret`s, resuming that
/// thread where its `enter_el0` call left off.
///
/// Abandons every stack frame below `saved_sp` -- the vector stub,
/// `el1_vector_common`'s saved registers, and `el1_exception_handler`'s own
/// frame. That is the point: there is nothing at EL0 left to `eret` back to,
/// so unwinding the exception normally is exactly what must *not* happen.
///
/// # Safety
/// `saved_sp` must be a continuation [`enter_el0`] wrote, on a stack that is
/// still live, reached with no intervening frame *above* it -- true on every
/// path that calls this, since `SP_EL1` has only moved downward since the
/// `eret`.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn resume_el1(saved_sp: usize) -> ! {
    core::arch::naked_asm!(
        "mov sp, x0",
        "ldp x19, x20, [sp, #0]",
        "ldp x21, x22, [sp, #16]",
        "ldp x23, x24, [sp, #32]",
        "ldp x25, x26, [sp, #48]",
        "ldp x27, x28, [sp, #64]",
        "ldp x29, x30, [sp, #80]",
        "ldp d8, d9, [sp, #96]",
        "ldp d10, d11, [sp, #112]",
        "ldp d12, d13, [sp, #128]",
        "ldp d14, d15, [sp, #144]",
        "add sp, sp, #160",
        "ret",
    );
}

/// True while an EL0 excursion is in flight, i.e. while [`take_continuation`]
/// and [`abort_from_fault`] have somewhere to resume to. `el1_vectors.rs`
/// consults this (through `el0_proof::continuation_live`) before converting
/// an EL0 fault into a caller-defined failure, so that nothing changes for
/// `el0_demo`, which runs later with no continuation live.
pub fn continuation_live() -> bool {
    EL0_CONTINUATION.load(Ordering::Relaxed) != 0
}

/// Hands `enter_el0`'s private slot to the caller so it can be written by
/// the assembly in [`enter_el0`]. Exists only so `el0_proof.rs` (and any
/// future caller) never reaches into [`EL0_CONTINUATION`] directly -- the
/// slot's only writer is [`enter_el0`]'s own `str`, and its only reader is
/// [`take_continuation`].
pub(crate) fn continuation_slot() -> *mut usize {
    EL0_CONTINUATION.as_ptr()
}

/// Atomically claims the one in-flight continuation, if any, clearing the
/// slot so a second claim (or a stray fault after the first one already
/// resumed) sees "none." Returns `None` if no excursion is live.
///
/// This is the split point between this module's generic mechanism and a
/// caller's own bookkeeping: a caller takes the continuation, does whatever
/// recording it needs (reading `SPSR_EL1`/`ELR_EL1`/its own observation
/// state), and then calls [`resume_el1`] with the value this returned.
/// Nothing here dictates what a caller records or in what order, because
/// that is specific to the payload each caller runs.
pub(crate) fn take_continuation() -> Option<usize> {
    match EL0_CONTINUATION.swap(0, Ordering::Relaxed) {
        0 => None,
        saved_sp => Some(saved_sp),
    }
}

/// Reached when the EL0 payload takes a *synchronous* exception that is not
/// its `SVC`. Claims the continuation, lets the caller record whatever it
/// needs about the fault via `on_fault`, and then either resumes EL1 or -- if
/// no continuation was live, which should not happen on the one path that
/// calls this -- halts, since there is no EL1 context to return to and EL0
/// cannot be resumed meaningfully.
///
/// The fault details themselves (`vector`/`esr`/`far`/`elr`) are not this
/// module's concern -- only the caller knows where to put them (e.g.
/// `el0_proof.rs`'s own `OBSERVED.fault`) -- so they are threaded through
/// `on_fault` rather than hard-coded here.
///
/// # Safety
/// Only valid from a synchronous lower-EL exception taken during an
/// in-flight excursion, i.e. with [`continuation_live`] true -- the same
/// stack reasoning as [`take_continuation`]/[`resume_el1`].
pub unsafe fn abort_from_fault(on_fault: impl FnOnce()) -> ! {
    let saved_sp = take_continuation();
    on_fault();
    match saved_sp {
        // SAFETY: the caller's contract is that a continuation is live; if
        // it somehow is not, halting is the only safe option left.
        None => loop {
            unsafe { core::arch::asm!("wfe") };
        },
        Some(saved_sp) => unsafe { resume_el1(saved_sp) },
    }
}

/// `mrs SPSR_EL1`: the CPU's own record of the exception level and stack the
/// interrupted context was using. Generically useful to any caller observing
/// where an `SVC` came from, not just `el0_proof.rs`'s.
pub(crate) fn read_spsr_el1() -> u64 {
    let value: u64;
    // SAFETY: a read of an EL1-accessible system register, no side effects.
    unsafe {
        core::arch::asm!("mrs {}, SPSR_EL1", out(reg) value, options(nomem, nostack));
    }
    value
}

/// `mrs ELR_EL1`: the instruction the interrupted context will resume at --
/// for an `SVC`, the instruction after it.
pub(crate) fn read_elr_el1() -> u64 {
    let value: u64;
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("mrs {}, ELR_EL1", out(reg) value, options(nomem, nostack));
    }
    value
}

/// `AT S1E0R`: does the MMU allow an *unprivileged* read of `va` under the
/// currently loaded tables? The one check that would catch a `TTBR0_EL1` the
/// scheduler never switched, for whichever VA a caller's payload touches.
pub(crate) fn el0_can_read(va: u64) -> bool {
    let par: u64;
    // SAFETY: `AT` translates without accessing memory and reports through
    // `PAR_EL1`; a faulting translation sets `PAR_EL1.F` rather than taking
    // an exception.
    unsafe {
        core::arch::asm!(
            "at S1E0R, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) va,
            par = out(reg) par,
        );
    }
    par & 1 == 0
}
