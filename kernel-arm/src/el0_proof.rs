//! The first real EL0 *process* in `kernel-arm`: a scheduled thread that
//! owns a `process::AddressSpace`, is resumed with its own `TTBR0_EL1`
//! installed by `scheduler.rs`, and `eret`s into an image that
//! `loader.rs`/`load_proof.rs` genuinely loaded -- the step
//! `docs/BETA_MOBILE_PROGRESS.md` item 2.4 calls "combining slices 3-5",
//! and the first time anything in this crate has executed at EL0 from a
//! loaded ELF rather than from a hand-written function compiled into the
//! kernel image (`el0.rs`'s `el0_demo`).
//!
//! This mirrors the *first* of the two pieces `kernel/src/scheduler.rs` was
//! split into on the x86_64 side ("`Cr3` now follows the schedule"), and
//! deliberately not the second.
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
//! one `SVC`, and [`finish`] (reached from `svc.rs`'s single new
//! [`crate::svc::SYS_EL0_PROOF_DONE`] arm) restores that block and `ret`s --
//! so `enter_el0` *returns to its caller*, at EL1, on the same stack, with
//! the same address space still active. The EL0 payload is a coroutine that
//! yields exactly once, by finishing.
//!
//! **Why no separate kernel-entry stack is needed for this, specifically.**
//! `eret` from EL1h to EL0t does not touch `SP_EL1`; EL0 runs on `SP_EL0`.
//! So at the moment the `SVC` is taken, `SP_EL1` is bit-for-bit what it was
//! at the `eret` instruction -- which is this thread's own scheduler-
//! allocated kernel stack, immediately below the saved continuation block.
//! The vector stub, `el1_vector_common`'s ten `stp`s and
//! `el1_exception_handler`'s frames therefore all land *below* the
//! continuation and cannot touch it, and when [`finish`] sets `sp` back to
//! the continuation it abandons exactly those frames, which nothing will
//! ever return to. The EL0 thread's kernel-entry stack is its own kernel
//! stack, and that is sound here rather than merely convenient.
//!
//! **What that costs, stated plainly, because it is exactly what the second
//! slice would buy:** at most one thread may be mid-`eret` at a time
//! ([`EL0_CONTINUATION`] is a single slot), and an EL0 thread may not yield
//! *while at EL0* -- only by finishing. A general process model needs both,
//! which is why a general `SYS_YIELD` and a per-thread EL1 stack are the
//! next slice and not smuggled into this one.
//!
//! **Why this is a proof and not a nicely-shaped assumption.** Every claim
//! below is read out of hardware, not out of this module's bookkeeping:
//!
//! - Before the `eret`, with the thread's own table live, `AT S1E0R` on the
//!   payload's private data VA. Under the kernel's identity map that VA is
//!   unmapped, so a `TTBR0_EL1` the scheduler failed to switch produces a
//!   translation fault here and the proof fails rather than passing for the
//!   wrong reason.
//! - Inside the `SVC` handler, `SPSR_EL1.M[3:0]` (must be `0b0000`, EL0t --
//!   the CPU's own record of which exception level the `SVC` came from) and
//!   `ELR_EL1` (must be inside the loaded text page's VA range, i.e. the
//!   instruction after the payload's `svc`, in *process-private* memory
//!   nothing else in this crate maps).
//! - The payload's own three reported values: the magic byte `loader.rs`
//!   copied into its private data page, a byte it *wrote and read back*
//!   through that same page's `AP[2:1]=0b01` mapping, and a byte pushed and
//!   popped on its own EL0 stack. Loads and stores, not just instruction
//!   fetch -- fetch alone would not need the address space's data mappings
//!   to be right.
//!
//! A no-op `TTBR0_EL1` switch, an `eret` that never left EL1, or an image
//! that was never really loaded each fail at least one of those.
//!
//! # Why the payload is assembled by the assembler and copied
//!
//! The EL0 payload ([`el0_proof_payload_start`]) is written as a
//! `global_asm!` block inside the kernel image, and its bytes are copied
//! into the hand-assembled ELF at runtime. There is no filesystem here, so
//! some form of hand-building is unavoidable (the same constraint
//! `load_proof.rs`'s image and `elf.rs`'s tests work under) -- but emitting
//! instruction *words* as `u32` literals from Rust would make the one part
//! of this proof that must be exactly right the one part nothing checks.
//! Letting the assembler encode real mnemonics, and bounding the copy by two
//! real symbols in the same section, keeps that correctness where a tool
//! owns it. The payload contains no PC-relative references at all (every
//! address it touches is built with `movz`/`movk` from a `const` operand
//! that *is* the Rust constant), so copying it to a different VA is sound
//! rather than lucky.

use crate::process::{self, AddressSpace};
use crate::serial_println;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use runix_kernel_arm::elf::{Elf64, PF_R, PF_W, PF_X};
use runix_kernel_arm::loader::{self, STACK_TOP};
use runix_kernel_arm::vm::{GRANULE_4KIB, PRIVATE_REGION_BASE};
use spin::Mutex;

/// Where the proof image asks to be loaded. Distinct pages from
/// `load_proof.rs`'s own (`+0x20_0000`/`+0x21_0000`) so the two proofs can
/// never be reading each other's leftovers, and both 64 KiB-aligned so the
/// payload can materialize [`DATA_VADDR`] with a single `movz ... lsl #16`.
const TEXT_VADDR: u64 = PRIVATE_REGION_BASE + 0x0040_0000;
const DATA_VADDR: u64 = PRIVATE_REGION_BASE + 0x0041_0000;

/// The byte `loader.rs` copies into the private data page from the ELF's
/// `PT_LOAD` content, and that the EL0 payload reads back through its own
/// mapping. Arbitrary, but *not* 0 or 0xFF: a zeroed page or an unwritten
/// frame must not be able to impersonate it.
const MAGIC: u64 = 0x7E;
/// The byte the payload *writes* into that page (one byte past [`MAGIC`],
/// inside the segment's BSS tail) and reads back, proving the mapping is
/// writable from EL0, not just readable.
const WITNESS: u64 = 0x5A;
/// The byte the payload pushes and pops on its own EL0 stack, in the page
/// `loader.rs` mapped at the top of the private window.
const STACK_WITNESS: u64 = 0x42;

/// `p_filesz` of the data segment: just [`MAGIC`]. The rest of `p_memsz` is
/// a real BSS tail, which is where [`WITNESS`] gets written -- so the
/// payload's store lands in memory the loader zero-filled, and a stale
/// 0x5A left over from anywhere else is not a possible explanation for the
/// read-back.
const DATA_FILESZ: u64 = 1;
const DATA_MEMSZ: u64 = 8;

const ELF_HEADER_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;

/// Sanity-check the proof's own geometry at compile time. The `movz ... lsl
/// #16` the payload uses to build [`DATA_VADDR`] is only correct if the low
/// 16 bits are zero, and the two VAs must sit on distinct pages for the
/// read-only text / read-write data split to mean anything.
const _: () = {
    assert!(TEXT_VADDR % GRANULE_4KIB == 0);
    assert!(DATA_VADDR % GRANULE_4KIB == 0);
    assert!(DATA_VADDR & 0xFFFF == 0);
    assert!(DATA_VADDR >> 16 <= 0xFFFF);
    assert!(TEXT_VADDR != DATA_VADDR);
    assert!(WITNESS != MAGIC);
    assert!(DATA_FILESZ < DATA_MEMSZ);
};

// ---------------------------------------------------------------------------
// The EL0 payload
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".balign 4",
    ".globl el0_proof_payload_start",
    "el0_proof_payload_start:",
    // x9 = DATA_VADDR, built from an immediate rather than read from
    // anywhere: this code is copied to a VA it was not assembled at, so
    // nothing PC-relative (`adrp`, a literal pool load) would survive the
    // move. The `const` operand is the Rust constant itself, so the two
    // cannot drift.
    "movz x9, {data_hi}, lsl #16",
    // The magic byte `loader.rs` copied in from the ELF's PT_LOAD content,
    // read back through this process's *own* private mapping. A real load,
    // not instruction fetch: this is the first thing that would fault if
    // TTBR0_EL1 were not actually this address space's.
    "ldrb w10, [x9]",
    // Write, then read back, one byte further in -- inside the segment's
    // zero-filled BSS tail. The write needs AP[2:1]=0b01 on this page from
    // EL0; the read-back is what makes it an observation rather than a
    // hope.
    "mov w11, {witness}",
    "strb w11, [x9, #1]",
    "ldrb w12, [x9, #1]",
    // The EL0 stack `loader.rs` mapped at the top of the private window,
    // reached through SP_EL0 -- a third independent private mapping, and the
    // one a stack-overflow guard gap sits below.
    "mov w13, {stack_witness}",
    "strb w13, [sp, #-16]!",
    "ldrb w14, [sp]",
    "add sp, sp, #16",
    // Report all three to EL1 and never come back here. `finish` does not
    // return to EL0; the spin below exists so that a future change which
    // *did* return lands somewhere harmless instead of running off the end
    // of the page.
    "movz x0, {syscall}",
    "mov x1, x10",
    "mov x2, x12",
    "mov x3, x14",
    "svc #0",
    "1:",
    "wfe",
    "b 1b",
    ".globl el0_proof_payload_end",
    "el0_proof_payload_end:",
    data_hi = const DATA_VADDR >> 16,
    witness = const WITNESS,
    stack_witness = const STACK_WITNESS,
    syscall = const crate::svc::SYS_EL0_PROOF_DONE,
);

extern "C" {
    static el0_proof_payload_start: u8;
    static el0_proof_payload_end: u8;
}

/// The payload's own machine code, as the assembler encoded it. Bounded by
/// two symbols the same `global_asm!` block emits consecutively, so the
/// length is exact rather than a padded guess.
fn payload_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(el0_proof_payload_start);
    let end = core::ptr::addr_of!(el0_proof_payload_end);
    // SAFETY: both symbols are defined in one `global_asm!` block, in
    // order, in `.text` -- so `end >= start` and the range between them is
    // exactly the emitted instructions, which are live for the whole
    // program. `.text` is EL1-readable (`mmu.rs` maps it `AP[2:1]=0b00`,
    // i.e. EL1 read/write), so reading it as data is valid.
    let len = unsafe { end.offset_from(start) };
    debug_assert!(len > 0);
    unsafe { core::slice::from_raw_parts(start, len as usize) }
}

// ---------------------------------------------------------------------------
// The one-shot EL1 continuation
// ---------------------------------------------------------------------------

/// `SPSR_EL1` for the `eret` to EL0: `M[3:0] = 0b0000` (EL0t) with
/// Debug/SError/IRQ/FIQ masked, identical to `el0.rs`'s `SPSR_EL0T_MASKED`
/// and for the same reasons -- in particular that masking `DAIF` does not
/// affect `SVC`, which is synchronous and never maskable.
const SPSR_EL0T_MASKED: u64 = 0b1111 << 6;

/// `M[3:0]` of a `SPSR_EL1` value, i.e. the exception level and stack the
/// interrupted context was using. `0b0000` is EL0t and nothing else is.
const SPSR_MODE_MASK: u64 = 0b1111;
const SPSR_MODE_EL0T: u64 = 0b0000;

/// The saved `sp` of the one in-flight EL1 continuation, or 0 for "no EL0
/// proof is running." Written by [`enter_el0`]'s assembly through
/// [`AtomicUsize::as_ptr`] and consumed by [`finish`].
///
/// A single slot, not a per-thread field: see this module's doc comment on
/// what that deliberately does not support.
static EL0_CONTINUATION: AtomicUsize = AtomicUsize::new(0);

/// [`scheduler::Context`](crate::scheduler)'s size, duplicated here as a
/// literal for the same reason `scheduler.rs` duplicates it: a naked
/// function's stack offsets must be assembly-time constants. The two blocks
/// are the same layout on purpose -- same registers, same order, same size
/// -- because [`enter_el0`] saves what `switch_to` saves and [`finish`]
/// restores it the same way; the assertion in `scheduler.rs` pins the
/// number itself.
const CONTINUATION_SIZE: usize = 160;
const _: () = assert!(CONTINUATION_SIZE == crate::scheduler::CONTEXT_SIZE);

/// Saves the calling EL1 thread's callee-saved context on its own kernel
/// stack, records it in `*slot`, and `eret`s to `entry` at EL0 with
/// `SP_EL0 = sp_el0`.
///
/// Returns -- from [`finish`]'s `ret`, once the EL0 payload has issued its
/// one `SVC` -- with `sp` and every callee-saved register exactly as they
/// were. Caller-saved registers are clobbered, which is what the `extern
/// "C"` boundary already licenses.
///
/// # Safety
/// `entry` must be a mapped, EL0-executable VA in the currently active
/// address space and `sp_el0` a mapped, EL0-writable, 16-byte-aligned stack
/// top in it; `slot` must point at a writable `usize` that outlives the EL0
/// excursion. The code at `entry` must reach EL1 again only through the
/// `SVC` [`finish`] handles -- anything else either halts in
/// `el1_vectors.rs` or, for a synchronous fault, is converted to a proof
/// failure by [`abort_from_fault`].
#[unsafe(naked)]
unsafe extern "C" fn enter_el0(entry: u64, sp_el0: u64, slot: *mut usize) {
    core::arch::naked_asm!(
        // Byte-for-byte `scheduler::switch_to`'s save half: same registers,
        // same offsets, same 160-byte block, so `finish`'s restore and
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
/// still live, reached with no intervening frame *above* it -- true on the
/// one path that calls this, since `SP_EL1` has only moved downward since
/// the `eret`.
#[unsafe(naked)]
unsafe extern "C" fn resume_el1(saved_sp: usize) -> ! {
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

/// Everything observed about the EL0 excursion, filled in across the two
/// sides of it (the EL1 thread before the `eret`, then [`finish`] inside the
/// `SVC` handler) and compared by [`el0_proof_thread`] afterwards.
#[derive(Default)]
struct Observation {
    /// `TTBR0_EL1` as the thread's EL1 side read it right before the `eret`
    /// -- the scheduler's switch, observed from the live register.
    thread_root: u64,
    /// `AT S1E0R` on [`DATA_VADDR`] under that same live table.
    data_el0_readable: bool,
    /// `SPSR_EL1` at `SVC` entry: the CPU's own record of the exception
    /// level the `SVC` came from.
    svc_spsr: u64,
    /// `ELR_EL1` at `SVC` entry: the instruction after the payload's `svc`.
    svc_elr: u64,
    /// `TTBR0_EL1` at `SVC` entry, still the process's.
    svc_root: u64,
    /// The payload's reported bytes: magic read, witness written+read back,
    /// EL0 stack byte round-tripped.
    magic: u64,
    witness: u64,
    stack_byte: u64,
    /// `Some((vector, esr, far, elr))` if control came back through
    /// [`abort_from_fault`] -- an EL0 fault -- rather than through the
    /// payload's `SVC`.
    fault: Option<(u64, u64, u64, u64)>,
}

static OBSERVED: Mutex<Observation> = Mutex::new(Observation {
    thread_root: 0,
    data_el0_readable: false,
    svc_spsr: 0,
    svc_elr: 0,
    svc_root: 0,
    magic: 0,
    witness: 0,
    stack_byte: 0,
    fault: None,
});

/// Set by [`el0_proof_thread`] once it has printed its verdict, so the boot
/// thread's bounded yield loop can stop.
static FINISHED: AtomicBool = AtomicBool::new(false);

/// `LoadedImage::entry`/`stack_top`, handed to the spawned thread through
/// statics because `scheduler::spawn_with_address_space` takes a bare
/// `extern "C" fn() -> !` with no argument slot -- the same reason
/// `scheduler.rs`'s own proof threads are three distinct functions rather
/// than one function with a tag parameter.
static IMAGE_ENTRY: AtomicU64 = AtomicU64::new(0);
static IMAGE_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static IMAGE_ROOT: AtomicU64 = AtomicU64::new(0);

/// True while an EL0 excursion is in flight, i.e. while [`finish`] and
/// [`abort_from_fault`] have somewhere to resume to. `el1_vectors.rs`
/// consults this before converting an EL0 fault into a proof failure, so
/// that nothing changes for `el0_demo`, which runs later with no
/// continuation live.
pub fn continuation_live() -> bool {
    EL0_CONTINUATION.load(Ordering::Relaxed) != 0
}

/// `svc.rs`'s [`crate::svc::SYS_EL0_PROOF_DONE`] arm: records what EL0
/// reported plus the hardware's own account of where the `SVC` came from,
/// then resumes the EL1 continuation -- never returning to EL0.
///
/// Returns `u64::MAX` (and stays at EL0) if no continuation is live. That is
/// the whole of this syscall's authority: it can end the *caller's own* EL0
/// excursion and nothing else, so there is no resource for a capability to
/// name and no privileged action to route through MARSHAL. With no
/// excursion in flight it is simply an unknown syscall, which is what
/// `u64::MAX` already means in `svc.rs`'s dispatch.
pub fn finish(magic: u64, witness: u64, stack_byte: u64) -> u64 {
    let saved_sp = EL0_CONTINUATION.swap(0, Ordering::Relaxed);
    if saved_sp == 0 {
        return u64::MAX;
    }
    {
        let mut observed = OBSERVED.lock();
        observed.magic = magic;
        observed.witness = witness;
        observed.stack_byte = stack_byte;
        observed.svc_spsr = read_spsr_el1();
        observed.svc_elr = read_elr_el1();
        observed.svc_root = process::active_root();
    }
    // SAFETY: `saved_sp` was written by `enter_el0` on this very thread's
    // kernel stack, which is still live, and `SP_EL1` has only moved
    // downward since (the `eret`, then this exception) -- see this module's
    // doc comment.
    unsafe { resume_el1(saved_sp) }
}

/// Reached from `el1_vectors.rs` when the EL0 payload takes a *synchronous*
/// exception that is not its `SVC` -- a data abort on a mapping that should
/// have been there, an undefined instruction from a mis-copied payload.
///
/// Exists so that the realistic failure mode of this proof is a `FAILED`
/// line naming `ESR_EL1`/`FAR_EL1`, not a silent hang. It would otherwise
/// hang rather than fail: the only thread that could report anything is the
/// one suspended inside `enter_el0`, and `el1_exception_handler`'s default
/// is to print and `wfe` forever. `el1_vectors.rs` still prints its full
/// diagnostic first, so nothing is lost.
///
/// # Safety
/// Only valid from a synchronous lower-EL exception taken during an
/// in-flight excursion, i.e. with [`continuation_live`] true -- the same
/// stack reasoning as [`finish`].
pub unsafe fn abort_from_fault(vector: u64, esr: u64, far: u64, elr: u64) -> ! {
    let saved_sp = EL0_CONTINUATION.swap(0, Ordering::Relaxed);
    OBSERVED.lock().fault = Some((vector, esr, far, elr));
    // SAFETY: the caller's contract is that a continuation is live; if it
    // somehow is not, halting is the only safe option left (there is no EL1
    // context to return to and EL0 cannot be resumed meaningfully).
    if saved_sp == 0 {
        loop {
            unsafe { core::arch::asm!("wfe") };
        }
    }
    unsafe { resume_el1(saved_sp) }
}

fn read_spsr_el1() -> u64 {
    let value: u64;
    // SAFETY: a read of an EL1-accessible system register, no side effects.
    unsafe {
        core::arch::asm!("mrs {}, SPSR_EL1", out(reg) value, options(nomem, nostack));
    }
    value
}

fn read_elr_el1() -> u64 {
    let value: u64;
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("mrs {}, ELR_EL1", out(reg) value, options(nomem, nostack));
    }
    value
}

/// `AT S1E0R`: does the MMU allow an *unprivileged* read of `va` under the
/// currently loaded tables? The same mechanism `load_proof.rs` uses, and the
/// one check here that would catch a `TTBR0_EL1` the scheduler never
/// switched: [`DATA_VADDR`] is unmapped in the kernel's identity table.
fn el0_can_read(va: u64) -> bool {
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

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

struct ProofPhdr {
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

/// Hand-assembles a two-segment AArch64 `ET_EXEC` image whose `.text` is
/// [`payload_bytes`] -- the same technique `load_proof.rs` and `elf.rs`'s
/// host tests use, with a real payload instead of a lone `nop`.
fn build_proof_image() -> Vec<u8> {
    let text = payload_bytes();
    let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
    let phdrs = [
        ProofPhdr {
            flags: PF_R | PF_X,
            offset: payload_offset as u64,
            vaddr: TEXT_VADDR,
            filesz: text.len() as u64,
            memsz: text.len() as u64,
        },
        ProofPhdr {
            flags: PF_R | PF_W,
            offset: (payload_offset + text.len()) as u64,
            vaddr: DATA_VADDR,
            filesz: DATA_FILESZ,
            memsz: DATA_MEMSZ,
        },
    ];

    let mut image = vec![0u8; ELF_HEADER_SIZE];
    image[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    image[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    image[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
    image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes()); // e_phoff
    image[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    image[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes()); // e_phnum
    for phdr in &phdrs {
        let mut entry = vec![0u8; PHDR_SIZE];
        entry[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        entry[4..8].copy_from_slice(&phdr.flags.to_le_bytes());
        entry[8..16].copy_from_slice(&phdr.offset.to_le_bytes());
        entry[16..24].copy_from_slice(&phdr.vaddr.to_le_bytes());
        entry[32..40].copy_from_slice(&phdr.filesz.to_le_bytes());
        entry[40..48].copy_from_slice(&phdr.memsz.to_le_bytes());
        image.extend_from_slice(&entry);
    }
    image.extend_from_slice(text);
    image.push(MAGIC as u8);
    image
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

/// The EL0 process's EL1 side. Entered by `scheduler::switch_to` with this
/// thread's `process::AddressSpace` already installed in `TTBR0_EL1` (that
/// is the mechanism under test), on this thread's own 8 KiB kernel stack.
///
/// Observes the live translation state, `eret`s into the loaded image, is
/// resumed here by [`finish`], prints the verdict, then parks on
/// `yield_now` like every other thread in this slice (there is still no
/// thread exit -- see `scheduler.rs`).
extern "C" fn el0_proof_thread() -> ! {
    {
        let mut observed = OBSERVED.lock();
        observed.thread_root = process::active_root();
        observed.data_el0_readable = el0_can_read(DATA_VADDR);
    }

    let entry = IMAGE_ENTRY.load(Ordering::Relaxed);
    let stack_top = IMAGE_STACK_TOP.load(Ordering::Relaxed);
    serial_println!(
        "Runix ARM kernel: EL0 process thread at EL1, TTBR0_EL1={:#x} (own address space), \
         about to eret to {:#x} with SP_EL0={:#x}",
        OBSERVED.lock().thread_root,
        entry,
        stack_top
    );

    // SAFETY: `entry`/`stack_top` are `loader::load`'s own verified output
    // for the address space this thread owns and which is active right now
    // (checked above, from the live register); `EL0_CONTINUATION` is a
    // writable `static` that outlives this call. The payload reaches EL1
    // only through the `SVC` `finish` handles -- and any synchronous fault
    // instead of it is turned into a proof failure by `abort_from_fault`
    // rather than left to hang.
    unsafe { enter_el0(entry, stack_top, EL0_CONTINUATION.as_ptr()) };

    report();
    FINISHED.store(true, Ordering::Relaxed);
    loop {
        crate::scheduler::yield_now();
    }
}

/// Compares every observation against what a genuine EL0 excursion must
/// produce and prints one greppable `PASS`/`FAILED` line.
fn report() {
    let observed = OBSERVED.lock();
    let root = IMAGE_ROOT.load(Ordering::Relaxed);

    if let Some((vector, esr, far, elr)) = observed.fault {
        serial_println!(
            "Runix ARM kernel: EL0 process FAILED -- the EL0 payload faulted instead of \
             finishing (vector {}, ESR_EL1={:#x} EC={:#x}, FAR_EL1={:#x}, ELR_EL1={:#x})",
            vector,
            esr,
            (esr >> 26) & 0x3F,
            far,
            elr
        );
        return;
    }

    let text_end = TEXT_VADDR + GRANULE_4KIB;
    let from_el0 = observed.svc_spsr & SPSR_MODE_MASK == SPSR_MODE_EL0T;
    let elr_in_text = (TEXT_VADDR..text_end).contains(&observed.svc_elr);
    let root_followed = observed.thread_root == root && observed.svc_root == root;

    serial_println!(
        "Runix ARM kernel: EL0 process observed SPSR_EL1={:#x} (M={:#x}, EL0t={}), \
         ELR_EL1={:#x} (inside loaded text {:#x}..{:#x}: {}), TTBR0_EL1 thread={:#x} \
         svc={:#x} space={:#x}, AT S1E0R data={}",
        observed.svc_spsr,
        observed.svc_spsr & SPSR_MODE_MASK,
        from_el0,
        observed.svc_elr,
        TEXT_VADDR,
        text_end,
        elr_in_text,
        observed.thread_root,
        observed.svc_root,
        root,
        if observed.data_el0_readable {
            "ok"
        } else {
            "fault"
        }
    );
    serial_println!(
        "Runix ARM kernel: EL0 process payload magic={:#x} witness={:#x} stack={:#x} \
         (expected {:#x}/{:#x}/{:#x})",
        observed.magic,
        observed.witness,
        observed.stack_byte,
        MAGIC,
        WITNESS,
        STACK_WITNESS
    );

    let payload_ok = observed.magic == MAGIC
        && observed.witness == WITNESS
        && observed.stack_byte == STACK_WITNESS;
    let (switches, skips) = crate::scheduler::ttbr0_switch_counts();

    if payload_ok && from_el0 && elr_in_text && root_followed && observed.data_el0_readable {
        serial_println!(
            "Runix ARM kernel: EL0 process PASS -- a scheduled thread owning its own \
             address space eret'd into a loader.rs-loaded image at EL0, read and wrote \
             through its private mappings, and returned to EL1 \
             (TTBR0_EL1 writes={} elided={})",
            switches,
            skips
        );
    } else {
        serial_println!(
            "Runix ARM kernel: EL0 process FAILED -- payload_ok={} came_from_el0={} \
             elr_in_loaded_text={} ttbr0_followed_schedule={} data_el0_readable={}",
            payload_ok,
            from_el0,
            elr_in_text,
            root_followed,
            observed.data_el0_readable
        );
    }
}

/// Builds the address space, loads the hand-assembled image into it, spawns
/// a thread that owns it, and schedules that thread for real.
///
/// Called from `nonsecure.rs`'s shared EL1 bring-up right after
/// `scheduler::prove_scheduling` -- it needs the MMU, the heap, *and* an
/// initialized run queue, which is the first prerequisite any proof in this
/// crate has had beyond the first two.
pub fn prove_el0_process() {
    let image = build_proof_image();
    let elf = match Elf64::parse(&image) {
        Ok(elf) => elf,
        Err(err) => {
            serial_println!("Runix ARM kernel: EL0 process FAILED -- parse: {}", err);
            return;
        }
    };
    let mut space = match AddressSpace::new() {
        Ok(space) => space,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: EL0 process FAILED -- address space: {}",
                err
            );
            return;
        }
    };
    let loaded = match loader::load(&elf, &mut space) {
        Ok(loaded) => loaded,
        Err(err) => {
            serial_println!("Runix ARM kernel: EL0 process FAILED -- load: {}", err);
            return;
        }
    };

    // The payload's bytes reached their frames as *data* writes, through the
    // kernel's identity mapping, and are about to be *fetched* through a
    // different VA. `mmu.rs` configures Normal Inner/Outer Non-cacheable
    // memory, so there is no dirty data line to clean to the point of
    // unification -- but an instruction cache may still hold a stale line
    // for those physical addresses, and "those frames have never been
    // fetched from before" is an assumption about the heap allocator, not an
    // architectural guarantee. One `ic iallu` at boot costs nothing and
    // makes the proof's correctness independent of it.
    //
    // SAFETY: cache maintenance on the current PE with no memory operands;
    // `ic iallu` is EL1-permitted and invalidates to the point of
    // unification only.
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }

    IMAGE_ENTRY.store(loaded.entry, Ordering::Relaxed);
    IMAGE_STACK_TOP.store(loaded.stack_top, Ordering::Relaxed);
    IMAGE_ROOT.store(space.root(), Ordering::Relaxed);

    serial_println!(
        "Runix ARM kernel: EL0 process image entry={:#x} stack_top={:#x} text_bytes={} \
         segment_pages={} stack_pages={} (root={:#x}, kernel root={:#x})",
        loaded.entry,
        loaded.stack_top,
        payload_bytes().len(),
        loaded.segment_pages,
        loaded.stack_pages,
        space.root(),
        crate::scheduler::kernel_root()
    );

    if let Err(err) = crate::scheduler::spawn_with_address_space(el0_proof_thread, space) {
        serial_println!("Runix ARM kernel: EL0 process FAILED -- spawn: {}", err);
        return;
    }

    // Bounded for the same reason `prove_scheduling`'s loop is: a switch
    // that never comes back must surface as a FAIL line, not a hang. One
    // yield is enough in principle (the run queue is traversed fully per
    // boot-thread turn), so 64 is generous.
    let mut yields = 0;
    while !FINISHED.load(Ordering::Relaxed) && yields < 64 {
        crate::scheduler::yield_now();
        yields += 1;
    }
    if !FINISHED.load(Ordering::Relaxed) {
        serial_println!(
            "Runix ARM kernel: EL0 process FAILED -- the EL0 thread never reported back after \
             {} boot-thread yields",
            yields
        );
    }

    // The thread's `AddressSpace` is still owned by the (parked, never
    // reclaimed) thread, and the kernel's own table is back in `TTBR0_EL1`
    // -- put there by the scheduler on the switch that resumed this boot
    // thread, not by anything here. The rest of the boot sequence, including
    // `el0::drop_to_el0`, depends on that.
    //
    // The counts differ from the ones on the `PASS` line above on purpose:
    // that line is printed by the EL0 thread *before* it yields back, so it
    // sees only the write that installed its own space. This one is after
    // the switch that restored the kernel's, which is the half that proves
    // the "no address space -> back to the kernel table" direction happens
    // too, rather than a process's table being left loaded under the next
    // kernel thread.
    let (switches, skips) = crate::scheduler::ttbr0_switch_counts();
    serial_println!(
        "Runix ARM kernel: EL0 process boot thread resumed, TTBR0_EL1={:#x} (kernel table), \
         TTBR0_EL1 writes={} elided={}",
        process::active_root(),
        switches,
        skips
    );
}

/// `STACK_TOP` is the loader's, not this module's -- referenced so a change
/// to the private-window layout that moved the EL0 stack out from under
/// `loader::load`'s own output would break here loudly rather than produce a
/// subtly wrong `SP_EL0`.
const _: () = assert!(STACK_TOP == runix_kernel_arm::vm::PRIVATE_REGION_END);
