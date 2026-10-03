//! Cooperative round-robin scheduler for EL1 kernel threads (slice 5 of
//! `docs/BETA_MOBILE_PROGRESS.md` item 2.4) -- the ARM analogue of
//! `kernel/src/scheduler.rs`'s *first*, cooperative-only version, before
//! that file grew timer preemption, guard pages, and stack reclamation.
//!
//! # Scope boundary (deliberate, not unfinished)
//!
//! Mirroring the x86_64 side's own staged history rather than jumping to
//! its current shape:
//!
//! - **Cooperative only.** Threads switch by calling [`yield_now`]; there
//!   is no timer involvement at all. A thread that never yields blocks
//!   everything else forever. Preemption off the generic timer
//!   (`CNTP_*_EL0` + a GIC PPI) is future work -- and on x86_64 it did not
//!   just add a timer, it replaced this whole callee-saved/`ret` mechanism
//!   with a full trap frame, because an interrupt can land at *any*
//!   instruction with arbitrary live caller-saved registers. That
//!   rewrite-shaped change is exactly why it is not smuggled in here.
//! - **Threads may now own an address space, but get no kernel-entry stack
//!   of their own.** A [`Thread`] can carry a `process::AddressSpace`
//!   ([`spawn_with_address_space`]), and [`yield_now`] installs the incoming
//!   thread's `TTBR0_EL1` -- or the kernel's own identity-mapped table for a
//!   thread without one -- right before resuming it. What is *not* here is
//!   the x86_64 side's second scheduling slice: a separate EL1-entry stack
//!   per EL0 thread, and a general `SYS_YIELD`. `el0_proof.rs` explains why
//!   its one EL0 thread does not need either (`SP_EL1` survives the `eret`
//!   unchanged, so the thread's own kernel stack *is* its exception landing
//!   site) and exactly what that costs: at most one EL0 thread may be
//!   mid-`eret` at a time, which is a property of that proof, not a
//!   general-purpose process model.
//! - **Heap-allocated stacks, no guard pages.** A thread's stack is a
//!   plain 16-byte-aligned heap block (see [`Thread::new`]), the same
//!   "simplest first version" the x86_64 scheduler started from. Guard
//!   pages need per-stack page-table entries, which in turn wants a real
//!   kernel VA layout -- deferred for the same staged reason.
//! - **No exit/reclamation.** A finished thread loops forever calling
//!   [`yield_now`]; nothing frees a thread's stack or removes it from the
//!   run queue. Stacks are leaked on purpose (and only ever allocated at
//!   boot today).
//! - **No syscalls.** Nothing here touches `svc.rs`. The proof
//!   ([`prove_scheduling`]) is entirely EL1-side.
//!
//! # Register save set (AAPCS64, worked out from the procedure call standard)
//!
//! [`switch_to`] is a *function call boundary*, so AAPCS64 already
//! guarantees every caller-saved register (`x0`-`x18`, `v0`-`v7`,
//! `v16`-`v31`) is dead across it -- the caller spilled anything it still
//! needed before the call. What a context switch must therefore save is
//! exactly the callee-saved set, since the switch hands those registers'
//! physical copies to a *different* thread:
//!
//! - `x19`-`x28` -- general-purpose callee-saved.
//! - `x29` -- the frame pointer.
//! - `x30` -- the link register. It doubles as this naked function's
//!   return address: restoring the target's saved `x30` and executing
//!   `ret` is precisely what makes the switch resume the target where
//!   *it* called `switch_to`.
//! - `sp` -- not in the saved block itself; it *is* the handle to the
//!   saved block (`Thread::stack_pointer`).
//! - `d8`-`d15` -- the low 64 bits of `v8`-`v15`, the FP/SIMD callee-saved
//!   set. **Included, not skipped.** This crate enables FP/SIMD at EL1
//!   (`nonsecure.rs`'s `set_cpacr_fpen`, `CPACR_EL1.FPEN = 0b11`) exactly
//!   because ordinary Rust codegen here *does* emit FP/SIMD instructions
//!   -- that module's doc comment records a bare `serial_println!` call
//!   trapping with `ESR_EL1.EC=0x7` for real. Once the compiler may use
//!   NEON at all, it may also keep a value live in a callee-saved
//!   `v8`-`v15` across a call, and this crate is built in both `dev` and
//!   `release` profiles with no `-C target-feature=-neon`. Omitting them
//!   would be a silent, codegen-dependent corruption of whichever thread
//!   happened to hold one -- 64 bytes and four `stp`/`ldp` pairs is not
//!   worth that bet. Only the low 64 bits of `v8`-`v15` are
//!   architecturally callee-saved (the upper halves are caller-saved), so
//!   `d8`-`d15` is the complete FP half, not an approximation.
//!
//! Nothing else belongs here for a cooperative switch: `SPSR`/`ELR` are
//! exception-return state (no exception is taken by the switch itself), and
//! `DAIF` is identical for every thread (see below). `TTBR0_EL1` is
//! deliberately *not* in [`Context`] either, even though it is now
//! per-thread: a saved-register block is restored by the *incoming* thread's
//! own `ldp`s running on its own stack, and the whole point of switching
//! `TTBR0_EL1` is to do it while the *outgoing* thread's mappings are still
//! the ones in force. It is written by [`yield_now`] just before
//! [`switch_to`] instead (see that function), which is also where x86_64's
//! `Cr3` write lives for the identical reason.
//!
//! # Interrupt state across a switch
//!
//! Checked rather than assumed: EL1 is entered with `SPSR_EL3.DAIF =
//! 0b1111` (`nonsecure.rs`'s `SPSR_EL1H_MASKED`), i.e. Debug/SError/IRQ/
//! FIQ all masked, and nothing at EL1 ever clears them -- the only
//! `msr daifclr` in this crate is in `main.rs`'s EL3 GIC test, before the
//! drop to EL1, and `gic::init` routes physical IRQ/FIQ to *EL3* via
//! `SCR_EL3.IRQ`/`FIQ`. `el0.rs` likewise `eret`s to EL0 with `DAIF =
//! 0b1111`. So no asynchronous exception can land mid-switch today, and
//! this module adds no masking of its own (a redundant `daifset` would
//! imply a protection it isn't providing). [`prove_scheduling`] prints the
//! live `DAIF` it actually observes, so this claim is checked at boot
//! rather than only asserted here. The moment timer preemption lands, that
//! changes: the switch mechanism itself gets replaced (see the scope note
//! above), and whatever replaces it must mask explicitly.

use crate::process::{self, AddressSpace};
use crate::serial_println;
use alloc::alloc::{alloc_zeroed, Layout};
use alloc::collections::VecDeque;
use core::arch::naked_asm;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

/// 8 KiB per thread. Small on purpose: these come out of `heap.rs`'s
/// 256 KiB heap, which also backs `process.rs`'s translation tables, and
/// nothing in this slice recurses deeply (the deepest call is a
/// `serial_println!`). Not guard-paged -- see this module's doc comment.
const STACK_SIZE: usize = 4096 * 2;

/// AArch64's stack is full-descending and `sp` must be 16-byte aligned at
/// every point it is used as a load/store base, so a thread stack is
/// allocated 16-aligned and its size kept a multiple of 16; both halves of
/// [`Thread::new`]'s derivation depend on it.
const STACK_ALIGN: usize = 16;

/// A saved cooperative execution context: exactly the AAPCS64 callee-saved
/// registers (see this module's doc comment for why this set and no
/// other), in the exact order [`switch_to`]'s `stp`/`ldp` pairs write and
/// read them at fixed offsets from `sp`.
///
/// `#[repr(C)]` and the field order are load-bearing: the assembly
/// addresses this block by numeric offset, so reordering a field here
/// without editing the matching `stp`/`ldp` offset silently swaps two
/// registers across every context switch.
#[repr(C)]
struct Context {
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    /// Frame pointer.
    x29: u64,
    /// Link register -- what `switch_to`'s final `ret` branches to.
    x30: u64,
    d8: u64,
    d9: u64,
    d10: u64,
    d11: u64,
    d12: u64,
    d13: u64,
    d14: u64,
    d15: u64,
}

/// Size of the [`Context`] block [`switch_to`] reserves on the outgoing
/// thread's stack, duplicated as a literal in the assembly (`sub sp, sp,
/// #160` / `add sp, sp, #160`) because a naked function's offsets must be
/// assembly-time constants. The assertion below is what keeps the two
/// definitions from drifting: 20 registers x 8 bytes = 160, itself a
/// multiple of 16, so subtracting it from a 16-aligned `sp` leaves `sp`
/// 16-aligned.
/// `pub(crate)` so `el0_proof.rs`, whose `enter_el0`/`resume_el1` save and
/// restore the *same* block in the same layout, can assert its own
/// duplicated literal against this one instead of two files quietly
/// disagreeing about 160.
pub(crate) const CONTEXT_SIZE: usize = 160;
const _: () = assert!(size_of::<Context>() == CONTEXT_SIZE);
const _: () = assert!(CONTEXT_SIZE % STACK_ALIGN == 0);

/// Why [`spawn`] can fail. Returned rather than panicked on: this crate is
/// `panic = "abort"`, and "the heap is full" is a condition a caller can
/// report and continue past (every caller today is a boot-time proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// [`init`] hasn't run, so there is no run queue to push onto.
    NotInitialized,
    /// `heap.rs`'s heap had no room for another thread stack.
    OutOfMemory,
    /// The `AddressSpace` handed to [`spawn_with_address_space`] was not
    /// seeded from the kernel's own level-1 table -- i.e. it was built while
    /// some *other* address space was active, so its copied level-1 entries
    /// may include that space's private sub-tables. See
    /// `process::AddressSpace::seeded_root`'s documentation for why that is
    /// an isolation break and not merely untidy.
    AddressSpaceNotSeededFromKernel { seeded_root: u64, kernel_root: u64 },
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::NotInitialized => f.write_str("scheduler::init() has not run"),
            SpawnError::OutOfMemory => f.write_str("out of heap for a new thread stack"),
            SpawnError::AddressSpaceNotSeededFromKernel {
                seeded_root,
                kernel_root,
            } => write!(
                f,
                "address space was seeded from {:#x}, not the kernel table {:#x}",
                seeded_root, kernel_root
            ),
        }
    }
}

struct Thread {
    /// Base of this thread's heap-allocated stack. Kept only so the
    /// allocation is attributable in a debugger -- deliberately never
    /// freed (no reclamation in this slice, see the module doc comment).
    /// A `usize`, not a `*mut u8`: a raw pointer here would make `Thread`
    /// (and so the `static` `SCHEDULER` holding it) `!Send`/`!Sync` for no
    /// real reason, since nothing ever dereferences this field.
    #[allow(dead_code)]
    stack_base: usize,
    /// This thread's `sp` while it is *not* running: points at its saved
    /// [`Context`] block, which lives at the top of its own stack. Stored
    /// as a plain `usize` because both sides of a switch treat it as a raw
    /// address (`switch_to` writes it through `x0`, reads it from `x1`).
    stack_pointer: usize,
    /// This thread's own translation tables, if it has any.
    ///
    /// `None` -- the case for every thread this module spawned before this
    /// slice, and for the boot context -- means "run under the kernel's own
    /// identity-mapped table," which [`yield_now`] installs explicitly
    /// rather than leaving whatever the previous thread happened to have
    /// loaded. Leaving it alone would mean a plain EL1 kernel thread
    /// inherited a *process's* `TTBR0_EL1`, which happens to work here only
    /// because `AddressSpace::new` copies the kernel's mappings -- i.e. it
    /// would work by accident, and would stop working the moment an address
    /// space stops being a superset of the kernel's.
    ///
    /// Owned, not borrowed or reduced to a bare root address: the tables
    /// must outlive every resume of this thread, and nothing in this crate
    /// frees an `AddressSpace` (`process.rs` has no `Drop` -- see its note,
    /// which wanted exactly this scheduler to exist before freeing could be
    /// made safe). Threads are never removed from the run queue in this
    /// slice, so "owned by the `Thread`" and "leaked" coincide today; when
    /// reclamation lands, this is the field that makes it expressible.
    address_space: Option<AddressSpace>,
}

impl Thread {
    /// Allocates a stack and hand-builds the initial [`Context`] so that
    /// the *first* switch into this thread behaves exactly like returning
    /// into a function that was never called.
    ///
    /// # Initial stack layout, derived (do not change this arithmetic
    /// without re-deriving it)
    ///
    /// Facts the layout follows from, not by analogy to x86_64:
    ///
    /// 1. AArch64's stack is **full descending**: `sp` holds the address
    ///    of the most recently used word, and a push is `sub` then store.
    ///    So the *empty* stack pointer is one past the end of the buffer,
    ///    `base + STACK_SIZE`, not `base + STACK_SIZE - 8`.
    /// 2. `sp` must be **16-byte aligned** wherever it is used as a
    ///    load/store base (and AAPCS64 requires it at every public
    ///    interface, i.e. at `entry`'s first instruction). `base` is
    ///    16-aligned by [`Layout`] and `STACK_SIZE` is a multiple of 16,
    ///    so `top = base + STACK_SIZE` is 16-aligned.
    /// 3. **The return address lives in `x30`, not on the stack.** This is
    ///    the key difference from x86_64, where `call` pushes 8 bytes and
    ///    the synthetic entry `rsp` therefore has to be `≡ 8 (mod 16)` to
    ///    imitate it (see `kernel/src/scheduler.rs`'s `entry_rsp`). Here a
    ///    real `bl` into `entry` would leave `sp` *exactly* 16-aligned and
    ///    untouched, so there is no 8-byte skew to reproduce: the `sp`
    ///    `entry` must see is `top` itself.
    /// 4. [`switch_to`] restores from `[sp .. sp + CONTEXT_SIZE)`, then
    ///    does `add sp, sp, #CONTEXT_SIZE`, then `ret` (branch to `x30`).
    ///
    /// Running (4) backwards from the state we want at `entry`'s first
    /// instruction (`sp == top`, `pc == entry`): the saved context must sit
    /// at `top - CONTEXT_SIZE` with `x30 = entry`. So
    /// `stack_pointer = top - CONTEXT_SIZE`, which is 16-aligned because
    /// both `top` and `CONTEXT_SIZE` are.
    ///
    /// Nothing is written at or above `top`: `entry` has type
    /// `extern "C" fn() -> !` and never returns, so there is no return
    /// address for it to consume -- and `x30` is seeded with 0 rather than
    /// a plausible address, so a thread that *did* somehow return would
    /// fault immediately at EL1 (`el1_vectors.rs` reports it) instead of
    /// branching into whatever address happened to be in the register.
    /// `x29` is seeded with 0 for the same reason it is at the root of any
    /// frame chain: it terminates a frame-pointer walk rather than
    /// continuing it into garbage.
    fn new(entry: extern "C" fn() -> !) -> Result<Self, SpawnError> {
        let layout = match Layout::from_size_align(STACK_SIZE, STACK_ALIGN) {
            Ok(layout) => layout,
            Err(_) => return Err(SpawnError::OutOfMemory),
        };
        // SAFETY: `layout` has a non-zero size, the one requirement
        // `alloc_zeroed` places on its caller. A null return (allocation
        // failure) is checked below rather than dereferenced.
        let stack_base = unsafe { alloc_zeroed(layout) };
        if stack_base.is_null() {
            return Err(SpawnError::OutOfMemory);
        }

        let top = stack_base as usize + STACK_SIZE;
        debug_assert_eq!(top % STACK_ALIGN, 0);
        let context_ptr = (top - CONTEXT_SIZE) as *mut Context;
        debug_assert_eq!(context_ptr as usize % STACK_ALIGN, 0);

        // SAFETY: `context_ptr` is `CONTEXT_SIZE` bytes below the top of a
        // freshly allocated `STACK_SIZE` block (and `STACK_SIZE >
        // CONTEXT_SIZE`), so the whole write lands inside that block, and
        // it is suitably aligned for `Context` (8-byte alignment; `top` is
        // 16-aligned and `CONTEXT_SIZE` is a multiple of 16).
        unsafe {
            context_ptr.write(Context {
                x19: 0,
                x20: 0,
                x21: 0,
                x22: 0,
                x23: 0,
                x24: 0,
                x25: 0,
                x26: 0,
                x27: 0,
                x28: 0,
                x29: 0,
                x30: entry as usize as u64,
                d8: 0,
                d9: 0,
                d10: 0,
                d11: 0,
                d12: 0,
                d13: 0,
                d14: 0,
                d15: 0,
            });
        }

        Ok(Thread {
            stack_base: stack_base as usize,
            stack_pointer: context_ptr as usize,
            address_space: None,
        })
    }

    /// Stands in for the boot context, which already has a stack this
    /// module neither allocated nor may touch (`EL1_STACK`, see
    /// `nonsecure.rs`). Its `stack_pointer` is meaningless until the first
    /// time it yields away, which is the only moment [`yield_now`] ever
    /// writes it.
    fn placeholder() -> Self {
        Thread {
            stack_base: 0,
            stack_pointer: 0,
            address_space: None,
        }
    }
}

struct Scheduler {
    run_queue: VecDeque<Thread>,
    current: Option<Thread>,
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// The kernel's own identity-mapped level-1 table (`mmu.rs`'s
/// `LEVEL1_TABLE`), captured once by [`init`] from the live `TTBR0_EL1`
/// rather than hardcoded or re-exported from `mmu.rs`.
///
/// Captured, because it is what [`yield_now`] must install when resuming a
/// thread with no address space of its own, and read from the live register
/// because that makes it the table that *actually* booted this kernel, not
/// the one a second source of truth claims did. 0 means [`init`] has not
/// run, which is also the state in which `yield_now` is a no-op anyway.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

/// How many times [`yield_now`] has actually written `TTBR0_EL1` (and so
/// paid for a `tlbi vmalle1`), versus [`TTBR0_SKIPS`], the resumes where
/// the incoming thread's table was already loaded and the write was elided.
///
/// Counted so the skip is a *demonstrated* property rather than an asserted
/// one: `el0_proof::prove_el0_process` prints both, and nine of
/// [`prove_scheduling`]'s ten switches are kernel-thread-to-kernel-thread,
/// which must show up as skips.
static TTBR0_SWITCHES: AtomicUsize = AtomicUsize::new(0);
static TTBR0_SKIPS: AtomicUsize = AtomicUsize::new(0);

/// Creates the run queue, with the calling (boot) context installed as the
/// current thread so the very first [`yield_now`] has somewhere to save
/// it, and records the kernel's own `TTBR0_EL1` (see [`KERNEL_ROOT`]).
/// Must run after `heap::init` -- `VecDeque` and the thread stacks are
/// both heap-allocated -- and after `mmu::install`, so there is a real
/// kernel table to record.
pub fn init() {
    KERNEL_ROOT.store(process::active_root(), Ordering::Relaxed);
    *SCHEDULER.lock() = Some(Scheduler {
        run_queue: VecDeque::new(),
        current: Some(Thread::placeholder()),
    });
}

/// The kernel's own level-1 table address as [`init`] recorded it, or 0 if
/// `init` has not run.
pub fn kernel_root() -> u64 {
    KERNEL_ROOT.load(Ordering::Relaxed)
}

/// `(TTBR0_EL1 writes performed, writes elided as already-loaded)` since
/// boot -- see [`TTBR0_SWITCHES`].
pub fn ttbr0_switch_counts() -> (usize, usize) {
    (
        TTBR0_SWITCHES.load(Ordering::Relaxed),
        TTBR0_SKIPS.load(Ordering::Relaxed),
    )
}

/// Queues a new EL1 kernel thread. `entry` never returns -- there is no
/// thread-exit path in this slice (see the module doc comment), so a
/// finished thread must loop, typically on [`yield_now`].
pub fn spawn(entry: extern "C" fn() -> !) -> Result<(), SpawnError> {
    let thread = Thread::new(entry)?;
    enqueue(thread)
}

/// Queues a kernel thread that owns `space`, so that every resume of it
/// installs `space`'s `TTBR0_EL1` (see [`Thread::address_space`]).
///
/// `entry` still starts at **EL1**, on this thread's own kernel stack: this
/// function gives a thread an address space, not an exception level. Getting
/// to EL0 is `entry`'s own job (`el0_proof.rs` does it with a real `eret`),
/// which keeps the one genuinely delicate step -- the EL1 -> EL0 transition
/// and the way back -- out of the scheduler, where it would have to be
/// general.
///
/// Refuses a space that was not seeded from the kernel's own table. That is
/// the one check this boundary can make cheaply that catches a real
/// isolation break rather than a typo: see
/// `process::AddressSpace::seeded_root`.
pub fn spawn_with_address_space(
    entry: extern "C" fn() -> !,
    space: AddressSpace,
) -> Result<(), SpawnError> {
    let kernel_root = KERNEL_ROOT.load(Ordering::Relaxed);
    if kernel_root == 0 {
        return Err(SpawnError::NotInitialized);
    }
    if space.seeded_root() != kernel_root {
        return Err(SpawnError::AddressSpaceNotSeededFromKernel {
            seeded_root: space.seeded_root(),
            kernel_root,
        });
    }
    let mut thread = Thread::new(entry)?;
    thread.address_space = Some(space);
    enqueue(thread)
}

fn enqueue(thread: Thread) -> Result<(), SpawnError> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().ok_or(SpawnError::NotInitialized)?;
    sched.run_queue.push_back(thread);
    Ok(())
}

/// Saves the calling thread's context, hands the CPU to the next thread in
/// the run queue, and returns only once *this* thread is scheduled again.
///
/// A no-op if [`init`] hasn't run or the run queue is empty: "nobody else
/// is runnable" is a normal state for a cooperative scheduler (the boot
/// context yields before anything is spawned, in principle), not a caller
/// bug worth aborting the kernel over.
pub fn yield_now() {
    let (current_sp_ptr, next_sp, next_root) = {
        let mut guard = SCHEDULER.lock();
        let Some(sched) = guard.as_mut() else {
            return;
        };
        let Some(next) = sched.run_queue.pop_front() else {
            return;
        };
        let next_sp = next.stack_pointer;
        // Read out before `next` is moved into `sched.current` below, for
        // the same reason `current_sp_ptr` is taken *after* its own move:
        // the value has to be captured on the side of the move where the
        // `Thread` is still reachable.
        let next_root = next
            .address_space
            .as_ref()
            .map(|space| space.root())
            .unwrap_or(KERNEL_ROOT.load(Ordering::Relaxed));

        let Some(current) = sched.current.take() else {
            // Can't happen: `current` is only ever `None` inside this
            // block. Put `next` back rather than dropping it on the floor.
            sched.run_queue.push_front(next);
            return;
        };
        sched.run_queue.push_back(current);
        sched.current = Some(next);

        // Taken *after* the push, for the reason
        // `kernel/src/scheduler.rs`'s first version documents: a pointer
        // into the `Thread` before it is moved into the `VecDeque` dangles
        // the instant the move happens.
        let Some(back) = sched.run_queue.back_mut() else {
            return;
        };
        let current_sp_ptr: *mut usize = &mut back.stack_pointer;

        (current_sp_ptr, next_sp, next_root)
        // `guard` drops here -- before `switch_to`, because the thread
        // being switched to will itself lock `SCHEDULER` in its own
        // `yield_now`, which would spin forever against a lock this
        // (now suspended) stack frame still held.
    };

    // Install the incoming thread's `TTBR0_EL1` -- its own address space's
    // table, or the kernel's own identity map for a thread that has none.
    //
    // **Why here and not inside `switch_to`, and why before rather than
    // after:** this is the last point at which the *outgoing* thread's
    // mappings are still what the CPU is translating with. After
    // `switch_to`, every instruction belongs to the incoming thread, so
    // "switch the table on the way in" would have to be assembly in the
    // middle of a register restore; before it, this is ordinary Rust whose
    // own code, stack and vectors are mapped identically in both tables (the
    // invariant `process::AddressSpace::new`'s kernel-entry copy exists to
    // guarantee, and the reason a `TTBR0_EL1` write from EL1 is survivable
    // at all). `kernel/src/scheduler.rs` puts its `Cr3` write in exactly the
    // same place for exactly this reason.
    //
    // **The skip.** Compared against the *live register*, not a cached
    // "what we last wrote", so the elision can never disagree with the
    // hardware. It matters: an unconditional write costs a `tlbi vmalle1`
    // plus two `isb`s, this crate uses no ASIDs (see `process.rs`), and the
    // overwhelmingly common case here is kernel-thread-to-kernel-thread,
    // where both sides want the same table. `next_root == 0` means `init`
    // never ran, in which case `SCHEDULER` was `None` and we returned above
    // -- it is re-checked rather than assumed because writing 0 into
    // `TTBR0_EL1` would unmap the kernel from under this instruction.
    if next_root != 0 && process::active_root() != next_root {
        // SAFETY: `next_root` is either `KERNEL_ROOT` (the table this
        // kernel booted and is still running on) or the root of an
        // `AddressSpace` that `spawn_with_address_space` verified was
        // seeded from that same kernel table -- so EL1's code, stack, and
        // `el1_vectors.rs` vectors are mapped identically either way, which
        // is `AddressSpace::activate`'s stated contract.
        unsafe { process::load_root(next_root) };
        TTBR0_SWITCHES.fetch_add(1, Ordering::Relaxed);
    } else {
        TTBR0_SKIPS.fetch_add(1, Ordering::Relaxed);
    }

    // SAFETY: `current_sp_ptr` points into the `Thread` that was just
    // pushed onto the run queue, which lives as long as the scheduler
    // (nothing removes threads in this slice), and `next_sp` is either a
    // `Thread::new`-built context or one saved by this same function.
    unsafe {
        switch_to(current_sp_ptr, next_sp);
    }
}

/// The context switch itself: save the *caller's* callee-saved registers
/// onto its own stack, record where they went, swap `sp` to the target
/// thread's saved block, restore the *target's* registers, and `ret` into
/// whatever `x30` it saved (its own [`yield_now`] call site, or -- for a
/// never-yet-run thread -- its entry point, see [`Thread::new`]).
///
/// Naked, because the whole function *is* its register discipline: any
/// compiler-generated prologue/epilogue would save and restore registers
/// around a body that deliberately changes which stack `sp` points at, and
/// restore them from the wrong thread's frame.
///
/// The `#160` offsets and the `stp`/`ldp` order must stay in lockstep with
/// [`Context`]'s field order and [`CONTEXT_SIZE`].
///
/// # Safety
/// `current_sp_ptr` must point at a writable `usize` that outlives this
/// call, and `next_sp` must be a stack pointer previously produced by
/// [`Thread::new`] or previously saved by this same function -- anything
/// else loads garbage into real registers and `ret`s to a garbage address.
#[unsafe(naked)]
unsafe extern "C" fn switch_to(current_sp_ptr: *mut usize, next_sp: usize) {
    naked_asm!(
        // Reserve the Context block on the caller's own stack. `sp` is
        // 16-aligned here (AAPCS64 guarantees it at a call boundary) and
        // 160 is a multiple of 16, so it stays 16-aligned throughout.
        "sub sp, sp, #160",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        // x29 = frame pointer, x30 = link register (this call's return
        // address -- the field the target's `ret` below consumes).
        "stp x29, x30, [sp, #80]",
        // FP/SIMD callee-saved halves: see the module doc comment on why
        // these are saved rather than assumed unused.
        "stp d8, d9, [sp, #96]",
        "stp d10, d11, [sp, #112]",
        "stp d12, d13, [sp, #128]",
        "stp d14, d15, [sp, #144]",
        // *current_sp_ptr = sp. x2 is caller-saved, free to use.
        "mov x2, sp",
        "str x2, [x0]",
        // The switch. Everything after this line reads the *target*
        // thread's stack.
        "mov sp, x1",
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
        // Returns into the target thread, not into this function's caller.
        "ret",
    );
}

// ---------------------------------------------------------------------------
// Boot-time proof
// ---------------------------------------------------------------------------

/// Rounds each proof thread runs. Three is the smallest count that can
/// distinguish real round-robin interleaving from "each thread ran to
/// completion in spawn order" *and* from a one-off swap.
const PROOF_ROUNDS: u8 = 3;
const PROOF_THREADS: usize = 3;

/// `A0,B0,C0,A1,B1,C1,A2,B2,C2` -- the interleaving a round-robin queue
/// must produce for three threads yielding between rounds. The actual
/// assertion of this slice: a scheduler that spawned three threads but ran
/// each to completion would log `A0,A1,A2,B0,...` and fail, even though
/// nothing crashed.
const EXPECTED_ORDER: &str = "A0,B0,C0,A1,B1,C1,A2,B2,C2";

/// Threads that have finished all [`PROOF_ROUNDS`] rounds. The boot thread
/// yields until this reaches [`PROOF_THREADS`].
static FINISHED: AtomicUsize = AtomicUsize::new(0);

/// Records the *global* order in which tagged rounds actually ran, across
/// all three threads -- a fixed buffer rather than a `String` so recording
/// never allocates on a thread stack mid-proof.
struct TagLog {
    buf: [u8; 64],
    len: usize,
}

impl TagLog {
    const fn new() -> Self {
        TagLog {
            buf: [0; 64],
            len: 0,
        }
    }

    /// Appends `,` (except first) then the two-byte `<tag><round>` pair.
    /// Silently stops at capacity: an overrun would mean more rounds ran
    /// than the proof expects, which the comparison against
    /// [`EXPECTED_ORDER`] then reports as a failure anyway.
    fn push(&mut self, tag: u8, round: u8) {
        let needed = if self.len == 0 { 2 } else { 3 };
        if self.len + needed > self.buf.len() {
            return;
        }
        if self.len > 0 {
            self.buf[self.len] = b',';
            self.len += 1;
        }
        self.buf[self.len] = tag;
        self.buf[self.len + 1] = b'0' + round;
        self.len += 2;
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<not utf-8>")
    }
}

static ORDER: Mutex<TagLog> = Mutex::new(TagLog::new());

/// Shared body of all three proof threads: print a tagged message, record
/// it in the global order log, yield, repeat -- then park forever on
/// `yield_now` (there is no thread exit in this slice).
///
/// The lock is taken and dropped around the record, never held across the
/// `yield_now` -- holding a `spin::Mutex` across a context switch would
/// deadlock the next thread that records.
fn proof_body(tag: u8) -> ! {
    for round in 0..PROOF_ROUNDS {
        ORDER.lock().push(tag, round);
        serial_println!(
            "Runix ARM kernel: scheduler thread {}{} running",
            tag as char,
            round
        );
        yield_now();
    }
    FINISHED.fetch_add(1, Ordering::Relaxed);
    loop {
        yield_now();
    }
}

extern "C" fn proof_thread_a() -> ! {
    proof_body(b'A')
}

extern "C" fn proof_thread_b() -> ! {
    proof_body(b'B')
}

extern "C" fn proof_thread_c() -> ! {
    proof_body(b'C')
}

/// Reads `DAIF` as the hardware actually has it right now -- see this
/// module's doc comment on interrupt state. `0x3c0` is all four bits
/// (D/A/I/F at bits 9/8/7/6) masked.
fn daif() -> u64 {
    let daif: u64;
    // SAFETY: a read of an EL1-accessible system register, no side effects.
    unsafe {
        core::arch::asm!("mrs {}, DAIF", out(reg) daif, options(nomem, nostack));
    }
    daif
}

/// The boot-time proof that context switching genuinely works (slice 5 of
/// `docs/BETA_MOBILE_PROGRESS.md` item 2.4), called from `nonsecure.rs`'s
/// shared EL1 bring-up exactly like `process::prove_isolation` and
/// `load_proof::prove_load` -- serial-grep from the boot sequence, since
/// this crate still has no QEMU-native `cargo test` harness (item 1.7).
///
/// Three threads each print and record three tagged rounds, yielding
/// between them; the boot thread yields until all three report finished
/// and then compares the *observed global order* against
/// [`EXPECTED_ORDER`]. Checking the order, not just "nothing crashed," is
/// what makes this a proof of context switching: registers and stacks
/// swapping correctly nine times in a specific pattern cannot happen by
/// accident, whereas "three threads were spawned and the kernel kept
/// booting" could.
///
/// Returns normally, with the three proof threads still parked in the run
/// queue (no exit path in this slice) -- the rest of the boot sequence
/// never yields again, so they simply never run once this returns.
pub fn prove_scheduling() {
    init();
    serial_println!(
        "Runix ARM kernel: scheduler init (cooperative, DAIF={:#x} -- IRQ/FIQ masked at EL1)",
        daif()
    );

    for (tag, entry) in [
        ('A', proof_thread_a as extern "C" fn() -> !),
        ('B', proof_thread_b as extern "C" fn() -> !),
        ('C', proof_thread_c as extern "C" fn() -> !),
    ] {
        if let Err(err) = spawn(entry) {
            serial_println!(
                "Runix ARM kernel: scheduler FAILED -- spawn {}: {}",
                tag,
                err
            );
            return;
        }
    }
    serial_println!("Runix ARM kernel: scheduler spawned 3 EL1 threads (8 KiB heap stacks)");

    // Bounded, so a broken switch that never returns control here can't
    // turn into a silent hang: 3 threads x 3 rounds x a boot-thread turn
    // between each is well under 64 yields, and exceeding it is itself
    // reported as a failure below.
    let mut yields = 0;
    while FINISHED.load(Ordering::Relaxed) < PROOF_THREADS && yields < 64 {
        yield_now();
        yields += 1;
    }

    let order = ORDER.lock();
    serial_println!(
        "Runix ARM kernel: scheduler interleaving {} (boot thread yielded {} times)",
        order.as_str(),
        yields
    );
    if order.as_str() == EXPECTED_ORDER {
        serial_println!("Runix ARM kernel: scheduler PASS");
    } else {
        serial_println!(
            "Runix ARM kernel: scheduler FAILED -- expected {}, finished {}/{}",
            EXPECTED_ORDER,
            FINISHED.load(Ordering::Relaxed),
            PROOF_THREADS
        );
    }
}
