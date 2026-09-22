//! Round-robin scheduler with **real, timer-interrupt-driven preemption** —
//! not just cooperative `yield_now()`. A thread that never yields no longer
//! blocks everything else forever; the PIT timer (`interrupts.rs`) forces a
//! reschedule on every tick regardless of what's currently running.
//!
//! # One resume mechanism for both triggers
//!
//! Voluntary yield and involuntary preemption share the exact same
//! save/resume mechanism: both trap into ring 0 through a real interrupt
//! (hardware, for the timer; `int RESCHEDULE_VECTOR`, for a voluntary
//! yield), which is what makes a
//! *complete* register capture (all GPRs, RFLAGS, CS/SS, RSP/RIP — a
//! [`TrapFrame`], not just the callee-saved subset a plain function call
//! can get away with) both correct and free: the CPU (for the timer) or the
//! `int` instruction (for a yield) captures it, [`reschedule_entry`]'s
//! naked stub finishes the GPR half, and resuming *any* thread later is
//! always the same `iretq`. A thread suspended by preemption might be
//! resumed by a different thread's voluntary yield, or vice versa — with
//! one unified frame format, it never matters which caused which.
//!
//! This replaced an earlier design (`switch_to`, callee-saved registers
//! only, resumed via a plain `ret`) that was correct for cooperative-only
//! yielding — at a real function-call boundary, the SysV ABI already
//! guarantees caller-saved registers are dead — but fundamentally can't
//! extend to preemption: an interrupt can land at *any* instruction, with
//! arbitrary live registers a `ret`-based resume would silently corrupt.
//! See `docs/STATUS.md`'s "Real preemption" entry for why a two-format
//! (`Cooperative`/`Preempted`) design was considered and rejected: RFLAGS.IF
//! handling across a resume triggered by the *other* mechanism than the one
//! that suspended a thread turns out to be a real correctness hazard, not
//! just extra bookkeeping.
//!
//! A thread can optionally own a [`process::AddressSpace`]
//! (`spawn_with_address_space`) — when it does, [`reschedule`] switches
//! `Cr3` to that space right before resuming it, and back to the kernel's
//! own table (`memory::kernel_p4_frame`) when resuming a thread that
//! doesn't. This is genuinely safe to do mid-switch, still on the
//! *previous* thread's stack: every thread's own stack lives in the
//! shared, kernel-space portion of every address space (mapped through the
//! ordinary global allocator in `Thread::new`, never through
//! `AddressSpace::map_private_page`'s detach logic), so it stays correctly
//! mapped no matter which `Cr3` happens to be loaded at the moment.

use crate::memory;
use crate::process::AddressSpace;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::arch::naked_asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use runix_capability_manager::CapabilityToken;
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, Page, PageTableFlags, Size4KiB,
};
use x86_64::VirtAddr;

// Bumped from `4096 * 4` (16 KiB): confirmed by real reproduction, not
// guessed — `grid_sandbox::spawn_instance`'s shadow-mode MARSHAL evaluation
// (kernel/src/grid_sandbox.rs's `shadow_marshal_evaluate`, calling
// `marshal_client::evaluate` over the sockets IPC surface) double-faulted
// with RSP landing exactly at `STACK_REGION_START` when `spawn_instance` ran
// on a `scheduler::spawn_with_capability`-spawned thread instead of a boot
// thread's own much larger stack (see `kernel/tests/
// grid_sandbox_marshal_shadow.rs`'s "configured" case) -- a real stack
// overflow into the guard page below, not silent corruption (the guard page
// did exactly its job; see this const's own doc comment on why one exists).
// `spawn_instance`'s own stack usage (ELF parsing, `AddressSpace` setup,
// several page-mapping calls) was already non-trivial in a debug build
// before this; adding `shadow_marshal_evaluate`'s own call depth (JSON
// formatting, request encoding, a socket round-trip) tipped it over 16 KiB.
// Virtual address space for thread stacks is 48-bit and effectively
// unlimited (see `NEXT_STACK_SLOT`'s own doc comment) -- there is no
// capacity reason to keep this tight. First doubled to `4096 * 8` (32 KiB);
// confirmed by re-running the same test that this was still insufficient
// (the double fault moved further into spawn_instance's own post-shadow-
// eval body -- ELF parsing, AddressSpace setup, page mapping -- rather
// than disappearing), so doubled again here rather than nudged repeatedly.
const STACK_SIZE: usize = 4096 * 16;
/// Left deliberately unmapped below every thread's stack, so a stack
/// overflow page-faults (or, more precisely — see `Thread::new`'s
/// doc comment — double-faults) instead of silently corrupting whatever
/// heap memory used to sit there. This is exactly the class of bug that
/// bit `capability-manager`'s integration for real: RSP ended up pointing
/// *into the kernel heap* before the fault was even detected. See
/// `kernel/tests/guard_page.rs` for the regression test.
const GUARD_PAGE_SIZE: usize = 4096;
/// Recognizable, fixed base for thread-stack virtual memory — same
/// "pick a memorable pattern" convention as `allocator::HEAP_START`
/// (`0x4444...`) and `userspace::USER_STACK_START` (`0x5555...`).
const STACK_REGION_START: usize = 0x_6666_6666_0000;
const STACK_REGION_STRIDE: usize = GUARD_PAGE_SIZE + STACK_SIZE;

/// Hands out non-overlapping thread-stack VA regions, one per spawned
/// thread. Deliberately still never reclaimed even though the *physical*
/// frames backing a thread's stack now are (see `exit_current_thread` /
/// `reap_zombies`) — virtual address space here is 48-bit and effectively
/// unlimited for how many threads this kernel will ever spawn, so reusing
/// VA slots would add bookkeeping for no real benefit. Physical memory was
/// the actual leak that mattered.
static NEXT_STACK_SLOT: AtomicUsize = AtomicUsize::new(0);

/// A ring 3-capable thread's *own* kernel-entry stack — separate region
/// from `STACK_REGION_START` (that one is each thread's cooperative-switch
/// stack; this one is what RSP0 points at while it's running, so its own
/// ring 3 traps land somewhere private — see `spawn_ring3_process`). `3`
/// picked for the same "unused leading nibble with the top bit clear"
/// reason as every other hand-picked address here (`0x4444`/`0x5555`/
/// `0x6666`/`0x7777`) — an `8`-`f` leading nibble makes the address
/// non-canonical (bit 47 set while bits 63-48 stay clear), which
/// `kernel/tests/process_isolation.rs`'s first attempt hit for real.
const KERNEL_ENTRY_STACK_SIZE: usize = 4096 * 4;
const KERNEL_ENTRY_STACK_REGION_START: usize = 0x_3333_3333_0000;
const KERNEL_ENTRY_STACK_REGION_STRIDE: usize = GUARD_PAGE_SIZE + KERNEL_ENTRY_STACK_SIZE;
static NEXT_KERNEL_ENTRY_STACK_SLOT: AtomicUsize = AtomicUsize::new(0);

/// Maps a fresh, guard-paged stack of `size` bytes at
/// `region_start + slot * (GUARD_PAGE_SIZE + size)` and returns
/// `(guard_page_base, stack_top)`. Shared by `Thread::new` (a thread's own
/// cooperative-switch stack) and `spawn_ring3_process` (a ring 3-capable
/// thread's separate, dedicated kernel-entry stack) — the same "overflow
/// should fault loudly, not corrupt whatever's mapped next to it"
/// reasoning applies to both.
fn map_guarded_stack(
    region_start: usize,
    stride: usize,
    slot: usize,
    size: usize,
) -> (VirtAddr, VirtAddr) {
    let region_base = region_start + slot * stride;
    let guard_page_base = VirtAddr::new(region_base as u64);
    let stack_start = guard_page_base + GUARD_PAGE_SIZE as u64;
    let stack_end = stack_start + size as u64 - 1u64;

    memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        let start_page = Page::<Size4KiB>::containing_address(stack_start);
        let end_page = Page::<Size4KiB>::containing_address(stack_end);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = frame_allocator
                .allocate_frame()
                .expect("out of physical memory for a new guarded stack");
            unsafe {
                mapper
                    .map_to(page, frame, flags, frame_allocator)
                    .expect("failed to map a guarded stack page")
                    .flush();
            }
        }
    });

    (guard_page_base, stack_start + size as u64)
}

/// A complete saved execution context — every general-purpose register plus
/// the hardware-defined `iretq` frame (`rip`/`cs`/`rflags`/`rsp`/`ss`) —
/// unlike the old `switch_to`'s callee-saved-only `Context`, this is
/// correct to capture from *any* instruction boundary, not just a
/// controlled function-call site. Field order matches
/// [`reschedule_entry`]/`interrupts::timer_entry`'s exact push sequence
/// (GPRs, low to high address) followed immediately by whatever pushed the
/// last five fields — the CPU itself, for a hardware interrupt, or
/// [`Thread::new`] synthesizing an identical layout for a thread that's
/// never actually run yet.
#[repr(C)]
pub(crate) struct TrapFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

struct Thread {
    /// Base of this thread's guard page (not the stack itself — the guard
    /// page sits immediately below it). Used by `reap_zombies` to recompute
    /// exactly which pages this thread's stack occupied, so they can be
    /// unmapped and their physical frames handed back to the allocator.
    guard_page_base: VirtAddr,
    /// Points at this thread's saved [`TrapFrame`] when it isn't the one
    /// running — cast, not stored typed, since it's read/written as a raw
    /// address on both sides of a context switch (`reschedule_entry`'s
    /// naked stub, `interrupts::timer_entry`'s). For the `main`-thread
    /// placeholder this is never read until the first time it's ever
    /// suspended (main always resumes on whatever real stack it was
    /// already running on, not this field, before that).
    stack_pointer: usize,
    /// What this thread is authorized to do, per `syscall::dispatch`'s
    /// capability checks (e.g. `SYS_IPC_SEND`) — `None` for threads that
    /// were never granted one, which any check treats as "denied," not
    /// "unrestricted."
    capability: Option<CapabilityToken>,
    /// Additional capabilities beyond `capability` — needed the moment a
    /// single thread must be authorized for more than one distinct
    /// resource at once (e.g. `blk-driver-host` serving filesystem IPC
    /// requests: one token for its own virtio-blk io-port range, a second
    /// for the reply port it sends responses on). Kept as a separate,
    /// empty-by-default `Vec` rather than turning `capability` itself into
    /// a `Vec` everywhere — every existing single-capability call site
    /// (`net-driver-host`, `grid-sandbox-host`, every kernel test) keeps
    /// compiling and behaving identically; only a thread that actually
    /// needs a second capability ever populates this.
    extra_capabilities: Vec<CapabilityToken>,
    /// `Some` for a thread that owns its own private address space (a
    /// "process," in the sense `process.rs` means it) — [`reschedule`]
    /// switches `Cr3` to it right before resuming this thread. `None`
    /// (every thread before this field existed, and most since) runs in
    /// the kernel's own shared table, exactly as before.
    address_space: Option<AddressSpace>,
    /// `Some` for a thread spawned via `spawn_ring3_process` — its own
    /// dedicated RSP0 target, which [`reschedule`] loads into the TSS (via
    /// `gdt::set_kernel_stack`) right before resuming this thread, so its
    /// ring 3 traps (in particular `SYS_YIELD`) land on a stack no other
    /// thread is using. `None` for everything else — a plain kernel
    /// thread never traps from ring 3, so it never touches RSP0 at all.
    kernel_entry_stack_top: Option<VirtAddr>,
}

impl Thread {
    /// Maps a fresh stack at its own dedicated virtual address range —
    /// not a `Box<[u8]>` carved out of the general kernel heap, on purpose:
    /// heap allocations don't get their own page-table entries, so there's
    /// nowhere to put a guard page below one. A dedicated, individually
    /// mapped region (same idea as `userspace::map_user_stack`) means the
    /// page immediately below the stack can be left deliberately unmapped.
    ///
    /// That still doesn't mean a stack overflow here cleanly page-faults:
    /// the CPU pushes the fault's own interrupt frame onto the *current*
    /// stack pointer, which at overflow time is already at (or past) the
    /// guard page boundary — pushing that frame faults too, which is a
    /// double fault, not a single page fault. That's exactly why
    /// `gdt::init()` gave the double-fault handler its own IST stack back
    /// in Phase 2: it has to run somewhere that isn't the stack that just
    /// overflowed. See `kernel/tests/guard_page.rs` for the actual proof.
    fn new(entry: extern "C" fn() -> !) -> Self {
        let slot = NEXT_STACK_SLOT.fetch_add(1, Ordering::Relaxed);
        let (guard_page_base, stack_top) =
            map_guarded_stack(STACK_REGION_START, STACK_REGION_STRIDE, slot, STACK_SIZE);

        let raw_top = stack_top.as_u64() as usize;

        // SysV ABI: RSP must be ≡ 0 (mod 16) immediately *before* a `call`,
        // which makes it ≡ 8 (mod 16) at the callee's entry (the `call`
        // itself pushed an 8-byte return address). `entry` is an ordinary
        // Rust function, compiled assuming it was reached that way (in
        // particular, any stack-spilled SSE register inside it assumes this
        // alignment) — resuming it for the first time via `iretq` instead of
        // an actual `call` doesn't change that requirement, so `rsp`'s value
        // *inside* the synthesized `TrapFrame` below still needs to land on
        // the same ≡ 8 (mod 16) offset a real `call` would have produced.
        let entry_rsp = (raw_top & !0xf) - 8;

        // Where this synthesized frame itself lives is unrelated to
        // `entry_rsp` above (that's the RSP `entry` will see *after* being
        // resumed, restored by `iretq` from this frame's own `rsp` field) —
        // it just needs to be some mapped, 8-byte-aligned location on this
        // same stack for `reschedule_entry`'s pops to read from.
        let frame_ptr = (entry_rsp - size_of::<TrapFrame>()) as *mut TrapFrame;

        // The values a *real* interrupt would have captured for this
        // thread, had it actually been running: current CS/SS (this is a
        // kernel thread — ring 0 — same segments regardless of which thread
        // asks), and RFLAGS with IF=1 (bit 9) so resuming this thread for
        // the first time leaves interrupts enabled, same as every other
        // context here runs with; bit 1 is always reserved-set.
        let cs: u64;
        let ss: u64;
        unsafe {
            core::arch::asm!("mov {}, cs", out(reg) cs);
            core::arch::asm!("mov {}, ss", out(reg) ss);
        }
        const RFLAGS_IF: u64 = 1 << 9;
        const RFLAGS_RESERVED_BIT1: u64 = 1 << 1;

        unsafe {
            frame_ptr.write(TrapFrame {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                r11: 0,
                r10: 0,
                r9: 0,
                r8: 0,
                rbp: 0,
                rdi: 0,
                rsi: 0,
                rdx: 0,
                rcx: 0,
                rbx: 0,
                rax: 0,
                rip: entry as usize as u64,
                cs,
                rflags: RFLAGS_IF | RFLAGS_RESERVED_BIT1,
                rsp: entry_rsp as u64,
                ss,
            });
        }

        Thread {
            guard_page_base,
            stack_pointer: frame_ptr as usize,
            capability: None,
            extra_capabilities: Vec::new(),
            address_space: None,
            kernel_entry_stack_top: None,
        }
    }

    /// Placeholder standing in for a real execution context that already
    /// has a stack we don't own and shouldn't touch (the kernel's boot
    /// stack). Never populated with a real `stack_pointer` up front — that
    /// only happens the first time this context yields away.
    fn placeholder() -> Self {
        Thread {
            guard_page_base: VirtAddr::new(0),
            stack_pointer: 0,
            capability: None,
            extra_capabilities: Vec::new(),
            address_space: None,
            kernel_entry_stack_top: None,
        }
    }
}

struct Scheduler {
    run_queue: VecDeque<Thread>,
    current: Option<Thread>,
    /// Threads that called [`exit_current_thread`] but whose stack hasn't
    /// been unmapped yet — deferred because a thread can't safely unmap the
    /// very stack it's still running on. Reaped from [`reschedule`], which
    /// by construction always runs on some *other* thread's stack.
    zombies: VecDeque<Thread>,
}

impl Scheduler {
    fn new() -> Self {
        Scheduler {
            run_queue: VecDeque::new(),
            current: Some(Thread::placeholder()),
            zombies: VecDeque::new(),
        }
    }
}

/// Unmaps every stack page a zombie thread was using and hands its frames
/// back to the frame allocator. Never called on the thread whose own stack
/// is being reaped — see `zombies`' doc comment.
fn reap_zombies(sched: &mut Scheduler) {
    while let Some(zombie) = sched.zombies.pop_front() {
        let stack_start = zombie.guard_page_base + GUARD_PAGE_SIZE as u64;
        let stack_end = stack_start + STACK_SIZE as u64 - 1u64;
        memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
            let start_page = Page::<Size4KiB>::containing_address(stack_start);
            let end_page = Page::<Size4KiB>::containing_address(stack_end);
            for page in Page::range_inclusive(start_page, end_page) {
                let (frame, flush) = mapper
                    .unmap(page)
                    .expect("zombie thread's stack page was already unmapped");
                flush.flush();
                unsafe {
                    frame_allocator.deallocate_frame(frame);
                }
            }
        });
    }
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

pub fn init() {
    *SCHEDULER.lock() = Some(Scheduler::new());
    reserve_p4_slot(STACK_REGION_START);
    reserve_p4_slot(KERNEL_ENTRY_STACK_REGION_START);
    // See `interrupts.rs`'s watchdog doc comment: armed as soon as
    // cooperative scheduling starts, disarmed explicitly before any code
    // path (e.g. `userspace::enter_usermode`) that leaves it for good.
    crate::interrupts::arm_watchdog();
    // Last, deliberately: interrupts are already enabled by the time
    // `main.rs` calls this (`boot::init()`, earlier), so a timer tick can
    // land *during* this very function — including while the `SCHEDULER`
    // lock above is still held on this same stack. `on_timer_tick` checks
    // `is_initialized()` before ever calling `reschedule` (which itself
    // locks `SCHEDULER`); setting this flag only once everything above has
    // genuinely finished means that check can never observe "initialized"
    // while a lock this function took is still outstanding, which would
    // otherwise deadlock the timer against itself.
    INITIALIZED.store(true, Ordering::Relaxed);
}

/// Maps one throwaway page just below `region_start`, purely to force that
/// region's top-level (P4) page-table entry into existence — permanently
/// "wastes" one page and its P3/P2/P1 chain, and that's the point.
///
/// Without this, calling `process::AddressSpace::new()` before any real
/// thread (or ring 3-capable thread, for `KERNEL_ENTRY_STACK_REGION_START`)
/// has ever been spawned would copy a *not-present* P4 entry for that
/// entire 512 GiB region (copying an empty slot has nothing to share —
/// there's no P3 table yet to point at). Every stack mapped afterward —
/// even a thread's *own*, mapped moments later inside the very
/// `spawn_with_address_space`/`spawn_ring3_process` call that attaches
/// that space to it — would then be invisible the instant that address
/// space's `Cr3` loaded: a double fault trying to run on its own,
/// suddenly-unmapped stack. Calling `init()` (which every caller already
/// must, before spawning anything) before building any `AddressSpace`
/// makes that ordering hazard impossible instead of merely documented.
/// See `kernel/tests/scheduler_address_space.rs` for the regression this
/// fixes — it hit exactly this double fault before `init()` reserved the
/// (then-only) stack region's slot up front.
fn reserve_p4_slot(region_start: usize) {
    let probe = Page::<Size4KiB>::containing_address(VirtAddr::new(
        (region_start - GUARD_PAGE_SIZE) as u64,
    ));
    memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        let frame = frame_allocator
            .allocate_frame()
            .expect("out of physical memory reserving a stack region's P4 slot");
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper
                .map_to(probe, frame, flags, frame_allocator)
                .expect("failed to reserve a stack region's P4 slot")
                .flush();
        }
    });
}

pub fn spawn(entry: extern "C" fn() -> !) {
    spawn_with_capability(entry, None);
}

/// Same as [`spawn`], but the new thread carries `capability` — checked by
/// `syscall::dispatch` against whatever a given syscall requires (today:
/// `SYS_IPC_SEND`, against a `port:<n>` resource string). `None` here is
/// exactly equivalent to `spawn`: no capability, every gated syscall denies
/// it.
pub fn spawn_with_capability(entry: extern "C" fn() -> !, capability: Option<CapabilityToken>) {
    let mut thread = Thread::new(entry);
    thread.capability = capability;
    push_thread(thread);
}

/// Same as [`spawn`], but the new thread owns `address_space` — every time
/// the scheduler resumes this thread, it switches `Cr3` to `address_space`
/// first (see this module's doc comment for why that's safe to do without
/// the thread's own stack going invalid mid-switch). `entry` still runs in
/// ring 0 today — this makes the *address space* real, not the ring 3
/// execution; that still needs a per-thread kernel-entry stack and a real
/// `SYS_YIELD`, both still future work (see `userspace.rs`).
pub fn spawn_with_address_space(entry: extern "C" fn() -> !, address_space: AddressSpace) {
    let mut thread = Thread::new(entry);
    thread.address_space = Some(address_space);
    push_thread(thread);
}

/// Same as [`spawn_with_address_space`], but the new thread also gets its
/// own dedicated kernel-entry stack — required for `entry` to actually
/// call `userspace::enter_usermode` and have its ring 3 traps (in
/// particular a real `SYS_YIELD`) land somewhere safe. Without a stack of
/// its own, every ring 3-capable thread would share one RSP0 — harmless
/// with only one such thread (as `userspace::user_hello`'s hand-run
/// transition gets away with today), but a second one trapping in while
/// the first is still suspended mid-syscall would corrupt it. [`reschedule`]
/// rewrites `Cr3` *and* RSP0 (via `gdt::set_kernel_stack`) together, right
/// before resuming a thread spawned this way — see
/// `kernel/tests/ring3_cooperative.rs` for two such threads proving they
/// don't corrupt each other.
pub fn spawn_ring3_process(entry: extern "C" fn() -> !, address_space: AddressSpace) {
    spawn_ring3_process_with_capability(entry, address_space, None);
}

/// Same as [`spawn_ring3_process`], but the new thread also carries
/// `capability` — checked by `syscall::dispatch` the same way
/// `spawn_with_capability`'s does for `SYS_IPC_SEND`, now also consulted by
/// `SYS_PORT_IN`/`SYS_PORT_OUT` for a ring 3 device-driver process (e.g. the
/// network stack's virtio-net driver) that needs capability-gated port I/O
/// without ever getting raw, ambient `in`/`out` privilege itself.
pub fn spawn_ring3_process_with_capability(
    entry: extern "C" fn() -> !,
    address_space: AddressSpace,
    capability: Option<CapabilityToken>,
) {
    let mut thread = Thread::new(entry);
    thread.address_space = Some(address_space);
    thread.kernel_entry_stack_top = Some(alloc_kernel_entry_stack());
    thread.capability = capability;
    push_thread(thread);
}

/// Same as [`spawn_ring3_process_with_capability`], but for a thread that
/// needs to be authorized for more than one distinct resource at once —
/// today, exactly `blk-driver-host` serving filesystem IPC requests: one
/// capability for its own virtio-blk io-port range (checked by
/// `SYS_PORT_IN`/`SYS_PORT_OUT`), a second for the reply port it sends
/// responses on (checked by `SYS_IPC_SEND`). `capability` keeps meaning
/// exactly what it already does everywhere else; `extra_capabilities` is
/// consulted by `syscall::dispatch`'s `SYS_IPC_SEND` check as an
/// additional set of tokens to search, never required to be non-empty.
pub fn spawn_ring3_process_with_capabilities(
    entry: extern "C" fn() -> !,
    address_space: AddressSpace,
    capability: Option<CapabilityToken>,
    extra_capabilities: Vec<CapabilityToken>,
) {
    let mut thread = Thread::new(entry);
    thread.address_space = Some(address_space);
    thread.kernel_entry_stack_top = Some(alloc_kernel_entry_stack());
    thread.capability = capability;
    thread.extra_capabilities = extra_capabilities;
    push_thread(thread);
}

/// Same as [`spawn_ring3_process`], but the new thread runs in the kernel's
/// own shared address space instead of a private [`AddressSpace`] — for
/// ring 3 code that lives on a page carved out of the kernel's existing
/// mappings (`userspace::allow_user_access`) rather than a fully isolated
/// process. Still gets its own dedicated kernel-entry stack: that part of
/// the hazard `spawn_ring3_process`'s doc comment describes (RSP0 shared
/// across ring 3-capable threads) has nothing to do with address-space
/// isolation — it's about *any* ring 3 trap needing a stack no other
/// suspended ring 3 thread is using, real preemption included. Before this
/// existed, `userspace::user_hello` was entered via a raw
/// `userspace::enter_usermode` call from the boot thread, invisible to the
/// scheduler entirely — the real timer preemption this module now does
/// would land its trap frame on whatever RSP0 last pointed at (a *different*
/// ring 3-capable thread's own dedicated stack, if one had ever run), which
/// is exactly the corruption this function's stack allocation prevents.
pub fn spawn_ring3_shared(entry: extern "C" fn() -> !) {
    let mut thread = Thread::new(entry);
    thread.kernel_entry_stack_top = Some(alloc_kernel_entry_stack());
    push_thread(thread);
}

/// Maps and returns the top of a fresh, dedicated kernel-entry stack —
/// shared allocation logic between [`spawn_ring3_process`] and
/// [`spawn_ring3_shared`].
fn alloc_kernel_entry_stack() -> VirtAddr {
    let slot = NEXT_KERNEL_ENTRY_STACK_SLOT.fetch_add(1, Ordering::Relaxed);
    let (_, stack_top) = map_guarded_stack(
        KERNEL_ENTRY_STACK_REGION_START,
        KERNEL_ENTRY_STACK_REGION_STRIDE,
        slot,
        KERNEL_ENTRY_STACK_SIZE,
    );
    stack_top
}

/// Pushes a freshly built [`Thread`] onto the run queue — shared tail end
/// of every `spawn*` function.
///
/// Runs with interrupts disabled for the same reason
/// `memory::with_mapper_and_frame_allocator` now does (see its doc
/// comment): every `spawn*` call runs in normal thread context (interrupts
/// enabled), so without this, a timer tick landing between `SCHEDULER.lock()`
/// and its release here would try to run [`reschedule`] — which locks the
/// *same* `SCHEDULER` mutex — from inside a handler that can never be
/// preempted away from it. A `spin::Mutex` doesn't know or care who's
/// holding it; from its own thread's perspective, this CPU just tries to
/// lock a lock it already holds, and spins forever. `current_capability`
/// (also called from normal thread context) needs the same protection.
fn push_thread(thread: Thread) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER
            .lock()
            .as_mut()
            .expect("scheduler::init() not called")
            .run_queue
            .push_back(thread);
    });
}

/// The capability (if any) granted to whichever thread is currently
/// running — what `syscall::dispatch` checks a gated syscall against. A
/// clone, not a reference: the caller is on a different stack than the
/// scheduler's internal state and has no business holding a live borrow
/// into it across a potential future `yield_now()`.
pub fn current_capability() -> Option<CapabilityToken> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER
            .lock()
            .as_ref()
            .and_then(|sched| sched.current.as_ref())
            .and_then(|thread| thread.capability.clone())
    })
}

/// The current thread's *additional* capabilities beyond
/// [`current_capability`] — see [`spawn_ring3_process_with_capabilities`]'s
/// doc comment for why a thread would ever hold more than one. Empty for
/// every thread spawned through any other `spawn*` function.
pub fn current_extra_capabilities() -> Vec<CapabilityToken> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER
            .lock()
            .as_ref()
            .and_then(|sched| sched.current.as_ref())
            .map(|thread| thread.extra_capabilities.clone())
            .unwrap_or_default()
    })
}

/// Adds `token` to whichever thread is currently running's own
/// `extra_capabilities` — for a thread that never went through a `spawn*`
/// call carrying the token it needs, most commonly a test harness's own
/// boot thread. Before `SYS_IPC_RECV` gained its capability gate
/// (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`), several kernel-test boot
/// threads called it directly, unauthorized, and got away with it only
/// because the syscall itself never checked. Post-gate, that same direct
/// call needs a real token — spawning a whole second thread purely to hold
/// one would be needless ceremony when the boot thread can simply grant
/// itself the capability it's about to use, the same way a
/// `spawn_ring3_process_with_capabilities` caller decides up front what a
/// *different* thread will be authorized for. Not exposed as a syscall —
/// ring 3 code granting itself capabilities on demand would defeat the
/// entire point of this being a *capability* system; this is kernel-internal
/// test/bootstrap plumbing only.
pub fn grant_current_extra_capability(token: CapabilityToken) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(sched) = SCHEDULER.lock().as_mut() {
            if let Some(thread) = sched.current.as_mut() {
                thread.extra_capabilities.push(token);
            }
        }
    });
}

/// The IDT vector a voluntary [`yield_now`]/[`exit_current_thread`] traps
/// through — `int RESCHEDULE_VECTOR` is deliberately the *same kind* of
/// event as a timer tick (a real interrupt, not a function call), so
/// [`reschedule`] never has to know or care which one triggered it. Kernel
/// code only (`interrupts.rs` registers this at the default Ring0 gate
/// privilege level) — every caller, including a ring 3 thread's
/// `SYS_YIELD`, already reaches this from ring 0, inside `syscall::dispatch`.
pub const RESCHEDULE_VECTOR: u8 = 0x81;

/// Set by [`exit_current_thread`] right before trapping in, so [`reschedule`]
/// zombies the outgoing thread instead of requeueing it. A single global
/// flag, not a parameter — software interrupts carry none — safe without
/// further synchronization because [`reschedule`] always runs with
/// `RFLAGS.IF=0` (an interrupt gate, not a trap gate): nothing else can
/// observe or modify this between the `store` and the `int` that follows
/// it, and [`reschedule`] atomically swaps it back to `false` on every
/// call, so it can never leak into an unrelated later reschedule.
static EXITING: AtomicBool = AtomicBool::new(false);

/// Hand the CPU to the next thread in the run queue, and return only once
/// *this* thread is scheduled again. Implemented as a real trap
/// (`int RESCHEDULE_VECTOR`), not a function call — see this module's doc
/// comment for why that's what makes the *exact same* resume mechanism
/// also correct for involuntary, timer-driven preemption.
pub fn yield_now() {
    unsafe {
        core::arch::asm!("int {vector}", vector = const RESCHEDULE_VECTOR);
    }
}

/// Ends the calling thread: hands the CPU to the next runnable thread and
/// never returns. The exiting thread's stack can't be unmapped here — it's
/// still running on it — so it's queued as a zombie instead and reclaimed
/// the next time some *other* thread reschedules (see `reap_zombies`).
/// Before this existed, the only way for a thread to stop running was to
/// loop forever, which meant every spawned thread's stack frames were
/// permanently unreclaimable — the "unbounded memory leak" this fixes.
///
/// Must not be called from the boot/placeholder thread (the one
/// `scheduler::init()` starts as `current` before anything is spawned) — it
/// has no dedicated stack region of its own for `reap_zombies` to reclaim.
pub fn exit_current_thread() -> ! {
    EXITING.store(true, Ordering::Relaxed);
    unsafe {
        core::arch::asm!("int {vector}", vector = const RESCHEDULE_VECTOR, options(noreturn));
    }
}

/// Whether [`init`] has run yet. The timer starts ticking well before that
/// — `boot::init()` enables interrupts long before `main.rs` ever calls
/// `scheduler::init()` — so `interrupts::on_timer_tick` checks this before
/// calling [`reschedule`] at all, and just resumes the interrupted context
/// unchanged otherwise. [`reschedule`] itself still `expect()`s a live
/// scheduler and panics loudly if that's missing: reaching `reschedule` at
/// all means something called `yield_now()`/`exit_current_thread()`
/// *before* `init()`, a real caller bug distinct from "the timer just
/// happened to tick during normal boot," which this flag exists to let
/// the timer path tell apart without conflating the two.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// The actual work of every context switch, cooperative or preemptive:
/// reap zombies, pick the next runnable thread, requeue (or zombie, if
/// [`EXITING`]) the outgoing one, swap `Cr3`/RSP0, and return the
/// [`TrapFrame`] to resume from. Called only from [`reschedule_entry`]'s
/// naked stub (a voluntary yield) or `interrupts::timer_entry`'s (an
/// involuntary tick, only once [`is_initialized`] confirms there's a
/// scheduler to reschedule against — see its own doc comment) — both
/// guarantee `current_frame` is a complete, valid `TrapFrame`, and both run
/// with `RFLAGS.IF=0` throughout, so this can never be reentered (no
/// `try_lock`/deadlock-avoidance needed on `SCHEDULER` — an interrupt
/// literally cannot land while this function is already running).
pub(crate) extern "C" fn reschedule(current_frame: *mut TrapFrame) -> *mut TrapFrame {
    // A reschedule happening at all — whether requested or forced — is
    // exactly the "the system is still making progress" signal the
    // watchdog cares about; see `interrupts.rs`'s updated doc comment on
    // why this makes the watchdog a backstop against `reschedule` itself
    // breaking, not against a misbehaving thread (real preemption already
    // handles that case without any panic).
    crate::interrupts::record_yield();

    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler::init() not called");
    reap_zombies(sched);

    let Some(next) = sched.run_queue.pop_front() else {
        // Nothing else is runnable — resume the same thread, unchanged.
        return current_frame;
    };
    let next_ptr = next.stack_pointer as *mut TrapFrame;

    // Switch `Cr3` *before* `next` becomes `current` — see the module doc
    // comment for why doing this now, still on the *previous* thread's
    // stack, is safe. Skipped when the target is already what's loaded
    // (the common case: switching between two plain kernel threads) — an
    // unconditional write here would flush the TLB on every single
    // reschedule for no reason.
    let target_frame = next
        .address_space
        .as_ref()
        .map_or_else(memory::kernel_p4_frame, AddressSpace::p4_frame);
    let (current_p4, flags) = Cr3::read();
    if current_p4 != target_frame {
        unsafe {
            Cr3::write(target_frame, flags);
        }
    }
    // RSP0 alongside Cr3, for the same reason and at the same moment — a
    // plain write, not worth conditionalizing like the Cr3/TLB-flush case
    // above. Left untouched (whatever the previous thread set) when `next`
    // has no kernel-entry stack of its own: it'll never trap from ring 3,
    // so RSP0 is never consulted for it anyway.
    if let Some(stack_top) = next.kernel_entry_stack_top {
        crate::gdt::set_kernel_stack(stack_top);
    }

    let mut outgoing = sched.current.take().expect("no current thread set");
    outgoing.stack_pointer = current_frame as usize;
    if EXITING.swap(false, Ordering::Relaxed) {
        sched.zombies.push_back(outgoing);
    } else {
        sched.run_queue.push_back(outgoing);
    }
    sched.current = Some(next);

    next_ptr
    // `guard` drops here, before `reschedule_entry`/`timer_entry` resume
    // whatever `next_ptr` points at — the thread being resumed may itself
    // reschedule again (a nested `SCHEDULER.lock()`), which would deadlock
    // against a lock this call is still holding otherwise.
}

/// Entry point installed at [`RESCHEDULE_VECTOR`] (from `interrupts.rs`).
/// Naked, not `extern "x86-interrupt"`: the interrupt-calling-convention
/// ABI only exposes the hardware-pushed `InterruptStackFrame` fields, not
/// the general-purpose registers a *complete* [`TrapFrame`] needs — pushed
/// here by hand, in the exact order `TrapFrame`'s fields expect, then
/// popped in exact reverse from whichever frame [`reschedule`] returns
/// (the same thread, unchanged, or a different one it just switched to).
///
/// # Safety
/// Never call this directly — reached only via `int RESCHEDULE_VECTOR`
/// (see [`yield_now`]/[`exit_current_thread`]), which guarantees a matching
/// CPU-pushed `iretq` frame already sits on the stack for the final
/// `iretq` to consume.
#[unsafe(naked)]
pub unsafe extern "C" fn reschedule_entry() {
    naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        // `rdi` (the `TrapFrame` pointer, and `reschedule`'s only argument)
        // must capture the *true* current RSP, before the alignment fix
        // below -- reap_zombies/Cr3 writes/etc. all trust `current_frame`
        // to be exactly where this GPR block starts. `rsp` itself, once
        // clobbered, is never restored to its pre-aligned value: the very
        // next instruction after the call unconditionally replaces it with
        // whichever frame `reschedule` returns, so nothing downstream
        // depends on it.
        //
        // Real SysV callers guarantee RSP ≡ 0 (mod 16) at a `call` site,
        // but this isn't a `call` site -- it's an interrupt entry, which
        // can land with RSP at *any* alignment (a ring 3 `SYS_YIELD`
        // trapping through `syscall::entry` into this exact vector, e.g.,
        // leaves RSP wherever `dispatch`'s own call chain happened to put
        // it, not guaranteed 16-aligned). `reschedule` is an ordinary Rust
        // function that can't safely assume otherwise (SSE spills and
        // similar codegen do), so align down explicitly before calling
        // it — confirmed as a real, not theoretical, bug: the first
        // version of this without the `and` general-protection-faulted
        // the first time a ring 3 thread's `SYS_YIELD` actually took this
        // exact nested path (`int 0x80` -> `dispatch` -> `yield_now` ->
        // `int RESCHEDULE_VECTOR`, landing here with whatever RSP that
        // call chain happened to leave, not 16-aligned).
        "and rsp, -16",
        "call {reschedule}",
        "mov rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        reschedule = sym reschedule,
    );
}
