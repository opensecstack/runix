//! Cooperative round-robin scheduler. Threads voluntarily call
//! [`yield_now`] — there's no timer-interrupt-driven preemption yet (that
//! needs a PIC/APIC timer, a later stage), so a thread that never yields
//! blocks everything else forever.

use crate::memory;
use alloc::collections::VecDeque;
use core::arch::naked_asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};
use runix_capability_manager::CapabilityToken;
use spin::Mutex;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, Page, PageTableFlags, Size4KiB,
};
use x86_64::VirtAddr;

const STACK_SIZE: usize = 4096 * 4;
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

/// Callee-saved registers, in the exact order `switch_to` pushes/pops them.
/// `rip` isn't pushed by us explicitly — it's what `ret` consumes, so a
/// freshly spawned thread's context has its entry point sitting there,
/// making the first switch into it behave like `ret`-ing into a function
/// that was never actually `call`ed.
#[repr(C)]
struct Context {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    rip: u64,
}

struct Thread {
    /// Base of this thread's guard page (not the stack itself — the guard
    /// page sits immediately below it). Used by `reap_zombies` to recompute
    /// exactly which pages this thread's stack occupied, so they can be
    /// unmapped and their physical frames handed back to the allocator.
    guard_page_base: VirtAddr,
    /// Saved RSP when this thread isn't the one running. For the
    /// `main`-thread placeholder this is never read (main always yields
    /// from — and resumes on — its real boot stack, not this field).
    stack_pointer: usize,
    /// What this thread is authorized to do, per `syscall::dispatch`'s
    /// capability checks (e.g. `SYS_IPC_SEND`) — `None` for threads that
    /// were never granted one, which any check treats as "denied," not
    /// "unrestricted."
    capability: Option<CapabilityToken>,
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
        let region_start = STACK_REGION_START + slot * STACK_REGION_STRIDE;
        let guard_page_base = VirtAddr::new(region_start as u64);
        let stack_start = guard_page_base + GUARD_PAGE_SIZE as u64;
        let stack_end = stack_start + STACK_SIZE as u64 - 1u64;

        memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
            let start_page = Page::<Size4KiB>::containing_address(stack_start);
            let end_page = Page::<Size4KiB>::containing_address(stack_end);
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
            for page in Page::range_inclusive(start_page, end_page) {
                let frame = frame_allocator
                    .allocate_frame()
                    .expect("out of physical memory for a new thread stack");
                unsafe {
                    mapper
                        .map_to(page, frame, flags, frame_allocator)
                        .expect("failed to map a thread stack page")
                        .flush();
                }
            }
        });

        let raw_top = stack_start.as_u64() as usize + STACK_SIZE;

        // SysV ABI: RSP must be ≡ 0 (mod 16) immediately *before* a `call`,
        // which makes it ≡ 8 (mod 16) at the callee's entry (the `call`
        // itself pushed an 8-byte return address). Our `ret` trick below
        // fakes that same entry state, so `entry_rsp` — where RSP lands
        // right after the synthetic "return" — must land on the same ≡ 8
        // (mod 16) offset. Get this wrong and nothing fails loudly here; it
        // silently misaligns any stack-spilled SSE register in `entry`,
        // faulting only once such a spill actually happens.
        let entry_rsp = (raw_top & !0xf) - 8;
        let context_ptr = (entry_rsp - size_of::<Context>()) as *mut Context;
        debug_assert_eq!(context_ptr as usize % 16, 0);

        unsafe {
            context_ptr.write(Context {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                rbx: 0,
                rbp: 0,
                rip: entry as usize as u64,
            });
        }

        Thread {
            guard_page_base,
            stack_pointer: context_ptr as usize,
            capability: None,
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
        }
    }
}

struct Scheduler {
    run_queue: VecDeque<Thread>,
    current: Option<Thread>,
    /// Threads that called [`exit_current_thread`] but whose stack hasn't
    /// been unmapped yet — deferred because a thread can't safely unmap the
    /// very stack it's still running on. Reaped from `yield_now`, which by
    /// construction always runs on some *other* thread's stack.
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
    // See `interrupts.rs`'s watchdog doc comment: armed as soon as
    // cooperative scheduling starts, disarmed explicitly before any code
    // path (e.g. `userspace::enter_usermode`) that leaves it for good.
    crate::interrupts::arm_watchdog();
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
    SCHEDULER
        .lock()
        .as_mut()
        .expect("scheduler::init() not called")
        .run_queue
        .push_back(thread);
}

/// The capability (if any) granted to whichever thread is currently
/// running — what `syscall::dispatch` checks a gated syscall against. A
/// clone, not a reference: the caller is on a different stack than the
/// scheduler's internal state and has no business holding a live borrow
/// into it across a potential future `yield_now()`.
pub fn current_capability() -> Option<CapabilityToken> {
    SCHEDULER
        .lock()
        .as_ref()
        .and_then(|sched| sched.current.as_ref())
        .and_then(|thread| thread.capability.clone())
}

/// Save the calling thread's context, hand the CPU to the next thread in
/// the run queue, and return only once *this* thread is scheduled again.
pub fn yield_now() {
    // Before anything else — a thread that's about to block on the
    // `SCHEDULER` lock or spend time in `reap_zombies` is still
    // cooperating, and the watchdog only cares that *some* thread called
    // this recently, not how long the rest of the function takes.
    crate::interrupts::record_yield();

    let (current_sp_ptr, next_sp) = {
        let mut guard = SCHEDULER.lock();
        let sched = guard.as_mut().expect("scheduler::init() not called");
        reap_zombies(sched);

        let Some(next) = sched.run_queue.pop_front() else {
            // Nothing else is runnable — carry on, there's no one to
            // switch to.
            return;
        };
        let next_sp = next.stack_pointer;

        let current = sched.current.take().expect("no current thread set");
        sched.run_queue.push_back(current);
        sched.current = Some(next);

        // Taken *after* pushing `current` into its final storage location
        // in `run_queue` — a pointer grabbed before the push would dangle
        // the moment `VecDeque` moves the `Thread` struct into place.
        let current_sp_ptr: *mut usize = &mut sched
            .run_queue
            .back_mut()
            .expect("just pushed a thread")
            .stack_pointer;

        (current_sp_ptr, next_sp)
        // `guard` drops here — must happen before `switch_to`, since the
        // thread we're switching to may itself try to lock `SCHEDULER`
        // (every thread does, via its own `yield_now()`), which would
        // deadlock against a lock this stack frame is still holding.
    };

    unsafe {
        switch_to(current_sp_ptr, next_sp);
    }
}

/// Ends the calling thread: hands the CPU to the next runnable thread and
/// never returns. The exiting thread's stack can't be unmapped here — it's
/// still running on it — so it's queued as a zombie instead and reclaimed
/// the next time some *other* thread calls [`yield_now`] (see
/// `reap_zombies`). Before this existed, the only way for a thread to stop
/// running was to loop forever, which meant every spawned thread's stack
/// frames were permanently unreclaimable — the "unbounded memory leak"
/// this fixes.
///
/// Must not be called from the boot/placeholder thread (the one
/// `scheduler::init()` starts as `current` before anything is spawned) — it
/// has no dedicated stack region of its own for `reap_zombies` to reclaim.
pub fn exit_current_thread() -> ! {
    crate::interrupts::record_yield();

    let next_sp = {
        let mut guard = SCHEDULER.lock();
        let sched = guard.as_mut().expect("scheduler::init() not called");
        reap_zombies(sched);

        let next = sched
            .run_queue
            .pop_front()
            .expect("exit_current_thread: no other thread left to run");
        let next_sp = next.stack_pointer;

        let exiting = sched.current.take().expect("no current thread set");
        sched.zombies.push_back(exiting);
        sched.current = Some(next);

        next_sp
        // `guard` drops here — same reasoning as `yield_now`.
    };

    let mut discard: usize = 0;
    unsafe {
        switch_to(&mut discard as *mut usize, next_sp);
    }
    // Unreachable in practice: `switch_to`'s `ret` jumps into whatever
    // thread `next_sp` belongs to, which never returns control to this
    // now-zombified stack. This only exists to satisfy `-> !` — the type
    // system has no way to know `switch_to` (an ordinary `fn`, not itself
    // `-> !`) never comes back here.
    loop {
        x86_64::instructions::hlt();
    }
}

/// # Safety
/// `current_sp_ptr` must point at a valid, writable `usize` that will
/// outlive this call, and `next_sp` must be a stack pointer previously
/// produced by [`Thread::new`] or previously saved by this same function —
/// anything else and the `pop`s on the far side read garbage into real
/// registers.
#[unsafe(naked)]
unsafe extern "C" fn switch_to(current_sp_ptr: *mut usize, next_sp: usize) {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}
