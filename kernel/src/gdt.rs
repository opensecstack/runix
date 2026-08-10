//! Global Descriptor Table + Task State Segment.
//!
//! The bootloader hands us long mode already set up with its own temporary
//! GDT, but we load our own so we control it going forward — in particular
//! so the TSS's Interrupt Stack Table gives the double-fault handler a
//! dedicated stack. Without that, a stack-overflow-triggered double fault
//! would try to push the exception frame onto the same (already exhausted)
//! stack, silently triple-faulting into a QEMU reboot instead of printing
//! anything.

use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// A default RSP0 target, used until the first ring 3-capable thread the
/// scheduler resumes overrides it via [`set_kernel_stack`] — matters only
/// as a safe fallback (e.g. `userspace::user_hello`'s hand-run, not
/// scheduler-managed, ring 3 transition still uses it) since a plain
/// kernel thread never traps from ring 3 and never touches RSP0 at all.
const DEFAULT_RSP0_STACK_SIZE: usize = 4096 * 5;
static mut DEFAULT_RSP0_STACK: [u8; DEFAULT_RSP0_STACK_SIZE] = [0; DEFAULT_RSP0_STACK_SIZE];

/// `static mut`, not `lazy_static!`'s usual `static ref` (immutable), on
/// purpose: `scheduler.rs` needs to rewrite `privilege_stack_table[0]`
/// (RSP0) on every context switch into a ring 3-capable thread, once each
/// such thread gets its own dedicated kernel-entry stack instead of every
/// ring 3 trap sharing one — see `set_kernel_stack`. The GDT's TSS
/// descriptor stores this struct's fixed address, not a value snapshot, so
/// mutating its fields after `init()` has already loaded the GDT is exactly
/// as valid as mutating it before.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// # Safety
/// Must only be called once, before [`init`] loads the GDT (which bakes in
/// `&TSS`'s address) — populates the IST/default-RSP0 fields a freshly
/// `const`-initialized `TaskStateSegment` doesn't have.
unsafe fn init_tss() {
    #[allow(static_mut_refs)]
    let tss = unsafe { &mut TSS };
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        const STACK_SIZE: usize = 4096 * 5;
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
        #[allow(static_mut_refs)]
        let stack_start = VirtAddr::from_ptr(&raw const STACK);
        stack_start + STACK_SIZE as u64
    };
    // RSP0: the stack the CPU switches to automatically on any
    // interrupt/exception that raises the privilege level back to ring 0 —
    // in particular a ring-3 `int 0x80` (see `syscall.rs`). Without this,
    // that transition would run the syscall entry gate on whatever ring
    // 3's stack pointer happened to be, which isn't a kernel stack at all.
    // Starts pointing at a default stack (see `DEFAULT_RSP0_STACK`);
    // `scheduler.rs` overrides this per-thread once a thread has its own.
    #[allow(static_mut_refs)]
    let default_top =
        VirtAddr::from_ptr(&raw const DEFAULT_RSP0_STACK) + DEFAULT_RSP0_STACK_SIZE as u64;
    tss.privilege_stack_table[0] = default_top;
}

/// Points RSP0 at `stack_top` — called by `scheduler::yield_now` right
/// before resuming any thread that owns a dedicated kernel-entry stack
/// (`scheduler::spawn_ring3_process`), so each such thread's ring 3 traps
/// land on *its own* stack instead of a single one shared (and corrupted)
/// across every ring 3-capable thread. Safe to call at any time — this is
/// a plain field write, not a privilege-changing operation itself.
pub fn set_kernel_stack(stack_top: VirtAddr) {
    #[allow(static_mut_refs)]
    let tss = unsafe { &mut TSS };
    tss.privilege_stack_table[0] = stack_top;
}

use lazy_static::lazy_static;

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        #[allow(static_mut_refs)]
        let tss_ref: &'static TaskStateSegment = unsafe { &TSS };
        let tss_selector = gdt.append(Descriptor::tss_segment(tss_ref));
        // `append` bakes the descriptor's own DPL into the returned
        // selector's RPL bits (see the `x86_64` crate's `GlobalDescriptorTable::append`),
        // so these are already RPL 3 — no manual `| 3` needed when loading
        // them into CS/SS for the ring 3 jump.
        let user_data_selector = gdt.append(Descriptor::user_data_segment());
        let user_code_selector = gdt.append(Descriptor::user_code_segment());
        (
            gdt,
            Selectors {
                code_selector,
                tss_selector,
                user_code_selector,
                user_data_selector,
            },
        )
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
}

/// The ring 3 code/data selectors, for building the `iretq` frame that
/// drops into user mode (see `userspace::enter_usermode`).
pub fn user_selectors() -> (SegmentSelector, SegmentSelector) {
    (GDT.1.user_code_selector, GDT.1.user_data_selector)
}

pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    use x86_64::instructions::tables::load_tss;
    use x86_64::structures::gdt::SegmentSelector;
    use x86_64::PrivilegeLevel;

    unsafe {
        init_tss();
    }
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);
        load_tss(GDT.1.tss_selector);

        // Every other segment register still holds whatever the bootloader
        // left in it, pointing at indices in a GDT we just replaced. Null
        // them out explicitly instead of relying on those stale values
        // happening not to collide with a real descriptor in *our* table —
        // they did collide here: the bootloader's leftover SS (index 2)
        // landed on our TSS descriptor's low half, which isn't a valid data
        // segment, and `iretq` general-protection-faulted trying to reload
        // it after the first breakpoint exception returned.
        let null_selector = SegmentSelector::new(0, PrivilegeLevel::Ring0);
        SS::set_reg(null_selector);
        DS::set_reg(null_selector);
        ES::set_reg(null_selector);
        FS::set_reg(null_selector);
        GS::set_reg(null_selector);
    }
}
