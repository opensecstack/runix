//! Global Descriptor Table + Task State Segment.
//!
//! The bootloader hands us long mode already set up with its own temporary
//! GDT, but we load our own so we control it going forward — in particular
//! so the TSS's Interrupt Stack Table gives the double-fault handler a
//! dedicated stack. Without that, a stack-overflow-triggered double fault
//! would try to push the exception frame onto the same (already exhausted)
//! stack, silently triple-faulting into a QEMU reboot instead of printing
//! anything.

use lazy_static::lazy_static;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            #[allow(static_mut_refs)]
            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            stack_start + STACK_SIZE as u64
        };
        // RSP0: the stack the CPU switches to automatically on any
        // interrupt/exception that raises the privilege level back to ring
        // 0 — in particular a ring-3 `int 0x80` (see `syscall.rs`). Without
        // this, that transition would run the syscall entry gate on
        // whatever ring 3's stack pointer happened to be, which isn't a
        // kernel stack at all.
        tss.privilege_stack_table[0] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            #[allow(static_mut_refs)]
            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            stack_start + STACK_SIZE as u64
        };
        tss
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));
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
