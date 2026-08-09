//! Post-bootloader initialization sequence. The bootloader (via
//! `bootloader_api::entry_point!` in `src/main.rs`) has already set up long
//! mode, paging, and handed us a `BootInfo`; this is where we take over CPU
//! state with our own GDT/TSS and IDT before anything else runs.

use crate::{gdt, interrupts};

pub fn init() {
    gdt::init();
    interrupts::init_idt();
    // Remaps and masks the PIC but does not enable interrupts (`sti`) — the
    // caller decides when hardware IRQs actually start firing.
    unsafe {
        interrupts::init_pics();
    }
}
