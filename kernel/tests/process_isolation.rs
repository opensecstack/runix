//! Proves `process::AddressSpace` provides real, hardware-enforced
//! isolation — not just "we allocated two different structs." Builds two
//! independent address spaces, maps the exact same virtual address
//! privately in each with different content, then actually switches `Cr3`
//! into each one in turn and reads back through that fixed VA — if page
//! tables were accidentally shared (or `map_private_page`'s "detach from
//! whatever the copied table pointed at" logic regressed), this would
//! observe the wrong value, or the same value both times.
//!
//! Entirely ring 0 on purpose: proving the address-space primitive itself
//! doesn't need ring 3 execution, a scheduler, or an ELF loader — none of
//! which exist yet for this (see `process.rs`'s module doc comment).
//! Interrupts are deliberately left disabled for the whole test — nothing
//! here needs the timer, and it removes any question of whether an IRQ
//! firing mid-`Cr3`-switch is itself safe (it should be, since kernel-space
//! stays identically mapped in every address space, but this test isn't
//! the place to also be proving that).

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::process::{self, AddressSpace};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::structures::paging::{Page, PageTableFlags};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Arbitrary, fixed VA both address spaces map privately — the whole point
/// is that this exact address means something different depending on which
/// `Cr3` is loaded.
const SHARED_VA: usize = 0x_7777_7777_0000;

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("bootloader did not map physical memory"),
    );
    let mapper = unsafe { runix_kernel::memory::init(physical_memory_offset) };
    let frame_allocator =
        unsafe { runix_kernel::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    runix_kernel::memory::install(mapper, frame_allocator);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        runix_kernel::allocator::init_heap(mapper, frame_allocator)
    })
    .expect("heap initialization failed");

    serial_println!("process_isolation: building two independent address spaces");
    let page = Page::containing_address(VirtAddr::new(SHARED_VA as u64));

    let page_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut space_a = AddressSpace::new();
    let data_a = space_a.map_private_page(page, page_flags);
    data_a[0] = 0xAA;

    let mut space_b = AddressSpace::new();
    let data_b = space_b.map_private_page(page, page_flags);
    data_b[0] = 0xBB;

    if data_a[0] != 0xAA {
        serial_println!(
            "process_isolation: FAIL — space A's own page was already clobbered before any \
             Cr3 switch (its own frame isn't even private)"
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!("process_isolation: switching into space A, reading through the shared VA");
    let previous = unsafe { space_a.activate() };
    let observed_a = unsafe { core::ptr::read_volatile(SHARED_VA as *const u8) };
    unsafe {
        process::restore(previous);
    }

    serial_println!("process_isolation: switching into space B, reading through the same VA");
    let previous = unsafe { space_b.activate() };
    let observed_b = unsafe { core::ptr::read_volatile(SHARED_VA as *const u8) };
    unsafe {
        process::restore(previous);
    }

    serial_println!(
        "process_isolation: back on the kernel's own table — observed A={:#x} B={:#x}",
        observed_a,
        observed_b
    );

    if observed_a == 0xAA && observed_b == 0xBB {
        serial_println!(
            "process_isolation: PASS — the same virtual address resolved to different \
             physical memory depending on which address space was active"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "process_isolation: FAIL — address spaces are not actually isolated from each other"
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("process_isolation: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
