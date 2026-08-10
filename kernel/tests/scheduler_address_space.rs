//! Proves the *scheduler itself* correctly tracks and switches `Cr3` per
//! thread — not just that a single manual `AddressSpace::activate()` call
//! works (`process_isolation.rs` already proved that). Spawns two threads,
//! each owning its own private `AddressSpace`, both mapping the exact same
//! virtual address privately with a distinct marker byte. Each thread
//! writes its marker, yields (handing control to the *other* thread, which
//! writes its own different marker to the same VA in its own space), and
//! on resuming re-reads that VA to confirm its own value survived the
//! round trip — if `yield_now`'s `Cr3` switch ever regressed (wrong
//! target, or skipped when it shouldn't be), one thread would observe the
//! other's marker instead of its own.
//!
//! Ring 0 throughout, same as `process_isolation.rs` and `elf_loader.rs` —
//! this only exercises the scheduler's address-space bookkeeping, not ring
//! 3 execution (still future work — see `scheduler.rs`'s module doc
//! comment on `spawn_with_address_space`).

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::process::AddressSpace;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use x86_64::structures::paging::{Page, PageTableFlags};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const SHARED_VA: u64 = 0x_7777_5555_0000;
const MARKER_A: u8 = 0xA5;
const MARKER_B: u8 = 0x5A;
const ITERATIONS: usize = 5;

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

    serial_println!("scheduler_address_space: building two per-thread address spaces");
    let page = Page::containing_address(VirtAddr::new(SHARED_VA));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut space_a = AddressSpace::new();
    space_a.map_private_page(page, flags);
    let mut space_b = AddressSpace::new();
    space_b.map_private_page(page, flags);

    scheduler::init();
    scheduler::spawn_with_address_space(thread_a, space_a);
    scheduler::spawn_with_address_space(thread_b, space_b);

    // Each thread does `ITERATIONS` rounds, each round = 2 yields (write
    // then yield, check then yield) — round-robin among 3 runnable
    // contexts (this boot thread + the two spawned ones) means plenty of
    // slack is needed for both to actually finish; failure exits
    // immediately from inside a thread regardless, so over-yielding here
    // just means "wait long enough," not "risk masking a failure."
    for _ in 0..(ITERATIONS * 8) {
        scheduler::yield_now();
    }

    serial_println!(
        "scheduler_address_space: PASS — both threads' address spaces survived every \
         round trip through the scheduler"
    );
    exit_qemu(QemuExitCode::Success);
}

extern "C" fn thread_a() -> ! {
    run_thread("A", MARKER_A);
}

extern "C" fn thread_b() -> ! {
    run_thread("B", MARKER_B);
}

/// Common body for both threads: write this thread's marker, yield (giving
/// the *other* thread — running under its *own* `Cr3` — a chance to write
/// its own different marker to the same VA), then re-read and confirm this
/// thread's own value is still what's there.
fn run_thread(name: &str, marker: u8) -> ! {
    for i in 0..ITERATIONS {
        unsafe {
            core::ptr::write_volatile(SHARED_VA as *mut u8, marker);
        }
        scheduler::yield_now();
        let seen = unsafe { core::ptr::read_volatile(SHARED_VA as *const u8) };
        if seen != marker {
            serial_println!(
                "scheduler_address_space: FAIL — thread {} expected {:#x} after round trip, \
                 saw {:#x} (the scheduler's Cr3 tracking is wrong)",
                name,
                marker,
                seen
            );
            exit_qemu(QemuExitCode::Failed);
        }
        serial_println!(
            "scheduler_address_space: thread {} iteration {} OK (saw its own {:#x} intact)",
            name,
            i,
            marker
        );
        scheduler::yield_now();
    }
    loop {
        scheduler::yield_now();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("scheduler_address_space: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
