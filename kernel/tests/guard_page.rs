//! Verifies scheduler thread stacks actually have a working guard page: a
//! thread whose stack overflows must be *detected* — not silently corrupt
//! whatever memory happens to sit below its stack, which is exactly what
//! happened for real integrating `capability-manager` (see the top-level
//! README's "stack overflow" note) before this guard page existed.
//!
//! The expected failure mode isn't a clean page fault: the CPU pushes the
//! fault's own interrupt frame onto the *current* stack pointer, which at
//! overflow time is already at (or past) the guard page boundary, so
//! pushing that frame faults too — a double fault, not a single page
//! fault. `boot::init()` already handles that correctly (the double-fault
//! handler runs on its own IST stack, from Phase 2), so this test needs no
//! custom IDT of its own — it just has to recognize that a double fault is
//! the *expected*, successful outcome here, not a failure.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();
    x86_64::instructions::interrupts::enable();

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

    serial_println!("guard_page: spawning a thread that overflows its own stack on purpose");
    runix_kernel::scheduler::init();
    runix_kernel::scheduler::spawn(overflow_thread);

    // `yield_now` hands control to `overflow_thread`, which never yields
    // back (it recurses until it faults) — so this loop only ever runs its
    // first iteration in practice. Looped anyway so a change to
    // `overflow_thread` that makes it *not* immediately overflow doesn't
    // silently make this test do nothing.
    for _ in 0..3 {
        runix_kernel::scheduler::yield_now();
    }

    serial_println!("guard_page: FAIL — overflow_thread returned control without faulting");
    exit_qemu(QemuExitCode::Failed);
}

extern "C" fn overflow_thread() -> ! {
    recurse(u64::MAX);
    // Unreachable in practice (`recurse` faults before ever returning) —
    // needed only so this function still type-checks as `-> !`.
    loop {
        x86_64::instructions::hlt();
    }
}

/// Forces real stack consumption per call (not just a return address) so
/// this reliably overflows in a handful of frames rather than however many
/// thousands a tail-call-optimized empty recursion might survive.
#[inline(never)]
fn recurse(n: u64) -> u64 {
    let buf = [0u8; 256];
    let sum: u64 = buf.iter().map(|&b| b as u64).sum();
    if n == 0 {
        sum
    } else {
        sum + recurse(n - 1)
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let message = alloc::format!("{info}");
    serial_println!("guard_page: {}", message);

    // A double fault (panicking from `interrupts::double_fault_handler`) is
    // exactly the expected outcome — see the module doc comment. Any other
    // panic (e.g. a bug in this test's own setup, before `overflow_thread`
    // even runs) is a real failure, not a false positive for "the guard
    // page worked."
    if message.contains("DOUBLE FAULT") {
        serial_println!(
            "guard_page: PASS — overflow was caught (double fault), not silently corrupted"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        exit_qemu(QemuExitCode::Failed);
    }
}
