//! Integration test: does the kernel boot to a stable, interrupt-safe state
//! at all? Runs as its own tiny freestanding binary — the standard pattern
//! for `no_std` integration tests, one bootable kernel per `tests/*.rs` file
//! — actually boots for real in QEMU (via the `runner` in
//! `.cargo/config.toml`, which delegates to `xtask`'s `test-runner`
//! subcommand), and signals pass/fail through the isa-debug-exit device.
//!
//! This is the `cargo test`-native version of what the `boot` GitHub
//! Actions job previously checked by hand-grepping serial text — same
//! underlying property (real QEMU boot, not `cargo test` on the host, which
//! can't see architecture-specific bugs like the GDT/segment-register one
//! documented in the top-level README), but now a real pass/fail signal
//! instead of string matching.

#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    serial_println!("basic_boot: starting");

    runix_kernel::boot::init();
    serial_println!("basic_boot: CPU init OK");

    // The actual assertion: a breakpoint exception must be handled and
    // control must return here afterward, not double-fault or hang. If
    // GDT/IDT/IST setup regresses, this is where it shows up.
    x86_64::instructions::interrupts::int3();
    serial_println!("basic_boot: breakpoint survived");

    serial_println!("basic_boot: PASS");
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("basic_boot: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
