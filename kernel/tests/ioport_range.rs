//! Regression test: a port-I/O capability must cover the *whole* access
//! (`port..=port+width-1`), not just its first port, and must not wrap at
//! 0xFFFF. Pure logic, but the kernel is no_std-only so it runs as a
//! freestanding QEMU test like its siblings.

#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::capabilities::{ioport_access_within, ioport_range_resource};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;

use bootloader_api::config::{BootloaderConfig, Mapping};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn check(name: &str, got: bool, want: bool) {
    if got != want {
        serial_println!("ioport_range: FAIL {}: got {} want {}", name, got, want);
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("ioport_range: ok {}", name);
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();
    // The resource strings are built with `format!`, so the heap is needed.
    let Some(offset) = boot_info.physical_memory_offset.into_option() else {
        serial_println!("ioport_range: FAIL no physical memory mapping");
        exit_qemu(QemuExitCode::Failed);
    };
    let mapper = unsafe { runix_kernel::memory::init(VirtAddr::new(offset)) };
    let frame_allocator =
        unsafe { runix_kernel::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    runix_kernel::memory::install(mapper, frame_allocator);
    if runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        runix_kernel::allocator::init_heap(mapper, frame_allocator)
    })
    .is_err()
    {
        serial_println!("ioport_range: FAIL heap init");
        exit_qemu(QemuExitCode::Failed);
    }
    let r = ioport_range_resource(0xC000, 0x20); // 0xC000-0xC01F
    let r = r.as_str();

    check("inside w4", ioport_access_within(r, 0xC010, 4), true);
    check("exactly fills w4", ioport_access_within(r, 0xC01C, 4), true);
    check("exactly fills w2", ioport_access_within(r, 0xC01E, 2), true);
    check("w1 at end", ioport_access_within(r, 0xC01F, 1), true);
    check("w4 at end", ioport_access_within(r, 0xC01F, 4), false);
    check("w2 at end", ioport_access_within(r, 0xC01F, 2), false);
    check("w4 crossing end", ioport_access_within(r, 0xC01D, 4), false);
    check("below base", ioport_access_within(r, 0xBFFF, 1), false);
    check("w0 rejected", ioport_access_within(r, 0xC000, 0), false);

    let top = "ioport:65520-65535"; // 0xFFF0-0xFFFF
    check("0xFFFF w1", ioport_access_within(top, 0xFFFF, 1), true);
    check("0xFFFF w2 overflow", ioport_access_within(top, 0xFFFF, 2), false);
    check("0xFFFF w4 overflow", ioport_access_within(top, 0xFFFF, 4), false);
    check("0xFFFE w4 overflow", ioport_access_within(top, 0xFFFE, 4), false);
    check("0xFFFC w4 fills", ioport_access_within(top, 0xFFFC, 4), true);

    // Issuer overflow / empty range must not panic and must grant nothing.
    let over = ioport_range_resource(0xFFF0, 0x20);
    check("issuer overflow grants nothing", ioport_access_within(&over, 0xFFF0, 1), false);
    let empty = ioport_range_resource(0x100, 0);
    check("issuer len 0 grants nothing", ioport_access_within(&empty, 0x100, 1), false);

    check("inverted range", ioport_access_within("ioport:100-50", 75, 1), false);
    check("not ioport", ioport_access_within("port:5", 5, 1), false);

    serial_println!("ioport_range: PASS");
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("ioport_range: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
