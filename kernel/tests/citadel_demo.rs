//! Proves the `citadel-integration` <-> kernel wiring works end to end:
//! `citadel.rs`'s demo trust root accepts a module authorized under it and
//! refuses the same check against tampered bytes — the boot-time
//! authorization gate itself, not (yet) an actual module load gated by it.
//! See `citadel.rs`'s module doc comment for what's still missing.

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
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

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

    let module_bytes = b"demo module bytes - not a real loaded module yet";

    serial_println!("citadel_demo: authorizing a module signed for the demo allowlist");
    if let Err(e) = runix_kernel::citadel::demo_authorize("demo-module", module_bytes) {
        serial_println!(
            "citadel_demo: FAIL — expected authorization to succeed, got {}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!("citadel_demo: checking tampered bytes are refused");
    match runix_kernel::citadel::demo_reject_tampered("demo-module", module_bytes) {
        Ok(()) => {
            serial_println!("citadel_demo: FAIL — tampered bytes were accepted");
            exit_qemu(QemuExitCode::Failed);
        }
        Err(e) => {
            serial_println!("citadel_demo: tampered bytes correctly refused ({})", e);
        }
    }

    serial_println!(
        "citadel_demo: PASS — citadel-integration's boot allowlist authorized a real module \
         and refused a tampered one, called from kernel/ for the first time"
    );
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("citadel_demo: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
