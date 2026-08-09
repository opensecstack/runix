//! Proves the scheduler watchdog actually catches a stuck thread: spawns
//! one that never calls `yield_now()` (a bug the cooperative scheduler
//! otherwise has no way to detect — see `scheduler.rs`'s module doc
//! comment) and asserts the kernel panics loudly instead of hanging
//! forever. See `interrupts.rs`'s watchdog doc comment for why this is
//! detection, not preemption — the stuck thread is never recovered from,
//! only reported.

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

    serial_println!("watchdog: spawning a thread that never yields, on purpose");
    runix_kernel::scheduler::init();
    runix_kernel::scheduler::spawn(rogue_thread);

    // Hands the CPU to `rogue_thread`, which never yields back — this call
    // never returns. The watchdog is expected to panic (from the timer
    // interrupt handler) before this loop's `yield_now` would ever fire
    // again, whether or not this line is even reached again in practice.
    runix_kernel::scheduler::yield_now();

    serial_println!("watchdog: FAIL — rogue_thread returned control without tripping anything");
    exit_qemu(QemuExitCode::Failed);
}

/// Spins forever without ever calling `yield_now()` — exactly the bug the
/// watchdog exists to catch. `hlt` still lets timer interrupts land (it
/// only halts until the next one), which is what actually gives the
/// watchdog a chance to check and panic.
extern "C" fn rogue_thread() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let message = alloc::format!("{info}");
    serial_println!("watchdog: {}", message);

    if message.contains("scheduler watchdog") {
        serial_println!("watchdog: PASS — stuck thread was caught, not hung forever");
        exit_qemu(QemuExitCode::Success);
    } else {
        exit_qemu(QemuExitCode::Failed);
    }
}
