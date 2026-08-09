//! Stress test for real memory reclamation: spawns and exits far more
//! threads than there is physical memory to back if their stacks were never
//! reclaimed, and asserts the run completes instead of exhausting memory.
//!
//! Before `scheduler::exit_current_thread`/`reap_zombies` existed, every
//! spawned thread's stack frames were permanently lost the moment the
//! thread was done with them (see the top-level README's "unbounded memory
//! leak" note) — fine for a demo that boots and stops, but this is exactly
//! the kind of gap a single boot-log grep never exercises: nothing in the
//! existing demo spawns enough threads, or exits any of them, to ever hit
//! it. `ITERATIONS` below is picked to comfortably exceed how many threads'
//! worth of stack (`STACK_SIZE` each, from `scheduler.rs`) would fit in the
//! QEMU instance's `-m 128M` if frames were never reused — if reclamation
//! regresses, `allocate_frame` runs out and panics well before this
//! completes.

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

/// 16 KiB/thread (`STACK_SIZE` in scheduler.rs) * 20,000 = ~312 MiB — well
/// past the 128 MiB QEMU is given in every test-runner config here (see
/// `xtask`), so a leak-driven `allocate_frame` failure would show up long
/// before this count is reached.
const ITERATIONS: usize = 20_000;

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

    serial_println!(
        "thread_reclaim: spawning and exiting {} short-lived threads",
        ITERATIONS
    );
    runix_kernel::scheduler::init();

    for i in 0..ITERATIONS {
        runix_kernel::scheduler::spawn(short_lived_thread);
        // Lets the spawned thread actually run (and exit) before the next
        // iteration spawns another — `exit_current_thread` queues its own
        // stack as a zombie, reaped by *this* `yield_now()` on some future
        // iteration (see `reap_zombies`'s doc comment for why it can't
        // reap itself).
        runix_kernel::scheduler::yield_now();
        if i % 5000 == 0 {
            serial_println!("thread_reclaim: {} threads done", i);
        }
    }

    serial_println!(
        "thread_reclaim: PASS — {} threads spawned and exited without exhausting memory",
        ITERATIONS
    );
    exit_qemu(QemuExitCode::Success);
}

extern "C" fn short_lived_thread() -> ! {
    runix_kernel::scheduler::exit_current_thread();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("thread_reclaim: PANIC (likely a real leak): {}", info);
    exit_qemu(QemuExitCode::Failed);
}
