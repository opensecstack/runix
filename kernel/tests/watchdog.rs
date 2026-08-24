//! Proves the scheduler now *recovers* from a stuck thread instead of only
//! detecting one: spawns `rogue_thread`, which never calls `yield_now()`
//! (once the only way to starve every other thread forever — see
//! `scheduler.rs`'s module doc comment for the real, timer-interrupt-driven
//! preemption that closed that gap), alongside `cooperative_thread`, which
//! just counts its own iterations. Asserts the counter keeps climbing —
//! proof `cooperative_thread` gets real CPU time no matter what
//! `rogue_thread` does — and that nothing panics along the way, including
//! the watchdog itself: with preemption forcing a reschedule on every timer
//! tick regardless of what's running, `reschedule` succeeds constantly, so
//! the watchdog (now a backstop against the reschedule mechanism breaking,
//! not a substitute for real recovery) should never have anything to catch
//! here.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
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

/// Bumped once per `cooperative_thread` iteration — the progress signal
/// `kernel_main` polls for. Never touched by `rogue_thread`.
static PROGRESS: AtomicUsize = AtomicUsize::new(0);

/// How many `cooperative_thread` iterations count as proof it's genuinely
/// making progress, not just one lucky scheduling accident.
const PROGRESS_TARGET: usize = 20;

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
    runix_kernel::scheduler::spawn(cooperative_thread);

    // `rogue_thread` never yields — under the old cooperative-only design
    // this loop would simply never run again. With real preemption, the
    // timer forces a reschedule regardless, so `cooperative_thread` still
    // gets turns and `PROGRESS` keeps climbing even though this thread's
    // own `yield_now()` calls are competing with a thread that never
    // voluntarily gives the CPU back.
    for _ in 0..1000 {
        runix_kernel::scheduler::yield_now();
        if PROGRESS.load(Ordering::Relaxed) >= PROGRESS_TARGET {
            serial_println!(
                "watchdog: PASS — cooperative_thread made progress ({} iterations) despite rogue_thread never yielding",
                PROGRESS.load(Ordering::Relaxed)
            );
            exit_qemu(QemuExitCode::Success);
        }
    }

    serial_println!(
        "watchdog: FAIL — cooperative_thread only reached {} iterations in time (preemption not recovering)",
        PROGRESS.load(Ordering::Relaxed)
    );
    exit_qemu(QemuExitCode::Failed);
}

/// Spins forever without ever calling `yield_now()` — exactly the bug real
/// preemption exists to make survivable. `hlt` still lets timer interrupts
/// land (it only halts until the next one), which is what actually gives
/// the timer a chance to preempt it.
extern "C" fn rogue_thread() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

/// Counts its own iterations so `kernel_main` has something to poll —
/// making progress here, with `rogue_thread` never cooperating, is the
/// entire thing this test exists to prove.
extern "C" fn cooperative_thread() -> ! {
    loop {
        PROGRESS.fetch_add(1, Ordering::Relaxed);
        runix_kernel::scheduler::yield_now();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Any panic here — including the scheduler watchdog's own, now a
    // backstop against `reschedule` itself breaking rather than a stuck
    // thread — is a failure: real preemption means nothing should ever need
    // to panic just because `rogue_thread` refuses to yield.
    serial_println!("watchdog: FAIL — unexpected panic: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
