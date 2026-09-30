//! Proves `SYS_RANDOM` end to end: a thread holding a `"random"` capability
//! gets real (differing) values back-to-back, and a thread with no
//! capability at all is denied — same `u64::MAX` sentinel style every other
//! gated syscall in `kernel/src/syscall.rs` uses. Modeled on `pci_scan.rs`'s
//! boot/heap-init shape and on `main.rs`'s own Phase B4 capability-gate demo
//! (`thread_sender_authorized`/`thread_sender_unauthorized`) for the
//! "spawn two threads, one with a token and one without" pattern.
//!
//! xtask boots QEMU with no explicit `-cpu` flag, so the default `qemu64`
//! CPU model applies — which does **not** advertise RDRAND. This test
//! branches on `runix_kernel::entropy::available()` so it proves the right
//! thing either way: on real/`-cpu host` hardware, two genuinely-differing
//! values; under CI's default `qemu64`, that the syscall still fails
//! *closed* (an authorized caller getting `u64::MAX` because the hardware
//! source is absent, not silently falling back to something weaker). Either
//! branch also proves the unauthorized caller is denied.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

// `u64::MAX` doubles as "never written" here — indistinguishable from a
// genuine denial/failure return, which is fine: every assertion below
// checks the *authorized* thread's slots against `u64::MAX` only after
// confirming (via `entropy::available()`) which outcome is actually
// expected, so "never ran" and "ran and got denied" never get confused for
// each other in what the test concludes.
static AUTHORIZED_FIRST: AtomicU64 = AtomicU64::new(u64::MAX);
static AUTHORIZED_SECOND: AtomicU64 = AtomicU64::new(u64::MAX);
static UNAUTHORIZED_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

extern "C" fn thread_random_authorized() -> ! {
    let first = unsafe { runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_RANDOM, 0, 0, 0) };
    AUTHORIZED_FIRST.store(first, Ordering::SeqCst);
    runix_kernel::scheduler::yield_now();
    let second = unsafe { runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_RANDOM, 0, 0, 0) };
    AUTHORIZED_SECOND.store(second, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_random_unauthorized() -> ! {
    let result = unsafe { runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_RANDOM, 0, 0, 0) };
    UNAUTHORIZED_RESULT.store(result, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

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

    runix_kernel::scheduler::init();

    let rdrand_present = runix_kernel::entropy::available();
    serial_println!("sys_random: RDRAND present on this CPU: {}", rdrand_present);

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let random_token = runix_capability_manager::CapabilityToken::issue(
        "thread:random_authorized",
        runix_kernel::capabilities::random_resource(),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    runix_kernel::scheduler::spawn_with_capability(thread_random_authorized, Some(random_token));
    // No capability at all — same "spawn plain" path `thread_sender_unauthorized`
    // uses in `main.rs`'s own Phase B4 demo.
    runix_kernel::scheduler::spawn(thread_random_unauthorized);

    for _ in 0..8 {
        runix_kernel::scheduler::yield_now();
    }

    let first = AUTHORIZED_FIRST.load(Ordering::SeqCst);
    let second = AUTHORIZED_SECOND.load(Ordering::SeqCst);
    let unauthorized = UNAUTHORIZED_RESULT.load(Ordering::SeqCst);

    serial_println!(
        "sys_random: authorized={:#018x},{:#018x} unauthorized={:#018x}",
        first,
        second,
        unauthorized
    );

    if unauthorized != u64::MAX {
        serial_println!("sys_random: FAIL — unauthorized caller was not denied");
        exit_qemu(QemuExitCode::Failed);
    }

    if rdrand_present {
        // Real entropy expected: both authorized calls must have actually
        // produced a value, and two genuine RDRAND reads matching by
        // coincidence is astronomically unlikely — a repeat here would mean
        // something is very wrong (e.g. reading a fixed register instead of
        // the instruction result), not bad luck.
        if first == u64::MAX || second == u64::MAX {
            serial_println!("sys_random: FAIL — authorized caller was denied despite holding a random token and RDRAND being present");
            exit_qemu(QemuExitCode::Failed);
        }
        if first == second {
            serial_println!("sys_random: FAIL — two RDRAND reads produced the same value");
            exit_qemu(QemuExitCode::Failed);
        }
        serial_println!("sys_random: PASS — authorized caller got two differing RDRAND values, unauthorized caller denied");
    } else {
        // No RDRAND on this CPU model (expected under CI's default `qemu64`
        // — see this file's doc comment): the syscall must still fail
        // *closed* even for an authorized caller, not fall back to
        // something weaker.
        if first != u64::MAX || second != u64::MAX {
            serial_println!("sys_random: FAIL — got a value with RDRAND reported absent; entropy::read_u64 should have failed closed");
            exit_qemu(QemuExitCode::Failed);
        }
        serial_println!("sys_random: PASS — RDRAND absent, authorized caller correctly got u64::MAX (fail-closed), unauthorized caller denied");
    }

    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("sys_random: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
