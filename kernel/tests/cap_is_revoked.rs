//! `SYS_CAP_IS_REVOKED` (kernel/src/syscall.rs): a thread holding the
//! `revocation:query` capability gets 1 for the fingerprint of a revoked
//! token's signature and 0 for an unrevoked one; a thread without that
//! capability is denied (`u64::MAX`) even when asking about a revoked
//! fingerprint, so the query cannot be used to probe the revocation list.
//! Needs no FAT image. Driven from kernel-mode threads, same approach as
//! `sys_random.rs`.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use runix_capability_manager::{signature_fingerprint, CapabilityToken};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use runix_kernel::syscall::{syscall, SYS_CAP_IS_REVOKED};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static REVOKED_FP: AtomicU64 = AtomicU64::new(0);
static UNREVOKED_FP: AtomicU64 = AtomicU64::new(0);

// 2 is never a valid result, so it doubles as "not yet written".
const UNSET: u64 = 2;
static AUTH_REVOKED: AtomicU64 = AtomicU64::new(UNSET);
static AUTH_UNREVOKED: AtomicU64 = AtomicU64::new(UNSET);
static UNAUTH_REVOKED: AtomicU64 = AtomicU64::new(UNSET);

extern "C" fn thread_authorized() -> ! {
    let r = unsafe { syscall(SYS_CAP_IS_REVOKED, REVOKED_FP.load(Ordering::SeqCst), 0, 0) };
    AUTH_REVOKED.store(r, Ordering::SeqCst);
    let u = unsafe {
        syscall(
            SYS_CAP_IS_REVOKED,
            UNREVOKED_FP.load(Ordering::SeqCst),
            0,
            0,
        )
    };
    AUTH_UNREVOKED.store(u, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_unauthorized() -> ! {
    let r = unsafe { syscall(SYS_CAP_IS_REVOKED, REVOKED_FP.load(Ordering::SeqCst), 0, 0) };
    UNAUTH_REVOKED.store(r, Ordering::SeqCst);
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

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let issue = |subject: &str, resource: alloc::string::String| {
        CapabilityToken::issue(
            subject,
            resource,
            now,
            now + 1_000_000,
            "demo-key",
            &signing_key,
        )
    };
    let revoked = issue("a", runix_kernel::capabilities::file_resource("A.TXT"));
    let unrevoked = issue("b", runix_kernel::capabilities::file_resource("B.TXT"));
    let (Some(fp_revoked), Some(fp_unrevoked)) = (
        signature_fingerprint(&revoked.signature),
        signature_fingerprint(&unrevoked.signature),
    ) else {
        serial_println!("cap_is_revoked: FAIL — no fingerprint for a freshly issued token");
        exit_qemu(QemuExitCode::Failed);
    };
    runix_kernel::capabilities::revoke(&revoked);
    REVOKED_FP.store(fp_revoked, Ordering::SeqCst);
    UNREVOKED_FP.store(fp_unrevoked, Ordering::SeqCst);

    // The boot thread holds no capability: denied, even for a revoked fp.
    let main_r = unsafe { syscall(SYS_CAP_IS_REVOKED, fp_revoked, 0, 0) };
    if main_r != u64::MAX {
        serial_println!(
            "cap_is_revoked: FAIL — capability-less caller got {:#x}",
            main_r
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let query_token = issue(
        "thread:authorized",
        runix_kernel::capabilities::revocation_query_resource(),
    );
    runix_kernel::scheduler::spawn_with_capability(thread_authorized, Some(query_token));
    // A valid token for some other resource must not authorize the query.
    let wrong = issue(
        "thread:unauthorized",
        runix_kernel::capabilities::random_resource(),
    );
    runix_kernel::scheduler::spawn_with_capability(thread_unauthorized, Some(wrong));

    for _ in 0..8 {
        runix_kernel::scheduler::yield_now();
    }

    let (ar, au, ur) = (
        AUTH_REVOKED.load(Ordering::SeqCst),
        AUTH_UNREVOKED.load(Ordering::SeqCst),
        UNAUTH_REVOKED.load(Ordering::SeqCst),
    );
    serial_println!(
        "cap_is_revoked: authorized revoked={} unrevoked={}; unauthorized={:#x}",
        ar,
        au,
        ur
    );
    if ar != 1 || au != 0 || ur != u64::MAX {
        serial_println!("cap_is_revoked: FAIL — unexpected results");
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "cap_is_revoked: PASS — revoked=1, unrevoked=0 for the holder; non-holders denied"
    );
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("cap_is_revoked: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
