//! Regression test: a syscall naming an out-of-range IPC port must return the
//! usual `u64::MAX` sentinel instead of indexing past the end of the fixed
//! port array (a kernel panic = abort, reachable by any ring-3 process with
//! no capability). Drives `syscall::syscall` (-> `dispatch`) directly from a
//! kernel-mode thread rather than a full ring-3 process; the vulnerable code
//! is in `dispatch`/`ipc`, which both paths share. Also checks a valid port
//! still works unchanged.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use runix_kernel::syscall::{
    syscall, SYS_IPC_RECV, SYS_IPC_SEND, SYS_IPC_SEND_LOCK, SYS_IPC_SEND_UNLOCK,
    SYS_IPC_SESSION_ACCEPT, SYS_IPC_SESSION_OPEN,
};
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
    runix_kernel::scheduler::init();

    // No capability is held by this thread at all.
    for bad in [16u64, 17, 1000, u32::MAX as u64, u64::MAX] {
        for num in [
            SYS_IPC_RECV,
            SYS_IPC_SEND,
            SYS_IPC_SEND_LOCK,
            SYS_IPC_SEND_UNLOCK,
            SYS_IPC_SESSION_OPEN,
            SYS_IPC_SESSION_ACCEPT,
        ] {
            let r = unsafe { syscall(num, bad, 0, 0) };
            if r != u64::MAX {
                serial_println!("ipc_bad_port: FAIL syscall {} port {:#x} -> {:#x}", num, bad, r);
                exit_qemu(QemuExitCode::Failed);
            }
        }
    }
    // Direct module-level calls are bounds-checked too.
    if runix_kernel::ipc::try_recv(16).is_some()
        || !runix_kernel::ipc::is_empty(16)
        || runix_kernel::ipc::send(16, 1)
        || runix_kernel::ipc::begin_send(16)
        || runix_kernel::ipc::end_send(16)
        || runix_kernel::ipc::recv(16).is_some()
    {
        serial_println!("ipc_bad_port: FAIL ipc module accepted port 16");
        exit_qemu(QemuExitCode::Failed);
    }
    // Valid port, empty channel: unchanged behaviour (sentinel, no panic).
    if unsafe { syscall(SYS_IPC_RECV, 0, 0, 0) } != u64::MAX {
        serial_println!("ipc_bad_port: FAIL valid empty port did not return sentinel");
        exit_qemu(QemuExitCode::Failed);
    }
    if !runix_kernel::ipc::send(3, 0x42) || runix_kernel::ipc::try_recv(3) != Some(0x42) {
        serial_println!("ipc_bad_port: FAIL valid port 3 send/recv broken");
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("ipc_bad_port: PASS -- out-of-range ports return u64::MAX, kernel survived");
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("ipc_bad_port: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
