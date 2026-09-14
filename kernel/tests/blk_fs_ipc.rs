//! Filesystem driver, Phase 3 (see docs/STATUS.md's filesystem-driver
//! narrative): proves the actual gap Phase 2 left open — nothing outside
//! `blk-driver-host` itself could ask it for a file. Spawns
//! `blk-driver-host` in its new request-serving mode
//! (`serve_fs_requests: 1`) against the Phase 2 FAT32 fixture, then proves
//! both directions of capability scoping over the real IPC syscalls
//! (`SYS_IPC_SEND`/`SYS_IPC_RECV`, `kernel/src/syscall.rs`): a thread
//! holding no capability at all is denied when it tries to send the
//! request trigger (the same way `kernel/src/main.rs`'s own Phase B4 demo
//! proves `thread_sender_unauthorized` is denied), and a thread holding a
//! capability scoped to exactly the request port gets the exact file
//! bytes back over the response port.
//!
//! This is also the first real exercise of `Thread::extra_capabilities`
//! (`kernel/src/scheduler.rs`) — `blk-driver-host` itself now holds *two*
//! capabilities at once (its usual virtio-blk io-port range, plus a new
//! one scoped to the response port it replies on), which is exactly the
//! scenario that field exists for.
//!
//! Filesystem driver, Phase 8 extends this same boot with a second,
//! independently capability-gated port (`FS_WRITE_REQUEST_PORT`) for
//! write requests against `WRITE.TXT` — proving both directions again for
//! the write path (unauthorized denied, authorized succeeds) and, unlike
//! Phase 3's "serves at most one request, then idles forever," that the
//! *same* server loop actually serves more than one request in a single
//! boot (a read, then two write attempts). `blk-driver-host` itself needs
//! no new capability for this — it only ever *receives* on ports 8/10
//! (unauthenticated, same as before) and *sends* on port 9 (already
//! covered by `response_token`); the new capability is granted to the
//! *client* thread that's allowed to send a write request, same shape as
//! `request_token` already is for reads.
//!
//! **Requires the same real FAT32 fixture image** `blk_fat32_read.rs`
//! does, via `RUNIX_BLK_IMG` — `blk-driver-host` locates the same
//! `HELLO.TXT` before ever entering its receive loop.
//!
//! **Manual build step required when running this locally** — same as
//! `blk_fat32_read.rs`:
//!
//! ```text
//! cd blk-driver-host && cargo build --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::elf::Elf64;
use runix_kernel::process::AddressSpace;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use runix_kernel::userspace;
use x86_64::structures::paging::{FrameAllocator, Page, PageTableFlags, PhysFrame};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static BLK_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../blk-driver-host/target/x86_64-unknown-none/release/blk-driver-host");

// Must match `blk-driver-host/src/main.rs`'s own constants exactly.
const BLK_HEAP_START: u64 = 0x_0999_1111_0000;
const BLK_HEAP_SIZE: u64 = 256 * 1024;
const BLK_STACK_VA: u64 = 0x_0999_2222_0000;
const BLK_STACK_SIZE: u64 = 4096 * 4;
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;
const BLK_QUEUE_ALIGN: u64 = 4096;

// Must match `blk-driver-host/src/main.rs`'s own `FS_REQUEST_PORT`/
// `FS_RESPONSE_PORT`/`FS_WRITE_REQUEST_PORT`.
const FS_REQUEST_PORT: usize = 8;
const FS_RESPONSE_PORT: usize = 9;
const FS_WRITE_REQUEST_PORT: usize = 10;

// Must match `blk-driver-host/src/main.rs`'s own
// `FS_WRITE_STATUS_OK`/`FS_WRITE_STATUS_BAD_LENGTH`.
const FS_WRITE_STATUS_OK: u8 = 0;

const IPC_WRITE_LEN: usize = 512;
fn ipc_write_pattern_byte(i: usize) -> u8 {
    b'z' - (i % 26) as u8
}

// Must match `blk-driver-host/src/main.rs`'s own `EXPECTED_FILE_CONTENTS`
// and `kernel/tests/support/make_fat32_image.sh`'s fixture byte-for-byte.
const EXPECTED_FILE_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem.\n";

#[repr(C)]
struct BlkBootInfo {
    io_base: u16,
    _pad: u16,
    queue_phys: u64,
    reqbuf_phys: u64,
    attempt_fat32: u8,
    serve_fs_requests: u8,
}

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

    scheduler::init();

    let devices = runix_kernel::pci::scan();
    let io_base = match runix_kernel::pci::find_virtio_blk(&devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => io_base,
        None => {
            serial_println!("blk_fs_ipc: FAIL — no virtio-blk I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "blk-driver-host",
        BLK_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "blk_fs_ipc: FAIL — CITADEL allowlist rejected blk-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(BLK_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!("blk_fs_ipc: FAIL — parse() rejected the binary: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("blk_fs_ipc: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!("blk_fs_ipc: loaded, entry point {:#x}", entry.as_u64());

    let rw_user_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    let map_zeroed_range = |space: &mut AddressSpace, start: u64, size: u64| {
        let start_page = Page::containing_address(VirtAddr::new(start));
        let end_page = Page::containing_address(VirtAddr::new(start + size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            space.map_private_page(page, rw_user_flags).fill(0);
        }
    };
    map_zeroed_range(&mut space, BLK_HEAP_START, BLK_HEAP_SIZE);
    map_zeroed_range(&mut space, BLK_STACK_VA, BLK_STACK_SIZE);

    let queue_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, BLK_QUEUE_VA, 3, rw_user_flags);

    let reqbuf_page = Page::containing_address(VirtAddr::new(BLK_REQBUF_VA));
    let reqbuf_content = space.map_private_page(reqbuf_page, rw_user_flags);
    reqbuf_content.fill(0);
    let reqbuf_phys = page_phys_addr(reqbuf_content);

    let info_page = Page::containing_address(VirtAddr::new(BLK_INFO_VA));
    let info_content = space.map_private_page(info_page, rw_user_flags);
    info_content.fill(0);
    let info = BlkBootInfo {
        io_base,
        _pad: 0,
        queue_phys: queue_first_frame_phys,
        reqbuf_phys,
        attempt_fat32: 0,
        serve_fs_requests: 1,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut BlkBootInfo).write(info);
    }

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let blk_token = runix_capability_manager::CapabilityToken::issue(
        "blk-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    // The second capability `blk-driver-host` needs to reply at all —
    // `Thread::extra_capabilities`'s whole reason for existing (see
    // `kernel/src/scheduler.rs`'s doc comment).
    let response_token = runix_capability_manager::CapabilityToken::issue(
        "blk-driver-host",
        runix_kernel::capabilities::port_resource(FS_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );

    #[allow(static_mut_refs)]
    unsafe {
        ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process_with_capabilities(
        kernel_trampoline,
        space,
        Some(blk_token),
        alloc::vec![response_token],
    );

    // Give it time to probe the device, locate HELLO.TXT, and reach its
    // receive loop before either requester attempts anything.
    for _ in 0..50 {
        scheduler::yield_now();
    }

    // Negative case first: this test's own boot thread holds no capability
    // at all (same "denied" expectation `thread_sender_unauthorized` in
    // `kernel/src/main.rs`'s own Phase B4 demo already proves for a plain
    // `spawn`-ed thread) — the request must never reach the channel.
    let denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_REQUEST_PORT as u64,
            1,
            0,
        )
    };
    if denied != u64::MAX {
        serial_println!(
            "blk_fs_ipc: FAIL — an unauthorized send to the request port was not denied \
             (returned {}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }

    for _ in 0..20 {
        scheduler::yield_now();
    }

    // Confirm the denied send really never reached blk-driver-host: no
    // response should exist yet.
    let premature = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_RECV,
            FS_RESPONSE_PORT as u64,
            0,
            0,
        )
    };
    if premature != u64::MAX {
        serial_println!(
            "blk_fs_ipc: FAIL — a response arrived on the response port before any authorized \
             request was ever sent"
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "blk_fs_ipc: unauthorized send correctly denied, no response leaked (capability gate OK)"
    );

    // Positive case: a thread holding a capability scoped to exactly the
    // request port.
    let request_token = runix_capability_manager::CapabilityToken::issue(
        "test-requester",
        runix_kernel::capabilities::port_resource(FS_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(authorized_requester_thread, Some(request_token));

    // Collect the 2-byte little-endian length header, then that many
    // payload bytes, off the response port.
    let mut response: Vec<u8> = Vec::new();
    let mut expected_len: Option<usize> = None;
    for _ in 0..4000 {
        scheduler::yield_now();
        let ret = unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_RECV,
                FS_RESPONSE_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            response.push(ret as u8);
        }
        if expected_len.is_none() && response.len() >= 2 {
            expected_len = Some(u16::from_le_bytes([response[0], response[1]]) as usize);
        }
        if let Some(len) = expected_len {
            if response.len() >= 2 + len {
                break;
            }
        }
    }

    let read_pass = match expected_len {
        Some(len) if response.len() >= 2 + len => &response[2..2 + len] == EXPECTED_FILE_CONTENTS,
        _ => false,
    };

    if read_pass {
        serial_println!(
            "blk_fs_ipc: authorized read got the exact file bytes back over capability-gated IPC"
        );
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — authorized read did not produce the expected response \
             (expected_len={:?}, got {} bytes)",
            expected_len,
            response.len()
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Filesystem driver, Phase 8, negative case: same shape as the
    // unauthorized-read check above, now for the write port -- this
    // thread holds no capability for `FS_WRITE_REQUEST_PORT` either, so
    // even a well-formed write request must never reach the channel.
    let write_denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_WRITE_REQUEST_PORT as u64,
            (IPC_WRITE_LEN as u16).to_le_bytes()[0] as u64,
            0,
        )
    };
    if write_denied != u64::MAX {
        serial_println!(
            "blk_fs_ipc: FAIL — an unauthorized send to the write port was not denied \
             (returned {}, expected u64::MAX)",
            write_denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("blk_fs_ipc: unauthorized write correctly denied (capability gate OK)");

    // Positive case: a thread holding a capability scoped to exactly the
    // write port sends a real 512-byte payload — the same "one port, one
    // capability, one file" scoping the read path already has, now
    // proven for a second, independently-gated file operation in the
    // same running server loop (Phase 8's actual point: more than one
    // request, more than one file, in a single boot).
    let write_token = runix_capability_manager::CapabilityToken::issue(
        "test-writer",
        runix_kernel::capabilities::port_resource(FS_WRITE_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(authorized_writer_thread, Some(write_token));

    let mut write_status: Option<u8> = None;
    for _ in 0..4000 {
        scheduler::yield_now();
        let ret = unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_RECV,
                FS_RESPONSE_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            write_status = Some(ret as u8);
            break;
        }
    }

    let write_pass = write_status == Some(FS_WRITE_STATUS_OK);
    if write_pass {
        serial_println!(
            "blk_fs_ipc: PASS — an authorized writer overwrote WRITE.TXT over capability-gated \
             IPC, and the same server loop served a read and a write in one boot (Phase 8)"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — authorized write did not report success (status={:?})",
            write_status
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

extern "C" fn authorized_requester_thread() -> ! {
    unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_REQUEST_PORT as u64,
            1,
            0,
        );
    }
    loop {
        scheduler::yield_now();
    }
}

/// Sends a real write request: 2-byte little-endian length header, then
/// `IPC_WRITE_LEN` payload bytes, one `SYS_IPC_SEND` per byte — matching
/// `blk-driver-host`'s `handle_write_ipc_request` wire format exactly
/// (the destination port already names the operation, so there's no
/// separate opcode byte).
extern "C" fn authorized_writer_thread() -> ! {
    let len_bytes = (IPC_WRITE_LEN as u16).to_le_bytes();
    unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_WRITE_REQUEST_PORT as u64,
            len_bytes[0] as u64,
            0,
        );
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_WRITE_REQUEST_PORT as u64,
            len_bytes[1] as u64,
            0,
        );
        for i in 0..IPC_WRITE_LEN {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_SEND,
                FS_WRITE_REQUEST_PORT as u64,
                ipc_write_pattern_byte(i) as u64,
                0,
            );
        }
    }
    loop {
        scheduler::yield_now();
    }
}

/// Same as `kernel/src/main.rs`'s function of the same name.
fn map_zeroed_contiguous_region(
    space: &mut AddressSpace,
    start_va: u64,
    page_count: u64,
    flags: PageTableFlags,
) -> u64 {
    let frames: Vec<PhysFrame> =
        runix_kernel::memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            (0..page_count)
                .map(|_| {
                    frame_allocator
                        .allocate_frame()
                        .expect("out of physical memory for blk-driver-host's virtqueue region")
                })
                .collect()
        });

    for (i, frame) in frames.iter().enumerate() {
        if i > 0 {
            assert_eq!(
                frame.start_address().as_u64(),
                frames[0].start_address().as_u64() + i as u64 * BLK_QUEUE_ALIGN,
                "blk-driver-host's virtqueue region at {start_va:#x} landed on non-contiguous \
                 physical frames"
            );
        }
        let page = Page::containing_address(VirtAddr::new(start_va + i as u64 * BLK_QUEUE_ALIGN));
        unsafe {
            space.map_existing_frame(page, *frame, flags);
        }
        let virt = runix_kernel::memory::physical_memory_offset() + frame.start_address().as_u64();
        unsafe {
            (*virt.as_mut_ptr::<[u8; 4096]>()).fill(0);
        }
    }
    frames[0].start_address().as_u64()
}

fn page_phys_addr(page: &mut [u8; 4096]) -> u64 {
    let virt = VirtAddr::from_ptr(page.as_ptr());
    virt - runix_kernel::memory::physical_memory_offset()
}

static mut ENTRY_POINT: u64 = 0;

extern "C" fn kernel_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { ENTRY_POINT };
    unsafe {
        userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(BLK_STACK_VA + BLK_STACK_SIZE),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("blk_fs_ipc: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
