//! Filesystem driver: concurrency/locking, the last gap named but
//! deliberately deferred by `blk-driver-host/src/main.rs`'s
//! `run_fs_ipc_server` doc comment. The concrete hazard that doc comment
//! named: a single `FsRequest` — even the smallest `Read` — already
//! exceeds `kernel::ipc`'s `CHANNEL_CAPACITY` (32 bytes) once its embedded
//! `CapabilityToken` is encoded (over a kilobyte on its own — see
//! `runix_ipc::fs`'s own size constants), so a sender's sole chance to
//! finish one message atomically depends on nothing else landing bytes on
//! the same port while `SYS_IPC_SEND`'s own per-byte loop is mid-message.
//! Two callers sending to the *same* port at genuinely the same time (both
//! spawned back-to-back, before either gets to run at all) used to be able
//! to interleave their bytes into a single franken-message neither sender
//! intended and the receiver had no way to detect after the fact.
//!
//! `kernel::ipc::begin_send`/`end_send` (backed by the new
//! `SYS_IPC_SEND_LOCK`/`SYS_IPC_SEND_UNLOCK` syscalls, capability-gated
//! identically to `SYS_IPC_SEND` itself) close this: a sender holds a
//! port's advisory lock for its entire message, so a second, concurrent
//! sender's `begin_send` on that same port blocks until the first calls
//! `end_send` — the two byte streams can only ever land back-to-back, never
//! interleaved.
//!
//! This test spawns **two** client threads back-to-back (no yield between
//! the two spawns, so both are genuinely ready to run before either gets a
//! turn — the actual "concurrent" scenario `run_fs_ipc_server`'s doc
//! comment described), each sending a `Read` request for a *different*
//! file over the *same* `FS_REQUEST_PORT`, and confirms both get back
//! their own, correct, uncorrupted file contents — not each other's, not a
//! decode failure, not a hang. Reuses the same fixture files
//! `blk_fs_ipc.rs` already proves individually (`HELLO.TXT`/`BIG.TXT`), so
//! a regression here is unambiguous: if this test fails while
//! `blk_fs_ipc.rs` still passes, the bug is specifically in concurrent
//! handling, not in the read path itself.
//!
//! **Requires the same real FAT32 fixture image** `blk_fat32_read.rs`/
//! `blk_fs_ipc.rs` do, via `RUNIX_BLK_IMG`.
//!
//! **Manual build step required when running this locally** — same as
//! `blk_fs_ipc.rs`:
//!
//! ```text
//! cd blk-driver-host && cargo build --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_capability_manager::CapabilityToken;
use runix_ipc::fs::{FsRequest, FsResponse};
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
const BLK_STACK_SIZE: u64 = 4096 * 16;
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;
const BLK_QUEUE_ALIGN: u64 = 4096;

// Must match `blk-driver-host/src/main.rs`'s own `FS_REQUEST_PORT`/
// `FS_RESPONSE_PORT`.
const FS_REQUEST_PORT: usize = 8;
const FS_RESPONSE_PORT: usize = 9;

// Same fixture files `blk_fs_ipc.rs` already proves individually.
const EXPECTED_HELLO_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem.\n";
const BIG_FILE_LEN: usize = 3000;
fn expected_big_file_byte(i: usize) -> u8 {
    b'0' + (i % 10) as u8
}

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
            serial_println!("blk_fs_concurrent: FAIL — no virtio-blk I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "blk-driver-host",
        BLK_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "blk_fs_concurrent: FAIL — CITADEL allowlist rejected blk-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(BLK_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "blk_fs_concurrent: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("blk_fs_concurrent: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "blk_fs_concurrent: loaded, entry point {:#x}",
        entry.as_u64()
    );

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
    let blk_token = CapabilityToken::issue(
        "blk-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    let response_token = CapabilityToken::issue(
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

    // Give it time to probe the device and reach its receive loop before
    // either requester attempts anything.
    for _ in 0..50 {
        scheduler::yield_now();
    }

    let request_port_token = |subject: &str| {
        CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::port_resource(FS_REQUEST_PORT),
            now,
            now + 1_000_000,
            "demo-key",
            &signing_key,
        )
    };
    let file_token = |subject: &str, file_name: &str| {
        CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::file_resource(file_name),
            now,
            now + 1_000_000,
            "demo-key",
            &signing_key,
        )
    };

    let hello_request = FsRequest::Read {
        name: String::from("HELLO.TXT"),
        token: file_token("test-hello", "HELLO.TXT"),
    };
    let big_request = FsRequest::Read {
        name: String::from("BIG.TXT"),
        token: file_token("test-big", "BIG.TXT"),
    };

    // The actual point: both sends are queued *before either thread has run
    // at all* -- no yield between the two spawns -- so whichever runs first
    // genuinely races the other for `FS_REQUEST_PORT`'s send lock, instead
    // of completing a full request/response round trip before the second
    // request is even sent (that sequential shape is what `blk_fs_ipc.rs`
    // already covers).
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_A = Some((FS_REQUEST_PORT, hello_request.encode()));
    }
    scheduler::spawn_with_capability(
        send_request_thread_a,
        Some(request_port_token("test-hello")),
    );
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_B = Some((FS_REQUEST_PORT, big_request.encode()));
    }
    scheduler::spawn_with_capability(send_request_thread_b, Some(request_port_token("test-big")));

    // Collect exactly two responses off the shared response port -- order
    // is whichever thread won the send lock first, which this test
    // deliberately doesn't assume either way (see the set-membership check
    // below instead of an ordered one).
    let first = recv_fs_response(80_000);
    let second = recv_fs_response(80_000);

    let matches_hello = |resp: &Option<FsResponse>| matches!(resp, Some(FsResponse::Data(bytes)) if bytes.as_slice() == EXPECTED_HELLO_CONTENTS);
    let matches_big = |resp: &Option<FsResponse>| match resp {
        Some(FsResponse::Data(bytes)) => {
            bytes.len() == BIG_FILE_LEN
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == expected_big_file_byte(i))
        }
        _ => false,
    };

    let both_correct = (matches_hello(&first) && matches_big(&second))
        || (matches_hello(&second) && matches_big(&first));

    if both_correct {
        serial_println!(
            "blk_fs_concurrent: PASS — two client threads sending to the same request port at \
             genuinely the same time (no yield between spawns) each got back their own, exact, \
             uncorrupted file contents — the send lock serialized them correctly instead of \
             letting their bytes interleave"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fs_concurrent: FAIL — concurrent requests did not both come back correct \
             (first={:?}, second={:?})",
            first,
            second
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

static mut PENDING_SEND_A: Option<(usize, Vec<u8>)> = None;
static mut PENDING_SEND_B: Option<(usize, Vec<u8>)> = None;

extern "C" fn send_request_thread_a() -> ! {
    #[allow(static_mut_refs)]
    let (port, bytes) =
        unsafe { PENDING_SEND_A.take() }.expect("send_request_thread_a: no pending send");
    send_locked_message(port, bytes);
    loop {
        scheduler::yield_now();
    }
}

extern "C" fn send_request_thread_b() -> ! {
    #[allow(static_mut_refs)]
    let (port, bytes) =
        unsafe { PENDING_SEND_B.take() }.expect("send_request_thread_b: no pending send");
    send_locked_message(port, bytes);
    loop {
        scheduler::yield_now();
    }
}

/// Sends every byte of `bytes` on `port`, holding `port`'s send lock for
/// the entire message — the actual mechanism this test exists to prove
/// (`kernel::ipc::begin_send`/`end_send`, `SYS_IPC_SEND_LOCK`/
/// `SYS_IPC_SEND_UNLOCK`).
fn send_locked_message(port: usize, bytes: Vec<u8>) {
    unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND_LOCK, port as u64, 0, 0);
    }
    for byte in bytes {
        unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_SEND,
                port as u64,
                byte as u64,
                0,
            );
        }
    }
    unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND_UNLOCK,
            port as u64,
            0,
            0,
        );
    }
}

/// Same as `blk_fs_ipc.rs`'s function of the same name.
fn recv_fs_response(max_iters: u32) -> Option<FsResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..max_iters {
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
            buf.push(ret as u8);
            if let Some((response, _consumed)) = FsResponse::decode(&buf) {
                return Some(response);
            }
        }
    }
    None
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
    serial_println!("blk_fs_concurrent: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
