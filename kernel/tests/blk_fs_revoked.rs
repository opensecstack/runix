//! Regression test: a file capability token that is validly signed and
//! unexpired but has been *revoked* (kernel-side, `capabilities::revoke`)
//! must be refused by `blk-driver-host`. The driver cannot see the kernel's
//! revocation list directly; it asks via `SYS_CAP_IS_REVOKED` (gated on the
//! `revocation:query` capability the driver is spawned with) and fails
//! closed. Flow: read `HELLO.TXT` with a fresh file token (succeeds),
//! revoke exactly that token, send the SAME token again (must be
//! `Unauthorized`), then confirm a different, unrevoked token for the same
//! file still works.
//!
//! Read-only against the fixture image (never modifies any checked file),
//! so it can run anywhere in CI after the write-asserting steps. Same
//! `RUNIX_BLK_IMG` FAT32 fixture and manual build step as `blk_fs_ipc.rs`:
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
use core::sync::atomic::{AtomicBool, Ordering};
use runix_capability_manager::CapabilityToken;
use runix_ipc::fs::{FsError, FsRequest, FsResponse};
use runix_kernel::elf::Elf64;
use runix_kernel::process::AddressSpace;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use runix_kernel::syscall::{
    self, SYS_IPC_SESSION_OPEN, SYS_IPC_SESSION_RECV, SYS_IPC_SESSION_SEND,
    SYS_IPC_SESSION_SEND_LOCK, SYS_IPC_SESSION_SEND_UNLOCK,
};
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
/// Bumped from `4096 * 4` (16 KiB): `blk-driver-host` now verifies a real
/// Ed25519 signature (`verify_file_token`) on every request this test
/// sends, the same unoptimized-crypto-stack-hungriness
/// `kernel/Cargo.toml`'s own `[profile.dev.package.*]` overrides already
/// document for the exact same dependency tree. `blk-driver-host`'s own
/// `Cargo.toml` carries the matching `opt-level = 3` overrides for a debug
/// build, but this is extra headroom on top, the same "size bump, not a
/// substitute for the real fix" reasoning `kernel/src/main.rs`'s
/// `BOOTLOADER_CONFIG` comment already gives for the boot stack.
const BLK_STACK_SIZE: u64 = 4096 * 16;
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;
const BLK_QUEUE_ALIGN: u64 = 4096;

// Must match `blk-driver-host/src/main.rs`'s own `FS_SERVER_PORT`.
const FS_SERVER_PORT: usize = 8;

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
            serial_println!("blk_fs_revoked: FAIL — no virtio-blk I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "blk-driver-host",
        BLK_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "blk_fs_revoked: FAIL — CITADEL allowlist rejected blk-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(BLK_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "blk_fs_revoked: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("blk_fs_revoked: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!("blk_fs_revoked: loaded, entry point {:#x}", entry.as_u64());

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
    // The second capability `blk-driver-host` needs to accept client
    // sessions at all — `Thread::extra_capabilities`'s whole reason for
    // existing (see `kernel/src/scheduler.rs`'s doc comment). One grant
    // now covers both read and write requests (the `FsRequest` enum tag
    // distinguishes them once a session is open) — the old fixed-port
    // transport needed a separate recv token per port.
    let fs_server_token = CapabilityToken::issue(
        "blk-driver-host",
        runix_kernel::capabilities::port_resource(FS_SERVER_PORT),
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
        alloc::vec![
            fs_server_token,
            // SYS_CAP_IS_REVOKED gate: without this the driver fails closed on every request.
            CapabilityToken::issue(
                "blk-driver-host",
                runix_kernel::capabilities::revocation_query_resource(),
                now,
                now + 1_000_000,
                "demo-key",
                &signing_key,
            ),
        ],
    );

    // Give it time to probe the device, locate HELLO.TXT, and reach its
    // receive loop before either requester attempts anything.
    for _ in 0..50 {
        scheduler::yield_now();
    }

    // Negative case first: a thread holding no capability at all is denied
    // `SYS_IPC_SESSION_OPEN` against `FS_SERVER_PORT` (same "denied"
    // expectation `thread_sender_unauthorized` in `kernel/src/main.rs`'s
    // own Phase B4 demo already proves for a plain `spawn`-ed thread, now
    // for session-open instead of a fixed-port send) — no session is ever
    // created, so there is nothing further to poll for (unlike the old
    // shared-response-port transport, there's no separate "confirm nothing
    // leaked" check needed: a session that was never opened has no
    // channel a response could possibly arrive on). Since reads and
    // writes now share this one server port (see `FS_SERVER_PORT`'s own
    // doc comment), this single check covers what used to be two separate
    // denied-send checks, one per port.
    let denied = unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, FS_SERVER_PORT as u64, 0, 0) };
    if denied != u64::MAX {
        serial_println!(
            "blk_fs_revoked: FAIL — an unauthorized session open was not denied \
             (returned {:#x}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "blk_fs_revoked: unauthorized session open correctly denied (capability gate OK)"
    );

    // Structural gap closed: dynamic filenames + per-request authorization.
    // A port-level capability (`port_resource(FS_SERVER_PORT)`) is now
    // only a coarse "may open a session against the filesystem service at
    // all" grant -- which *file* that session's requests are allowed to
    // touch is authorized separately, per request, by a `CapabilityToken`
    // scoped to `file:<name>` that `blk-driver-host` itself verifies
    // (`verify_file_token`). Every case below issues its own fresh
    // port-level token (a real system would let many callers share one,
    // but a fresh one per case keeps each proof independent) plus
    // whatever file-scoped token that case actually needs.
    let server_port_token = |subject: &str| {
        CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::port_resource(FS_SERVER_PORT),
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
    let server_port_token = |subject: &str| {
        CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::port_resource(FS_SERVER_PORT),
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
    let read_hello = |file_token: CapabilityToken, subject: &str| {
        let request = FsRequest::Read {
            name: String::from("HELLO.TXT"),
            token: file_token,
        };
        send_fs_request_and_recv(server_port_token(subject), request.encode())
    };

    // Step 1: a fresh, valid, unrevoked token reads HELLO.TXT.
    let revoked_token = file_token("test-revoked", "HELLO.TXT");
    let first = read_hello(revoked_token.clone(), "test-revoked-1");
    if !matches!(&first, Some(FsResponse::Data(bytes)) if bytes.as_slice() == EXPECTED_FILE_CONTENTS)
    {
        serial_println!(
            "blk_fs_revoked: FAIL — unrevoked token did not read HELLO.TXT (got {:?})",
            first
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("blk_fs_revoked: unrevoked file token read HELLO.TXT OK");

    // Step 2: revoke that exact token kernel-side. Signature and expiry are
    // still valid; only the revocation list differs.
    runix_kernel::capabilities::revoke(&revoked_token);
    if !runix_kernel::capabilities::is_revoked(&revoked_token) {
        serial_println!("blk_fs_revoked: FAIL — revoke() did not take effect");
        exit_qemu(QemuExitCode::Failed);
    }

    // Step 3: the SAME token must now be refused by the driver.
    let second = read_hello(revoked_token, "test-revoked-2");
    if matches!(second, Some(FsResponse::Error(FsError::Unauthorized))) {
        serial_println!(
            "blk_fs_revoked: PASS — a revoked-but-unexpired file token was refused \
             (Unauthorized)"
        );
    } else {
        serial_println!(
            "blk_fs_revoked: FAIL — revoked token was not refused (got {:?}, expected \
             Error(Unauthorized))",
            second
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Step 4: control -- a different, unrevoked token for the same file
    // still works, so the denial above is the revocation and not a broken
    // query path failing everything closed.
    let third = read_hello(file_token("test-unrevoked", "HELLO.TXT"), "test-revoked-3");
    if matches!(&third, Some(FsResponse::Data(bytes)) if bytes.as_slice() == EXPECTED_FILE_CONTENTS)
    {
        serial_println!("blk_fs_revoked: PASS — a different unrevoked token still reads HELLO.TXT");
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fs_revoked: FAIL — unrevoked control token was refused (got {:?})",
            third
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

/// One full request/response round trip over a fresh session: opens a
/// session against [`FS_SERVER_PORT`] (retry-looping on `u64::MAX`, same
/// convention `kernel/tests/ipc_session.rs`'s own `open_session_blocking`
/// uses), sends `bytes` (an already-encoded [`FsRequest`]) locked as one
/// message, then accumulates bytes back off that same session until
/// [`FsResponse::decode`] reports a complete message or a generous bound
/// of polls passes with nothing decodable. All of this runs on one freshly
/// spawned thread holding `port_token` -- necessarily so, since a
/// session's `SEND`/`RECV` is only ever available to its own owner or
/// accepted server (`kernel/src/ipc.rs`'s `is_participant`), identified by
/// `ThreadId`, not by which thread merely knows the session id. Reuses one
/// pair of statics across sequential calls (never two calls in flight at
/// once in this test -- every call here waits for its own full response
/// before the next one starts; `blk_fs_concurrent.rs`/
/// `blk_fs_concurrent_write.rs` are the ones that actually need two
/// requests in flight, and use their own per-thread slots for that
/// reason).
fn send_fs_request_and_recv(port_token: CapabilityToken, bytes: Vec<u8>) -> Option<FsResponse> {
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_REQUEST_BYTES = bytes;
    }
    RESPONSE_READY.store(false, Ordering::SeqCst);
    scheduler::spawn_with_capability(session_request_thread, Some(port_token));
    for _ in 0..200_000u32 {
        scheduler::yield_now();
        if RESPONSE_READY.load(Ordering::SeqCst) {
            break;
        }
    }
    #[allow(static_mut_refs)]
    unsafe {
        RESPONSE_BUF.take()
    }
}

static mut PENDING_REQUEST_BYTES: Vec<u8> = Vec::new();
static RESPONSE_READY: AtomicBool = AtomicBool::new(false);
static mut RESPONSE_BUF: Option<FsResponse> = None;

extern "C" fn session_request_thread() -> ! {
    // Copies the pending-request static into a local *before* doing
    // anything else, so the next `send_fs_request_and_recv` call is free
    // to overwrite it the moment this thread has started running -- this
    // thread never touches that static again afterward.
    #[allow(static_mut_refs)]
    let bytes = unsafe { core::mem::take(&mut PENDING_REQUEST_BYTES) };

    let session_id = loop {
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, FS_SERVER_PORT as u64, 0, 0) };
        if ret != u64::MAX {
            break ret;
        }
        scheduler::yield_now();
    };
    serial_println!(
        "blk_fs_revoked: session_request_thread opened session {} len={}",
        session_id,
        bytes.len()
    );

    unsafe {
        syscall::syscall(SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0);
    }
    for byte in bytes {
        loop {
            let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_SEND, session_id, byte as u64, 0) };
            if ret != u64::MAX {
                break;
            }
            scheduler::yield_now();
        }
    }
    unsafe {
        syscall::syscall(SYS_IPC_SESSION_SEND_UNLOCK, session_id, 0, 0);
    }

    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..200_000u32 {
        scheduler::yield_now();
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_RECV, session_id, 0, 0) };
        if ret != u64::MAX {
            buf.push(ret as u8);
            if let Some((response, _consumed)) = FsResponse::decode(&buf) {
                #[allow(static_mut_refs)]
                unsafe {
                    RESPONSE_BUF = Some(response);
                }
                RESPONSE_READY.store(true, Ordering::SeqCst);
                break;
            }
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
    serial_println!("blk_fs_revoked: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
