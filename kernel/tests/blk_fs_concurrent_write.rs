//! Filesystem driver, concurrency — the **write half** of the gap
//! `docs/STATUS.md` named as still open after
//! `kernel/tests/blk_fs_concurrent.rs` closed the concurrent-*sender*
//! half: "allocating in response to concurrent *callers* racing each other
//! (single-writer internally remains true ... today's fix closes concurrent
//! *senders*, not concurrent *allocators*)."
//!
//! **Transport migration note**: `blk-driver-host`'s filesystem IPC
//! surface has since moved off fixed ports onto the `SYS_IPC_SESSION_*`
//! primitive — see `blk_fs_concurrent.rs`'s own migration note and
//! `runix_ipc::fs`'s doc comment for the full account. Two clients now get
//! two private sessions, so their wire bytes can no longer land in the
//! same buffer at all; what this test actually exercises is unchanged by
//! that migration (see below).
//!
//! What this test establishes, and what it deliberately does not:
//!
//! * `blk_fs_concurrent.rs` already proves two genuinely concurrent callers
//!   opening independent sessions cannot interleave their wire bytes. It
//!   proves nothing about what `blk-driver-host`'s own single execution
//!   context does once two full requests have both arrived — and read
//!   requests never mutate the disk, so a serialization bug there could
//!   not corrupt anything.
//! * This test is the mutating counterpart: two client threads spawned
//!   back-to-back with **no yield between the spawns** (so both are
//!   genuinely runnable before either gets a turn) each open their own
//!   session against [`FS_SERVER_PORT`] and send a full `FsRequest::Write`
//!   for two *different* files (`WRITE.TXT`, `PARTIAL.TXT`), each carrying
//!   a byte pattern drawn from a **disjoint value range** from the other's
//!   (`b'A'..=b'G'` vs `b'a'..=b'k'`) — so any single byte of one writer's
//!   payload landing in the other's file is detectable at every offset, not
//!   merely statistically unlikely. Both writes must report
//!   `FsResponse::Ok`, and reading each file back afterwards (over the
//!   ordinary, unmodified read path) must yield that file's own pattern and
//!   nothing else.
//!
//! That is a real demonstration that `run_fs_ipc_server`'s single
//! sequential loop finishes handling one mutating request — device round
//! trips included — before it starts decoding the next, even when both
//! requests' senders were racing each other.
//!
//! It is **not** a test of `allocate_cluster_chain` under concurrency,
//! because no concurrency exists to test it under: in this driver's
//! request-serving mode (`serve_fs_requests: 1`) nothing reachable over IPC
//! allocates at all (`handle_write_ipc_request` is fixed at exactly one
//! already-allocated sector), and every allocation call site lives in the
//! mutually exclusive `attempt_fat32` boot mode, which never enters the IPC
//! server. See `allocate_cluster_chain`'s own doc comment in
//! `blk-driver-host/src/main.rs` for that argument in full.
//!
//! **Requires the same real FAT32 fixture image** `blk_fat32_read.rs`/
//! `blk_fs_ipc.rs`/`blk_fs_concurrent.rs` do, via `RUNIX_BLK_IMG`, and
//! mutates two of its files (`WRITE.TXT`, `PARTIAL.TXT`) — run it *after*
//! any step checking those files' earlier contents, the same ordering
//! `blk_fs_ipc.rs`'s own write already requires.
//!
//! **Manual build step required when running this locally** — same as
//! `blk_fs_concurrent.rs`:
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
use runix_ipc::fs::{FsRequest, FsResponse};
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
const BLK_STACK_SIZE: u64 = 4096 * 16;
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;
const BLK_QUEUE_ALIGN: u64 = 4096;

// Must match `blk-driver-host/src/main.rs`'s own `FS_SERVER_PORT`.
const FS_SERVER_PORT: usize = 8;

/// `handle_write_ipc_request` accepts exactly one sector's worth of data
/// and nothing else — the same fixed length `blk_fs_ipc.rs`'s own write
/// already uses.
const IPC_WRITE_LEN: usize = 512;

const FILE_A: &str = "WRITE.TXT";
const FILE_B: &str = "PARTIAL.TXT";

/// Two patterns over **disjoint byte-value ranges** on purpose (see this
/// file's own doc comment): `b'A'..=b'G'` can never be mistaken for
/// `b'a'..=b'k'`, so a single stray byte from the other writer is a
/// detectable failure at every offset, not only at offsets where two
/// similar patterns happen to differ.
fn pattern_a_byte(i: usize) -> u8 {
    b'A' + (i % 7) as u8
}
fn pattern_b_byte(i: usize) -> u8 {
    b'a' + (i % 11) as u8
}

/// The fixture's `PARTIAL.TXT` is 512 bytes as built, but
/// `blk_fat32_read.rs`'s partial-write proof shrinks it to 300 if it ran
/// against this same image first (which it does in CI) — so this test
/// checks "every byte the read path returns matches this file's own
/// pattern, and there are meaningfully many of them" rather than hardcoding
/// a length that depends on which earlier tests touched the image.
const MIN_READBACK_LEN: usize = 64;

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
            serial_println!("blk_fs_concurrent_write: FAIL — no virtio-blk I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "blk-driver-host",
        BLK_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "blk_fs_concurrent_write: FAIL — CITADEL allowlist rejected blk-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(BLK_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "blk_fs_concurrent_write: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!(
                "blk_fs_concurrent_write: FAIL — load_segments() failed: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "blk_fs_concurrent_write: loaded, entry point {:#x}",
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
    // `SYS_IPC_SESSION_ACCEPT` is gated identically to
    // `SYS_IPC_SESSION_OPEN` (same `port:<n>` resource) -- `blk-driver-host`
    // itself needs this token to accept client sessions on the one server
    // port it polls.
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
        alloc::vec![fs_server_token],
    );

    // Give it time to probe the device and reach its receive loop before
    // either writer attempts anything.
    for _ in 0..50 {
        scheduler::yield_now();
    }

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

    let mut payload_a = alloc::vec![0u8; IPC_WRITE_LEN];
    for (i, byte) in payload_a.iter_mut().enumerate() {
        *byte = pattern_a_byte(i);
    }
    let mut payload_b = alloc::vec![0u8; IPC_WRITE_LEN];
    for (i, byte) in payload_b.iter_mut().enumerate() {
        *byte = pattern_b_byte(i);
    }

    let write_a = FsRequest::Write {
        name: String::from(FILE_A),
        token: file_token("test-write-a", FILE_A),
        data: payload_a,
    };
    let write_b = FsRequest::Write {
        name: String::from(FILE_B),
        token: file_token("test-write-b", FILE_B),
        data: payload_b,
    };

    // The actual point: both writers are queued *before either thread has
    // run at all* -- no yield between the two spawns -- so whichever runs
    // first genuinely races the other to open a session against
    // `FS_SERVER_PORT` and start sending, and the driver's own request loop
    // genuinely has two complete, *mutating* requests to serve back-to-back
    // rather than one full request/response round trip at a time (that
    // sequential shape is what `blk_fs_ipc.rs` already covers).
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_A = Some(write_a.encode());
    }
    scheduler::spawn_with_capability(
        send_request_thread_a,
        Some(server_port_token("test-write-a")),
    );
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_B = Some(write_b.encode());
    }
    scheduler::spawn_with_capability(
        send_request_thread_b,
        Some(server_port_token("test-write-b")),
    );

    // Wait for both concurrent writers' own independent request/response
    // round trips to finish -- order is whichever writer's session got
    // accepted and served first, which this test deliberately does not
    // assume either way (both responses are `FsResponse::Ok`,
    // indistinguishable by construction; the *disk* is where the two
    // writers' work is told apart, below).
    for _ in 0..400_000u32 {
        scheduler::yield_now();
        if DONE_A.load(Ordering::SeqCst) && DONE_B.load(Ordering::SeqCst) {
            break;
        }
    }
    #[allow(static_mut_refs)]
    let first = unsafe { RESULT_A.take() };
    #[allow(static_mut_refs)]
    let second = unsafe { RESULT_B.take() };
    let both_ok = matches!(first, Some(FsResponse::Ok)) && matches!(second, Some(FsResponse::Ok));
    if !both_ok {
        serial_println!(
            "blk_fs_concurrent_write: FAIL — the two concurrent writes did not both report Ok \
             (first={:?}, second={:?})",
            first,
            second
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "blk_fs_concurrent_write: both concurrent writers got FsResponse::Ok — now checking what \
         actually landed on disk"
    );

    // Read both files back through the ordinary, unmodified read path --
    // sequentially this time, since what is under test here is the *state
    // the two concurrent writes left behind*, not the read path's own
    // concurrency (already covered by `blk_fs_concurrent.rs`).
    let readback_a = read_file(
        FILE_A,
        server_port_token("test-read-a"),
        file_token("test-read-a", FILE_A),
    );
    let readback_b = read_file(
        FILE_B,
        server_port_token("test-read-b"),
        file_token("test-read-b", FILE_B),
    );

    let a_ok = check_readback(FILE_A, &readback_a, pattern_a_byte);
    let b_ok = check_readback(FILE_B, &readback_b, pattern_b_byte);

    if a_ok && b_ok {
        serial_println!(
            "blk_fs_concurrent_write: PASS — two client threads opening sessions and sending \
             *write* requests against the same server port at genuinely the same time (no yield \
             between spawns) both completed, and each file holds exactly its own writer's byte \
             pattern with no byte of the other's anywhere in it — the driver's single sequential \
             request loop finished handling one mutating request, device round trips included, \
             before starting the next"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fs_concurrent_write: FAIL — concurrent writes did not leave both files intact"
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

/// Every returned byte must match `expected`'s pattern at its own offset,
/// and there must be a meaningful number of them — see
/// [`MIN_READBACK_LEN`]'s doc comment for why the length itself is not
/// hardcoded.
fn check_readback(name: &str, response: &Option<FsResponse>, expected: fn(usize) -> u8) -> bool {
    match response {
        Some(FsResponse::Data(bytes)) => {
            if bytes.len() < MIN_READBACK_LEN {
                serial_println!(
                    "blk_fs_concurrent_write: FAIL — read-back of {} returned only {} bytes",
                    name,
                    bytes.len()
                );
                return false;
            }
            for (i, &byte) in bytes.iter().enumerate() {
                if byte != expected(i) {
                    serial_println!(
                        "blk_fs_concurrent_write: FAIL — {} byte {} is {:#04x}, expected {:#04x} \
                         (a byte of the *other* concurrent writer's payload, or corruption)",
                        name,
                        i,
                        byte,
                        expected(i)
                    );
                    return false;
                }
            }
            serial_println!(
                "blk_fs_concurrent_write: {} holds {} bytes of exactly its own writer's pattern",
                name,
                bytes.len()
            );
            true
        }
        other => {
            serial_println!(
                "blk_fs_concurrent_write: FAIL — read-back of {} returned {:?}, expected Data",
                name,
                other
            );
            false
        }
    }
}

/// One sequential read request/response round trip, on a freshly spawned
/// thread holding exactly the two capabilities it needs (the server port,
/// and the file itself), opening its own session and waiting for its own
/// response.
fn read_file(
    name: &str,
    read_port_token: CapabilityToken,
    file_token: CapabilityToken,
) -> Option<FsResponse> {
    let request = FsRequest::Read {
        name: String::from(name),
        token: file_token,
    };
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_SEQ = Some(request.encode());
    }
    DONE_SEQ.store(false, Ordering::SeqCst);
    scheduler::spawn_with_capability(send_request_thread_seq, Some(read_port_token));
    for _ in 0..200_000u32 {
        scheduler::yield_now();
        if DONE_SEQ.load(Ordering::SeqCst) {
            break;
        }
    }
    #[allow(static_mut_refs)]
    unsafe {
        RESULT_SEQ.take()
    }
}

static mut PENDING_SEND_A: Option<Vec<u8>> = None;
static mut PENDING_SEND_B: Option<Vec<u8>> = None;
static mut RESULT_A: Option<FsResponse> = None;
static mut RESULT_B: Option<FsResponse> = None;
static DONE_A: AtomicBool = AtomicBool::new(false);
static DONE_B: AtomicBool = AtomicBool::new(false);
/// Reused across the two *sequential* read-backs (never two in flight at
/// once — each `read_file` call waits for its own full response before the
/// next one starts), unlike the two concurrent writers above, which need a
/// slot each precisely because both are queued before either runs.
static mut PENDING_SEND_SEQ: Option<Vec<u8>> = None;
static mut RESULT_SEQ: Option<FsResponse> = None;
static DONE_SEQ: AtomicBool = AtomicBool::new(false);

extern "C" fn send_request_thread_a() -> ! {
    #[allow(static_mut_refs)]
    let bytes =
        unsafe { PENDING_SEND_A.take() }.expect("send_request_thread_a: no pending send");
    let response = session_round_trip(bytes);
    #[allow(static_mut_refs)]
    unsafe {
        RESULT_A = response;
    }
    DONE_A.store(true, Ordering::SeqCst);
    loop {
        scheduler::yield_now();
    }
}

extern "C" fn send_request_thread_b() -> ! {
    #[allow(static_mut_refs)]
    let bytes =
        unsafe { PENDING_SEND_B.take() }.expect("send_request_thread_b: no pending send");
    let response = session_round_trip(bytes);
    #[allow(static_mut_refs)]
    unsafe {
        RESULT_B = response;
    }
    DONE_B.store(true, Ordering::SeqCst);
    loop {
        scheduler::yield_now();
    }
}

extern "C" fn send_request_thread_seq() -> ! {
    #[allow(static_mut_refs)]
    let bytes =
        unsafe { PENDING_SEND_SEQ.take() }.expect("send_request_thread_seq: no pending send");
    let response = session_round_trip(bytes);
    #[allow(static_mut_refs)]
    unsafe {
        RESULT_SEQ = response;
    }
    DONE_SEQ.store(true, Ordering::SeqCst);
    loop {
        scheduler::yield_now();
    }
}

/// Same as `blk_fs_concurrent.rs`'s function of the same name: opens a
/// fresh session against [`FS_SERVER_PORT`], sends `bytes` (an
/// already-encoded [`FsRequest`]) holding the session's send lock for the
/// entire message, then accumulates bytes back off that same session
/// until [`FsResponse::decode`] reports a complete message or a generous
/// bound of polls passes with nothing decodable.
fn session_round_trip(bytes: Vec<u8>) -> Option<FsResponse> {
    let session_id = loop {
        let ret =
            unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, FS_SERVER_PORT as u64, 0, 0) };
        if ret != u64::MAX {
            break ret;
        }
        scheduler::yield_now();
    };

    unsafe {
        syscall::syscall(SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0);
    }
    for byte in bytes {
        loop {
            let ret =
                unsafe { syscall::syscall(SYS_IPC_SESSION_SEND, session_id, byte as u64, 0) };
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
    serial_println!("blk_fs_concurrent_write: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
