//! Filesystem driver, Phase 3 (see docs/STATUS.md's filesystem-driver
//! narrative): proves the actual gap Phase 2 left open — nothing outside
//! `blk-driver-host` itself could ask it for a file. Spawns
//! `blk-driver-host` in its new request-serving mode
//! (`serve_fs_requests: 1`) against the Phase 2 FAT32 fixture, then proves
//! both directions of capability scoping over the real session IPC
//! syscalls (`SYS_IPC_SESSION_OPEN`/`SYS_IPC_SESSION_SEND`/
//! `SYS_IPC_SESSION_RECV`, `kernel/src/syscall.rs`): a thread holding no
//! capability at all is denied when it tries to open a session (the same
//! way `kernel/src/main.rs`'s own Phase B4 demo proves
//! `thread_sender_unauthorized` is denied), and a thread holding a
//! capability scoped to exactly the server port gets the exact file bytes
//! back over that same session.
//!
//! This is also the first real exercise of `Thread::extra_capabilities`
//! (`kernel/src/scheduler.rs`) — `blk-driver-host` itself now holds *two*
//! capabilities at once (its usual virtio-blk io-port range, plus a new
//! one scoped to the filesystem server port it accepts sessions on), which
//! is exactly the scenario that field exists for.
//!
//! Filesystem driver, Phase 8 extended this same boot with write requests,
//! and the structural gap closed here generalizes the wire format from
//! "one fixed file per port, one trigger byte" into a real, typed
//! [`runix_ipc::fs::FsRequest`] carrying an arbitrary filename *and* a
//! per-file [`runix_capability_manager::CapabilityToken`] on every single
//! request — verified by `blk-driver-host` itself (`verify_file_token`),
//! not just by the kernel's own port-level `SYS_IPC_SESSION_OPEN` gate.
//! Proven three ways past what Phase 8 already covered: **two different
//! files** (`HELLO.TXT`, `BIG.TXT`) served successfully over the *same*
//! session-server port in one boot (Phase 8 could only ever serve one
//! fixed file); a caller holding a perfectly valid port-level capability
//! but a file-scoped token minted for a *different* file gets
//! [`runix_ipc::fs::FsError::Unauthorized`], not the file's contents — the
//! actual point of per-request authorization, since the coarse port-level
//! gate alone would have let this caller through; and the same
//! mismatched-token denial proven again for the write path.
//!
//! **Transport**: migrated off the old fixed-port-plus-embedded-
//! response-token transport onto the `SYS_IPC_SESSION_*` primitive
//! (`kernel/tests/ipc_session.rs` proves the primitive itself) — each
//! logical client below opens its own session against
//! [`FS_SERVER_PORT`], sends one `FsRequest`, and reads back one
//! `FsResponse` on that same session, rather than sharing one fixed
//! request port and naming a response port inside the request. See
//! `runix_ipc::fs`'s own doc comment for why `FsRequest` no longer carries
//! `response_port`/`response_token` fields at all.
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

const IPC_WRITE_LEN: usize = 512;
fn ipc_write_pattern_byte(i: usize) -> u8 {
    b'z' - (i % 26) as u8
}

// Must match `blk-driver-host/src/main.rs`'s own `EXPECTED_FILE_CONTENTS`
// and `kernel/tests/support/make_fat32_image.sh`'s fixture byte-for-byte.
const EXPECTED_FILE_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem.\n";

// Matches `blk-driver-host/src/main.rs`'s own `BIG_FILE_LEN`/
// `expected_big_file_byte` -- the second, independently-named file this
// test requests over the *same* read port as `HELLO.TXT`, proving the
// dynamic-filename lookup actually varies by request rather than always
// resolving to whatever `blk-driver-host` happened to locate at boot.
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
        alloc::vec![fs_server_token],
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
    let denied =
        unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, FS_SERVER_PORT as u64, 0, 0) };
    if denied != u64::MAX {
        serial_println!(
            "blk_fs_ipc: FAIL — an unauthorized session open was not denied \
             (returned {:#x}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("blk_fs_ipc: unauthorized session open correctly denied (capability gate OK)");

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

    // Case 1 (item 1 -- dynamic filenames): read `HELLO.TXT` by name over
    // the same server port Phase 3/8 already proved, now over a real
    // session carrying a real `FsRequest::Read` instead of a fixed trigger
    // byte on a fixed port.
    let hello_token = file_token("test-hello", "HELLO.TXT");
    let hello_request = FsRequest::Read {
        name: String::from("HELLO.TXT"),
        token: hello_token,
    };
    let hello_response =
        send_fs_request_and_recv(server_port_token("test-hello"), hello_request.encode());
    let hello_pass = matches!(&hello_response, Some(FsResponse::Data(bytes)) if bytes.as_slice() == EXPECTED_FILE_CONTENTS);
    if hello_pass {
        serial_println!(
            "blk_fs_ipc: authorized dynamic read of HELLO.TXT got the exact file bytes back"
        );
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — dynamic read of HELLO.TXT did not produce the expected response \
             (got {:?})",
            hello_response
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Case 2 (item 1, continued -- a *second*, different file over the
    // *same* server instance and the *same* port, proving this driver's
    // lookup genuinely varies per request rather than always resolving to
    // whatever it happened to locate once at boot): `BIG.TXT`.
    let big_token = file_token("test-big", "BIG.TXT");
    let big_request = FsRequest::Read {
        name: String::from("BIG.TXT"),
        token: big_token,
    };
    let big_response =
        send_fs_request_and_recv(server_port_token("test-big"), big_request.encode());
    let big_pass = match &big_response {
        Some(FsResponse::Data(bytes)) => {
            bytes.len() == BIG_FILE_LEN
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == expected_big_file_byte(i))
        }
        _ => false,
    };
    if big_pass {
        serial_println!(
            "blk_fs_ipc: authorized dynamic read of BIG.TXT (a second, different file over the \
             same port) got the exact file bytes back"
        );
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — dynamic read of BIG.TXT did not produce the expected response"
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Case 3 (item 2 -- per-caller dynamic authorization, the actual
    // point): a caller with a perfectly valid *port-level* capability, but
    // whose *file-scoped* token was minted for `HELLO.TXT`, requests
    // `BIG.TXT` instead. If the coarse port-level gate were the only
    // authorization checked, this would succeed -- it must not.
    let mismatched_token = file_token("test-mismatch", "HELLO.TXT");
    let mismatched_request = FsRequest::Read {
        name: String::from("BIG.TXT"),
        token: mismatched_token,
    };
    let mismatched_response = send_fs_request_and_recv(
        server_port_token("test-mismatch"),
        mismatched_request.encode(),
    );
    let mismatched_pass = matches!(
        mismatched_response,
        Some(FsResponse::Error(FsError::Unauthorized))
    );
    if mismatched_pass {
        serial_println!(
            "blk_fs_ipc: PASS — a valid port-level capability with a file-token scoped to a \
             *different* file was correctly denied (Unauthorized), not served BIG.TXT's \
             contents (per-caller dynamic authorization OK)"
        );
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — a mismatched file-scoped token was not denied \
             (got {:?}, expected Error(Unauthorized))",
            mismatched_response
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Filesystem driver, Phase 8, negative case, generalized: the earlier
    // unauthorized-session-open check already covers the write path too
    // now that reads and writes share one server port (`FS_SERVER_PORT`'s
    // own doc comment) -- no separate write-port denial to re-prove here.

    // Case 4 (item 2, write path): a valid port-level capability, but a
    // file-scoped token minted for the wrong file (`HELLO.TXT` instead of
    // `WRITE.TXT`) -- must be denied, and must not touch the disk.
    let mismatched_write_token = file_token("test-write-mismatch", "HELLO.TXT");
    let mut mismatched_payload = alloc::vec![0u8; IPC_WRITE_LEN];
    for (i, byte) in mismatched_payload.iter_mut().enumerate() {
        *byte = ipc_write_pattern_byte(i);
    }
    let mismatched_write_request = FsRequest::Write {
        name: String::from("WRITE.TXT"),
        token: mismatched_write_token,
        data: mismatched_payload,
    };
    let mismatched_write_response = send_fs_request_and_recv(
        server_port_token("test-write-mismatch"),
        mismatched_write_request.encode(),
    );
    let mismatched_write_pass = matches!(
        mismatched_write_response,
        Some(FsResponse::Error(FsError::Unauthorized))
    );
    if mismatched_write_pass {
        serial_println!(
            "blk_fs_ipc: PASS — a write request with a file-token scoped to the wrong file was \
             correctly denied (Unauthorized), not written to WRITE.TXT"
        );
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — a mismatched write file-token was not denied \
             (got {:?}, expected Error(Unauthorized))",
            mismatched_write_response
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Positive case: a thread holding a capability scoped to exactly the
    // write port *and* a file-scoped token that actually matches
    // `WRITE.TXT` sends a real 512-byte payload -- the same "one file, one
    // matching token" scoping the read path already proved, now for the
    // write path, over the same server loop that already served three
    // reads and one denied write in this same boot.
    let write_token = file_token("test-writer", "WRITE.TXT");
    let mut write_payload = alloc::vec![0u8; IPC_WRITE_LEN];
    for (i, byte) in write_payload.iter_mut().enumerate() {
        *byte = ipc_write_pattern_byte(i);
    }
    let write_request = FsRequest::Write {
        name: String::from("WRITE.TXT"),
        token: write_token,
        data: write_payload,
    };
    let write_response =
        send_fs_request_and_recv(server_port_token("test-writer"), write_request.encode());
    let write_pass = matches!(write_response, Some(FsResponse::Ok));

    if write_pass {
        serial_println!(
            "blk_fs_ipc: PASS — an authorized writer (matching port *and* file-scoped tokens) \
             overwrote WRITE.TXT over capability-gated IPC, and the same server loop served \
             two dynamically-named reads, two denied mismatched-token attempts, and one \
             authorized write in one boot"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fs_ipc: FAIL — authorized write did not report success (got {:?})",
            write_response
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
        "blk_fs_ipc: session_request_thread opened session {} len={}",
        session_id,
        bytes.len()
    );

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
    serial_println!("blk_fs_ipc: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
