//! Filesystem driver, Phase 3 (see docs/STATUS.md's filesystem-driver
//! narrative): proves the actual gap Phase 2 left open — nothing outside
//! `blk-driver-host` itself could ask it for a file. Spawns
//! `blk-driver-host` in its new request-serving mode
//! (`serve_fs_requests: 1`) against the Phase 2 FAT32 fixture, then proves
//! both directions of capability scoping over the real IPC syscalls
//! (`SYS_IPC_SEND`/`SYS_IPC_RECV`, `kernel/src/syscall.rs`): a thread
//! holding no capability at all is denied when it tries to send a
//! request (the same way `kernel/src/main.rs`'s own Phase B4 demo proves
//! `thread_sender_unauthorized` is denied), and a thread holding a
//! capability scoped to exactly the request port gets the exact file
//! bytes back over the response port.
//!
//! This is also the first real exercise of `Thread::extra_capabilities`
//! (`kernel/src/scheduler.rs`) — `blk-driver-host` itself now holds *two*
//! capabilities at once (its usual virtio-blk io-port range, plus a new
//! one scoped to the response port it replies on), which is exactly the
//! scenario that field exists for.
//!
//! Filesystem driver, Phase 8 extended this same boot with a second,
//! independently capability-gated port (`FS_WRITE_REQUEST_PORT`) for
//! write requests, and the structural gap closed here generalizes both
//! ports' wire format from "one fixed file per port, one trigger byte"
//! into a real, typed [`runix_ipc::fs::FsRequest`] carrying an arbitrary
//! filename *and* a per-file [`runix_capability_manager::CapabilityToken`]
//! on every single request — verified by `blk-driver-host` itself
//! (`verify_file_token`), not just by the kernel's own port-level
//! `SYS_IPC_SEND` gate. Proven three ways past what Phase 8 already
//! covered: **two different files** (`HELLO.TXT`, `BIG.TXT`) served
//! successfully over the *same* read port in one boot (Phase 8 could only
//! ever serve one fixed file); a caller holding a perfectly valid
//! port-level capability but a file-scoped token minted for a *different*
//! file gets [`runix_ipc::fs::FsError::Unauthorized`], not the file's
//! contents — the actual point of per-request authorization, since the
//! coarse port-level gate alone would have let this caller through; and
//! the same mismatched-token denial proven again for the write path.
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
use runix_capability_manager::CapabilityToken;
use runix_ipc::fs::{FsError, FsRequest, FsResponse};
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

// Must match `blk-driver-host/src/main.rs`'s own `FS_REQUEST_PORT`/
// `FS_RESPONSE_PORT`/`FS_WRITE_REQUEST_PORT`.
const FS_REQUEST_PORT: usize = 8;
const FS_RESPONSE_PORT: usize = 9;
const FS_WRITE_REQUEST_PORT: usize = 10;

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
    // The second capability `blk-driver-host` needs to reply at all —
    // `Thread::extra_capabilities`'s whole reason for existing (see
    // `kernel/src/scheduler.rs`'s doc comment).
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

    // Structural gap closed: dynamic filenames + per-request authorization.
    // A port-level capability (`port_resource(FS_REQUEST_PORT)`) is now
    // only a coarse "may talk to the filesystem service at all" grant --
    // which *file* that talking is allowed to touch is authorized
    // separately, per request, by a `CapabilityToken` scoped to
    // `file:<name>` that `blk-driver-host` itself verifies
    // (`verify_file_token`). Every case below issues its own fresh
    // port-level token (a real system would let many callers share one,
    // but a fresh one per case keeps each proof independent) plus
    // whatever file-scoped token that case actually needs.
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
    let write_port_token = |subject: &str| {
        CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::port_resource(FS_WRITE_REQUEST_PORT),
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
    // the same request port Phase 3/8 already proved, now carrying a real
    // `FsRequest::Read` instead of a fixed trigger byte.
    let hello_token = file_token("test-hello", "HELLO.TXT");
    let hello_request = FsRequest::Read {
        name: String::from("HELLO.TXT"),
        token: hello_token,
    };
    send_fs_request(
        FS_REQUEST_PORT,
        request_port_token("test-hello"),
        hello_request.encode(),
    );
    let hello_response = recv_fs_response(40000);
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
    send_fs_request(
        FS_REQUEST_PORT,
        request_port_token("test-big"),
        big_request.encode(),
    );
    let big_response = recv_fs_response(40000);
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
    send_fs_request(
        FS_REQUEST_PORT,
        request_port_token("test-mismatch"),
        mismatched_request.encode(),
    );
    let mismatched_response = recv_fs_response(40000);
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

    // Filesystem driver, Phase 8, negative case, generalized: same shape
    // as the unauthorized-read check above, now for the write port --
    // this thread holds no capability for `FS_WRITE_REQUEST_PORT` at all,
    // so even a well-formed write request must never reach the channel.
    let write_denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            FS_WRITE_REQUEST_PORT as u64,
            1,
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
    send_fs_request(
        FS_WRITE_REQUEST_PORT,
        write_port_token("test-write-mismatch"),
        mismatched_write_request.encode(),
    );
    let mismatched_write_response = recv_fs_response(40000);
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
    send_fs_request(
        FS_WRITE_REQUEST_PORT,
        write_port_token("test-writer"),
        write_request.encode(),
    );
    let write_response = recv_fs_response(40000);
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

/// Encodes and sends `bytes` (an already-encoded [`FsRequest`]) one byte
/// per `SYS_IPC_SEND` syscall on `port`, from a freshly spawned thread
/// holding `port_token` -- the same per-syscall capability check every
/// other sender in this codebase goes through, now carrying a real
/// multi-byte structured message instead of a single trigger byte. Reuses
/// one pair of statics across sequential calls (never two calls in
/// flight at once in this test -- every call here is followed by a full
/// [`recv_fs_response`] wait before the next one starts). Every real
/// sender, including this one, wraps its byte loop in
/// `SYS_IPC_SEND_LOCK`/`SYS_IPC_SEND_UNLOCK` (`kernel::ipc`'s own doc
/// comment) -- this test's own sends are already sequential, so the lock
/// is a no-op contention-wise here, but `blk_fs_concurrent.rs` is the one
/// that actually needs it, and there is exactly one correct calling
/// convention, not two.
fn send_fs_request(port: usize, port_token: CapabilityToken, bytes: Vec<u8>) {
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_SEND_PORT = port;
        PENDING_SEND_BYTES = bytes;
    }
    scheduler::spawn_with_capability(send_request_thread, Some(port_token));
}

static mut PENDING_SEND_PORT: usize = 0;
static mut PENDING_SEND_BYTES: Vec<u8> = Vec::new();

extern "C" fn send_request_thread() -> ! {
    // Copies both statics into locals *before* doing anything else, so
    // `send_fs_request` is free to overwrite them for its next call the
    // moment this thread has started running -- this thread never touches
    // either static again afterward.
    #[allow(static_mut_refs)]
    let (port, bytes) = unsafe { (PENDING_SEND_PORT, core::mem::take(&mut PENDING_SEND_BYTES)) };
    serial_println!(
        "blk_fs_ipc: send_request_thread starting, port={} len={}",
        port,
        bytes.len()
    );
    let lock_denied = unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND_LOCK, port as u64, 0, 0)
    } == u64::MAX;
    let mut sent = 0usize;
    let mut denied = if lock_denied { bytes.len() } else { 0 };
    if !lock_denied {
        for byte in bytes {
            let ret = unsafe {
                runix_kernel::syscall::syscall(
                    runix_kernel::syscall::SYS_IPC_SEND,
                    port as u64,
                    byte as u64,
                    0,
                )
            };
            if ret == u64::MAX {
                denied += 1;
            } else {
                sent += 1;
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
    serial_println!(
        "blk_fs_ipc: send_request_thread done, port={} sent={} denied={}",
        port,
        sent,
        denied
    );
    loop {
        scheduler::yield_now();
    }
}

/// Accumulates bytes off [`FS_RESPONSE_PORT`] until [`FsResponse::decode`]
/// reports a complete message, or `max_iters` polls pass with nothing
/// decodable -- same bounded-wait discipline every other poll loop in this
/// codebase uses, generalized from a fixed-shape reply
/// (`kernel/tests/blk_fs_ipc.rs`'s previous length-header-then-bytes
/// parsing) to a real typed decode.
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
    serial_println!("blk_fs_ipc: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
