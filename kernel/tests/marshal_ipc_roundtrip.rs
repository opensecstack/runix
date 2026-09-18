//! Proves `runix_ipc::marshal`'s wire format and `kernel::marshal_client`'s
//! IPC plumbing work end to end, for real, over capability-gated
//! `SYS_IPC_SEND`/`SYS_IPC_RECV` — the same round-trip proof shape
//! `kernel/tests/net_driver_sockets.rs`/`blk_fs_ipc.rs` already establish
//! for their own IPC surfaces, now for the MARSHAL evaluation surface
//! described in `kernel/src/marshal_client.rs`'s doc comment.
//!
//! The "server" side here is a fake, test-only in-kernel thread
//! (`fake_proxy_thread`) that receives one [`MarshalRequest`] and replies
//! with one canned [`MarshalResponse`] — **this is not a MARSHAL proxy, a
//! MARSHAL client, or a stand-in for either.** It exists purely to answer
//! the wire format on the other end, the same role `net-driver-host`'s real
//! sockets server plays for `net_driver_sockets.rs`, except there is no
//! real desktop-side HTTP transport to MARSHAL yet (a separate, parallel
//! change owns building that) — so this test proves the plumbing without
//! needing it. No real governance logic lives here: the canned response is
//! a fixed, hardcoded `MarshalOutcome::Refuse`, chosen deliberately (not
//! `Execute`) so a future accidental wiring-up of this exact thread as if
//! it were real governance would fail closed, not open.
//!
//! Unlike `net_driver_sockets.rs`/`blk_fs_ipc.rs`, both threads here are
//! plain kernel threads (`scheduler::spawn_with_capability`) in the same
//! address space as `kernel_main` — no ring 3 process, no ELF binary to
//! load, since this is pure kernel-to-kernel-thread IPC over the ports
//! `kernel::marshal_client` already names
//! (`MARSHAL_REQUEST_PORT`/`MARSHAL_RESPONSE_PORT`).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_ipc::marshal::{MarshalOutcome, MarshalRequest, MarshalResponse};
use runix_kernel::marshal_client::{self, MARSHAL_REQUEST_PORT, MARSHAL_RESPONSE_PORT};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const FAKE_KERKESE_JSON: &[u8] = br#"{"kerkese_version":"1.0","action":{"type":"TEST_ACTION"}}"#;
const FAKE_DECISION_JSON: &[u8] = br#"{"outcome":"REFUSE","reasons":["test-only fake proxy"]}"#;

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

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();

    // Negative case first, same "unauthorized send never reaches the
    // channel" proof every other IPC surface in this codebase establishes
    // for its own request port: this test's own boot thread holds no
    // capability for `MARSHAL_REQUEST_PORT` at all.
    let denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            MARSHAL_REQUEST_PORT as u64,
            0,
            0,
        )
    };
    if denied != u64::MAX {
        serial_println!(
            "marshal_ipc_roundtrip: FAIL — an unauthorized send to the request port was not \
             denied (returned {}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "marshal_ipc_roundtrip: unauthorized send correctly denied (capability gate OK)"
    );

    // The fake proxy thread needs a capability to receive on the request
    // port and reply on the response port -- `Thread::extra_capabilities`
    // isn't needed here (unlike `blk-driver-host`/`net-driver-host`, which
    // each need one for device I/O *plus* one for their reply port): a
    // plain kernel thread spawned via `spawn_with_capability` only ever
    // needs the one capability it actually uses `SYS_IPC_RECV`/`SYS_IPC_SEND`
    // with, and `SYS_IPC_RECV` itself is never capability-gated in this
    // codebase (see `syscall::dispatch`'s `SYS_IPC_RECV` arm) -- only
    // *sending* is. So the proxy thread's one capability just needs to
    // authorize sending on the response port.
    let proxy_send_token = runix_capability_manager::CapabilityToken::issue(
        "test-fake-marshal-proxy",
        runix_kernel::capabilities::port_resource(MARSHAL_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(fake_proxy_thread, Some(proxy_send_token));

    // The client thread needs a capability to send on the request port --
    // `kernel::marshal_client::send_request`'s own doc comment spells out
    // that it does not check this itself, it relies on the syscall gate.
    let client_send_token = runix_capability_manager::CapabilityToken::issue(
        "test-marshal-client",
        runix_kernel::capabilities::port_resource(MARSHAL_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(authorized_client_thread, Some(client_send_token));

    let mut result = TestResult::Pending;
    for _ in 0..20_000 {
        scheduler::yield_now();
        #[allow(static_mut_refs)]
        let current = unsafe { RESULT };
        if current != TestResult::Pending {
            result = current;
            break;
        }
    }

    if result == TestResult::Pass {
        serial_println!(
            "marshal_ipc_roundtrip: PASS — a MarshalRequest sent through \
             kernel::marshal_client::send_request was received and answered by a fake proxy \
             thread, and kernel::marshal_client::recv_response decoded the exact \
             MarshalResponse back, all over capability-gated IPC"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "marshal_ipc_roundtrip: FAIL — client thread reported {:?}",
            result
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestResult {
    Pending,
    Pass,
    Fail,
}

static mut RESULT: TestResult = TestResult::Pending;

/// Test-only scaffolding, **not a MARSHAL proxy or any stand-in for one** —
/// see this file's own doc comment. Receives one [`MarshalRequest`] off
/// [`MARSHAL_REQUEST_PORT`] (accumulating bytes with
/// `MarshalRequest::decode`, the same typed decode a real proxy would use)
/// and replies with one hardcoded [`MarshalResponse`] on
/// [`MARSHAL_RESPONSE_PORT`].
extern "C" fn fake_proxy_thread() -> ! {
    let mut buf: Vec<u8> = Vec::new();
    let mut received: Option<MarshalRequest> = None;
    for _ in 0..200_000u32 {
        let ret = unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_RECV,
                MARSHAL_REQUEST_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            buf.push(ret as u8);
            if let Some((request, _consumed)) = MarshalRequest::decode(&buf) {
                received = Some(request);
                break;
            }
        } else {
            scheduler::yield_now();
        }
    }

    match received {
        Some(request) if request.kerkese_json == FAKE_KERKESE_JSON => {
            let response = MarshalResponse::Decision {
                outcome: MarshalOutcome::Refuse,
                decision_json: FAKE_DECISION_JSON.to_vec(),
            };
            for byte in response.encode() {
                unsafe {
                    runix_kernel::syscall::syscall(
                        runix_kernel::syscall::SYS_IPC_SEND,
                        MARSHAL_RESPONSE_PORT as u64,
                        byte as u64,
                        0,
                    );
                }
            }
        }
        other => {
            serial_println!(
                "marshal_ipc_roundtrip: fake proxy thread got unexpected request {:?}",
                other
            );
        }
    }

    loop {
        scheduler::yield_now();
    }
}

/// Drives the client half entirely through `kernel::marshal_client` -- this
/// thread holds the one capability scoped to [`MARSHAL_REQUEST_PORT`]
/// (`kernel_main`'s own boot thread deliberately doesn't, proving the
/// capability gate above).
extern "C" fn authorized_client_thread() -> ! {
    let request = MarshalRequest {
        kerkese_json: FAKE_KERKESE_JSON.to_vec(),
    };
    let outcome = match marshal_client::evaluate(&request, 200_000) {
        Some(MarshalResponse::Decision {
            outcome: MarshalOutcome::Refuse,
            decision_json,
        }) if decision_json == FAKE_DECISION_JSON => TestResult::Pass,
        other => {
            serial_println!(
                "marshal_ipc_roundtrip: client got unexpected response {:?}",
                other
            );
            TestResult::Fail
        }
    };
    #[allow(static_mut_refs)]
    unsafe {
        RESULT = outcome;
    }
    loop {
        scheduler::yield_now();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("marshal_ipc_roundtrip: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
