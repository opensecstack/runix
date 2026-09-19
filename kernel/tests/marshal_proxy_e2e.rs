//! Proves the *full* MARSHAL evaluation chain end to end: a Runix kernel
//! booted in QEMU, calling `kernel::marshal_client::evaluate` over a real
//! TCP connection through `net-driver-host`'s sockets IPC surface, to the
//! REAL, compiled `citadel_proxy` binary (`desktop/src/bin/citadel_proxy.rs`)
//! running on the host — which itself makes a REAL HTTP call (via
//! `HttpKerkeseTransport`) to a mock CITADEL HTTP endpoint
//! (`tests/support/mock_citadel_server.py`) standing in for a live
//! opensecstack deployment.
//!
//! `marshal_tcp_roundtrip.rs` already proved the kernel-side socket
//! transport speaks the right wire format, but only against
//! `marshal_proof_listener.py` — a Python stand-in that never calls
//! `desktop`'s actual proxy logic. This test is the first place
//! `kernel::marshal_client` and `desktop::citadel::proxy` are proven to
//! actually interoperate, one hop further than either side's own
//! independent proof:
//!
//!   guest kernel --(sockets IPC, net-driver-host)--> real TCP -->
//!   citadel_proxy --(real HTTP, HttpKerkeseTransport)--> mock_citadel_server.py
//!
//! Unlike `marshal_proof_listener.py` (which always replies `Refuse`, on
//! purpose, so it can never be mistaken for a real proxy), the mock CITADEL
//! endpoint here answers `EXECUTE` — chosen deliberately so this test's
//! assertion is unambiguous: a `Refuse` result here couldn't distinguish
//! "the whole chain worked and CITADEL said no" from "the chain is broken
//! and `evaluate` just timed out/failed closed", since this codebase's own
//! `evaluate` doc comment says a failure looks like `None`, not a forged
//! `Refuse`. Getting back the *exact* canned `EXECUTE` decision JSON is
//! only possible if every hop actually carried the real bytes through.
//!
//! **Manual build steps required when running this locally** — same as
//! `marshal_tcp_roundtrip.rs`, plus building the real proxy binary:
//!
//! ```text
//! cd net-driver-host && cargo build --target x86_64-unknown-none --release
//! cargo build -p runix-desktop --bin citadel_proxy --release
//! ```
//!
//! **Host-side setup** — start the mock CITADEL endpoint, then the real
//! proxy pointed at it, then bridge QEMU's `guestfwd` to the proxy's own
//! listen address (not to a Python stand-in — the whole point of this test
//! is that the real proxy sits behind that bridge):
//!
//! ```text
//! python3 tests/support/mock_citadel_server.py &
//! CITADEL_PROXY_LISTEN_ADDR=127.0.0.1:9104 \
//!   RUNIX_CITADEL_URL=http://127.0.0.1:9105/marshal/kerkese \
//!   ../target/release/citadel_proxy &
//! RUNIX_NETDEV_ARG="user,id=net0,guestfwd=tcp:10.0.2.100:9000-cmd:nc 127.0.0.1 9104" \
//!   cargo test --target x86_64-unknown-none --test marshal_proxy_e2e
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_ipc::marshal::{MarshalOutcome, MarshalRequest, MarshalResponse};
use runix_kernel::elf::Elf64;
use runix_kernel::marshal_client;
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

static NET_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../net-driver-host/target/x86_64-unknown-none/release/net-driver-host");

// Must match `net-driver-host/src/main.rs`'s own constants exactly — see
// `kernel/src/main.rs`'s identical set for the full "why 0x1" account.
const NET_HEAP_START: u64 = 0x_1111_1111_0000;
const NET_HEAP_SIZE: u64 = 256 * 1024;
const NET_STACK_VA: u64 = 0x_1111_2222_0000;
const NET_STACK_SIZE: u64 = 4096 * 4;
const NET_INFO_VA: u64 = 0x_1111_3333_0000;
const NET_RXQ_VA: u64 = 0x_1111_4444_0000;
const NET_TXQ_VA: u64 = 0x_1111_5555_0000;
const NET_RXBUF_VA: u64 = 0x_1111_6666_0000;
const NET_TXBUF_VA: u64 = 0x_1111_7777_0000;
const NET_QUEUE_ALIGN: u64 = 4096;
const NET_RX_BUFFER_COUNT: u64 = 8;
const NET_TX_BUFFER_COUNT: u64 = 4;

// Same `guestfwd` target `net_driver_tcp.rs`/`marshal_tcp_roundtrip.rs`
// already use -- see those tests' own doc comments for why `10.0.2.100`,
// not the gateway `10.0.2.2`, is used. `TCP_LOCAL_PORT` is a fresh value,
// distinct from every other test's own local port, purely so a stray
// leftover connection from a previous test run can never be confused with
// this one.
const TCP_REMOTE_IP: [u8; 4] = [10, 0, 2, 100];
const TCP_REMOTE_PORT: u16 = 9000;
const TCP_LOCAL_PORT: u16 = 49157;

// This test's own Kerkese envelope is opaque to every hop it passes
// through (`kernel::marshal_client`, the sockets IPC surface, and
// `citadel_proxy`'s own TCP/decode layer never parse it) -- only the mock
// CITADEL HTTP endpoint's *response* is asserted on exactly, since that's
// the only hop this test can prove actually happened by its content.
const FAKE_KERKESE_JSON: &[u8] = br#"{"kerkese_version":"1.0","action":{"type":"TEST_ACTION"}}"#;

// Copied byte-for-byte from `tests/support/mock_citadel_server.py`'s
// `DECISION_JSON` (itself copied from
// `desktop/src/citadel/proxy.rs`'s `CANNED_EXECUTE_RESPONSE` fixture) --
// the exact bytes `citadel_proxy` must forward back unmodified as
// `MarshalResponse::Decision::decision_json` for this test to prove the
// full chain, not just "got back something naming EXECUTE."
const EXPECTED_DECISION_JSON: &[u8] = br#"{"execution_id":"00000000-0000-0000-0000-000000000000","outcome":"EXECUTE","gates":[],"reasons":[],"ts_utc":"2026-07-26T12:00:01Z"}"#;

#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; 8],
    tx_buffer_phys: [u64; 4],
    attempt_tcp: u8,
    serve_sockets: u8,
    /// `0` -- this test's `guestfwd` route/fixed remote address assumes
    /// net-driver-host's own address is the static `LOCAL_IP`, not
    /// whatever a real DHCP lease would hand back; see `net_driver_dhcp.rs`
    /// for the test that sets this to `1`.
    use_dhcp: u8,
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
    let io_base = match runix_kernel::pci::find_virtio_net(&devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => io_base,
        None => {
            serial_println!("marshal_proxy_e2e: FAIL — no virtio-net I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "net-driver-host",
        NET_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "marshal_proxy_e2e: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "marshal_proxy_e2e: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("marshal_proxy_e2e: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "marshal_proxy_e2e: loaded net-driver-host, entry point {:#x}",
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
    map_zeroed_range(&mut space, NET_HEAP_START, NET_HEAP_SIZE);
    map_zeroed_range(&mut space, NET_STACK_VA, NET_STACK_SIZE);

    let rxq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_RXQ_VA, 3, rw_user_flags);
    let txq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_TXQ_VA, 3, rw_user_flags);

    let mut rx_buffer_phys = [0u64; 8];
    for i in 0..NET_RX_BUFFER_COUNT {
        let page = Page::containing_address(VirtAddr::new(NET_RXBUF_VA + i * 4096));
        let content = space.map_private_page(page, rw_user_flags);
        content.fill(0);
        rx_buffer_phys[i as usize] = page_phys_addr(content);
    }
    let mut tx_buffer_phys = [0u64; 4];
    for i in 0..NET_TX_BUFFER_COUNT {
        let page = Page::containing_address(VirtAddr::new(NET_TXBUF_VA + i * 4096));
        let content = space.map_private_page(page, rw_user_flags);
        content.fill(0);
        tx_buffer_phys[i as usize] = page_phys_addr(content);
    }

    let info_page = Page::containing_address(VirtAddr::new(NET_INFO_VA));
    let info_content = space.map_private_page(info_page, rw_user_flags);
    info_content.fill(0);
    let info = NetBootInfo {
        io_base,
        _pad: 0,
        rx_queue_phys: rxq_first_frame_phys,
        tx_queue_phys: txq_first_frame_phys,
        rx_buffer_phys,
        tx_buffer_phys,
        attempt_tcp: 0,
        serve_sockets: 1,
        use_dhcp: 0,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut NetBootInfo).write(info);
    }

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let net_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    // `net-driver-host` needs a second capability to reply at all --
    // `Thread::extra_capabilities`, same shape `net_driver_sockets.rs`
    // already proves for its own response port.
    let response_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_RESPONSE_PORT),
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
        Some(net_token),
        alloc::vec![response_token],
    );

    // Give it time to probe the device, bring up the interface, and reach
    // its sockets server loop before either requester attempts anything --
    // same budget `marshal_tcp_roundtrip.rs` already uses.
    for _ in 0..2000 {
        scheduler::yield_now();
    }

    // Negative case first: this test's own boot thread holds no capability
    // for the sockets request port at all -- the request must never reach
    // the channel, same expectation every other IPC surface in this
    // codebase already proves for its own request port.
    let denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            marshal_client::SOCK_REQUEST_PORT as u64,
            0,
            0,
        )
    };
    if denied != u64::MAX {
        serial_println!(
            "marshal_proxy_e2e: FAIL — an unauthorized send to the sockets request port was not \
             denied (returned {}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("marshal_proxy_e2e: unauthorized send correctly denied (capability gate OK)");

    // Positive case: a thread holding a capability scoped to exactly the
    // sockets request port drives a full MarshalRequest/MarshalResponse
    // round trip through `kernel::marshal_client::evaluate`, all the way
    // through the REAL `citadel_proxy` binary and its REAL HTTP call to the
    // mock CITADEL endpoint.
    let request_token = runix_capability_manager::CapabilityToken::issue(
        "test-marshal-client",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(authorized_client_thread, Some(request_token));

    let mut result = TestResult::Pending;
    for _ in 0..30_000 {
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
            "marshal_proxy_e2e: PASS — a MarshalRequest sent through \
             kernel::marshal_client::evaluate reached the real citadel_proxy binary over the \
             sockets IPC surface and a real TCP connection, citadel_proxy made a real HTTP call \
             to the mock CITADEL endpoint, and the exact canned EXECUTE Decision came all the way \
             back and decoded correctly"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "marshal_proxy_e2e: FAIL — client thread reported {:?} (is RUNIX_NETDEV_ARG/the real \
             citadel_proxy/the mock CITADEL server all actually set up? see this test's own doc \
             comment)",
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

/// Drives the client half entirely through `kernel::marshal_client` -- this
/// thread holds the one capability scoped to
/// [`marshal_client::SOCK_REQUEST_PORT`] (`kernel_main`'s own boot thread
/// deliberately doesn't, proving the capability gate above).
extern "C" fn authorized_client_thread() -> ! {
    let request = MarshalRequest {
        kerkese_json: FAKE_KERKESE_JSON.to_vec(),
    };
    let outcome = match marshal_client::evaluate(
        TCP_REMOTE_IP,
        TCP_REMOTE_PORT,
        TCP_LOCAL_PORT,
        &request,
        200_000,
    ) {
        Some(MarshalResponse::Decision {
            outcome: MarshalOutcome::Execute,
            decision_json,
        }) if decision_json == EXPECTED_DECISION_JSON => TestResult::Pass,
        other => {
            serial_println!(
                "marshal_proxy_e2e: client got unexpected response {:?}",
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

/// Same as `kernel/src/main.rs`'s function of the same name.
fn map_zeroed_contiguous_region(
    space: &mut AddressSpace,
    start_va: u64,
    page_count: u64,
    flags: PageTableFlags,
) -> u64 {
    let frames: alloc::vec::Vec<PhysFrame> =
        runix_kernel::memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            (0..page_count)
                .map(|_| {
                    frame_allocator
                        .allocate_frame()
                        .expect("out of physical memory for net-driver-host's virtqueue region")
                })
                .collect()
        });

    for (i, frame) in frames.iter().enumerate() {
        if i > 0 {
            assert_eq!(
                frame.start_address().as_u64(),
                frames[0].start_address().as_u64() + i as u64 * NET_QUEUE_ALIGN,
                "net-driver-host's virtqueue region at {start_va:#x} landed on non-contiguous \
                 physical frames"
            );
        }
        let page = Page::containing_address(VirtAddr::new(start_va + i as u64 * NET_QUEUE_ALIGN));
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
            VirtAddr::new(NET_STACK_VA + NET_STACK_SIZE),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("marshal_proxy_e2e: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
