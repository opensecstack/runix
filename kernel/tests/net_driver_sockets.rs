//! Sockets IPC surface (see `net-driver-host/src/main.rs`'s
//! `run_socket_ipc_server` doc comment and `docs/STATUS.md`'s
//! network-stack section — "a sockets API/IPC surface for other ring 3
//! processes to use this stack" is exactly the gap this closes): proves a
//! client can open/send/recv/close a real TCP connection through
//! `net-driver-host` over capability-gated IPC, using the typed wire format
//! `runix_ipc::sockets` defines on *both* ends — this test decodes
//! `net-driver-host`'s responses with `runix_ipc::sockets::SocketResponse::decode`
//! the same way `net-driver-host` itself decodes requests with
//! `SocketRequest::decode`, not a hand-rolled parser of its own.
//!
//! Same capability-scoping proof shape `kernel/tests/blk_fs_ipc.rs` already
//! established for the filesystem driver's IPC surface: a thread holding no
//! capability is denied when it tries to send a request, and a thread
//! holding a capability scoped to exactly the request port gets served.
//!
//! Reuses `net_driver_tcp.rs`'s exact host-listener setup
//! (`kernel/tests/support/tcp_proof_listener.py`, `guestfwd` to
//! `10.0.2.100:9000`) rather than a new one — same fixed PING/PONG payload,
//! same one-connection-then-exit listener, just driven through this
//! surface's IPC ports instead of `net-driver-host`'s own hardcoded Phase 2b
//! proof.
//!
//! **Manual build step required when running this locally** — same as
//! `net_driver_tcp.rs`:
//!
//! ```text
//! cd net-driver-host && cargo build --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_ipc::sockets::{SocketRequest, SocketResponse};
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

// Must match `net-driver-host/src/main.rs`'s own `SOCK_REQUEST_PORT`/
// `SOCK_RESPONSE_PORT` constants exactly.
const SOCK_REQUEST_PORT: usize = 11;
const SOCK_RESPONSE_PORT: usize = 12;

// Same `guestfwd` target and fixed payload `net_driver_tcp.rs` already
// proves against `tcp_proof_listener.py` -- see that test's own doc
// comment for why `10.0.2.100`, not the gateway `10.0.2.2`, is used.
const TCP_REMOTE_IP: [u8; 4] = [10, 0, 2, 100];
const TCP_REMOTE_PORT: u16 = 9000;
const TCP_LOCAL_PORT: u16 = 49153;
const TCP_PING: &[u8] = b"RUNIX-TCP-PROOF-PING";
const TCP_PONG: &[u8] = b"RUNIX-TCP-PROOF-PONG";

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
            serial_println!("net_driver_sockets: FAIL — no virtio-net I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "net-driver-host",
        NET_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "net_driver_sockets: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "net_driver_sockets: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("net_driver_sockets: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "net_driver_sockets: loaded, entry point {:#x}",
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
    // `net-driver-host` needs a second capability to reply at all —
    // `Thread::extra_capabilities`, same shape `blk_fs_ipc.rs` already
    // proves for `blk-driver-host`'s own response port.
    let response_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(SOCK_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    // `SYS_IPC_RECV` is now capability-gated identically to `SYS_IPC_SEND`
    // (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`) -- `net-driver-host` itself
    // now needs its own token to *receive* on `SOCK_REQUEST_PORT`
    // (`run_socket_ipc_server`'s `ipc_try_recv(SOCK_REQUEST_PORT)`), not
    // only the response-port send token it already held. This is the
    // recv-side gate landing "for free" on the sockets surface the RFC's
    // own "What changes" section predicted -- it closes ambient receive
    // access to this port, it does not add per-handle owner attribution
    // (see `runix_ipc::sockets`'s own updated caveat).
    let request_recv_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(SOCK_REQUEST_PORT),
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
        alloc::vec![response_token, request_recv_token],
    );

    // Give it time to probe the device, bring up the interface (including
    // its own unconditional ICMP proof against the gateway), and reach its
    // sockets server loop before either requester attempts anything.
    for _ in 0..2000 {
        scheduler::yield_now();
    }

    // Negative case first: this test's own boot thread holds no capability
    // at all -- the request must never reach the channel, same expectation
    // `blk_fs_ipc.rs` already proves for the filesystem driver's request
    // port.
    let denied = unsafe {
        runix_kernel::syscall::syscall(
            runix_kernel::syscall::SYS_IPC_SEND,
            SOCK_REQUEST_PORT as u64,
            SocketRequest::Close { handle: 0 }.encode()[0] as u64,
            0,
        )
    };
    if denied != u64::MAX {
        serial_println!(
            "net_driver_sockets: FAIL — an unauthorized send to the request port was not denied \
             (returned {}, expected u64::MAX)",
            denied
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!("net_driver_sockets: unauthorized send correctly denied (capability gate OK)");

    // Positive case: a thread holding a capability scoped to exactly the
    // request port drives a full connect/send/recv/close round trip.
    let request_token = runix_capability_manager::CapabilityToken::issue(
        "test-socket-client",
        runix_kernel::capabilities::port_resource(SOCK_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    // This thread also needs to *receive* on `SOCK_RESPONSE_PORT`
    // (`recv_response`'s own `SYS_IPC_RECV`) now that that syscall is
    // capability-gated too -- `spawn_with_capability` only carries one
    // token, so this one is granted to the thread by itself, at its own
    // start, via `scheduler::grant_current_extra_capability` (see that
    // function's doc comment for why that's the right shape here rather
    // than spawning a second thread purely to hold it).
    let response_recv_token = runix_capability_manager::CapabilityToken::issue(
        "test-socket-client",
        runix_kernel::capabilities::port_resource(SOCK_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    #[allow(static_mut_refs)]
    unsafe {
        PENDING_RESPONSE_RECV_TOKEN = Some(response_recv_token);
    }
    scheduler::spawn_with_capability(authorized_client_thread, Some(request_token));

    let mut result = SocketTestResult::Pending;
    for _ in 0..20_000 {
        scheduler::yield_now();
        #[allow(static_mut_refs)]
        let current = unsafe { RESULT };
        if current != SocketTestResult::Pending {
            result = current;
            break;
        }
    }

    if result == SocketTestResult::Pass {
        serial_println!(
            "net_driver_sockets: PASS — connect/send/recv/close all round-tripped through the \
             typed sockets IPC surface, capability-gated, against a real TCP peer"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "net_driver_sockets: FAIL — socket client thread reported {:?} (is \
             RUNIX_NETDEV_ARG/the host listener actually set up? see net_driver_tcp.rs)",
            result
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketTestResult {
    Pending,
    Pass,
    Fail,
}

static mut RESULT: SocketTestResult = SocketTestResult::Pending;
static mut PENDING_RESPONSE_RECV_TOKEN: Option<runix_capability_manager::CapabilityToken> = None;

/// Drives the whole connect -> send -> recv -> close sequence, entirely
/// through `runix_ipc::sockets`'s typed request/response wire format —
/// this thread holds the one capability scoped to [`SOCK_REQUEST_PORT`]
/// ([`kernel_main`]'s own boot thread deliberately doesn't, proving the
/// capability gate above). Writes its final verdict to [`RESULT`] rather
/// than returning one, since a `spawn`-ed thread's entry point is
/// `extern "C" fn() -> !` -- same "write a result byte/flag somewhere the
/// spawning thread polls" convention every other proof in this codebase
/// already uses (`NetBootInfo`'s own `NET_RESULT_OFFSET`, etc.), just a
/// `static` instead of a shared memory page since both threads already
/// share this process's address space.
extern "C" fn authorized_client_thread() -> ! {
    #[allow(static_mut_refs)]
    let response_recv_token =
        unsafe { PENDING_RESPONSE_RECV_TOKEN.take() }.expect("no pending response-recv token");
    runix_kernel::scheduler::grant_current_extra_capability(response_recv_token);
    let outcome = run_socket_client();
    #[allow(static_mut_refs)]
    unsafe {
        RESULT = outcome;
    }
    loop {
        scheduler::yield_now();
    }
}

fn run_socket_client() -> SocketTestResult {
    send_request(&SocketRequest::Open);
    let handle = match recv_response() {
        Some(SocketResponse::Opened { handle }) => handle,
        other => {
            serial_println!("net_driver_sockets: open failed, got {:?}", other);
            return SocketTestResult::Fail;
        }
    };

    send_request(&SocketRequest::Connect {
        handle,
        remote_ip: TCP_REMOTE_IP,
        remote_port: TCP_REMOTE_PORT,
        local_port: TCP_LOCAL_PORT,
    });
    match recv_response() {
        Some(SocketResponse::Connected { handle: h }) if h == handle => {}
        other => {
            serial_println!("net_driver_sockets: connect failed, got {:?}", other);
            return SocketTestResult::Fail;
        }
    }

    send_request(&SocketRequest::Send {
        handle,
        data: TCP_PING.to_vec(),
    });
    match recv_response() {
        Some(SocketResponse::Sent { handle: h, len })
            if h == handle && len as usize == TCP_PING.len() => {}
        other => {
            serial_println!("net_driver_sockets: send failed, got {:?}", other);
            return SocketTestResult::Fail;
        }
    }

    // The listener's reply may not have arrived yet by the time the first
    // `Recv` is served -- `SocketRequest::Recv` never blocks (see
    // `runix_ipc::sockets`'s own doc comment), so a caller polls by
    // resending it, same as this codebase's other bounded wait loops.
    let mut received: Vec<u8> = Vec::new();
    for _ in 0..2000 {
        send_request(&SocketRequest::Recv {
            handle,
            max_len: TCP_PONG.len() as u16,
        });
        match recv_response() {
            Some(SocketResponse::Data { handle: h, data }) if h == handle => {
                received.extend_from_slice(&data);
                if received.len() >= TCP_PONG.len() {
                    break;
                }
            }
            other => {
                serial_println!("net_driver_sockets: recv failed, got {:?}", other);
                return SocketTestResult::Fail;
            }
        }
        scheduler::yield_now();
    }

    // Exact bytes checked, not just "received something" -- the same
    // discipline every other proof in this codebase applies.
    if received != TCP_PONG {
        serial_println!(
            "net_driver_sockets: FAIL — expected {:?}, got {:?}",
            TCP_PONG,
            received
        );
        return SocketTestResult::Fail;
    }

    send_request(&SocketRequest::Close { handle });
    match recv_response() {
        Some(SocketResponse::Closed { handle: h }) if h == handle => SocketTestResult::Pass,
        other => {
            serial_println!("net_driver_sockets: close failed, got {:?}", other);
            SocketTestResult::Fail
        }
    }
}

/// Sends `request`'s encoded bytes one at a time on [`SOCK_REQUEST_PORT`] —
/// same "one byte per `SYS_IPC_SEND`" convention
/// `blk_fs_ipc.rs`'s `authorized_writer_thread` already uses.
fn send_request(request: &SocketRequest) {
    for byte in request.encode() {
        unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_SEND,
                SOCK_REQUEST_PORT as u64,
                byte as u64,
                0,
            );
        }
    }
}

/// Polls [`SOCK_RESPONSE_PORT`] for one full [`SocketResponse`], decoding
/// with `runix_ipc::sockets::SocketResponse::decode` (the same typed
/// wire-format function `net-driver-host` itself uses to decode requests)
/// rather than a hand-rolled parser here. `None` if nothing arrives within
/// the bound -- there is no blocking-receive syscall in this codebase (see
/// `blk-driver-host/src/main.rs`'s `poll_recv_byte` doc comment for the
/// same constraint on the transport this rides over).
fn recv_response() -> Option<SocketResponse> {
    let mut buf: Vec<u8> = Vec::new();
    for i in 0..200_000u32 {
        let ret = unsafe {
            runix_kernel::syscall::syscall(
                runix_kernel::syscall::SYS_IPC_RECV,
                SOCK_RESPONSE_PORT as u64,
                0,
                0,
            )
        };
        if ret != u64::MAX {
            buf.push(ret as u8);
            if let Some((response, _consumed)) = SocketResponse::decode(&buf) {
                return Some(response);
            }
        }
        if i % 1000 == 0 {
            scheduler::yield_now();
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
    serial_println!("net_driver_sockets: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
