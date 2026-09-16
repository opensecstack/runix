//! Concurrent sockets (see `net-driver-host/src/main.rs`'s
//! `run_socket_ipc_server` doc comment and `ipc/src/sockets.rs`'s own doc
//! comment on [`SocketRequest::Open`]/handles): proves two independent TCP
//! connections, opened as two separate handles through the same sockets
//! IPC surface `net_driver_sockets.rs` already proves for one connection,
//! genuinely run *concurrently* without clobbering each other's state --
//! not just two connections used one after another (which the old
//! single-socket server already effectively allowed, just without a
//! handle to distinguish them).
//!
//! Opens handle A and handle B, connects both (to the *same*
//! guest-visible remote address/port -- deliberately: QEMU's `guestfwd`
//! spawns a fresh bridge for every new guest-initiated connection to that
//! destination regardless of how many prior connections to it are still
//! open, so this alone is enough to get two independent, concurrently
//! open TCP connections without depending on whether repeating
//! `guestfwd=` twice in one `-netdev user` string is parsed as two
//! independent rules or one overwriting the other -- see
//! `kernel/tests/support/two_socket_proof_listener.py`'s own doc comment),
//! then deliberately interleaves `Send`/`Recv` across both handles (A,
//! then B, then back to A) before closing either -- a bug that let one
//! handle's request touch the *other* handle's socket would show up here
//! as a wrong PING/PONG pair or a response tagged with the wrong handle,
//! not silently pass the way it might if each connection were driven to
//! completion before the other ever opened.
//!
//! **Manual build step required when running this locally** — same as
//! `net_driver_sockets.rs`:
//!
//! ```text
//! cd net-driver-host && cargo build --target x86_64-unknown-none --release
//! ```
//!
//! **QEMU `-netdev` setup**: one `guestfwd` route, bridged to
//! `two_socket_proof_listener.py`'s port 9002 instead of
//! `tcp_proof_listener.py`'s 9001:
//!
//! ```text
//! RUNIX_NETDEV_ARG="user,id=net0,guestfwd=tcp:10.0.2.100:9000-cmd:nc 127.0.0.1 9002" \
//!   cargo test --target x86_64-unknown-none --test net_driver_sockets_concurrent
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

// Same guest-visible remote address/port both handles connect to --
// deliberate, not an oversight; see this file's own module doc comment for
// why one `guestfwd` route is enough to prove two concurrent connections.
const REMOTE_IP: [u8; 4] = [10, 0, 2, 100];
const REMOTE_PORT: u16 = 9000;
const LOCAL_PORT_A: u16 = 49154;
const LOCAL_PORT_B: u16 = 49155;

const PING_A: &[u8] = b"RUNIX-SOCK-A-PING";
const PONG_A: &[u8] = b"RUNIX-SOCK-A-PONG";
const PING_B: &[u8] = b"RUNIX-SOCK-B-PING";
const PONG_B: &[u8] = b"RUNIX-SOCK-B-PONG";

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
    /// `0` -- this test's two `guestfwd` routes/fixed remote addresses
    /// assume net-driver-host's own address is the static `LOCAL_IP`, not
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
            serial_println!(
                "net_driver_sockets_concurrent: FAIL — no virtio-net I/O-space BAR0 found"
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "net-driver-host",
        NET_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "net_driver_sockets_concurrent: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "net_driver_sockets_concurrent: FAIL — parse() rejected the binary: {:?}",
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
                "net_driver_sockets_concurrent: FAIL — load_segments() failed: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "net_driver_sockets_concurrent: loaded, entry point {:#x}",
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
    let response_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(SOCK_RESPONSE_PORT),
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
    // its sockets server loop before the client attempts anything -- same
    // budget `net_driver_sockets.rs` already uses.
    for _ in 0..2000 {
        scheduler::yield_now();
    }

    let request_token = runix_capability_manager::CapabilityToken::issue(
        "test-socket-client",
        runix_kernel::capabilities::port_resource(SOCK_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(authorized_client_thread, Some(request_token));

    let mut result = SocketTestResult::Pending;
    for _ in 0..30_000 {
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
            "net_driver_sockets_concurrent: PASS — two independently-opened socket handles ran \
             concurrently through the sockets IPC surface without clobbering each other's state"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "net_driver_sockets_concurrent: FAIL — socket client thread reported {:?} (are both \
             `guestfwd` routes and `two_socket_proof_listener.py` actually set up? see this \
             test's own doc comment)",
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

extern "C" fn authorized_client_thread() -> ! {
    let outcome = run_socket_client();
    #[allow(static_mut_refs)]
    unsafe {
        RESULT = outcome;
    }
    loop {
        scheduler::yield_now();
    }
}

/// Opens two handles, connects both, then deliberately interleaves
/// `Send`/`Recv` across both (A, then B, then back to A for its reply,
/// then B for its reply) before closing either -- see this file's own
/// module doc comment for why interleaving (not "finish A entirely, then
/// start B") is the actual property this test needs to prove.
fn run_socket_client() -> SocketTestResult {
    let handle_a = match open_handle() {
        Some(h) => h,
        None => return SocketTestResult::Fail,
    };
    let handle_b = match open_handle() {
        Some(h) => h,
        None => return SocketTestResult::Fail,
    };
    if handle_a == handle_b {
        serial_println!(
            "net_driver_sockets_concurrent: FAIL — Open handed back the same handle ({}) twice",
            handle_a
        );
        return SocketTestResult::Fail;
    }

    if !connect(handle_a, REMOTE_IP, LOCAL_PORT_A) {
        return SocketTestResult::Fail;
    }
    if !connect(handle_b, REMOTE_IP, LOCAL_PORT_B) {
        return SocketTestResult::Fail;
    }

    if !send_and_check(handle_a, PING_A) {
        return SocketTestResult::Fail;
    }
    if !send_and_check(handle_b, PING_B) {
        return SocketTestResult::Fail;
    }

    // Recv A first, then B -- if the server ever routed A's reply to B's
    // handle (or vice versa), this ordering (and the exact-byte check
    // inside `recv_and_check`) is what would catch it.
    if !recv_and_check(handle_a, PONG_A) {
        return SocketTestResult::Fail;
    }
    if !recv_and_check(handle_b, PONG_B) {
        return SocketTestResult::Fail;
    }

    if !close(handle_a) {
        return SocketTestResult::Fail;
    }
    if !close(handle_b) {
        return SocketTestResult::Fail;
    }

    SocketTestResult::Pass
}

fn open_handle() -> Option<u8> {
    send_request(&SocketRequest::Open);
    match recv_response() {
        Some(SocketResponse::Opened { handle }) => Some(handle),
        other => {
            serial_println!(
                "net_driver_sockets_concurrent: open failed, got {:?}",
                other
            );
            None
        }
    }
}

fn connect(handle: u8, remote_ip: [u8; 4], local_port: u16) -> bool {
    send_request(&SocketRequest::Connect {
        handle,
        remote_ip,
        remote_port: REMOTE_PORT,
        local_port,
    });
    match recv_response() {
        Some(SocketResponse::Connected { handle: h }) if h == handle => true,
        other => {
            serial_println!(
                "net_driver_sockets_concurrent: connect on handle {} failed, got {:?}",
                handle,
                other
            );
            false
        }
    }
}

fn send_and_check(handle: u8, ping: &[u8]) -> bool {
    send_request(&SocketRequest::Send {
        handle,
        data: ping.to_vec(),
    });
    match recv_response() {
        Some(SocketResponse::Sent { handle: h, len })
            if h == handle && len as usize == ping.len() =>
        {
            true
        }
        other => {
            serial_println!(
                "net_driver_sockets_concurrent: send on handle {} failed, got {:?}",
                handle,
                other
            );
            false
        }
    }
}

/// Same "`Recv` never blocks, so poll by resending" pattern
/// `net_driver_sockets.rs`'s own `run_socket_client` already uses.
fn recv_and_check(handle: u8, pong: &[u8]) -> bool {
    let mut received: Vec<u8> = Vec::new();
    for _ in 0..2000 {
        send_request(&SocketRequest::Recv {
            handle,
            max_len: pong.len() as u16,
        });
        match recv_response() {
            Some(SocketResponse::Data { handle: h, data }) if h == handle => {
                received.extend_from_slice(&data);
                if received.len() >= pong.len() {
                    break;
                }
            }
            other => {
                serial_println!(
                    "net_driver_sockets_concurrent: recv on handle {} failed, got {:?}",
                    handle,
                    other
                );
                return false;
            }
        }
        scheduler::yield_now();
    }

    if received != pong {
        serial_println!(
            "net_driver_sockets_concurrent: FAIL — handle {} expected {:?}, got {:?}",
            handle,
            pong,
            received
        );
        return false;
    }
    true
}

fn close(handle: u8) -> bool {
    send_request(&SocketRequest::Close { handle });
    match recv_response() {
        Some(SocketResponse::Closed { handle: h }) if h == handle => true,
        other => {
            serial_println!(
                "net_driver_sockets_concurrent: close on handle {} failed, got {:?}",
                handle,
                other
            );
            false
        }
    }
}

/// Sends `request`'s encoded bytes one at a time on [`SOCK_REQUEST_PORT`] —
/// same "one byte per `SYS_IPC_SEND`" convention `net_driver_sockets.rs`
/// already uses.
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

/// Same as `net_driver_sockets.rs`'s function of the same name.
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
    serial_println!("net_driver_sockets_concurrent: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
