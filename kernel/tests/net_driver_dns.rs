//! DNS (see `net-driver-host/src/main.rs`'s `run_dns_lookup`/
//! `NetBootInfo::use_dns` doc comments): proves `net-driver-host` can
//! resolve a real hostname via `smoltcp::socket::dns`, reached through
//! QEMU/SLIRP's default NAT to a real public resolver
//! (`net-driver-host`'s own `DNS_SERVER_IP`, `8.8.8.8`) — no
//! `guestfwd`/host-listener infrastructure needed, unlike
//! `net_driver_tcp.rs`/`net_driver_sockets.rs`. **Not** SLIRP's own
//! documented built-in DNS forwarder (`10.0.2.3`, alongside the gateway
//! `10.0.2.2`) — see `DNS_SERVER_IP`'s own doc comment for why that
//! address never answers in this project's QEMU/libslirp build. Uses the
//! same static `LOCAL_IP` every other single-phase `net_driver_*` test
//! deliberately keeps using (`net_driver_icmp.rs`'s own convention) rather
//! than DHCP's.
//!
//! Runs strictly after the ICMP echo proof, on the same `Interface` — same
//! "one shared, always-increasing timestamp counter across phases" model
//! `run_tcp_proof`'s own doc comment establishes and `net_driver_dhcp.rs`
//! re-verifies for the DHCP -> ICMP transition.
//!
//! **Manual build step required when running this locally** — same as
//! `net_driver_icmp.rs`:
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

// Must match `net-driver-host/src/main.rs`'s `NET_RESULT_OFFSET`/
// `NET_DNS_RESULT_OFFSET`/`NET_DNS_ADDR_OFFSET`/`NET_RESULT_PASS`.
const NET_RESULT_OFFSET: u64 = 128;
const NET_DNS_RESULT_OFFSET: u64 = 135;
const NET_DNS_ADDR_OFFSET: u64 = 136;
const NET_RESULT_PASS: u8 = 1;

#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; 8],
    tx_buffer_phys: [u64; 4],
    /// `0` -- this test has no `guestfwd` route or host listener for
    /// net-driver-host's Phase 2b TCP attempt to reach.
    attempt_tcp: u8,
    /// `0` -- this test never spawns a second process to send socket
    /// requests.
    serve_sockets: u8,
    /// `0` -- this test uses the static `LOCAL_IP`, same convention
    /// `net_driver_icmp.rs` already uses, not a real DHCP lease.
    use_dhcp: u8,
    /// `1` -- the whole point of this test: resolve a real hostname via
    /// `smoltcp::socket::dns` against QEMU/SLIRP's own DNS forwarder.
    use_dns: u8,
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

    // Before any `AddressSpace::new()` — see `scheduler::init`'s doc comment.
    scheduler::init();

    let devices = runix_kernel::pci::scan();
    let io_base = match runix_kernel::pci::find_virtio_net(&devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => io_base,
        None => {
            serial_println!("net_driver_dns: FAIL — no virtio-net I/O-space BAR0 found");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "net-driver-host",
        NET_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "net_driver_dns: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "net_driver_dns: parsing net-driver-host ({} bytes)",
        NET_DRIVER_HOST_ELF.len()
    );
    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!("net_driver_dns: FAIL — parse() rejected the binary: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("net_driver_dns: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!("net_driver_dns: loaded, entry point {:#x}", entry.as_u64());

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
        serve_sockets: 0,
        use_dhcp: 0,
        use_dns: 1,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut NetBootInfo).write(info);
    }
    // Raw pointers to both result bytes -- reachable via the physical-
    // memory-offset mapping regardless of which `Cr3` is active, same as
    // `info_content` itself (see `map_private_page`'s doc comment).
    let dns_result_ptr = unsafe { info_content.as_mut_ptr().add(NET_DNS_RESULT_OFFSET as usize) };
    let dns_addr_ptr = unsafe { info_content.as_mut_ptr().add(NET_DNS_ADDR_OFFSET as usize) };
    let icmp_result_ptr = unsafe { info_content.as_mut_ptr().add(NET_RESULT_OFFSET as usize) };

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

    #[allow(static_mut_refs)]
    unsafe {
        ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process_with_capability(kernel_trampoline, space, Some(net_token));

    // ICMP's own poll bound is 2,000,000 iterations, then the DNS phase
    // runs its own further 2,000,000 -- same generous headroom convention
    // `net_driver_dhcp.rs` already uses for its two phases.
    let mut icmp_result = 0u8;
    let mut dns_result = 0u8;
    for _ in 0..6000 {
        scheduler::yield_now();
        icmp_result = unsafe { core::ptr::read_volatile(icmp_result_ptr) };
        dns_result = unsafe { core::ptr::read_volatile(dns_result_ptr) };
        if icmp_result != 0 && dns_result != 0 {
            break;
        }
    }

    if icmp_result != NET_RESULT_PASS {
        serial_println!(
            "net_driver_dns: FAIL — ICMP result byte was {} (0 = never finished, 2 = no echo \
             reply)",
            icmp_result
        );
        exit_qemu(QemuExitCode::Failed);
    }

    if dns_result != NET_RESULT_PASS {
        serial_println!(
            "net_driver_dns: FAIL — DNS result byte was {} after ICMP (0 = never finished, 2 = \
             no answer within poll bound -- the phase-transition timestamp offset `run_dns_lookup` \
             receives may be wrong)",
            dns_result
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let resolved_ip: [u8; 4] = unsafe {
        [
            core::ptr::read_volatile(dns_addr_ptr),
            core::ptr::read_volatile(dns_addr_ptr.add(1)),
            core::ptr::read_volatile(dns_addr_ptr.add(2)),
            core::ptr::read_volatile(dns_addr_ptr.add(3)),
        ]
    };
    // A real answer, not a placeholder -- `0.0.0.0` would mean the result
    // byte lied about actually resolving a name.
    if resolved_ip == [0, 0, 0, 0] {
        serial_println!(
            "net_driver_dns: FAIL — DNS reported PASS but the resolved address was 0.0.0.0"
        );
        exit_qemu(QemuExitCode::Failed);
    }
    serial_println!(
        "net_driver_dns: real DNS answer received: {}.{}.{}.{}",
        resolved_ip[0],
        resolved_ip[1],
        resolved_ip[2],
        resolved_ip[3]
    );

    serial_println!(
        "net_driver_dns: PASS — net-driver-host resolved a real hostname via QEMU/SLIRP's DNS \
         forwarder and still completed the ICMP echo proof beforehand on the same Interface"
    );
    exit_qemu(QemuExitCode::Success);
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
    serial_println!("net_driver_dns: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
