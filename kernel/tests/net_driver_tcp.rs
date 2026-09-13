//! Network stack, Phase 2b (see docs/STATUS.md's network-stack section):
//! proves a real TCP client works, not just the IP/ICMP layer Phase 2a
//! already proved. Loads `net-driver-host` (a real compiled ELF, same
//! mechanism `grid_sandbox_wasm.rs` already proved for `grid-sandbox-host`)
//! as a capability-gated ring 3 process, sets `NetBootInfo::attempt_tcp`,
//! and lets it connect out to a `guestfwd`-bridged host listener
//! (`kernel/tests/support/tcp_proof_listener.py`), send a fixed payload,
//! and check the exact reply.
//!
//! SLIRP (QEMU's `-netdev user` backend) has no built-in TCP listener at
//! all -- connecting to the gateway would prove nothing. This test instead
//! relies on the CI/test harness having already started
//! `tcp_proof_listener.py` on `127.0.0.1:9001` and set
//! `RUNIX_NETDEV_ARG=user,id=net0,guestfwd=tcp:10.0.2.100:9000-cmd:nc 127.0.0.1 9001`
//! (`.github/workflows/ci.yml`'s `kernel-tests` job) before `xtask`'s
//! `test-runner` boots this test in QEMU -- `xtask/src/main.rs::run_qemu`
//! reads that env var to override its otherwise-hardcoded `-netdev` value.
//! Running this file directly without that setup will simply time out
//! waiting for a TCP reply that never arrives (result byte stays `2`/FAIL,
//! not a fault) -- see the module doc comment in
//! `kernel/tests/support/tcp_proof_listener.py` for the manual local
//! invocation this needs.
//!
//! **Manual build step required when running this locally** (same
//! requirement `grid_sandbox_wasm.rs` already has for its own payload):
//!
//! ```text
//! cd net-driver-host && cargo build --target x86_64-unknown-none --release
//! ```
//!
//! Pass/fail is a real result code, not "didn't crash": `net-driver-host`
//! writes a PASS/FAIL byte into the shared `NetBootInfo` page at
//! `NET_TCP_RESULT_OFFSET` after its own bounded poll loop finishes --
//! reaching the end of this test's yield budget without a fault only
//! proves nothing crashed; reading back an actual PASS byte proves the TCP
//! round-trip through QEMU's `guestfwd` bridge and the host listener
//! genuinely succeeded, with the exact payload bytes verified on both
//! ends (the guest checks the exact reply; `tcp_proof_listener.py`
//! independently checks the exact request).

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
// `kernel/src/main.rs`'s identical set for the full "why 0x1" account (a
// prior `0x_3333_...` choice collided with `scheduler.rs`'s
// `KERNEL_ENTRY_STACK_REGION_START`).
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

// Must match `net-driver-host/src/main.rs`'s `NET_TCP_RESULT_OFFSET`/`NET_RESULT_PASS`.
const NET_TCP_RESULT_OFFSET: u64 = 129;
const NET_RESULT_PASS: u8 = 1;

#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; 8],
    tx_buffer_phys: [u64; 4],
    attempt_tcp: u8,
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
            serial_println!(
                "net_driver_tcp: FAIL — no virtio-net I/O-space BAR0 found (is xtask's \
                 -device virtio-net-pci still wired into run_qemu?)"
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
            "net_driver_tcp: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "net_driver_tcp: parsing net-driver-host ({} bytes)",
        NET_DRIVER_HOST_ELF.len()
    );
    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "net_driver_tcp: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("net_driver_tcp: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!("net_driver_tcp: loaded, entry point {:#x}", entry.as_u64());

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
        attempt_tcp: 1,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut NetBootInfo).write(info);
    }
    // Keep a raw pointer to the result byte -- reachable via the physical-
    // memory-offset mapping regardless of which `Cr3` is active, same as
    // `info_content` itself (see `map_private_page`'s doc comment).
    let result_ptr = unsafe {
        info_content
            .as_mut_ptr()
            .add(NET_TCP_RESULT_OFFSET as usize)
    };

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

    // Bigger budget than net_driver_icmp.rs's 3000: this run does the ICMP
    // proof *first* (its own full poll bound before falling through) and
    // only starts the TCP attempt afterward, so the TCP result byte can
    // take longer to appear even on a successful run.
    let mut result = 0u8;
    for _ in 0..6000 {
        scheduler::yield_now();
        result = unsafe { core::ptr::read_volatile(result_ptr) };
        if result != 0 {
            break;
        }
    }

    if result == NET_RESULT_PASS {
        serial_println!(
            "net_driver_tcp: PASS — a real compiled binary connected out over TCP through QEMU's \
             guestfwd bridge and exchanged exact bytes with a real host listener, from an \
             isolated ring 3 process"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "net_driver_tcp: FAIL — net-driver-host reported TCP result byte {} (0 = never \
             finished -- is RUNIX_NETDEV_ARG/the host listener actually set up?, 2 = reply \
             missing or wrong)",
            result
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

/// Same as `kernel/src/main.rs`'s function of the same name — see its doc
/// comment for why the leaf frames are batched *before* any `map_to`-driven
/// page-table-build can interleave and break physical contiguity.
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
    serial_println!("net_driver_tcp: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
