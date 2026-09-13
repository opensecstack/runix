//! Filesystem driver, Phase 2 (see docs/STATUS.md's filesystem-driver
//! narrative): proves a real `blk-driver-host` ring-3 process can locate
//! `HELLO.TXT` in a real FAT32 image's root directory, walk its cluster
//! chain via the FAT, and read back its exact contents. Structurally
//! identical to `blk_driver_rw.rs` (Phase 1's raw sector round-trip test —
//! see that file for why each ELF-load/map/spawn step is shaped the way it
//! is), except `attempt_fat32: 1` is set in `BlkBootInfo` and this test
//! polls `BLK_FAT32_RESULT_OFFSET` instead of `BLK_RESULT_OFFSET` (Phase 1's
//! own sector round-trip proof stays covered by `blk_driver_rw.rs`, not
//! re-checked here).
//!
//! **Requires a real FAT32 fixture image**, built by
//! `kernel/tests/support/make_fat32_image.sh`, with `xtask`'s virtio-blk
//! `-drive` pointed at it via `RUNIX_BLK_IMG` (see `xtask/src/main.rs`'s
//! `run_qemu`) — without both, `blk-driver-host` finds no valid FAT32 boot
//! sector and reports FAIL.
//!
//! **Manual build step required when running this locally** (same
//! requirement `net_driver_icmp.rs` has for its own payload):
//!
//! ```text
//! cd blk-driver-host && cargo build --target x86_64-unknown-none --release
//! ```
//!
//! CI does this automatically (`.github/workflows/ci.yml`'s `kernel-tests`
//! job builds `blk-driver-host` before running this test).

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

static BLK_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../blk-driver-host/target/x86_64-unknown-none/release/blk-driver-host");

// Must match `blk-driver-host/src/main.rs`'s own constants exactly — see
// `kernel/src/main.rs`'s identical set for the full "why 0x0999" account.
const BLK_HEAP_START: u64 = 0x_0999_1111_0000;
const BLK_HEAP_SIZE: u64 = 256 * 1024;
const BLK_STACK_VA: u64 = 0x_0999_2222_0000;
const BLK_STACK_SIZE: u64 = 4096 * 4;
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;
const BLK_QUEUE_ALIGN: u64 = 4096;

// Must match `blk-driver-host/src/main.rs`'s `BLK_FAT32_RESULT_OFFSET`/`BLK_RESULT_PASS`.
const BLK_FAT32_RESULT_OFFSET: u64 = 129;
const BLK_RESULT_PASS: u8 = 1;

#[repr(C)]
struct BlkBootInfo {
    io_base: u16,
    _pad: u16,
    queue_phys: u64,
    reqbuf_phys: u64,
    attempt_fat32: u8,
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
    let io_base = match runix_kernel::pci::find_virtio_blk(&devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => io_base,
        None => {
            serial_println!(
                "blk_fat32_read: FAIL — no virtio-blk I/O-space BAR0 found (is xtask's \
                 -device virtio-blk-pci still wired into run_qemu?)"
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "blk-driver-host",
        BLK_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "blk_fat32_read: FAIL — CITADEL allowlist rejected blk-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "blk_fat32_read: parsing blk-driver-host ({} bytes)",
        BLK_DRIVER_HOST_ELF.len()
    );
    let elf = match Elf64::parse(BLK_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "blk_fat32_read: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("blk_fat32_read: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!("blk_fat32_read: loaded, entry point {:#x}", entry.as_u64());

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
        attempt_fat32: 1,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut BlkBootInfo).write(info);
    }
    // Keep a raw pointer to the result byte -- reachable via the physical-
    // memory-offset mapping regardless of which `Cr3` is active, same as
    // `info_content` itself (see `map_private_page`'s doc comment).
    let result_ptr = unsafe {
        info_content
            .as_mut_ptr()
            .add(BLK_FAT32_RESULT_OFFSET as usize)
    };

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let blk_token = runix_capability_manager::CapabilityToken::issue(
        "blk-driver-host",
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
    scheduler::spawn_ring3_process_with_capability(kernel_trampoline, space, Some(blk_token));

    // No network wait needed here -- a virtio-blk write-then-read-back round
    // trip is local to QEMU, not dependent on an external reply arriving.
    // Bumped from 100 as Phase 3-6 each added more sequential virtio
    // requests to this one boot's combined proof (subdirectory, big
    // file, long name, case-insensitive match, write, partial write) --
    // same "the poll bound needs to grow as the work it's waiting for
    // grows" adjustment the `boot` job's own QEMU timeout already needed
    // (90s -> 150s) for the same underlying reason. Still bounded, not
    // infinite; breaks early once the result byte goes non-zero.
    let mut result = 0u8;
    for _ in 0..2000 {
        scheduler::yield_now();
        result = unsafe { core::ptr::read_volatile(result_ptr) };
        if result != 0 {
            break;
        }
    }

    if result == BLK_RESULT_PASS {
        serial_println!(
            "blk_fat32_read: PASS — a real compiled binary located HELLO.TXT on a real FAT32 \
             filesystem over virtio-blk and read back its exact contents, in an isolated ring 3 \
             process"
        );
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "blk_fat32_read: FAIL — blk-driver-host reported FAT32 result byte {} (0 = never \
             finished, 2 = locate/read failed)",
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
    serial_println!("blk_fat32_read: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
