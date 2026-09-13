//! Boot-level tier-correctness proof, T1Critical: same real `grid-sandbox-host`
//! binary and load mechanism as `grid_sandbox_wasm.rs` (see that file's own
//! doc comment for the full chain this proves), but assigns `T1Critical`
//! instead of `T2Trusted` and asserts the *opposite* outcome for the same
//! fixed grow request — see `grid-sandbox-host/src/main.rs`'s
//! `GROW_PROBE_DELTA_PAGES` doc comment for why this one request size (70
//! total pages, ~4.375 MiB) is allowed under T1Critical's 128-page/8 MiB
//! ceiling but rejected under T2Trusted's and T3Untrusted's.
//!
//! This is the piece `wasm-runtime/tests/tier_isolation.rs` (host-side,
//! effectively unlimited host process memory) can't prove on its own: that
//! the real ring-3 `grid-sandbox-host` process, with its own real
//! 8-MiB-capped private heap, can actually *satisfy* a T1-permitted growth
//! request, not just that `wasmi::Store::limiter` abstractly says yes.
//!
//! **Manual build step required when running this locally** — same as
//! `grid_sandbox_wasm.rs`:
//!
//! ```text
//! cd grid-sandbox-host && cargo build --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::elf::Elf64;
use runix_kernel::process::AddressSpace;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use runix_kernel::userspace;
use x86_64::structures::paging::{Page, PageTableFlags};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Must match `grid-sandbox-host/src/main.rs`'s `HEAP_START`/`HEAP_SIZE` —
/// see that constant's doc comment for why 8 MiB, not 256 KiB.
const PAYLOAD_HEAP_START: u64 = 0x_2222_2222_0000;
const PAYLOAD_HEAP_SIZE: u64 = 8 * 1024 * 1024;
const PAYLOAD_STACK_VA: u64 = 0x_2222_3333_0000;
const PAYLOAD_STACK_SIZE: u64 = 4096 * 4;
/// Must match `kernel/src/main.rs`'s own `GRID_INFO_VA`/`GRID_GROW_RESULT_OFFSET`
/// and `grid-sandbox-host/src/main.rs`'s own constants of the same names.
const GRID_INFO_VA: u64 = 0x_2222_4444_0000;
const GRID_GROW_RESULT_OFFSET: usize = 128;
const GRID_GROW_RESULT_SUCCEEDED: u8 = 1;

/// Mirrors `kernel/src/main.rs`'s own `GridBootInfo` — `repr(C)`, same field
/// order, agreed ABI convention only (see that struct's doc comment).
#[repr(C)]
struct GridBootInfo {
    tier: u8,
}

static GRID_SANDBOX_HOST_ELF: &[u8] =
    include_bytes!("../../grid-sandbox-host/target/x86_64-unknown-none/release/grid-sandbox-host");

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

    serial_println!(
        "grid_sandbox_tier_t1: parsing grid-sandbox-host ({} bytes)",
        GRID_SANDBOX_HOST_ELF.len()
    );
    let elf = match Elf64::parse(GRID_SANDBOX_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "grid_sandbox_tier_t1: FAIL — parse() rejected the binary: {:?}",
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
                "grid_sandbox_tier_t1: FAIL — load_segments() failed: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "grid_sandbox_tier_t1: loaded, entry point {:#x}",
        entry.as_u64()
    );

    let heap_start_page = Page::containing_address(VirtAddr::new(PAYLOAD_HEAP_START));
    let heap_end_page =
        Page::containing_address(VirtAddr::new(PAYLOAD_HEAP_START + PAYLOAD_HEAP_SIZE - 1));
    let heap_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        space.map_private_page(page, heap_flags).fill(0);
    }

    let stack_start_page = Page::containing_address(VirtAddr::new(PAYLOAD_STACK_VA));
    let stack_end_page =
        Page::containing_address(VirtAddr::new(PAYLOAD_STACK_VA + PAYLOAD_STACK_SIZE - 1));
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(stack_start_page, stack_end_page) {
        space.map_private_page(page, stack_flags);
    }

    // GridBootInfo: tier 0 == T1Critical (see kernel/src/main.rs's
    // `GridBootInfo` doc comment for the 0/1/2 -> T1/T2/T3 mapping) — the
    // one thing this test changes relative to `grid_sandbox_wasm.rs`.
    let info_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let info_page = Page::containing_address(VirtAddr::new(GRID_INFO_VA));
    let info_content = space.map_private_page(info_page, info_flags);
    info_content.fill(0);
    unsafe {
        core::ptr::write_volatile(
            info_content.as_mut_ptr() as *mut GridBootInfo,
            GridBootInfo { tier: 0 },
        );
    }
    let grow_result_ptr = unsafe { info_content.as_mut_ptr().add(GRID_GROW_RESULT_OFFSET) };

    #[allow(static_mut_refs)]
    unsafe {
        ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process(kernel_trampoline, space);

    let mut grow_result = 0u8;
    for _ in 0..20 {
        scheduler::yield_now();
        grow_result = unsafe { core::ptr::read_volatile(grow_result_ptr) };
        if grow_result != 0 {
            break;
        }
    }

    if grow_result != GRID_GROW_RESULT_SUCCEEDED {
        serial_println!(
            "grid_sandbox_tier_t1: FAIL — expected the T1Critical-tier grow probe to succeed \
             (byte {}), got {}",
            GRID_GROW_RESULT_SUCCEEDED,
            grow_result
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "grid_sandbox_tier_t1: PASS — a real ring-3 grid-sandbox-host process, assigned \
         T1Critical by a CITADEL-signed tier, actually grew its WASM memory past what \
         T2Trusted/T3Untrusted would allow, backed by its own real (8 MiB) heap"
    );
    exit_qemu(QemuExitCode::Success);
}

static mut ENTRY_POINT: u64 = 0;

extern "C" fn kernel_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { ENTRY_POINT };
    unsafe {
        userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(PAYLOAD_STACK_VA + PAYLOAD_STACK_SIZE),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("grid_sandbox_tier_t1: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
