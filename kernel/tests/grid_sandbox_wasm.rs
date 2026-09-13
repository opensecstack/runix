//! The real integration this session's process-isolation/ELF-loader/
//! multi-process-scheduling work was for: loads an *actual compiled
//! binary* (`grid-sandbox-host`, a separate freestanding crate — see
//! `grid-sandbox-host/src/main.rs`) through `elf::Elf64`, maps it into its
//! own `process::AddressSpace`, and runs it as a real ring 3 process via
//! `scheduler::spawn_ring3_process` — not a hand-written naked function
//! like `ring3_cooperative.rs`'s processes, a genuine `rustc`-compiled
//! program that hosts the `wasmi` engine and executes a real WASM module.
//!
//! **Manual build step required when running this locally**: unlike every
//! other test here, `include_bytes!` below needs `grid-sandbox-host`'s
//! compiled output to already exist on disk — this crate isn't part of any
//! workspace `cargo test` orchestrates automatically (it targets
//! `x86_64-unknown-none` from a separate standalone package, like
//! `kernel`/`xtask` themselves). Build it first:
//!
//! ```text
//! cd grid-sandbox-host && cargo build --target x86_64-unknown-none --release
//! ```
//!
//! CI does this step automatically (`.github/workflows/ci.yml` builds
//! `grid-sandbox-host` before running this test) — the manual step above is
//! only needed for a local `cargo test` run.
//!
//! If `grid-sandbox-host`'s expected output ("Hi", via two `host.print`
//! calls from its embedded `hello.wat` module) reaches the kernel's
//! `SYS_WRITE` handler, the whole chain worked: host allocator init on a
//! kernel-mapped private heap, `wasmi` engine/module/store construction,
//! host-function import wiring, guest bytecode execution, and the syscall
//! gate back out — running entirely inside a hardware-isolated ring 3
//! process the ELF loader built from a real compiled binary.

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
/// that binary has no privilege to map its own memory (ring 3 code can't
/// touch page tables at all), so whoever loads it has to set this up.
const PAYLOAD_HEAP_START: u64 = 0x_2222_2222_0000;
/// 8 MiB, not 256 KiB — see `grid-sandbox-host/src/main.rs`'s own
/// `HEAP_SIZE` doc comment: the boot-level tier-correctness probe below
/// needs this process's real allocator to back a real `memory.grow`, not
/// just a limiter that abstractly permits it.
const PAYLOAD_HEAP_SIZE: u64 = 8 * 1024 * 1024;
const PAYLOAD_STACK_VA: u64 = 0x_2222_3333_0000;
const PAYLOAD_STACK_SIZE: u64 = 4096 * 4;
/// Must match `kernel/src/main.rs`'s own `GRID_INFO_VA` — this test doesn't
/// import that private const, so it's redefined here, same as
/// `PAYLOAD_HEAP_START` etc. above already mirror `main.rs`'s constants.
const GRID_INFO_VA: u64 = 0x_2222_4444_0000;
/// Must match `kernel/src/main.rs`'s own `GRID_GROW_RESULT_OFFSET` and
/// `grid-sandbox-host/src/main.rs`'s own constants of the same names —
/// same "kernel writes the request, ring-3 process writes the result"
/// convention `net_driver_icmp.rs` already uses for `NET_RESULT_OFFSET`.
const GRID_GROW_RESULT_OFFSET: usize = 128;
const GRID_GROW_RESULT_FAILED: u8 = 2;

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

    // Before any `AddressSpace::new()` — see `scheduler::init`'s doc
    // comment on why.
    scheduler::init();

    serial_println!(
        "grid_sandbox_wasm: parsing grid-sandbox-host ({} bytes)",
        GRID_SANDBOX_HOST_ELF.len()
    );
    let elf = match Elf64::parse(GRID_SANDBOX_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "grid_sandbox_wasm: FAIL — parse() rejected the binary: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("grid_sandbox_wasm: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "grid_sandbox_wasm: loaded, entry point {:#x}",
        entry.as_u64()
    );

    // The ELF loader only maps what the ELF itself declares. The payload's
    // heap and its ring 3 stack are runtime-only regions with no PT_LOAD
    // segment behind them — mapping those is this loader's job, same as
    // `ring3_cooperative.rs`'s `build_process` maps a stack alongside
    // whatever code it's granting access to.
    let heap_start_page = Page::containing_address(VirtAddr::new(PAYLOAD_HEAP_START));
    let heap_end_page =
        Page::containing_address(VirtAddr::new(PAYLOAD_HEAP_START + PAYLOAD_HEAP_SIZE - 1));
    let heap_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        // Unlike `elf::Elf64::load_segments` (which fills BSS explicitly),
        // a freshly allocated frame here carries whatever its previous
        // owner left in it, not guaranteed-zero — `LockedHeap::init` only
        // writes its own free-list header at the front of the region, not
        // every byte, so a payload that reads before writing (or a
        // corrupted-looking pointer surfacing from stale physical memory)
        // can observe that leftover content. Zero explicitly rather than
        // relying on it happening to already be clean.
        space.map_private_page(page, heap_flags).fill(0);
    }

    // `map_private_page` maps exactly one 4 KiB page per call — mapping only
    // `stack_page` (the first of `PAYLOAD_STACK_SIZE`'s 4 pages) left the
    // upper 3 pages unmapped while `kernel_trampoline` below still handed
    // `_start` a top-of-stack pointer 4 pages up (`PAYLOAD_STACK_VA +
    // PAYLOAD_STACK_SIZE`), so the very first push near the top of that
    // stack (inside `wasmi`/the allocator, well before any guest bytecode
    // runs) page-faulted. Loop over the whole range, same pattern as the
    // heap mapping just above.
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

    // GridBootInfo: the one page grid-sandbox-host reads at startup to learn
    // its sandbox tier — same pattern `net_driver_icmp.rs` uses for
    // `NetBootInfo`. T2Trusted here, matching the real boot path's choice
    // for grid-sandbox-host.
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
            GridBootInfo { tier: 1 },
        );
    }
    // Same pointer-into-the-shared-page trick `net_driver_icmp.rs` uses for
    // `NetBootInfo`'s result byte — reachable via the physical-memory-offset
    // mapping regardless of which `Cr3` is active.
    let grow_result_ptr = unsafe { info_content.as_mut_ptr().add(GRID_GROW_RESULT_OFFSET) };

    #[allow(static_mut_refs)]
    unsafe {
        ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process(kernel_trampoline, space);

    // The payload writes 'H', 'i', runs the tier-correctness grow probe,
    // then yields forever — a handful of round trips is plenty; a fault or
    // corruption aborts immediately regardless, from the payload's own
    // panic handler or a kernel fault.
    let mut grow_result = 0u8;
    for _ in 0..20 {
        scheduler::yield_now();
        grow_result = unsafe { core::ptr::read_volatile(grow_result_ptr) };
        if grow_result != 0 {
            break;
        }
    }

    // This tier (T2Trusted, 64-page/4 MiB cap) must reject the same
    // 70-page growth request `grid_sandbox_tier_t1.rs` proves T1Critical
    // allows — see `grid-sandbox-host`'s `GROW_PROBE_DELTA_PAGES` doc
    // comment for why this one request size distinguishes all three tiers.
    if grow_result != GRID_GROW_RESULT_FAILED {
        serial_println!(
            "grid_sandbox_wasm: FAIL — expected the T2Trusted-tier grow probe to fail \
             (byte {}), got {}",
            GRID_GROW_RESULT_FAILED,
            grow_result
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "grid_sandbox_wasm: PASS — a real compiled binary ran wasmi in an isolated ring 3 \
         process, called back through the syscall gate, and its T2Trusted tier correctly \
         rejected a real memory.grow past its 4 MiB ceiling"
    );
    exit_qemu(QemuExitCode::Success);
}

/// `entry` (the ELF's own entry point, `_start` in `grid-sandbox-host`) is
/// only known at runtime (parsed from the loaded binary), unlike
/// `ring3_cooperative.rs`'s hardcoded constants — captured in this
/// `static` so the `extern "C" fn() -> !` trampoline `spawn_ring3_process`
/// requires (a bare function pointer, no captures) can still reach it.
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
    serial_println!("grid_sandbox_wasm: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
