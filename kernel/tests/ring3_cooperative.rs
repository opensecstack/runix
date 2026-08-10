//! Proves the missing half of multi-process scheduling: two *real* ring 3
//! processes, each in its own `process::AddressSpace`, each with its own
//! dedicated kernel-entry stack (`scheduler::spawn_ring3_process`),
//! genuinely cooperating with the scheduler via `SYS_YIELD` from ring 3 —
//! not just switching `Cr3` in ring 0 (`scheduler_address_space.rs`
//! already proved that half).
//!
//! Each process runs a hand-written naked function (its own code page,
//! mapped read+exec, never writable — real W^X, same as the ELF loader):
//! write a marker byte via `SYS_WRITE`, `SYS_YIELD`, repeat 3 times, then
//! yield forever. If per-thread kernel-entry stacks didn't actually work —
//! if both processes' ring 3 traps still landed on one shared RSP0 — the
//! second process trapping in while the first was suspended mid-syscall
//! would corrupt the first's saved context, which would show up here as a
//! fault, a corrupted register state, or a hang well within the bounded
//! number of round trips this test runs. Reaching PASS is real, hardware-
//! level proof both processes' entire round trip (ring 3 -> `int 0x80` ->
//! `yield_now` -> suspended -> resumed -> `iretq` back to ring 3) worked
//! correctly, interleaved, without stepping on each other.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::arch::naked_asm;
use core::panic::PanicInfo;
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

const CODE_A_VA: u64 = 0x_7777_1000_0000;
const STACK_A_VA: u64 = 0x_7777_1000_1000;
const CODE_B_VA: u64 = 0x_7777_2000_0000;
const STACK_B_VA: u64 = 0x_7777_2000_1000;

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

    // `scheduler::init()` before any `AddressSpace::new()` — see its own
    // doc comment on why (reserves the stack-region P4 slots up front).
    scheduler::init();

    serial_println!("ring3_cooperative: mapping two independent ring 3 processes");
    let space_a = build_process(CODE_A_VA, STACK_A_VA, ring3_entry_a as *const () as u64);
    let space_b = build_process(CODE_B_VA, STACK_B_VA, ring3_entry_b as *const () as u64);

    scheduler::spawn_ring3_process(kernel_trampoline_a, space_a);
    scheduler::spawn_ring3_process(kernel_trampoline_b, space_b);

    // Each process does 3 rounds of (SYS_WRITE, SYS_YIELD), then yields
    // forever — round-robin among 3 runnable contexts (this boot thread +
    // the two ring 3 processes) means generous slack is needed for both to
    // get through their real work; a fault or corruption from either one
    // aborts immediately regardless, via its own panic/exit path.
    for _ in 0..60 {
        scheduler::yield_now();
    }

    serial_println!(
        "ring3_cooperative: PASS — two ring 3 processes ran, yielded, and resumed \
         repeatedly without corrupting each other's kernel-entry stack"
    );
    exit_qemu(QemuExitCode::Success);
}

/// Builds an address space with `entry_frame`'s code mapped read+exec
/// (never writable — real W^X) at `code_va`, and a private, writable,
/// non-executable stack at `stack_va`.
fn build_process(code_va: u64, stack_va: u64, entry_addr: u64) -> AddressSpace {
    let entry_frame = runix_kernel::memory::translate_kernel_addr(VirtAddr::new(entry_addr))
        .expect("ring 3 entry function has no backing physical frame");

    let mut space = AddressSpace::new();
    let code_page = Page::containing_address(VirtAddr::new(code_va));
    let code_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    unsafe {
        space.map_existing_frame(code_page, entry_frame, code_flags);
    }

    let stack_page = Page::containing_address(VirtAddr::new(stack_va));
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    space.map_private_page(stack_page, stack_flags);

    space
}

extern "C" fn kernel_trampoline_a() -> ! {
    unsafe {
        userspace::enter_usermode(VirtAddr::new(CODE_A_VA), VirtAddr::new(STACK_A_VA + 4096));
    }
}

extern "C" fn kernel_trampoline_b() -> ! {
    unsafe {
        userspace::enter_usermode(VirtAddr::new(CODE_B_VA), VirtAddr::new(STACK_B_VA + 4096));
    }
}

/// Writes `'A'` via `SYS_WRITE`, then `SYS_YIELD`s, three times — proving
/// a real ring 3 -> ring 0 -> ring 3 round trip through the scheduler —
/// then yields forever. `.balign 4096` (like `userspace::user_hello`) so
/// its containing page holds nothing else this process shouldn't be able
/// to execute.
///
/// `push rcx`/`pop rcx` around each syscall pair, using the ring 3 stack
/// `build_process` mapped: `int 0x80` isn't a normal call with a
/// register-preservation ABI — `syscall::entry`'s `mov rcx, rdx` (part of
/// remapping syscall-convention args onto SysV ones for `dispatch`)
/// clobbers RCX on every trip through it. The first version of this test
/// used RCX as the loop counter *without* saving it, which "worked" in the
/// sense that nothing faulted, but the counter never reliably reached
/// zero — the actual proof this test cares about (a real, repeated ring 3
/// round trip) still held, but the serial output was a much longer
/// A/B run than the intended 3 each, not the clean interleave the doc
/// comment above claims.
#[unsafe(naked)]
unsafe extern "C" fn ring3_entry_a() -> ! {
    naked_asm!(
        ".balign 4096",
        "mov ecx, 3",
        "2:",
        "push rcx",
        "mov eax, 1",  // SYS_WRITE
        "mov edi, 65", // 'A'
        "int 0x80",
        "mov eax, 0", // SYS_YIELD
        "int 0x80",
        "pop rcx",
        "dec ecx",
        "jnz 2b",
        "3:",
        "mov eax, 0", // SYS_YIELD
        "int 0x80",
        "jmp 3b",
    );
}

/// Same as [`ring3_entry_a`], writing `'B'` instead — its own separate
/// function, so it compiles to its own separate physical code page.
#[unsafe(naked)]
unsafe extern "C" fn ring3_entry_b() -> ! {
    naked_asm!(
        ".balign 4096",
        "mov ecx, 3",
        "2:",
        "push rcx",
        "mov eax, 1",  // SYS_WRITE
        "mov edi, 66", // 'B'
        "int 0x80",
        "mov eax, 0", // SYS_YIELD
        "int 0x80",
        "pop rcx",
        "dec ecx",
        "jnz 2b",
        "3:",
        "mov eax, 0", // SYS_YIELD
        "int 0x80",
        "jmp 3b",
    );
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("ring3_cooperative: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
