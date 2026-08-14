//! Runix microkernel, ARM/TrustZone boot bring-up (L1, mobile) -- Alpha
//! scope: boot to EL3 (Secure Monitor, the exception level TrustZone
//! Secure-world firmware runs at) with a working UART, nothing more yet.
//!
//! # Status
//!
//! Proven in QEMU (`qemu-system-aarch64 -M virt,secure=on -cpu cortex-a53`):
//! boots, sets up its own stack (hardware/QEMU doesn't guarantee a sane SP
//! at entry, unlike x86_64 BIOS boot), and confirms via `CurrentEL` that it
//! is genuinely running at EL3, not just assumed to be. That is the entire
//! scope so far -- no exception vector table, no GIC, no EL3->EL1
//! Non-secure transition (the actual "TrustZone" boundary), no RIL/SIM
//! work. See `mobile/src/lib.rs`'s doc comment: that work "starts once the
//! shared kernel boots on target hardware" -- this crate is the first slice
//! of making that true, not the target hardware bring-up itself yet.
//!
//! **Known gap**: the identical binary produces no UART output at all when
//! booted without secure mode (`-M virt` without `secure=on`, which starts
//! at EL1 instead of EL3). Not yet root-caused -- flagged rather than
//! silently ignored. Not a blocker for Alpha's actual target (EL3 Secure
//! Monitor boot, which does work), but worth investigating before anything
//! depends on a non-secure boot path specifically.
//!
//! # Why a separate crate from `kernel/`
//!
//! `kernel/` is deeply `x86_64`-specific today: GDT/IDT (`extern
//! "x86-interrupt"`), the 8259 PIC/PIT, `int 0x80`, and a dependency on the
//! `bootloader` crate (BIOS/UEFI image building) that has no ARM
//! equivalent. The root README's layer table lists a single crate `kernel`
//! covering both desktop's microkernel and mobile's "microkernel + ARM
//! TrustZone" -- this crate does *not* yet realize that (one crate, two
//! architectures via `cfg(target_arch)`); reconciling the two is an open
//! design question, not a decision made here. `runix-kernel-arm` is the
//! pragmatic Alpha-stage choice: get a real, QEMU-verified ARM boot path
//! established quickly, in its own freestanding workspace (same pattern
//! `kernel`/`xtask`/`grid-sandbox-host` already use for their own distinct
//! target triples), rather than block on that architecture decision first.
//!
//! # Why no bootloader crate
//!
//! Unlike x86_64 BIOS boot, QEMU's `virt` machine loads a `-kernel` ELF
//! image and jumps straight to its entry point -- no separate
//! bootloader/image-building step the way `xtask` provides for `kernel/`.
//! `linker.ld` places `.text` at a fixed, conventional load address
//! (0x40080000, safely inside `virt`'s default RAM window) instead.

#![no_std]
#![no_main]

mod serial;

use core::arch::naked_asm;
use core::panic::PanicInfo;

const STACK_SIZE: usize = 4096 * 16;

// The field is never read through Rust -- only its address (via `adrp`/
// `add` in `_start`'s asm) and its raw memory (as stack space the CPU
// writes to directly) are ever used.
#[repr(align(16))]
#[allow(dead_code)]
struct Stack([u8; STACK_SIZE]);

#[unsafe(no_mangle)]
static mut BOOT_STACK: Stack = Stack([0; STACK_SIZE]);

/// Hardware/QEMU doesn't guarantee a sane SP at entry -- set one explicitly
/// before touching anything else. Naked, not normal Rust: the very first
/// instructions here run before there is a stack to run ordinary
/// (potentially stack-using) Rust function-call code on at all.
///
/// # Safety
/// Never call this directly -- it's the ELF entry point, only ever reached
/// by QEMU (or eventually real firmware) jumping the CPU to it with no
/// stack, no runtime, and no other state established yet. Calling it as a
/// normal Rust function would run its raw asm body in the current, wrong
/// context.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "adrp x0, {stack}",
        "add x0, x0, :lo12:{stack}",
        "add x0, x0, {size}",
        "mov sp, x0",
        "bl rust_start",
        "2:",
        "wfe",
        "b 2b",
        stack = sym BOOT_STACK,
        size = const STACK_SIZE,
    );
}

/// Reads `CurrentEL` and returns the exception level (0-3) -- bits [3:2] of
/// the register, per the Arm Architecture Reference Manual. Confirms *at
/// runtime* which level booted us, rather than assuming `secure=on` implies
/// EL3 without checking.
fn current_el() -> u8 {
    let current_el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el);
    }
    ((current_el >> 2) & 0b11) as u8
}

#[unsafe(no_mangle)]
extern "C" fn rust_start() -> ! {
    serial_println!("Runix ARM kernel: boot OK");
    serial_println!("Runix ARM kernel: CurrentEL = EL{}", current_el());

    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}
