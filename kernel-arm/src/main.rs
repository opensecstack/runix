//! Runix microkernel, ARM/TrustZone boot bring-up (L1, mobile) -- Alpha
//! scope: boot to EL3 (Secure Monitor, the exception level TrustZone
//! Secure-world firmware runs at), install a real exception vector table,
//! drop to EL1 Non-secure (the actual TrustZone boundary), and start
//! bringing up the GIC.
//!
//! # Status
//!
//! Proven in QEMU (`qemu-system-aarch64 -M virt,secure=on -cpu cortex-a53`):
//!
//! - Boots, sets up its own stack (hardware/QEMU doesn't guarantee a sane
//!   SP at entry, unlike x86_64 BIOS boot), and confirms via `CurrentEL`
//!   that it is genuinely running at EL3, not just assumed to be.
//! - A real `VBAR_EL3` exception vector table (see `vectors.rs`) catches a
//!   deliberately-triggered synchronous exception (`brk`), reports it
//!   (vector index + `ESR_EL3`), and resumes execution afterward with the
//!   interrupted code's full register context correctly preserved -- not
//!   assumed safe, fixed after a real corruption bug during development
//!   (see `vectors.rs`'s doc comment).
//! - The actual TrustZone boundary: drops from EL3 to EL1 Non-secure via
//!   `eret` (see `nonsecure.rs`), and EL1 code confirms via `CurrentEL`
//!   that it landed there.
//! - GIC bring-up (see `gic.rs`) is **partial**: a Software Generated
//!   Interrupt genuinely reaches the distributor (`GICD_ISPENDR0` reads
//!   back pending), but delivery all the way into the IRQ/FIQ vector isn't
//!   proven yet -- flagged honestly in `gic.rs`, not papered over.
//!
//! Not yet started: RIL/SIM work. See `mobile/src/lib.rs`'s doc comment:
//! that work "starts once the shared kernel boots on target hardware" --
//! this crate is that first slice, not the target hardware bring-up
//! itself yet (everything above is QEMU-only so far).
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

mod gic;
mod nonsecure;
mod serial;
mod vectors;

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

    vectors::install();
    serial_println!("Runix ARM kernel: VBAR_EL3 installed");

    // Deliberately trip a synchronous exception (a breakpoint instruction
    // exception) to prove the vector table actually catches something,
    // rather than trusting that installing it was enough on its own.
    // `exception_handler` (see vectors.rs) reports which vector fired,
    // resumes past it, and execution continues right here -- reaching the
    // line after this is the test passing, not a coincidence.
    serial_println!("Runix ARM kernel: EXCEPTION test (deliberate brk)");
    unsafe {
        core::arch::asm!("brk #0");
    }
    serial_println!("Runix ARM kernel: EXCEPTION test OK (resumed after brk)");

    // GIC test: enable the distributor/CPU interface, unmask IRQ+FIQ at the
    // PSTATE level (`daifclr` -- masked by default, see `nonsecure.rs`'s
    // SPSR_EL1H_MASKED for the same bit meaning), then trigger a Software
    // Generated Interrupt targeted at this same CPU. **Partial proof only**
    // -- see `gic.rs`'s doc comment: the distributor genuinely accepts and
    // holds the SGI pending (confirmed below), but delivery all the way
    // into `vectors.rs`'s IRQ/FIQ vector isn't proven yet, so this
    // deliberately doesn't claim more than what's actually shown.
    gic::init();
    serial_println!("Runix ARM kernel: GIC initialized (distributor + CPU interface)");
    unsafe {
        core::arch::asm!("msr daifclr, #3"); // clear I (IRQ) and F (FIQ) mask bits
    }
    serial_println!("Runix ARM kernel: GIC test (triggering SGI 0)");
    gic::trigger_self_sgi0();
    serial_println!(
        "Runix ARM kernel: GICD_ISPENDR0 = {:#x} (bit 0 = SGI 0 pending at distributor -- \
         distributor-level delivery confirmed; CPU-interface trap not yet proven, see gic.rs)",
        gic::pending_raw()
    );

    // The actual TrustZone boundary: drop from EL3 (Secure Monitor) to EL1
    // Non-secure. Never returns -- see nonsecure.rs's doc comment for why
    // this is the last thing this boot path does.
    unsafe {
        nonsecure::drop_to_el1_nonsecure();
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
