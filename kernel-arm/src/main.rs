//! Runix microkernel, ARM/TrustZone boot bring-up (L1, mobile) -- Alpha
//! scope: boot to EL3 (Secure Monitor, the exception level TrustZone
//! Secure-world firmware runs at), install a real exception vector table,
//! bring up the GIC, and drop to EL1 Non-secure (the actual TrustZone
//! boundary).
//!
//! # Status
//!
//! Proven in QEMU (`qemu-system-aarch64 -M virt,secure=on,gic-version=2
//! -cpu cortex-a53`):
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
//! - GIC bring-up (see `gic.rs`) is now **fully proven**: a Software
//!   Generated Interrupt is triggered, delivered all the way into
//!   `vectors.rs`'s IRQ vector, acknowledged and EOI'd through the GIC,
//!   and execution resumes -- found via GDB attached to QEMU that the
//!   actual missing piece was `SCR_EL3.IRQ`/`SCR_EL3.FIQ` (physical
//!   interrupt routing to EL3, distinct from the GIC's own state and from
//!   `PSTATE` masking), not any GIC register -- see `gic.rs`'s doc
//!   comment for the full path to finding that.
//! - The actual TrustZone boundary: drops from EL3 to EL1 Non-secure via
//!   `eret` (see `nonsecure.rs`), and EL1 code confirms via `CurrentEL`
//!   that it landed there.
//! - EL1's own MMU is up (see `mmu.rs`): identity-mapped, two 1 GiB
//!   blocks (Device for the GIC/UART, Normal for RAM), verified with
//!   `AT S1E1R` actually asking the hardware to translate an address and
//!   confirming the result, not just that `SCTLR_EL1.M`'s write didn't
//!   crash. This is the prerequisite every future isolation boundary (RIL,
//!   SIM provisioning, anything else under the Non-secure kernel) actually
//!   needs -- see `mmu.rs`'s doc comment for scope (identity-mapped,
//!   non-cacheable, two coarse 1 GiB blocks; no per-process address
//!   spaces, no fine-grained permissions yet). Getting here needed EL1's
//!   own exception vector table first (`el1_vectors.rs`) -- without one, a
//!   translation-table bug is not a diagnosable fault, it's a silent jump
//!   to whatever raw bytes sit at physical address `0x200` (`VBAR_EL1`'s
//!   reset value) -- and a `CPACR_EL1.FPEN` fix, since compiler-generated
//!   code can hit FP/SIMD-trapped-by-default in ordinary-looking code
//!   (see `nonsecure.rs`'s doc comment on `el1_entry` for both).
//!
//! Not yet started: RIL/SIM work itself. See `mobile/src/lib.rs`'s doc
//! comment: that work "starts once the shared kernel boots on target
//! hardware" -- this crate is that first slice, not the target hardware
//! bring-up itself yet (everything above is QEMU-only so far), but with
//! MMU bring-up done, the actual RIL isolation boundary (a separate,
//! restricted EL1 (or eventually EL0) context RIL code runs in, gated by
//! capability tokens the same way `capability-manager` already gates
//! things on the x86_64 side) is the next real step, not blocked on
//! further infrastructure.
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

mod el1_vectors;
mod gic;
mod mmu;
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

    // GIC test: enable the distributor/CPU interface and physical IRQ/FIQ
    // routing to EL3 (see `gic::init`), unmask IRQ+FIQ at the PSTATE level
    // (`daifclr` -- masked by default, see `nonsecure.rs`'s
    // SPSR_EL1H_MASKED for the same bit meaning), then trigger a Software
    // Generated Interrupt targeted at this same CPU. `vectors.rs`'s IRQ
    // vector (vector 5) catches it, acknowledges/EOIs it through the GIC,
    // and returns -- reaching the line after this is that whole path
    // (distributor -> CPU interface -> EL3 exception -> GIC ack/EOI)
    // genuinely working, not assumed.
    gic::init();
    serial_println!(
        "Runix ARM kernel: GIC initialized (distributor + CPU interface + SCR_EL3 IRQ/FIQ routing)"
    );
    unsafe {
        core::arch::asm!("msr daifclr, #3"); // clear I (IRQ) and F (FIQ) mask bits
    }
    serial_println!("Runix ARM kernel: GIC test (triggering SGI 0)");
    gic::trigger_self_sgi0();
    serial_println!(
        "Runix ARM kernel: GIC test OK (SGI 0 delivered, acknowledged, and EOI'd -- \
         GICD_ISPENDR0 = {:#x})",
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
