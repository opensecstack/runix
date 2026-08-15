//! The actual TrustZone boundary: dropping from EL3 (Secure Monitor) to
//! EL1 Non-secure via `eret`. Everything before this module (boot, UART,
//! exception vectors) ran entirely inside the Secure world -- this is the
//! first line separating "trusted, privileged Runix code" from "the
//! eventual Non-secure kernel that RIL/SIM/app code will actually run
//! under," which is the whole reason TrustZone matters for this project's
//! threat model (see the root README's sandbox tiers).
//!
//! Alpha scope: prove the transition itself works -- reach EL1, confirm it
//! via `CurrentEL`, and confirm (as best `EL1` code can) that it landed in
//! the Non-secure world, not just "some EL1." No return path to EL3, no
//! SMC handling for the Non-secure side to call back into Secure Monitor
//! services, no real Non-secure kernel -- this is the drop itself, once.

use crate::serial_println;
use core::arch::naked_asm;

const EL1_STACK_SIZE: usize = 4096 * 16;

#[repr(align(16))]
#[allow(dead_code)]
struct El1Stack([u8; EL1_STACK_SIZE]);

#[unsafe(no_mangle)]
static mut EL1_STACK: El1Stack = El1Stack([0; EL1_STACK_SIZE]);

/// `SCR_EL3` (Secure Configuration Register) bits this sets:
/// - `NS` (bit 0) = 1: the next lower EL runs Non-secure -- this is the
///   actual security-state switch; everything else here is just getting a
///   valid EL1 execution context to land in.
/// - `RW` (bit 10) = 1: EL1 executes in AArch64 state, not AArch32 --
///   Runix has no 32-bit-mode plans (see `vectors.rs`'s doc comment on the
///   AArch32 vector group).
const SCR_EL3_NS: u64 = 1 << 0;
const SCR_EL3_RW: u64 = 1 << 10;

/// `SPSR_EL3` (Saved Program Status Register) value `eret` restores
/// `PSTATE` from: `M[3:0] = 0b0101` selects EL1h (EL1 using its own
/// `SP_EL1`, not borrowing `SP_EL0`) -- matches `SP_EL1` being set
/// explicitly below, not left as whatever `_start` happened to leave it.
/// `DAIF = 1111` (bits 6-9) masks Debug/SError/IRQ/FIQ on entry to EL1:
/// deliberate for this first landing -- EL1 has no exception vector table
/// of its own installed yet (unlike EL3's, see `vectors.rs`), so anything
/// that traps before one exists needs to stay masked rather than fault
/// into nothing.
const SPSR_EL1H_MASKED: u64 = 0b0101 | (0b1111 << 6);

/// Sets up `SCR_EL3`/`SPSR_EL3`/`ELR_EL3`/`SP_EL1` and executes `eret` --
/// the actual EL3 -> EL1 Non-secure drop. Never returns: `eret` is a jump,
/// not a call, and nothing in this crate transitions back to EL3 yet (see
/// this module's doc comment).
///
/// # Safety
/// Must only be called once, from EL3, with EL3's own stack still valid
/// (this function itself still runs at EL3, right up until `eret`) --
/// `el1_entry`'s own stack (`EL1_STACK`) is set up here, not shared with
/// whatever called this.
pub unsafe fn drop_to_el1_nonsecure() -> ! {
    unsafe {
        core::arch::asm!(
            "msr SCR_EL3, {scr}",
            "msr SPSR_EL3, {spsr}",
            "adrp x0, {entry}",
            "add x0, x0, :lo12:{entry}",
            "msr ELR_EL3, x0",
            "adrp x1, {stack}",
            "add x1, x1, :lo12:{stack}",
            "add x1, x1, {stack_size}",
            "msr SP_EL1, x1",
            "eret",
            scr = in(reg) SCR_EL3_NS | SCR_EL3_RW,
            spsr = in(reg) SPSR_EL1H_MASKED,
            entry = sym el1_entry_trampoline,
            stack = sym EL1_STACK,
            stack_size = const EL1_STACK_SIZE,
            options(noreturn),
        );
    }
}

/// `eret`'s actual landing point -- naked because, like `_start`, it's
/// reached with no call stack (a jump, not a call: there's no return
/// address on any stack pointing back to `drop_to_el1_nonsecure`), just an
/// already-valid `SP_EL1` (set by `drop_to_el1_nonsecure` before `eret`).
/// Immediately hands off to a normal Rust function once that's true.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn el1_entry_trampoline() -> ! {
    naked_asm!("b {e}", e = sym el1_entry);
}

fn current_el() -> u8 {
    let current_el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el);
    }
    ((current_el >> 2) & 0b11) as u8
}

/// Reads `SCR_EL3`... except `SCR_EL3` doesn't exist at EL1 (it's an EL3-only
/// register -- reading it here would itself trap). What EL1 code *can*
/// check is indirect: whether a Secure-only resource behaves as
/// inaccessible/different from EL1. `dumping ELR_EL3`/`SCR_EL3` isn't
/// possible from here by design (that's the isolation working) --
/// reaching this function at `CurrentEL == EL1` at all, immediately after
/// `drop_to_el1_nonsecure` set `SCR_EL3.NS = 1` and `eret`'d, is the
/// available proof at Alpha's scope: a real security-state switch
/// happened, evidenced by the mechanism used to get here, not by EL1
/// re-deriving it after the fact.
#[unsafe(no_mangle)]
extern "C" fn el1_entry() -> ! {
    // CPACR_EL1.FPEN (bits [21:20]) traps FP/SIMD access by default at
    // reset -- and compiler-generated code can use NEON registers for
    // things as mundane as a string copy (observed for real: one
    // `serial_println!` call with no format arguments faulted here with
    // ESR_EL1.EC=0x7, "FP/SIMD access trapped", while earlier ones with
    // the exact same shape didn't -- the compiler's own memcpy-lowering
    // threshold, not anything this code does deliberately). Set to
    // `0b11` (access permitted from EL0 and EL1, uncontrolled) before any
    // other EL1 code runs, rather than debug this class of trap on a
    // case-by-case basis.
    unsafe {
        core::arch::asm!(
            "mrs x0, CPACR_EL1",
            "orr x0, x0, #0x300000", // FPEN = 0b11 at bits [21:20]
            "msr CPACR_EL1, x0",
            "isb",
            out("x0") _,
        );
    }

    serial_println!("Runix ARM kernel: reached EL1 (dropped from EL3, SCR_EL3.NS=1)");
    serial_println!("Runix ARM kernel: CurrentEL = EL{}", current_el());

    // Install EL1's own exception vector table *before* touching the MMU:
    // VBAR_EL1 defaults to 0 at reset, so a fault here before this point
    // (in particular, from a wrong mmu::install page table entry) jumps
    // into whatever raw bytes sit at physical address 0x200, silently --
    // see el1_vectors.rs's doc comment for how that was actually found.
    crate::el1_vectors::install();
    serial_println!("Runix ARM kernel: VBAR_EL1 installed");

    unsafe {
        crate::mmu::install();
    }
    serial_println!("Runix ARM kernel: MMU enabled (SCTLR_EL1.M=1, identity-mapped)");

    // Prove translation is actually active and correct, not just that
    // SCTLR_EL1.M didn't crash on write: `AT S1E1R` asks the MMU hardware
    // itself to translate a VA (UART0's) and report the result in
    // PAR_EL1, the same mechanism a real page-fault handler would use to
    // inspect a faulting address. Reaching this print at all already
    // proves *something* (an identity-map error would instruction-abort
    // into EL1's nonexistent vector table immediately after SCTLR_EL1.M's
    // write, right on the next fetch -- not further down the function
    // like this), but PAR_EL1's F bit and physical-address field
    // independently confirm it.
    let uart_va: u64 = 0x0900_0000;
    let par_el1: u64;
    unsafe {
        core::arch::asm!(
            "at S1E1R, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) uart_va,
            par = out(reg) par_el1,
        );
    }
    let translation_faulted = par_el1 & 1 != 0;
    let translated_pa = par_el1 & 0x000F_FFFF_FFFF_F000;
    serial_println!(
        "Runix ARM kernel: AT S1E1R UART0 VA {:#x} -> PAR_EL1={:#x} (fault={}, PA={:#x})",
        uart_va,
        par_el1,
        translation_faulted,
        translated_pa
    );

    loop {
        unsafe {
            core::arch::asm!("wfe");
        }
    }
}
