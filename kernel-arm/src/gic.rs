//! GICv2 (Generic Interrupt Controller) bring-up. Explicitly requested via
//! `-M virt,gic-version=2` -- QEMU's `virt` board docs note the *default*
//! GIC version under TCG (no KVM) resolves to GICv3 (`gic-version=max`),
//! not v2, so this isn't a "the default happens to be v2" assumption.
//! ARM has no PIC/PIT the way
//! x86_64 does (see `kernel/src/interrupts.rs`'s use of the 8259 PIC) --
//! interrupt routing and masking both go through this instead.
//!
//! Two halves, both memory-mapped, both at fixed, documented addresses on
//! `virt` (not board-specific guesswork -- a real device tree walk to
//! discover them is later work, once this targets anything other than
//! QEMU):
//! - **Distributor (GICD)** at `0x0800_0000`: routes interrupts to CPUs,
//!   enables/disables them by ID.
//! - **CPU interface (GICC)** at `0x0801_0000`: this CPU's view of
//!   "what's pending for me right now" -- acknowledge (`IAR`) and
//!   end-of-interrupt (`EOIR`) both go through here.
//!
//! Alpha scope: enable both halves following the same `GICC_CTLR`/
//! `GICD_CTLR` configuration ARM Trusted Firmware's own real GICv2 EL3
//! driver uses (`gicv2_cpuif_enable`/`gicv2_distif_init` in
//! `drivers/arm/gic/v2/gicv2_main.c`), then prove interrupt delivery end
//! to end with a Software Generated Interrupt (SGI, IDs 0-15 reserved for
//! exactly this -- a CPU can trigger one directly by writing to
//! `GICD_SGIR`, no external device or timer needed). **Fully proven**: a
//! triggered SGI is caught by `vectors.rs`'s IRQ vector, acknowledged and
//! EOI'd through the GIC, and execution resumes -- confirmed in QEMU, not
//! assumed.
//!
//! # The actual missing piece, and how it was found
//!
//! Getting here took two real fixes, not one. The first (matching ATF's
//! `GICC_CTLR`/`GICD_CTLR` values -- Group 0 only, `FIQEn` set, all four
//! `{FIQ,IRQ}_BYP_DIS_GRP{0,1}` bypass-disable bits set) was necessary but
//! not sufficient: applied on its own, the distributor still confirmed
//! the SGI pending (`GICD_ISPENDR0` read back `0x1`), but nothing trapped
//! into EL3. GDB attached to QEMU (`qemu-system-aarch64 ... -S -s`, `gdb
//! -x script.py`) is what actually resolved it: with `PSTATE.I`/`F` both
//! confirmed clear and `GICC_HPPIR` confirmed showing the SGI as the
//! highest-priority pending interrupt -- i.e. every register that looked
//! relevant said "this should fire" -- a `continue` still ran straight
//! past the trigger into unrelated later code, never touching
//! `exception_handler`. The one register neither ATF's own driver
//! (`gicv2_main.c` alone doesn't set `SCR_EL3`; a separate driver layer
//! does) nor any of this module's own earlier attempts had touched:
//! `SCR_EL3.IRQ`/`SCR_EL3.FIQ` (bits 1/2) -- physical interrupt *routing*
//! to EL3, a separate concern from both the GIC's own state and `PSTATE`
//! masking. Left at 0 (reset default), physical IRQ/FIQ simply never
//! route to EL3 at all, regardless of anything else being correct. Set in
//! [`init`] via `mrs`/`orr`/`msr` on `SCR_EL3`, and delivery started
//! working immediately, no other change needed.
//!
//! Ruled out along the way, each with a real test, not a guess: wrong
//! interrupt group, wrong signal (IRQ vs FIQ -- both `vectors.rs` vector 5
//! and vector 6 are wired to the same handler, so either would have been
//! caught), `PSTATE` masking, legacy CPU-interface bypass left enabled,
//! and QEMU defaulting to GICv3 instead of GICv2 under TCG (the `virt`
//! board's own docs note `gic-version=max` resolves to GICv3 by default
//! without KVM -- retested with `-M virt,gic-version=2` explicit).

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;

// `+ 0x000` on the first offset of each block is a no-op arithmetically --
// kept anyway so every register's real hardware offset (straight from the
// GICv2 spec) is visible at a glance, consistent with every other entry.
#[allow(clippy::identity_op)]
const GICD_CTLR: usize = GICD_BASE + 0x000;
const GICD_ISENABLER0: usize = GICD_BASE + 0x100;
const GICD_ISPENDR0: usize = GICD_BASE + 0x200;
const GICD_SGIR: usize = GICD_BASE + 0xF00;

#[allow(clippy::identity_op)]
const GICC_CTLR: usize = GICC_BASE + 0x000;
const GICC_PMR: usize = GICC_BASE + 0x004;
const GICC_IAR: usize = GICC_BASE + 0x00C;
const GICC_EOIR: usize = GICC_BASE + 0x010;

// GICD_CTLR / GICC_CTLR bit layout, matching ARM Trusted Firmware's own
// constant names (`include/drivers/arm/gicv2.h`) so this is checkable
// against that source directly, not just against this module's own doc
// comment.
const CTLR_ENABLE_G0_BIT: u32 = 1 << 0;
/// `GICC_CTLR` only: routes Group 0 interrupts to the CPU as FIQ (1) rather
/// than IRQ (0) -- the Secure-world convention this module follows.
const FIQ_EN_BIT: u32 = 1 << 3;
/// `GICC_CTLR` only, all four: disable the CPU interface's legacy signal
/// bypass for each (FIQ/IRQ) x (Group 0/Group 1) combination. Left at
/// their reset value (bypass *enabled*), delivery can be silently
/// suppressed even with everything else configured correctly -- see this
/// module's doc comment for how that was found.
const FIQ_BYP_DIS_GRP0: u32 = 1 << 5;
const IRQ_BYP_DIS_GRP0: u32 = 1 << 6;
const FIQ_BYP_DIS_GRP1: u32 = 1 << 7;
const IRQ_BYP_DIS_GRP1: u32 = 1 << 8;

fn write32(addr: usize, value: u32) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, value);
    }
}

fn read32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Enables the distributor and this CPU's interface (Group 0/Secure only,
/// matching ATF's own EL3 GICv2 driver -- see this module's doc comment),
/// unmasks SGI 0 specifically (`GICD_ISENABLER0` bit 0) -- the one
/// interrupt [`trigger_self_sgi0`] uses to prove delivery works -- and sets
/// `SCR_EL3.IRQ`/`SCR_EL3.FIQ` (bits 1/2) so physical IRQ/FIQ actually
/// *route to EL3* at all. That routing is a separate thing from the GIC's
/// own state and from `PSTATE.I`/`F` masking -- confirmed the hard way (see
/// this module's doc comment): with everything else correct (distributor
/// pending, `GICC_HPPIR` showing the interrupt as highest-priority-pending,
/// `PSTATE.I`/`F` both clear), a physical interrupt still never traps into
/// EL3 while `SCR_EL3.IRQ`/`FIQ` are 0 (their reset value). A real driver
/// would enable whatever the caller asks for; Alpha's only caller is this
/// module's own proof, so it only enables what that needs. SGI 0 is left
/// at its reset group (Group 0) deliberately -- not written to
/// `GICD_IGROUPR0` -- since Group 0 is exactly what this configuration
/// expects to handle.
pub fn init() {
    write32(GICD_CTLR, CTLR_ENABLE_G0_BIT);
    write32(
        GICC_CTLR,
        CTLR_ENABLE_G0_BIT
            | FIQ_EN_BIT
            | FIQ_BYP_DIS_GRP0
            | IRQ_BYP_DIS_GRP0
            | FIQ_BYP_DIS_GRP1
            | IRQ_BYP_DIS_GRP1,
    );
    write32(GICC_PMR, 0xFF); // priority mask: 0xFF admits every priority level
    write32(GICD_ISENABLER0, 1 << 0); // enable SGI 0

    // Read-modify-write, not an unconditional overwrite: this runs before
    // `nonsecure::drop_to_el1_nonsecure` sets the rest of SCR_EL3 (NS/RW),
    // and preserves whatever reset-time bits (e.g. RES1 fields) were
    // already there.
    unsafe {
        core::arch::asm!(
            "mrs x0, SCR_EL3",
            "orr x0, x0, #0x6", // bit 1 (IRQ) | bit 2 (FIQ)
            "msr SCR_EL3, x0",
            out("x0") _,
        );
    }
}

/// Triggers SGI 0, targeted at this same CPU (`TargetList` = bit 0 of
/// `GICD_SGIR`'s bits [23:16], `CPU 0`) -- proves the whole delivery path
/// (distributor -> CPU interface -> IRQ exception -> `GICC_IAR`/`EOIR`)
/// without needing a second CPU or an external device to interrupt from.
pub fn trigger_self_sgi0() {
    const SGI_ID_0: u32 = 0;
    const TARGET_CPU_0: u32 = 1 << 16; // TargetList bit 0 = CPU interface 0
    write32(GICD_SGIR, TARGET_CPU_0 | SGI_ID_0);
}

/// Diagnostic-only: raw `GICD_ISPENDR0` value -- bit 0 set means SGI 0 is
/// pending at the distributor, regardless of whether it has actually
/// trapped into this CPU yet. Not part of the normal init/trigger/ack
/// flow; exists to tell "distributor never saw it" apart from "distributor
/// has it pending but routing/masking is stopping the trap."
pub fn pending_raw() -> u32 {
    read32(GICD_ISPENDR0)
}

/// Reads `GICC_IAR` (Interrupt Acknowledge Register) -- the *raw* value,
/// including the source-CPU-ID bits `GICC_IAR` carries for SGIs (bits
/// [12:10]) alongside the interrupt ID itself (bits [9:0]). Returned raw,
/// not pre-masked to just the ID, because [`end_of_interrupt`] must be
/// given back this exact value -- an interrupt left un-EOI'd with the
/// wrong bits stays "active" and never re-fires. Use [`interrupt_id`] to
/// extract just the ID for comparison/logging.
///
/// This is the *only* correct way to find out which interrupt fired --
/// there's no "which interrupt" info from the exception itself the way
/// `vectors.rs`'s `vector` index tells you *which table entry*, but not
/// *which interrupt*.
pub fn acknowledge() -> u32 {
    read32(GICC_IAR)
}

/// Extracts just the interrupt ID (bits [9:0]) from a raw [`acknowledge`]
/// result, for comparison/logging -- not for feeding to
/// [`end_of_interrupt`], which needs the raw value.
pub fn interrupt_id(raw_iar: u32) -> u32 {
    raw_iar & 0x3FF
}

/// Writes `GICC_EOIR` (End Of Interrupt) with `raw_iar` -- the exact value
/// [`acknowledge`] returned, unmodified -- telling the GIC this CPU is
/// done servicing it, so it can be delivered again later.
pub fn end_of_interrupt(raw_iar: u32) {
    write32(GICC_EOIR, raw_iar);
}
