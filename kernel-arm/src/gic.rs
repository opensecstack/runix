//! GICv2 (Generic Interrupt Controller) bring-up -- QEMU `virt`'s default
//! interrupt controller (unless started with `-M virt,gic-version=3`,
//! which this crate doesn't target yet). ARM has no PIC/PIT the way
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
//! Alpha scope, and current status: enable both halves, then try to prove
//! interrupt delivery end to end with a Software Generated Interrupt (SGI,
//! IDs 0-15 reserved for exactly this -- a CPU can trigger one directly by
//! writing to `GICD_SGIR`, no external device or timer needed). **Proven
//! so far**: [`trigger_self_sgi0`] genuinely reaches the distributor --
//! [`pending_raw`] (`GICD_ISPENDR0`) reads back `0x1` immediately after
//! triggering, confirmed in QEMU. **Not yet proven**: delivery all the way
//! into `vectors.rs`'s IRQ (or FIQ) vector at EL3. Tried so far without
//! success: `GICD_CTLR`/`GICC_CTLR` `EnableGrp0` alone, both
//! `EnableGrp0`+`EnableGrp1`, marking the SGI Group 1 via `GICD_IGROUPR0`
//! (Group 1 should signal as IRQ; Group 0's `FIQEn` bit controls whether
//! it signals as FIQ or IRQ), and unmasking both `PSTATE.I` and
//! `PSTATE.F`. The distributor-level proof confirms the SGI mechanism and
//! addresses are right; what's still missing is specific to GICv2's
//! Security-Extensions CPU-interface configuration for a Secure EL3
//! context, which needs the architecture reference manual open next to it
//! to get right, not further guessing. Flagged rather than papered over
//! with a claimed pass -- see `docs/THREAT_MODEL.md`.

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;

// `+ 0x000` on the first offset of each block is a no-op arithmetically --
// kept anyway so every register's real hardware offset (straight from the
// GICv2 spec) is visible at a glance, consistent with every other entry.
#[allow(clippy::identity_op)]
const GICD_CTLR: usize = GICD_BASE + 0x000;
const GICD_IGROUPR0: usize = GICD_BASE + 0x080;
const GICD_ISENABLER0: usize = GICD_BASE + 0x100;
const GICD_ISPENDR0: usize = GICD_BASE + 0x200;
const GICD_SGIR: usize = GICD_BASE + 0xF00;

#[allow(clippy::identity_op)]
const GICC_CTLR: usize = GICC_BASE + 0x000;
const GICC_PMR: usize = GICC_BASE + 0x004;
const GICC_IAR: usize = GICC_BASE + 0x00C;
const GICC_EOIR: usize = GICC_BASE + 0x010;

fn write32(addr: usize, value: u32) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, value);
    }
}

fn read32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Enables the distributor and this CPU's interface, and unmasks SGI 0
/// specifically (`GICD_ISENABLER0` bit 0) -- the one interrupt
/// [`trigger_self_sgi0`] uses to prove delivery works. A real driver would
/// enable whatever the caller asks for; Alpha's only caller is this
/// module's own proof, so it only enables what that needs.
pub fn init() {
    // Bit 0 = EnableGrp0 (Secure), bit 1 = EnableGrp1 (Non-secure) -- both
    // set on both distributor and CPU interface. SGI 0 is also explicitly
    // marked Group 1 (`GICD_IGROUPR0` bit 0) below: from a Secure GICC_CTLR
    // view, Group 0 interrupts route to FIQ by default (`FIQEn`), Group 1
    // to plain IRQ -- marking it Group 1 is what makes `vectors.rs`'s IRQ
    // vector (not FIQ) the one that actually fires for this test.
    write32(GICD_CTLR, 0b11);
    write32(GICC_CTLR, 0b11);
    write32(GICC_PMR, 0xFF); // priority mask: 0xFF admits every priority level
    write32(GICD_IGROUPR0, 1 << 0); // SGI 0 -> Group 1 (Non-secure/IRQ)
    write32(GICD_ISENABLER0, 1 << 0); // enable SGI 0
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
