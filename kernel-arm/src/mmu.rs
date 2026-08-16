//! EL1 MMU bring-up -- the one piece every future isolation boundary
//! (RIL, SIM provisioning, anything else running under the Non-secure
//! kernel) actually depends on. Nothing before this module provides any
//! memory isolation at all: the MMU has been off since boot, every
//! access is a flat physical-address passthrough, and there is no way to
//! mark any region privileged, read-only, or execute-never.
//!
//! # Scope
//!
//! Deliberately minimal, matching this repo's own "prove it works, then
//! extend" pattern (see e.g. `kernel/src/elf.rs`'s W^X work): two 1 GiB
//! block mappings, identity-mapped (VA == PA, so nothing else in this
//! crate has to change how it computes addresses), covering exactly what
//! this crate currently touches --
//! - `0x0000_0000`-`0x3FFF_FFFF`: **Device-nGnRnE** memory. Contains the
//!   GIC distributor (`0x0800_0000`), GIC CPU interface (`0x0801_0000`),
//!   and UART0 (`0x0900_0000`) -- see `gic.rs`/`serial.rs`.
//! - `0x4000_0000`-`0x7FFF_FFFF`: **Normal, non-cacheable** memory. QEMU
//!   `virt`'s RAM starts at `0x4000_0000`; this crate's own code, data,
//!   and every stack (`BOOT_STACK` in `main.rs`, `EL1_STACK` in
//!   `nonsecure.rs`) live at `0x4008_0000`+ (see `linker.ld`), safely
//!   inside this block.
//!
//! Non-cacheable, not write-back: correctness first. Enabling caching is
//! a real follow-up (better performance, but adds cache-maintenance
//! concerns -- e.g. flushing after writing new page table entries -- this
//! first slice deliberately avoids), not something to bundle into
//! getting translation working at all.
//!
//! No fine-grained (4 KiB page) mappings, no per-region access-permission
//! variation (both blocks are EL1 read/write, execute-never for Device
//! only), no support for anything outside these two 1 GiB windows -- an
//! access outside them, or a real permission violation, would take a data/
//! instruction abort into EL1's *own* exception vector table, which
//! doesn't exist yet (see `vectors.rs`'s EL3 table -- there is no EL1
//! equivalent). That's real fault-isolation infrastructure this module is
//! the prerequisite for, not something it builds itself.

const GRANULE_1GIB: u64 = 1 << 30;

/// `MAIR_EL1` attribute encodings this table's `AttrIndx` field selects
/// into -- index position in this array is the `AttrIndx` value used
/// below, not just documentation.
const MAIR_ATTR_DEVICE_NGNRNE: u8 = 0x00;
/// Normal memory, Inner Non-cacheable, Outer Non-cacheable (`0b0100_0100`
/// -- each nibble is one of Inner/Outer's own cacheability field, `0100`
/// = Non-cacheable in the standard AArch64 encoding).
const MAIR_ATTR_NORMAL_NC: u8 = 0x44;
const ATTRINDX_DEVICE: u64 = 0;
const ATTRINDX_NORMAL: u64 = 1;

/// Level-1 block descriptor bit layout (AArch64 VMSA, 4 KiB granule).
/// Bits [1:0] = `0b01` marks this a *block* descriptor, not a table
/// descriptor (`0b11`) -- at level 1, a block descriptor maps a full
/// 1 GiB region directly, no further table walk.
const DESC_BLOCK: u64 = 0b01;
/// `AF` (Access Flag, bit 10): hardware requires this set on first use of
/// any translation, or every access -- not just a missing/invalid one --
/// takes an Access Flag fault. Software (not hardware) managing this flag
/// is a real optimization some OSes use; not relevant at this scope.
const AF: u64 = 1 << 10;
/// `UXN`/`PXN` (bits 54/53): Execute-Never for unprivileged/privileged
/// contexts. Set on the Device block only -- there is no reason EL1 (or,
/// eventually, EL0) code should ever execute out of MMIO space, and
/// leaving code there executable for no reason is exactly the kind of gap
/// `kernel/src/elf.rs`'s W^X work exists to avoid on the x86_64 side.
const UXN: u64 = 1 << 54;
const PXN: u64 = 1 << 53;
/// `SH` (Shareability, bits [9:8]): `0b10` Outer Shareable for Device
/// memory (the conventional choice -- MMIO access ordering vs. other
/// observers matters even though caching doesn't), `0b11` Inner Shareable
/// for Normal memory (standard for memory a single cluster's CPUs share;
/// this is a single-CPU system today, but the encoding costs nothing to
/// get right now instead of revisiting once a second CPU exists).
const SH_OUTER: u64 = 0b10 << 8;
const SH_INNER: u64 = 0b11 << 8;

fn device_block_descriptor(output_addr: u64) -> u64 {
    output_addr | DESC_BLOCK | AF | (ATTRINDX_DEVICE << 2) | SH_OUTER | UXN | PXN
}

/// `AP[2:1]` (Access Permissions, bits [7:6]) `0b01` (`AP[2]`=bit7=0,
/// `AP[1]`=bit6=1) would grant read/write from *both* EL1 and EL0 -- the
/// architecturally correct bit to set once `el0.rs` needs EL0 to touch its
/// own stack/code page directly, rather than only through the `SVC` gate.
///
/// **Not currently set -- tried twice, with a real second investigation, and
/// reverted both times.** First pass: setting `0b01<<6` reproducibly hangs
/// QEMU (`virt`) right at `mmu::install`'s `SCTLR_EL1.M` write/`isb`,
/// entirely on the EL1 side, before any EL0 code has run -- confirmed not a
/// stale-TLB artifact (`tlbi vmalle1`, kept below regardless as a real
/// correctness fix, made no difference).
///
/// Second pass, narrowing it down further rather than re-deriving the same
/// result: swept all four `AP[2:1]` encodings on this exact table entry.
/// `0b00` (today's value, EL1 rw / no EL0) boots the full RIL+SIM demo
/// end to end -- the known-good baseline. `0b01` (`AP[2]`=0, EL1 rw / EL0
/// rw) hangs immediately, as above. `0b10` (`AP[2]`=1, EL1 *read-only* / no
/// EL0) and `0b11` (`AP[2]`=1, EL1 read-only / EL0 read-only) both instead
/// get *past* `SCTLR_EL1.M`/`isb` -- "MMU enabled" prints -- and hang one
/// step later, right where the next code needs to write to this same
/// block's stack, which is architecturally the expected consequence of
/// making EL1's own data read-only, not a QEMU anomaly.
///
/// That rules out a simple wrong-bit-position mistake (both interpretations
/// of the field were tried, at both possible byte positions) and localizes
/// the actual anomaly precisely: **`AP[2]=0` (EL1 keeps full read/write,
/// architecturally unaffected by `AP[1]`) combined with `AP[1]=1` (EL0
/// access newly granted) hangs immediately, while every encoding with
/// `AP[2]=1` gets further.** Also ruled out: `nG` (bit 11, not-global) set
/// alongside `0b01<<6` -- identical immediate hang, not the missing
/// variable either. Checked for a matching known QEMU issue (none found by
/// search at the time of writing, QEMU 10.1.5). Not run further to ground
/// at Alpha's scope -- it isn't the enforced isolation boundary anyway
/// (that's the capability-token check at the `SVC` gate in `svc.rs`, the
/// same layer `SYS_IPC_SEND` gates on the x86_64 side), and `el0.rs`'s
/// current demo never performs an EL0 data access (`el0_demo` is pure
/// `mov`/`svc`/`wfe`, no loads or stores), so nothing today actually
/// depends on this bit being set. Revisit once EL0 code needs to touch
/// memory directly instead of only through `SVC` -- worth trying GDB
/// single-stepping through the exact faulting instruction next (flaky in
/// this environment when last attempted, see the RIL isolation work's own
/// history, not impossible with more patience), or filing a minimal
/// reproduction upstream against QEMU's `target/arm` TCG code given how
/// precisely this is now characterized.
fn normal_block_descriptor(output_addr: u64) -> u64 {
    output_addr | DESC_BLOCK | AF | (ATTRINDX_NORMAL << 2) | SH_INNER
}

/// The level-1 translation table `TTBR0_EL1` points at directly (see
/// `install`'s `TCR_EL1.T0SZ` choice for why level 1, not level 0, is the
/// walk's starting point). 512 entries, each covering 1 GiB -- only
/// indices 0 and 1 (covering `0x0`-`0x7FFF_FFFF`) are ever populated;
/// every other entry stays all-zero, which VMSA defines as "invalid" --
/// an access anywhere else faults instead of silently working, matching
/// this module's doc comment on why that's the correct behavior for
/// Alpha's scope.
#[repr(align(4096))]
struct Level1Table([u64; 512]);

#[unsafe(no_mangle)]
static mut LEVEL1_TABLE: Level1Table = Level1Table([0; 512]);

/// Builds the two block descriptors, installs the table, configures
/// `MAIR_EL1`/`TCR_EL1`/`TTBR0_EL1`, and sets `SCTLR_EL1.M` -- the actual
/// MMU-on switch. Must run with the MMU currently off (true unconditionally
/// today -- nothing before this ever touches `SCTLR_EL1`) and from EL1
/// (`TTBR0_EL1`/`TCR_EL1`/`SCTLR_EL1` are all EL1 registers).
///
/// # Safety
/// Every address this crate's code, static data, and stacks occupy must
/// fall inside the two ranges this function maps (true today -- see this
/// module's doc comment -- but not checked here, since there is no
/// generic "what addresses does a running binary occupy" query available
/// at this scope). Getting that wrong means code keeps executing from a
/// physical address, VA == PA, that the new table no longer maps: the very
/// next fetch after `SCTLR_EL1.M` takes effect instruction-aborts into a
/// non-existent EL1 vector table.
pub unsafe fn install() {
    unsafe {
        let table = &raw mut LEVEL1_TABLE;
        (*table).0[0] = device_block_descriptor(0x0000_0000);
        (*table).0[1] = normal_block_descriptor(GRANULE_1GIB);

        let mair: u64 = (MAIR_ATTR_DEVICE_NGNRNE as u64) | ((MAIR_ATTR_NORMAL_NC as u64) << 8);
        core::arch::asm!("msr MAIR_EL1, {}", in(reg) mair);

        // TCR_EL1: T0SZ=25 -> 39-bit VA space (512 GiB), which for a 4 KiB
        // granule starts table walks at level 1 directly (skips level 0
        // entirely) -- exactly what lets `TTBR0_EL1` point straight at
        // `LEVEL1_TABLE` instead of needing a level-0 table with one
        // entry pointing at it. TG0=0b00 (4 KiB granule, bits [15:14]).
        // SH0=0b11/ORGN0=IRGN0=0b00 (bits [13:8]): inner-shareable,
        // non-cacheable table walks -- matches the non-cacheable memory
        // this table itself describes, so no cache-maintenance step is
        // needed between writing a descriptor and the hardware walker
        // seeing it. IPS=0b000 (bits [34:32]): 32-bit physical address
        // space (4 GiB) -- plenty for QEMU `virt`'s low RAM. EPD1=1 (bit
        // 23): disable `TTBR1_EL1` walks entirely -- this crate has no
        // higher-half mapping and never will at this scope.
        let tcr: u64 = 25 // T0SZ
            | (0b11 << 12) // SH0 = Inner Shareable
            | (1 << 23); // EPD1 = 1 (disable TTBR1 walks)
        core::arch::asm!("msr TCR_EL1, {}", in(reg) tcr);

        let ttbr0 = table as u64;
        core::arch::asm!("msr TTBR0_EL1, {}", in(reg) ttbr0);

        // Invalidate any stale EL1&0 TLB entries before enabling translation --
        // architecturally, TLB state at reset is unspecified, not guaranteed
        // empty, so relying on it never having cached anything for this VA
        // range is not safe even on a cold boot.
        core::arch::asm!("tlbi vmalle1");

        // Every table/register write above must be visible to the walker
        // before the MMU starts using them, and the pipeline must not
        // have anything fetched-but-not-yet-executed from before this
        // point when translation semantics change out from under it.
        core::arch::asm!("dsb ish", "isb");

        let mut sctlr: u64;
        core::arch::asm!("mrs {}, SCTLR_EL1", out(reg) sctlr);
        sctlr |= 1 << 0; // M: enable the MMU
        core::arch::asm!("msr SCTLR_EL1, {}", in(reg) sctlr);
        core::arch::asm!("isb"); // the next fetched instruction must see translation active
    }
}
