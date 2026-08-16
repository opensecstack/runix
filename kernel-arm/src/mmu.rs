//! EL1 MMU bring-up -- the one piece every future isolation boundary
//! (RIL, SIM provisioning, anything else under the Non-secure kernel)
//! actually depends on. Nothing before this module provides any memory
//! isolation at all: the MMU has been off since boot, every access is a
//! flat physical-address passthrough, and there is no way to mark any
//! region privileged, read-only, or execute-never.
//!
//! # Scope
//!
//! Two top-level regions, identity-mapped (VA == PA, so nothing else in
//! this crate has to change how it computes addresses) --
//! - `0x0000_0000`-`0x3FFF_FFFF`: **Device-nGnRnE** memory, one flat 1 GiB
//!   block. Contains the GIC distributor (`0x0800_0000`), GIC CPU
//!   interface (`0x0801_0000`), and UART0 (`0x0900_0000`) -- see
//!   `gic.rs`/`serial.rs`. EL1-only, execute-never; nothing here ever
//!   needs EL0 access or needs to run code out of MMIO space.
//! - `0x4000_0000`-`0x7FFF_FFFF`: **Normal, non-cacheable** memory. QEMU
//!   `virt`'s RAM starts at `0x4000_0000`; this crate's own code, data,
//!   and every stack (`BOOT_STACK` in `main.rs`, `EL1_STACK` in
//!   `nonsecure.rs`, `EL0_STACK` in `el0.rs`) live at `0x4008_0000`+ (see
//!   `linker.ld`), safely inside this block. **Not one flat block** --
//!   see `NORMAL_SPLIT_GRANULE_2MIB`'s doc comment for why this one
//!   region descends to page (4 KiB) granularity for a small slice of
//!   itself, unlike the Device region above.
//!
//! Non-cacheable, not write-back: correctness first. Enabling caching is
//! a real follow-up (better performance, but adds cache-maintenance
//! concerns -- e.g. flushing after writing new page table entries -- this
//! first slice deliberately avoids), not something to bundle into
//! getting translation working at all.
//!
//! An access outside either mapped region, or a real permission
//! violation, takes a data/instruction abort into EL1's *own* exception
//! vector table (`el1_vectors.rs`) -- real fault-isolation infrastructure
//! this module is the prerequisite for, not something it builds itself.

use crate::el0;

const GRANULE_1GIB: u64 = 1 << 30;
const GRANULE_2MIB: u64 = 1 << 21;
const GRANULE_4KIB: u64 = 1 << 12;

/// Base VA/PA of the Normal region -- also `LEVEL1_TABLE`'s index-1 output
/// address, and the base every 2 MiB/4 KiB granule offset below is
/// computed relative to.
const NORMAL_BASE: u64 = GRANULE_1GIB;

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

/// Descriptor type, bits `[1:0]` (AArch64 VMSA, 4 KiB granule). `0b01` is a
/// *block* descriptor -- valid at level 1 (1 GiB) or level 2 (2 MiB),
/// mapping that whole range directly with no further table walk. `0b11` is
/// dual-purpose depending on level: at level 1/2 it's a *table* descriptor
/// (points at the next-level table instead of mapping memory itself); at
/// level 3 there is no further level to walk to, so the architecture
/// reuses the same encoding to mean *page* descriptor (maps one 4 KiB page
/// directly) -- same bits, different meaning, purely a function of which
/// level is being processed.
const DESC_BLOCK: u64 = 0b01;
const DESC_TABLE_OR_PAGE: u64 = 0b11;
/// `AF` (Access Flag, bit 10): hardware requires this set on first use of
/// any translation, or every access -- not just a missing/invalid one --
/// takes an Access Flag fault. Software (not hardware) managing this flag
/// is a real optimization some OSes use; not relevant at this scope.
const AF: u64 = 1 << 10;
/// `UXN`/`PXN` (bits 54/53): Execute-Never for unprivileged/privileged
/// contexts. Set on the Device block always, and on `EL0_STACK`'s pages
/// below (data, never code -- the same W^X reasoning `kernel/src/elf.rs`
/// applies on the x86_64 side) -- everything else stays executable, since
/// leaving code non-executable for no reason is its own kind of gap.
const UXN: u64 = 1 << 54;
const PXN: u64 = 1 << 53;
/// `SH` (Shareability, bits `[9:8]`): `0b10` Outer Shareable for Device
/// memory (the conventional choice -- MMIO access ordering vs. other
/// observers matters even though caching doesn't), `0b11` Inner Shareable
/// for Normal memory (standard for memory a single cluster's CPUs share;
/// this is a single-CPU system today, but the encoding costs nothing to
/// get right now instead of revisiting once a second CPU exists).
const SH_OUTER: u64 = 0b10 << 8;
const SH_INNER: u64 = 0b11 << 8;
/// `AP[2:1]` (Access Permissions, bits `[7:6]`), `0b01` (`AP[2]`=bit7=0,
/// `AP[1]`=bit6=1): read/write from *both* EL1 and EL0. Applied only to
/// the specific 4 KiB pages below that actually need EL0 access -- see
/// `NORMAL_SPLIT_GRANULE_2MIB`'s doc comment for why this is never set on
/// anything block-granular.
const AP_EL0_RW: u64 = 0b01 << 6;

fn device_block_descriptor(output_addr: u64) -> u64 {
    output_addr | DESC_BLOCK | AF | (ATTRINDX_DEVICE << 2) | SH_OUTER | UXN | PXN
}

fn table_descriptor(next_level_table: u64) -> u64 {
    next_level_table | DESC_TABLE_OR_PAGE
}

fn normal_2mib_block_descriptor(output_addr: u64) -> u64 {
    output_addr | DESC_BLOCK | AF | (ATTRINDX_NORMAL << 2) | SH_INNER
}

/// `extra` folds in whatever the specific page needs beyond the shared
/// Normal-memory attributes -- `AP_EL0_RW` for EL0-accessible pages, `UXN`
/// for data pages, both, or neither (the EL1-only, executable default).
fn normal_4kib_page_descriptor(output_addr: u64, extra: u64) -> u64 {
    output_addr | DESC_TABLE_OR_PAGE | AF | (ATTRINDX_NORMAL << 2) | SH_INNER | extra
}

/// The level-1 translation table `TTBR0_EL1` points at directly (see
/// `install`'s `TCR_EL1.T0SZ` choice for why level 1, not level 0, is the
/// walk's starting point). 512 entries, each covering 1 GiB -- only index
/// 0 (Device, a block) and index 1 (Normal, a *table* descriptor down to
/// [`Level2Table`]) are ever populated; every other entry stays all-zero,
/// which VMSA defines as "invalid" -- an access anywhere else faults
/// instead of silently working.
#[repr(align(4096))]
struct Level1Table([u64; 512]);

#[unsafe(no_mangle)]
static mut LEVEL1_TABLE: Level1Table = Level1Table([0; 512]);

/// Covers the Normal region (`NORMAL_BASE`, 1 GiB) in 2 MiB granules. 511
/// of its 512 entries are plain blocks, identical in spirit to the old
/// single-1-GiB-block design. Exactly one entry -- whichever
/// [`normal_split_index`] computes at runtime -- is instead a *table*
/// descriptor down to [`Level3Table`], for the one 2 MiB slice that needs
/// page-granular permissions.
#[repr(align(4096))]
struct Level2Table([u64; 512]);

#[unsafe(no_mangle)]
static mut LEVEL2_TABLE: Level2Table = Level2Table([0; 512]);

/// Covers exactly one 2 MiB granule of the Normal region in 4 KiB pages --
/// the one containing this crate's own linked image (code, data, every
/// stack). 510 of its 512 entries are the same "EL1 rw, executable"
/// default the old flat block gave the *whole* region; the remaining two
/// small ranges -- `el0.rs`'s `el0_demo` code page and `EL0_STACK`'s pages
/// -- additionally carry `AP_EL0_RW`, computed at runtime in `install`
/// from their real addresses (`el0::el0_demo`/`el0::stack_base`), not
/// hardcoded offsets that could silently drift out of sync with the
/// linker's actual placement.
///
/// # Why this table exists at all -- a real QEMU hang, not a style choice
///
/// An earlier version of this module set `AP_EL0_RW` on the *entire* 1 GiB
/// Normal block (one flat block descriptor, no page table below level 1 at
/// all). That reproducibly hung QEMU (`virt`, both `cortex-a53` and `max`)
/// immediately after `SCTLR_EL1.M` took effect -- confirmed via `-d
/// int,guest_errors` tracing (not guesswork) to be a genuine, repeating
/// `Instruction Abort, Permission fault, level 1` at the *exact address of
/// `el1_exception_vectors`' own vector-4 entry* -- EL1's exception vector
/// table, in the same block, could no longer be fetched once `AP[1]=1` was
/// set on it, even though `AP` bits are architecturally defined to gate
/// *data* access, not instruction fetch (`UXN`/`PXN` govern that, and
/// neither was set). That's a QEMU/TCG emulation bug in how it enforces
/// `AP[1]` for instruction fetch on this table shape, not a logic error in
/// this crate's descriptors -- see the git history for the full
/// investigation (bit-position sweep across all four `AP[2:1]` encodings,
/// `nG` ruled out, CPU-model-independent, no matching upstream QEMU issue
/// found).
///
/// The fix isn't to work around QEMU's bug directly (impossible without
/// patching QEMU) -- it's to stop triggering it: never put `AP[1]=1` on a
/// region that also contains code EL1 needs to keep fetching. Splitting to
/// page granularity for just the two small ranges that actually need EL0
/// access, and leaving everything else (in particular `el1_vectors.rs`)
/// at `AP[2:1]=0b00`, sidesteps the bug entirely *and* is the
/// architecturally correct design anyway -- real EL0/EL1 isolation needs
/// page-granular permissions, not "the whole 1 GiB block or nothing," which
/// was always documented as a known limitation of the flat-block approach.
#[repr(align(4096))]
struct Level3Table([u64; 512]);

#[unsafe(no_mangle)]
static mut LEVEL3_TABLE: Level3Table = Level3Table([0; 512]);

/// Which of [`Level2Table`]'s 512 entries needs to descend to
/// [`Level3Table`] instead of staying a plain 2 MiB block -- the one
/// containing both `el0_demo`'s code page and `EL0_STACK`. Computed from
/// their real linked addresses, not assumed: this crate's whole image is
/// far smaller than 2 MiB today, so both currently fall in the same
/// granule, but asserting that (rather than silently mismapping one of
/// them) is what makes this safe to rely on instead of a coincidence.
fn normal_split_index() -> usize {
    let demo_addr = el0::el0_demo as *const () as u64;
    let stack_addr = el0::stack_base();
    let demo_index = ((demo_addr - NORMAL_BASE) / GRANULE_2MIB) as usize;
    let stack_index = ((stack_addr - NORMAL_BASE) / GRANULE_2MIB) as usize;
    assert!(
        demo_index == stack_index,
        "el0_demo and EL0_STACK span different 2 MiB granules -- \
         Level3Table only covers one and would silently mismap the other"
    );
    demo_index
}

/// Builds the three-level translation table, installs it, configures
/// `MAIR_EL1`/`TCR_EL1`/`TTBR0_EL1`, and sets `SCTLR_EL1.M` -- the actual
/// MMU-on switch. Must run with the MMU currently off (true unconditionally
/// today -- nothing before this ever touches `SCTLR_EL1`) and from EL1
/// (`TTBR0_EL1`/`TCR_EL1`/`SCTLR_EL1` are all EL1 registers).
///
/// # Safety
/// Every address this crate's code, static data, and stacks occupy must
/// fall inside the Device or Normal region this function maps (true today
/// -- see this module's doc comment -- but not checked here beyond the
/// `el0_demo`/`EL0_STACK` granule-match assertion). Getting that wrong
/// means code keeps executing from a physical address, VA == PA, that the
/// new table no longer maps: the very next fetch after `SCTLR_EL1.M`
/// takes effect instruction-aborts into EL1's own exception vector table.
pub unsafe fn install() {
    unsafe {
        let l1 = &raw mut LEVEL1_TABLE;
        let l2 = &raw mut LEVEL2_TABLE;
        let l3 = &raw mut LEVEL3_TABLE;

        (*l1).0[0] = device_block_descriptor(0x0000_0000);
        (*l1).0[1] = table_descriptor(l2 as u64);

        let split_index = normal_split_index();
        for (i, entry) in (*l2).0.iter_mut().enumerate() {
            let granule_addr = NORMAL_BASE + (i as u64) * GRANULE_2MIB;
            *entry = if i == split_index {
                table_descriptor(l3 as u64)
            } else {
                normal_2mib_block_descriptor(granule_addr)
            };
        }

        // el0_demo: exactly one page (`.balign 4096`, and the function
        // itself is a couple hundred bytes -- nowhere near a second page)
        // gets AP_EL0_RW, executable (no UXN) -- EL0 needs to fetch this
        // code, not just any code in the granule.
        let demo_addr = el0::el0_demo as *const () as u64;
        let demo_page = ((demo_addr - NORMAL_BASE - (split_index as u64) * GRANULE_2MIB)
            / GRANULE_4KIB) as usize;

        // EL0_STACK: however many pages `EL0_STACK_SIZE` actually spans
        // (today 4, at 4 KiB pages) get AP_EL0_RW | UXN -- data EL0 both
        // reads and writes (see `el0_demo`'s stack push/pop proof), never
        // executes.
        let stack_addr = el0::stack_base();
        let stack_first_page = ((stack_addr - NORMAL_BASE - (split_index as u64) * GRANULE_2MIB)
            / GRANULE_4KIB) as usize;
        let stack_page_count = el0::EL0_STACK_SIZE.div_ceil(GRANULE_4KIB as usize);

        let granule_base = NORMAL_BASE + (split_index as u64) * GRANULE_2MIB;
        for (j, entry) in (*l3).0.iter_mut().enumerate() {
            let page_addr = granule_base + (j as u64) * GRANULE_4KIB;
            *entry = if j == demo_page {
                normal_4kib_page_descriptor(page_addr, AP_EL0_RW)
            } else if j >= stack_first_page && j < stack_first_page + stack_page_count {
                normal_4kib_page_descriptor(page_addr, AP_EL0_RW | UXN)
            } else {
                normal_4kib_page_descriptor(page_addr, 0)
            };
        }

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

        let ttbr0 = l1 as u64;
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
