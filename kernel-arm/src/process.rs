//! Per-process address spaces for `kernel-arm` -- a real, hardware-enforced
//! privacy boundary, not a bookkeeping struct. The ARM counterpart of
//! `kernel/src/process.rs` on the x86_64 side, and the prerequisite that
//! gives `elf.rs`'s parser (slice 1 of this same item) something to
//! actually load *into*.
//!
//! Deliberately scoped exactly as narrow as x86_64's own first slice was:
//! build an address space, map one private page into it, switch into it for
//! real, and prove the *same* virtual address resolves to *different*
//! physical memory depending on which address space is active
//! ([`prove_isolation`]). No ELF loading, no scheduler, no IPC, no EL0
//! execution inside one of these -- all later slices. The proof is entirely
//! EL1-side, for the same reason `kernel/tests/process_isolation.rs` is
//! entirely ring 0: the address-space primitive does not need any of those
//! things to be demonstrably correct.
//!
//! # The `TTBR0_EL1`/`TTBR1_EL1` decision -- and why the obvious split
//! doesn't apply here
//!
//! AArch64 EL1 has two translation table base registers, and the
//! conventional OS design is "`TTBR1_EL1` = kernel (high half, identical in
//! every context), `TTBR0_EL1` = process (low half, swapped per context
//! switch)," which looks like a strictly cleaner primitive than the
//! top-level-entry copying x86_64 has to do with a single `Cr3`.
//!
//! It does not apply to this kernel as it exists today, for an
//! architectural reason, not a convenience one: **which TTBR a lookup uses
//! is decided by the *top* bits of the VA.** `TTBR1_EL1` is selected only
//! when `VA[63:64-T1SZ]` are all ones -- its region is always anchored at
//! the top of the 64-bit address space (`TCR_EL1.T1SZ` only chooses how far
//! down it extends), and `TTBR0_EL1`'s is always anchored at the bottom
//! (`TCR_EL1.T0SZ`). `mmu.rs` maps everything **identity-mapped (VA == PA)**
//! -- MMIO at `0x0000_0000`-`0x3FFF_FFFF`, and this crate's own code, data,
//! stacks, and heap in RAM at `0x4000_0000`+. Those are *low* VAs by
//! definition of being identity mappings of low physical addresses, so they
//! are structurally unreachable through `TTBR1_EL1` no matter how `T1SZ` is
//! set. Putting the kernel under `TTBR1_EL1` means giving up identity
//! mapping: relinking the image to a high-half VA and fixing every place in
//! this crate that treats a pointer as a physical address -- `virtio_net.rs`
//! handing ring/buffer addresses to the device, `virtio_mmio.rs`'s slot
//! bases, `heap.rs`'s hardcoded `0x4100_0000`, `mmu.rs`'s own descriptor
//! output addresses. That is a far larger change than this slice, and it
//! would buy nothing here.
//!
//! So: **the kernel stays identity-mapped under `TTBR0_EL1`, exactly as
//! `mmu.rs` installs it, and `TTBR1_EL1` stays disabled
//! (`TCR_EL1.EPD1 = 1`, unchanged).** A per-process address space is a
//! fresh level-1 table whose kernel-space entries are *copied* from the
//! currently active table -- x86_64's design, transliterated honestly
//! rather than dressed up as a TTBR split it isn't. Copying by value means
//! the kernel's level-2/level-3 sub-tables are *physically shared* across
//! every address space, which is the point: EL1 keeps fetching its own
//! code, its own stack, and `el1_vectors.rs`'s vector table identically no
//! matter which `TTBR0_EL1` is loaded, which is what makes switching
//! `TTBR0_EL1` from EL1 survivable at all.
//!
//! Revisit trigger: if this kernel ever stops being identity-mapped (a real
//! physical frame allocator with a separate kernel VA layout, which the
//! loader slice may well want), move the kernel to `TTBR1_EL1` then --
//! that's the right moment, and the only one where the split is free.
//!
//! # The private region, and why the QEMU/TCG `AP[1]` bug cannot recur here
//!
//! Process-private mappings live in their own dedicated 1 GiB VA window,
//! [`PRIVATE_REGION_BASE`]`..`[`PRIVATE_REGION_END`]
//! (`0x8000_0000`-`0xBFFF_FFFF`) -- level-1 index 2, which `mmu.rs` leaves
//! entirely unpopulated. Nothing is identity-mapped there, nothing else in
//! this crate has any layout expectation of it, and -- the part that
//! matters -- it is a **different level-1 block from the one containing
//! `el1_exception_vectors`** (that lives in the Normal region, level-1
//! index 1).
//!
//! Read `mmu.rs`'s `Level3Table` doc comment for the real bug this
//! structure is defending against: setting `AP[1]=1` anywhere inside the
//! 1 GiB block that also contained EL1's exception vector table made QEMU
//! stop being able to *fetch* those vectors -- architecturally impossible
//! (`AP` gates data access; `UXN`/`PXN` gate fetch), genuinely a TCG bug,
//! root-caused with `-d int,guest_errors`. The lesson is not "avoid that
//! one descriptor" -- it is **never let an EL0-accessible mapping share a
//! translation structure with code EL1 must keep fetching.** Confining
//! every private page to its own level-1 slot, with its own privately-owned
//! level-2/level-3 tables, satisfies that by construction: no descriptor
//! this module writes is ever reachable from the walk that translates
//! `el1_exception_vectors`, so there is no shared block for the bug class to
//! act through. [`map_private_page`](AddressSpace::map_private_page)
//! enforces the window with a real bounds check rather than trusting
//! callers.
//!
//! # ASIDs: deliberately not used
//!
//! `TTBR0_EL1[63:48]` can carry an ASID so a context switch doesn't need a
//! full TLB invalidation. This module does not use one: it writes ASID = 0
//! in every `TTBR0_EL1` value and does a full `tlbi vmalle1` on every
//! [`activate`](AddressSpace::activate). Two reasons, in order of weight:
//!
//! 1. **ASIDs would not currently work even if set.** ASID tagging only
//!    applies to translations from descriptors with `nG` (bit 11, not
//!    Global) set. Neither `mmu.rs`'s descriptors nor this module's set
//!    `nG`, so every entry is Global and matches regardless of ASID --
//!    adopting ASIDs means also setting `nG` on every process-private
//!    descriptor *and* owning an ASID allocation/rollover policy
//!    (`TCR_EL1.AS` picks 8- or 16-bit), which is scheduler-shaped work.
//! 2. There is no scheduler here yet, so the cost a full `TLBI` is meant to
//!    avoid is a cost nothing pays: this crate performs a handful of
//!    address-space switches total, all from one boot path.
//!
//! A full invalidation is *correct*, just slower -- this is a performance
//! decision deferred, not a correctness detail skipped. Revisit alongside
//! the scheduler slice.
//!
//! # Memory attributes
//!
//! Private pages reuse `mmu.rs`'s existing **Normal, Inner/Outer
//! Non-cacheable** attribute (`AttrIndx = ATTRINDX_NORMAL`, Inner
//! Shareable) unchanged. Changing cacheability policy is a bigger decision
//! than this slice should make on its own, and the non-cacheable choice is
//! what lets this module write a descriptor and let the hardware walker see
//! it with only a `dsb`, no cache maintenance (see `mmu.rs`'s `TCR_EL1`
//! comment on non-cacheable table walks).

use crate::mmu::{
    normal_4kib_page_descriptor, table_descriptor, AP_EL0_RW, DESC_TABLE_OR_PAGE, GRANULE_4KIB,
    PXN, UXN,
};
use runix_kernel_arm::vm::AP_EL0_RO;
use crate::serial_println;
use alloc::alloc::{alloc_zeroed, Layout};
use alloc::collections::BTreeSet;
use core::fmt;

/// The process-private VA window (`0x8000_0000`..`0xC000_0000`) -- level-1
/// index 2, which `mmu.rs` never populates. See this module's doc comment
/// for why private mappings get their own level-1 slot rather than sharing
/// the kernel's.
///
/// Defined in the library half of this crate (`vm.rs`) and re-exported
/// here, because `loader.rs` -- which is host-tested and therefore cannot
/// see this module -- subdivides the same window into a segment region, a
/// guard gap, and the EL0 stack. One definition, two consumers.
pub use runix_kernel_arm::vm::{PRIVATE_REGION_BASE, PRIVATE_REGION_END};

/// Output-address field of a translation descriptor, bits `[47:12]`. Used
/// both to build a `TTBR0_EL1` value's table address and to read a
/// next-level table address back out of an existing descriptor.
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// 512 `u64` entries, 4 KiB, 4 KiB-aligned -- the shape every level of a
/// 4 KiB-granule AArch64 translation table has, and the alignment
/// `TTBR0_EL1` requires of a level-1 table under `mmu.rs`'s `T0SZ = 25`
/// (39-bit VA, walk starts at level 1).
const TABLE_ENTRIES: usize = 512;
const TABLE_BYTES: usize = TABLE_ENTRIES * 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// The requested VA is outside [`PRIVATE_REGION_BASE`]..
    /// [`PRIVATE_REGION_END`]. Rejected rather than mapped: a private,
    /// EL0-accessible page anywhere in the kernel's own level-1 blocks is
    /// exactly the shape of the QEMU/TCG `AP[1]` bug this module's doc
    /// comment describes, and would also alias the kernel's shared
    /// sub-tables.
    VaOutsidePrivateRegion,
    /// The requested VA is not 4 KiB-aligned.
    VaMisaligned,
    /// The heap could not supply a 4 KiB-aligned 4 KiB block for a
    /// translation table or a backing page. Returned, never panicked on --
    /// this crate is `panic = "abort"`.
    OutOfMemory,
}

impl AddressSpaceError {
    /// This error's message as a `&'static str`, so a caller can carry the
    /// real reason across a crate boundary that cannot name this type --
    /// `loader.rs` lives in the library half of this crate and its
    /// `LoaderError::MapFailed` stores exactly this (see
    /// `load_proof.rs`'s `PrivatePageMapper` impl). [`fmt::Display`] is
    /// implemented in terms of this, so the two can't drift.
    pub fn message(&self) -> &'static str {
        match self {
            AddressSpaceError::VaOutsidePrivateRegion => {
                "virtual address is outside the process-private region"
            }
            AddressSpaceError::VaMisaligned => "virtual address is not 4 KiB-aligned",
            AddressSpaceError::OutOfMemory => "out of memory for a page or translation table",
        }
    }
}

impl fmt::Display for AddressSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Allocates one zeroed, 4 KiB-aligned 4 KiB block and returns its address.
///
/// Because `mmu.rs` maps all of RAM identity (VA == PA), this one value is
/// simultaneously the pointer this code writes through and the physical
/// address a descriptor must name -- the single biggest simplification ARM
/// gets here versus x86_64's `physical_memory_offset` arithmetic. If this
/// kernel ever stops being identity-mapped, every `as u64` in this module
/// becomes a bug, which is why that is called out as the revisit trigger in
/// the module doc comment and not left implicit.
fn alloc_page() -> Result<u64, AddressSpaceError> {
    // Unwrap-free: the size/align pair is a compile-time-known valid
    // combination, but `from_size_align` is still fallible, so the error is
    // folded into `OutOfMemory` rather than `expect`ed on a path this crate
    // aborts from.
    let layout = Layout::from_size_align(GRANULE_4KIB as usize, GRANULE_4KIB as usize)
        .map_err(|_| AddressSpaceError::OutOfMemory)?;
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(AddressSpaceError::OutOfMemory);
    }
    Ok(ptr as u64)
}

/// An independent set of translation tables rooted at a private level-1
/// table -- the actual unit of isolation here: everything reachable from a
/// given `TTBR0_EL1` value is exactly what that context can address.
///
/// Known limitation, stated rather than left to be discovered: there is no
/// `Drop`. Dropping an `AddressSpace` leaks its tables and backing pages,
/// because freeing them safely requires knowing this space isn't the one
/// currently in `TTBR0_EL1` — a question only a scheduler can answer, and
/// there isn't one yet. The boot-path caller ([`prove_isolation`]) builds
/// exactly two and never releases them, so nothing leaks in practice today;
/// this becomes real work in the scheduler slice, not before.
pub struct AddressSpace {
    /// Physical (== virtual, identity-mapped) address of this space's
    /// level-1 table, and the value loaded into `TTBR0_EL1` by
    /// [`activate`](Self::activate).
    root: u64,
    /// Every translation table this address space *owns*, by address --
    /// including [`root`](Self::root).
    ///
    /// This is the ARM answer to the real bug x86_64's `process.rs`
    /// documents (a naive "detach the top-level slot on every map call"
    /// silently erased an earlier mapping when a second page landed in the
    /// same slot). Tracking ownership rather than "slots already detached"
    /// makes the rule directly checkable at every level of the walk:
    /// descend into a next-level table **only** if this space owns it;
    /// otherwise the descriptor is either invalid, a block, or -- the
    /// dangerous case -- a table descriptor copied verbatim from the kernel
    /// table by [`new`](Self::new) and therefore *physically shared with
    /// every other address space*, so writing through it would mutate
    /// everyone's mappings at once. In that case the entry is replaced with
    /// a freshly allocated, privately owned table.
    ///
    /// For today's [`PRIVATE_REGION_BASE`] window the shared-table case
    /// cannot actually arise (level-1 index 2 is unpopulated in the kernel
    /// table, so it copies as invalid), but the check is what keeps that a
    /// *checked* property rather than a coincidence of the current layout.
    owned_tables: BTreeSet<u64>,
    /// The `TTBR0_EL1` table address this space's level-1 entries were
    /// *copied from* by [`new`](Self::new) -- in practice `mmu.rs`'s
    /// boot-time `LEVEL1_TABLE`.
    ///
    /// Recorded, not assumed, because [`new`](Self::new) seeds from whatever
    /// is **active at the moment of construction**, and that is the ARM
    /// analogue of a real bug x86_64's `process.rs` documents. Two distinct
    /// hazards live here, and they are not the same:
    ///
    /// 1. *"A level-1 slot that was empty at copy time gets populated in the
    ///    live kernel table afterwards."* Structurally impossible in this
    ///    crate: `mmu::install` builds the entire kernel level-1 table once,
    ///    before the heap exists, and nothing ever writes a kernel level-1
    ///    entry again. (Changes at level 2 or 3 inside an *existing* kernel
    ///    slot would propagate to every space automatically, since those
    ///    sub-tables are shared by pointer -- see [`new`](Self::new). Only a
    ///    brand-new level-1 slot could be missed, and the only level-1 slot
    ///    written after `install` is index 2, which is per-space private by
    ///    design.)
    /// 2. *"The space was seeded while some **other** `AddressSpace` was
    ///    active."* Genuinely possible the moment a scheduler exists, and
    ///    strictly worse: the copy would pick up that space's private
    ///    level-1 index 2 table descriptor, so the two spaces' private
    ///    windows would share translation structures -- the exact aliasing
    ///    `owned_tables` exists to prevent, arriving through the one door it
    ///    cannot see. [`seeded_root`](Self::seeded_root) is what lets
    ///    `scheduler::spawn_with_address_space` refuse such a space instead
    ///    of discovering it as a mysterious isolation failure.
    seeded_root: u64,
}

impl AddressSpace {
    /// Builds a new, independent address space seeded from whichever table
    /// `TTBR0_EL1` currently points at (in practice `mmu.rs`'s
    /// `LEVEL1_TABLE`). All 512 level-1 entries are copied **by value**, so
    /// kernel-space mappings stay reachable identically -- mandatory, since
    /// EL1 continues executing its own code, on its own stack, and must be
    /// able to take an exception into `el1_vectors.rs`, from the instruction
    /// right after a `TTBR0_EL1` switch.
    ///
    /// Copying by value shares the kernel's level-2/level-3 tables by
    /// *pointer*, not content -- deliberate (kernel mappings are meant to be
    /// identical everywhere, and deep-copying to 4 KiB leaves would be
    /// enormous for no benefit) and the reason `owned_tables` exists.
    pub fn new() -> Result<Self, AddressSpaceError> {
        let root = alloc_page()?;
        let active = active_root();
        unsafe {
            core::ptr::copy_nonoverlapping(active as *const u8, root as *mut u8, TABLE_BYTES);
        }
        let mut owned_tables = BTreeSet::new();
        owned_tables.insert(root);
        Ok(AddressSpace {
            root,
            owned_tables,
            seeded_root: active,
        })
    }

    /// Maps a fresh, zeroed, private 4 KiB page at `va` -- within this
    /// address space only -- and returns a mutable view of its contents.
    ///
    /// The returned reference is usable **immediately, without
    /// [`activate`](Self::activate)ing this space**, because the page is
    /// reached through the kernel's own identity mapping of the heap it came
    /// from; the EL0-facing permissions written into the descriptor don't
    /// constrain the kernel's access to the same physical memory. That is
    /// what will let a later loader slice copy a segment's bytes in before
    /// anything runs.
    ///
    /// Descriptor bits: Normal non-cacheable (`ATTRINDX_NORMAL`), Inner
    /// Shareable, `AF` set, `AP[2:1] = 0b01` (read/write from both EL1 and
    /// EL0), and `UXN | PXN` -- a data page, never executable from either
    /// exception level. That is the right default for a page nothing
    /// executes, and it is what this crate's own isolation proof
    /// ([`prove_isolation`]) relies on; a *loaded* `.text` page needs
    /// different bits, which is what
    /// [`map_private_page_with`](Self::map_private_page_with) is for.
    pub fn map_private_page(
        &mut self,
        va: u64,
    ) -> Result<&'static mut [u8; 4096], AddressSpaceError> {
        self.map_private_page_with(va, AP_EL0_RW | UXN | PXN)
    }

    /// [`map_private_page`](Self::map_private_page) with explicit
    /// permission bits -- the `extra` argument of
    /// `mmu::normal_4kib_page_descriptor`, i.e. `AP[2:1]` plus `UXN`/`PXN`.
    ///
    /// Added for `loader.rs` (slice 3), which computes those bits per
    /// segment from its real `PF_R`/`PF_W`/`PF_X` flags -- the same
    /// generalization x86_64's `AddressSpace::map_private_page` went
    /// through when its loader landed, and for the same reason: hardcoding
    /// one flag set here makes every mapped page simultaneously writable
    /// and (at best accidentally) non-executable, which cannot express W^X.
    /// Memory *attributes* (cacheability, shareability) stay fixed; only
    /// permissions are the caller's choice.
    pub fn map_private_page_with(
        &mut self,
        va: u64,
        permissions: u64,
    ) -> Result<&'static mut [u8; 4096], AddressSpaceError> {
        if va % GRANULE_4KIB != 0 {
            return Err(AddressSpaceError::VaMisaligned);
        }
        if !(PRIVATE_REGION_BASE..PRIVATE_REGION_END).contains(&va) {
            return Err(AddressSpaceError::VaOutsidePrivateRegion);
        }

        let l1_index = ((va >> 30) & 0x1ff) as usize;
        let l2_index = ((va >> 21) & 0x1ff) as usize;
        let l3_index = ((va >> 12) & 0x1ff) as usize;

        let l2 = self.descend(self.root, l1_index)?;
        let l3 = self.descend(l2, l2_index)?;

        let frame = alloc_page()?;
        unsafe {
            entry_ptr(l3, l3_index).write_volatile(normal_4kib_page_descriptor(frame, permissions));
        }
        // The hardware table walker must observe every descriptor written
        // above before any translation uses them. `dsb ishst` is sufficient
        // (and no cache maintenance is needed) only because `TCR_EL1`
        // configures non-cacheable table walks over non-cacheable memory --
        // see this module's "Memory attributes" note.
        unsafe {
            core::arch::asm!("dsb ishst");
        }

        Ok(unsafe { &mut *(frame as *mut [u8; 4096]) })
    }

    /// Maps `pa` -- a caller-supplied **physical** address, not a
    /// freshly allocated heap frame -- at `va`, within this address space
    /// only. Everything about the walk (bounds check, level-2/level-3
    /// descend-and-build, the `dsb ishst` after the write) is identical to
    /// [`map_private_page_with`](Self::map_private_page_with); the only
    /// difference is the one line that matters: this never calls
    /// [`alloc_page`] and never owns the page it maps. That is the whole
    /// point -- it exists for physical ranges this crate does not and
    /// cannot allocate, because they are not RAM at all. The motivating
    /// case is `virtio_mmio.rs`'s `VIRTIO_MMIO_BASE` device window: a
    /// fixed physical region the virtio device itself owns, which a future
    /// EL0 driver needs mapped into its own private window to poke
    /// registers through, not a page this kernel could hand out of its
    /// heap even if it wanted to.
    ///
    /// Descriptor bits: still Normal, Inner/Outer Non-cacheable
    /// (`ATTRINDX_NORMAL`, Inner Shareable) -- this module's "Memory
    /// attributes" note explains why that attribute index is not changed
    /// here even though real hardware MMIO is conventionally Device
    /// memory: introducing a second `AttrIndx`/`MAIR_EL1` encoding for
    /// device pages is a bigger decision than this primitive should make
    /// unilaterally, and is deferred to whichever slice actually maps a
    /// real device into a process (see `mmu.rs`'s own
    /// `ATTRINDX_DEVICE`/`ATTRINDX_NORMAL` split for the existing
    /// precedent this would need to extend). `AF` set, `UXN | PXN` always
    /// (an MMIO register window is data, never code, under any
    /// circumstance), and `AP[2:1]` chosen by `writable`: [`AP_EL0_RO`]
    /// (readable from EL0, read-only everywhere including EL1) when
    /// `false`, [`AP_EL0_RW`] when `true` -- virtio MMIO registers need
    /// both read and write, but a future caller mapping something
    /// read-only shouldn't have to ask for more than it needs.
    ///
    /// # Safety
    /// `pa` must be 4 KiB-aligned (checked, returns
    /// [`AddressSpaceError::VaMisaligned`] rather than silently truncating
    /// low bits into the descriptor) and must genuinely be a physical
    /// address this process is authorized to see and touch for as long as
    /// this mapping exists. Unlike [`map_private_page_with`], which only
    /// ever hands out memory this module itself allocated and therefore
    /// owns outright, this function has no way to verify either of those
    /// things from inside itself -- it will map whatever `pa` it is given,
    /// including kernel memory, another process's private frames, or a
    /// device register window nobody granted this process a capability
    /// for. That verification is the caller's job: the intended caller is
    /// a future EL0-driver loader that calls
    /// `capabilities::check_mmio_window` against the process's own
    /// capability token *before* calling this, the same
    /// verify-then-act ordering `kernel/src/capabilities.rs::check_ioport_range`
    /// already uses on the x86_64 side. Calling this with an unchecked
    /// `pa` is exactly the "ambient authority" shortcut this crate's
    /// capability model exists to prevent.
    /// `allow(dead_code)`: no caller yet, same reasoning as
    /// `capabilities.rs`'s `check_mmio_window` -- this is the mapping
    /// primitive a future proof module will call *after* `check_mmio_window`
    /// authorizes the range, not written yet.
    #[allow(dead_code)]
    pub unsafe fn map_mmio_page(
        &mut self,
        va: u64,
        pa: u64,
        writable: bool,
    ) -> Result<(), AddressSpaceError> {
        if va % GRANULE_4KIB != 0 || pa % GRANULE_4KIB != 0 {
            return Err(AddressSpaceError::VaMisaligned);
        }
        if !(PRIVATE_REGION_BASE..PRIVATE_REGION_END).contains(&va) {
            return Err(AddressSpaceError::VaOutsidePrivateRegion);
        }

        let l1_index = ((va >> 30) & 0x1ff) as usize;
        let l2_index = ((va >> 21) & 0x1ff) as usize;
        let l3_index = ((va >> 12) & 0x1ff) as usize;

        let l2 = self.descend(self.root, l1_index)?;
        let l3 = self.descend(l2, l2_index)?;

        let ap = if writable { AP_EL0_RW } else { AP_EL0_RO };
        unsafe {
            entry_ptr(l3, l3_index).write_volatile(normal_4kib_page_descriptor(pa, ap | UXN | PXN));
        }
        // Same reasoning as `map_private_page_with`: `dsb ishst` alone is
        // sufficient because table walks over this non-cacheable memory
        // need no cache maintenance.
        unsafe {
            core::arch::asm!("dsb ishst");
        }

        Ok(())
    }

    /// Returns the address of the next-level table reached through
    /// `table[index]`, allocating and installing a privately owned one
    /// unless this address space already owns whatever is there. See
    /// [`owned_tables`](Self::owned_tables) for why ownership -- not merely
    /// "is it a valid table descriptor" -- is the condition.
    fn descend(&mut self, table: u64, index: usize) -> Result<u64, AddressSpaceError> {
        let descriptor = unsafe { entry_ptr(table, index).read_volatile() };
        let next = descriptor & DESC_ADDR_MASK;
        let is_table = descriptor & 0b11 == DESC_TABLE_OR_PAGE;
        if is_table && self.owned_tables.contains(&next) {
            return Ok(next);
        }
        let fresh = alloc_page()?;
        self.owned_tables.insert(fresh);
        unsafe {
            entry_ptr(table, index).write_volatile(table_descriptor(fresh));
        }
        Ok(fresh)
    }

    /// This space's level-1 table address, i.e. the `TTBR0_EL1` value
    /// [`activate`](Self::activate) writes. Exposed for a future scheduler
    /// to compare against the currently loaded value and skip a switch (and
    /// its TLB invalidation) when it would be a no-op -- the same reason
    /// x86_64's `AddressSpace::p4_frame` exists.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The table this space's kernel-space entries were copied from -- see
    /// [`seeded_root`](Self::seeded_root)'s field documentation for the two
    /// hazards this exists to make checkable, and
    /// `scheduler::spawn_with_address_space` for the one caller that checks
    /// it.
    pub fn seeded_root(&self) -> u64 {
        self.seeded_root
    }

    /// The raw level-3 page descriptor this space maps `va` with, or `None`
    /// if `va` is not mapped by a privately owned level-3 entry.
    ///
    /// Introspection, added for `load_proof.rs`: checking that the loader's
    /// W^X bits actually landed means reading the real descriptor back, not
    /// re-deriving what it *should* be from the same translation function
    /// that wrote it. Deliberately walks only *owned* tables, the same rule
    /// [`descend`](Self::descend) enforces on the write path, so this can
    /// never report a kernel-shared mapping as this space's own private
    /// one.
    ///
    /// Complements, not replaces, the hardware's own account: `AT S1E0R`/
    /// `AT S1E0W` (see `load_proof.rs`) ask the MMU whether EL0 may read or
    /// write an address, which is the behavioural check. This is the bit
    /// pattern behind that behaviour.
    pub fn page_descriptor(&self, va: u64) -> Option<u64> {
        let mut table = self.root;
        // Level 1 and level 2 must both be owned table descriptors; level 3
        // is the page descriptor itself.
        for shift in [30u32, 21] {
            let index = ((va >> shift) & 0x1ff) as usize;
            let descriptor = unsafe { entry_ptr(table, index).read_volatile() };
            if descriptor & 0b11 != DESC_TABLE_OR_PAGE {
                return None;
            }
            let next = descriptor & DESC_ADDR_MASK;
            if !self.owned_tables.contains(&next) {
                return None;
            }
            table = next;
        }
        let index = ((va >> 12) & 0x1ff) as usize;
        let descriptor = unsafe { entry_ptr(table, index).read_volatile() };
        if descriptor & 0b11 == DESC_TABLE_OR_PAGE {
            Some(descriptor)
        } else {
            None
        }
    }

    /// Loads this address space into `TTBR0_EL1` for real, returning the
    /// previous raw register value for [`restore`] to put back.
    ///
    /// ASID is written as 0 and the whole EL1&0 TLB is invalidated -- see
    /// this module's ASID note for why that is a deliberate,
    /// correctness-preserving choice rather than an omission.
    ///
    /// # Safety
    /// The code currently executing, its stack, and anything an exception
    /// handler would need must stay correctly mapped in the *new* table.
    /// True for every space built by [`new`](Self::new), which copies the
    /// active table's kernel-space entries -- but unverifiable from here, so
    /// the caller is trusted, exactly as with `Cr3::write` on x86_64.
    pub unsafe fn activate(&self) -> u64 {
        let previous = active_ttbr0();
        unsafe { write_ttbr0(self.root & DESC_ADDR_MASK) };
        previous
    }
}

/// Restores a raw `TTBR0_EL1` value saved from an earlier
/// [`AddressSpace::activate`] -- usually the kernel's own boot-time table,
/// which is why this is a free function rather than a method (the value
/// being restored needn't belong to any `AddressSpace`).
///
/// # Safety
/// Same contract as [`AddressSpace::activate`].
pub unsafe fn restore(previous: u64) {
    // Written back *raw*, unlike [`load_root`]: `previous` came out of
    // `TTBR0_EL1` verbatim, so putting back exactly those bits (any ASID or
    // `CnP` included, even though this crate sets neither) is what "restore"
    // has to mean.
    unsafe { write_ttbr0(previous) };
}

/// Loads a raw level-1 table address into `TTBR0_EL1` -- the same single
/// operation [`restore`] performs, named for the other direction.
///
/// [`restore`] reads as "put back what was there," which is what the
/// save/restore proofs ([`prove_isolation`], `load_proof::prove_load`) do;
/// `scheduler.rs` instead *installs* the incoming thread's table (or the
/// kernel's own) on every resume, where "restore" would actively misdescribe
/// what is happening. One implementation, two honest names, so neither
/// caller has to read against the grain of the other's idiom.
///
/// # Safety
/// Same contract as [`AddressSpace::activate`]: `root` must name a correctly
/// aligned level-1 table that maps the currently executing code, its stack,
/// and anything an exception handler would need.
pub unsafe fn load_root(root: u64) {
    unsafe { write_ttbr0(root & DESC_ADDR_MASK) };
}

fn active_ttbr0() -> u64 {
    let ttbr0: u64;
    unsafe {
        core::arch::asm!("mrs {}, TTBR0_EL1", out(reg) ttbr0, options(nomem, nostack));
    }
    ttbr0
}

/// Address of the level-1 table `TTBR0_EL1` currently points at, with any
/// ASID/CnP bits masked off.
///
/// Public because `scheduler.rs` compares it against the incoming thread's
/// target table to skip a redundant `msr`/`tlbi` pair: the comparison is
/// made against **the live register**, not a cached "what we last wrote"
/// value, so the optimization cannot silently desync from the hardware.
pub fn active_root() -> u64 {
    active_ttbr0() & DESC_ADDR_MASK
}

/// # Safety
/// `value` must name a correctly aligned level-1 table that maps everything
/// the current execution context needs -- see [`AddressSpace::activate`].
unsafe fn write_ttbr0(value: u64) {
    unsafe {
        core::arch::asm!(
            // Any descriptor writes must be visible to the walker before
            // the new table is in use.
            "dsb ishst",
            "msr TTBR0_EL1, {ttbr}",
            // The register write must take effect before the invalidation
            // that follows, and before any subsequent translation.
            "isb",
            // Full EL1&0 invalidation: no ASIDs (see the module doc
            // comment), and the previous table's entries for this VA range
            // must not survive the switch.
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            ttbr = in(reg) value,
        );
    }
}

/// # Safety
/// `table` must be a live 4 KiB-aligned translation table and `index` < 512.
/// Both hold for every caller here (`index` is masked to 9 bits; `table`
/// comes from [`alloc_page`] or an owned descriptor).
unsafe fn entry_ptr(table: u64, index: usize) -> *mut u64 {
    unsafe { (table as *mut u64).add(index) }
}

/// Arbitrary, fixed VA inside the private window that *both* address spaces
/// in [`prove_isolation`] map privately -- the whole point being that this
/// one address means something different depending on which `TTBR0_EL1` is
/// loaded.
const PROOF_VA: u64 = PRIVATE_REGION_BASE + 0x0012_3000;

/// The actual proof that this module provides isolation, not bookkeeping:
/// two address spaces, the same VA mapped privately in each with different
/// content, a real `TTBR0_EL1` switch into each, and a volatile read back
/// through that fixed VA. The AArch64 counterpart of
/// `kernel/tests/process_isolation.rs`, and structured as a boot-sequence
/// routine with a grepped pass/fail print because this crate has no
/// QEMU-native `cargo test` harness (see `docs/BETA_MOBILE_PROGRESS.md`
/// item 1.7's note on that deferred decision).
///
/// Also prints `AT S1E1R` translations of the shared VA under each space --
/// asking the MMU hardware itself what that VA resolves to, the same
/// independent check `nonsecure.rs` applies to the boot-time identity map.
/// Two different physical addresses there, from the same VA, is the
/// hardware's own account of the isolation, not this code's.
///
/// Requires the MMU to be on and the heap initialized. Returns to the
/// kernel's own `TTBR0_EL1` before returning, on every path.
pub fn prove_isolation() {
    let mut space_a = match AddressSpace::new() {
        Ok(space) => space,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: address-space isolation FAILED -- space A: {}",
                err
            );
            return;
        }
    };
    let mut space_b = match AddressSpace::new() {
        Ok(space) => space,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: address-space isolation FAILED -- space B: {}",
                err
            );
            return;
        }
    };

    let page_a = match space_a.map_private_page(PROOF_VA) {
        Ok(page) => page,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: address-space isolation FAILED -- map A: {}",
                err
            );
            return;
        }
    };
    page_a[0] = 0xAA;
    let frame_a = page_a.as_ptr() as u64;

    let page_b = match space_b.map_private_page(PROOF_VA) {
        Ok(page) => page,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: address-space isolation FAILED -- map B: {}",
                err
            );
            return;
        }
    };
    page_b[0] = 0xBB;
    let frame_b = page_b.as_ptr() as u64;

    serial_println!(
        "Runix ARM kernel: address-space roots A={:#x} B={:#x}, private frames A={:#x} B={:#x} \
         (kernel TTBR0_EL1={:#x})",
        space_a.root(),
        space_b.root(),
        frame_a,
        frame_b,
        active_root()
    );

    // Space A's own page must still hold what was written into it before
    // any switch -- if the two spaces had accidentally been handed the same
    // backing page, this alone would catch it, with no TTBR0 switch
    // involved (x86_64's test makes the same early check for the same
    // reason).
    if page_a[0] != 0xAA {
        serial_println!(
            "Runix ARM kernel: address-space isolation FAILED -- space A's page was clobbered \
             before any TTBR0_EL1 switch (the two spaces share backing memory)"
        );
        return;
    }

    let previous = unsafe { space_a.activate() };
    let observed_a = unsafe { core::ptr::read_volatile(PROOF_VA as *const u8) };
    let translated_a = translate_read(PROOF_VA);
    unsafe { restore(previous) };

    let previous = unsafe { space_b.activate() };
    let observed_b = unsafe { core::ptr::read_volatile(PROOF_VA as *const u8) };
    let translated_b = translate_read(PROOF_VA);
    unsafe { restore(previous) };

    serial_println!(
        "Runix ARM kernel: address-space isolation VA {:#x} A={:#x} B={:#x} (AT S1E1R PA \
         A={:#x} B={:#x})",
        PROOF_VA,
        observed_a,
        observed_b,
        translated_a,
        translated_b
    );

    if observed_a == 0xAA && observed_b == 0xBB && translated_a != translated_b {
        serial_println!(
            "Runix ARM kernel: address-space isolation PASS -- the same VA resolved to different \
             physical memory depending on which TTBR0_EL1 was active"
        );
    } else {
        serial_println!(
            "Runix ARM kernel: address-space isolation FAILED -- the two address spaces are not \
             isolated from each other"
        );
    }
}

/// Asks the MMU to translate `va` for an EL1 read and returns the physical
/// address, or 0 if the translation faulted. Same `AT S1E1R`/`PAR_EL1`
/// mechanism `nonsecure.rs` uses on the boot-time map.
fn translate_read(va: u64) -> u64 {
    let par_el1: u64;
    unsafe {
        core::arch::asm!(
            "at S1E1R, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) va,
            par = out(reg) par_el1,
        );
    }
    if par_el1 & 1 != 0 {
        0
    } else {
        (par_el1 & DESC_ADDR_MASK) | (va & (GRANULE_4KIB - 1))
    }
}
