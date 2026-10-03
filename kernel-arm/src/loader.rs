//! The ELF *loader*: takes `elf.rs`'s parsed, validated [`Elf64`] and
//! `process.rs`'s real `TTBR0_EL1`-rooted address space and puts the one
//! inside the other -- slice 3 of `docs/BETA_MOBILE_PROGRESS.md`'s item 2.4,
//! the piece that turns "this crate can parse an ELF" (slice 1) and "this
//! crate can isolate address spaces" (slice 2) into "this crate can put a
//! real program into one."
//!
//! The AArch64 counterpart of `kernel/src/elf.rs`'s `load_segments` on the
//! x86_64 side, with the same two substantive jobs -- per-segment W^X
//! permissions and an explicitly zero-filled BSS tail -- and one extra:
//! allocating the EL0 stack, which on x86_64 belongs to the scheduler's
//! thread setup rather than the loader.
//!
//! # Scope: a loaded address space, not a running process
//!
//! There is still no scheduler, no context switch, and no `eret` into a
//! loaded image. This module's output is a verified-correct address space
//! plus the two values an eventual scheduler will need from it
//! ([`LoadedImage::entry`], [`LoadedImage::stack_top`]). Executing it is the
//! next slice's job, exactly as x86_64's loader existed before it had ring 3
//! threads to run the result on.
//!
//! # Why this lives in the library, and what [`PrivatePageMapper`] is for
//!
//! `process.rs`'s `AddressSpace` is meaningless without real system
//! registers, so it stays in the `#![no_std] #![no_main]` binary, which has
//! no host test harness at all. The genuinely error-prone parts of a loader
//! -- the `PF_*` -> descriptor-bit translation and the partial-page copy
//! arithmetic -- have no hardware dependency, so they live here in the
//! library behind a one-method [`PrivatePageMapper`] trait that
//! `AddressSpace` implements in the binary (`load_proof.rs`). That is what
//! lets `cargo test --lib` exercise W^X translation, BSS zero-filling, and
//! page-boundary-straddling segments against a fake mapper on the host,
//! leaving only "do these descriptors do what we think on real hardware"
//! for the QEMU proof (`load_proof::prove_load`) rather than *everything*.
//!
//! # The private VA layout this module fixes
//!
//! `process.rs` establishes one 1 GiB process-private window,
//! [`PRIVATE_REGION_BASE`]`..`[`PRIVATE_REGION_END`]
//! (`0x8000_0000`..`0xC000_0000`). This module divides it:
//!
//! ```text
//!   0x8000_0000  +---------------------------------+  PRIVATE_REGION_BASE
//!                |  loadable segments              |  SEGMENT_WINDOW_BASE
//!                |  (wherever the ELF asks, as     |
//!                |   long as it stays below)       |
//!   0xBFFE_C000  +---------------------------------+  SEGMENT_WINDOW_END
//!                |  guard gap, 64 KiB, UNMAPPED    |
//!   0xBFFF_C000  +---------------------------------+  STACK_BASE
//!                |  EL0 stack, 16 KiB, grows down  |
//!   0xC000_0000  +---------------------------------+  STACK_TOP == PRIVATE_REGION_END
//! ```
//!
//! Decisions, and why:
//!
//! - **The stack sits at the very top of the window and grows down**, away
//!   from the segments, so stack growth moves *toward* the guard gap rather
//!   than toward loaded code. [`STACK_TOP`] is one past the last mapped
//!   byte, which is what AArch64 wants in `SP_EL0`: pushes are
//!   pre-decrementing, and `PRIVATE_REGION_END` is 16-byte aligned (an
//!   AArch64 SP alignment requirement under `SCTLR_EL1.SA0`).
//! - **16 KiB of stack**, matching `el0.rs`'s existing static `EL0_STACK`
//!   (`EL0_STACK_SIZE = 4096 * 4`) rather than inventing a second size. It
//!   is also a real constraint today: `heap.rs` has 256 KiB total, and
//!   every page mapped here comes out of it.
//! - **A 64 KiB unmapped guard gap below the stack**, not just one page.
//!   Nothing maps it and [`SEGMENT_WINDOW_END`] refuses to load a segment
//!   into it, so a stack overflow faults into `el1_vectors.rs` instead of
//!   quietly writing over whatever a linker happened to place highest --
//!   the same reasoning as the x86_64 kernel's thread guard pages, which
//!   `kernel/tests/guard_page.rs` proves for real over there. (This slice
//!   does not run anything at EL0, so there is nothing yet to prove the
//!   fault *with* -- it is a layout property here, not a tested one.)
//! - **Segment placement stays the ELF's choice**, bounded. This crate does
//!   no relocation (see `elf.rs`'s `ET_EXEC`-only note), so a segment's
//!   `p_vaddr` is not something a loader may move; all this module can do is
//!   refuse addresses it cannot honor safely, which is
//!   [`LoaderError::SegmentOutsideWindow`].
//!
//! # The permission translation, and RWX
//!
//! Four `PF_*` combinations are meaningful for a loadable segment; see
//! [`page_permissions`] for the exact table. The one real policy decision:
//! **a writable *and* executable segment is rejected**, where
//! `kernel/src/elf.rs` on the x86_64 side would map it W+X without comment
//! (its `translate_flags` sets `WRITABLE` for `PF_W` and omits
//! `NO_EXECUTE` for `PF_X`, so `PF_W | PF_X` quietly yields a W+X page).
//! Stricter here, deliberately: nothing in this workspace's own linking
//! convention produces an RWX `PT_LOAD` (every EL0/ring-3 binary here is
//! linked from a hand-written linker script with separate text and data
//! segments), so an RWX segment means either a broken build or an image
//! this kernel should not be loading -- and silently handing a process a
//! page it can write and then execute is the exact primitive W^X exists to
//! deny. Failing closed costs nothing real and removes the possibility.

use crate::elf::{Elf64, PF_R, PF_W, PF_X};
use crate::vm::{
    AP_EL0_RO, AP_EL0_RW, GRANULE_4KIB, PRIVATE_REGION_BASE, PRIVATE_REGION_END, PXN, UXN,
};
use alloc::collections::BTreeSet;
use core::fmt;

/// One past the last mapped stack byte -- the value an eventual scheduler
/// puts in `SP_EL0`. See the module doc comment's layout diagram.
pub const STACK_TOP: u64 = PRIVATE_REGION_END;
/// EL0 stack size, matching `el0.rs`'s static `EL0_STACK_SIZE`.
pub const STACK_SIZE: u64 = 4 * GRANULE_4KIB;
/// Lowest mapped stack VA.
pub const STACK_BASE: u64 = STACK_TOP - STACK_SIZE;
/// Unmapped gap between the top of the segment window and the bottom of the
/// stack -- a stack overflow faults here instead of reaching a segment.
pub const STACK_GUARD_SIZE: u64 = 16 * GRANULE_4KIB;
/// Lowest VA a loadable segment may occupy.
pub const SEGMENT_WINDOW_BASE: u64 = PRIVATE_REGION_BASE;
/// One past the highest VA a loadable segment may occupy.
pub const SEGMENT_WINDOW_END: u64 = STACK_BASE - STACK_GUARD_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    /// A `PT_LOAD` segment without `PF_R`. AArch64's `AP[2:1]` has no
    /// encoding for "EL0 may write but not read" or "EL0 may execute but
    /// not read" (see [`crate::vm::AP_EL0_RW`]'s table), so such a segment
    /// cannot be honored as written -- and mapping it readable anyway would
    /// silently grant more than the image asked for.
    SegmentNotReadable,
    /// A `PT_LOAD` segment with both `PF_W` and `PF_X`. See the module doc
    /// comment for why this is refused rather than mapped W+X.
    SegmentWritableAndExecutable,
    /// A segment's `[vaddr, vaddr + memsz)` range falls outside
    /// [`SEGMENT_WINDOW_BASE`]..[`SEGMENT_WINDOW_END`] -- either outside the
    /// process-private window entirely (which `process.rs` would reject
    /// anyway, for the QEMU/TCG `AP[1]` reason its doc comment records) or
    /// inside the stack/guard region this module reserves.
    SegmentOutsideWindow { vaddr: u64, end: u64 },
    /// Two segments want the same 4 KiB page. Checked at page granularity,
    /// which is stricter than "do the byte ranges overlap": one page gets
    /// one descriptor with one set of permissions and one backing frame, so
    /// mapping it twice would both pick a winner between two permission sets
    /// and silently discard the first segment's content (the second
    /// `map_page` allocates a fresh, zeroed frame). Every binary this
    /// kernel loads comes from a linker script that page-aligns segments, so
    /// this is a corrupt-or-hostile-image case, not a legitimate one.
    OverlappingSegments { page: u64 },
    /// `e_entry` is not inside any mapped, executable segment -- an image
    /// that would fault on its first instruction. `elf.rs` deliberately
    /// leaves this check to the loader, since which segment must contain the
    /// entry point is loader policy.
    EntryPointNotExecutable { entry: u64 },
    /// The address space could not map a page. `reason` is the underlying
    /// `AddressSpaceError`'s own message, passed through as a string because
    /// that type lives in the hardware-side binary half of this crate (see
    /// the module doc comment on [`PrivatePageMapper`]).
    MapFailed { va: u64, reason: &'static str },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::SegmentNotReadable => {
                f.write_str("PT_LOAD segment is not readable (no PF_R)")
            }
            LoaderError::SegmentWritableAndExecutable => {
                f.write_str("PT_LOAD segment is both writable and executable (W^X violation)")
            }
            LoaderError::SegmentOutsideWindow { vaddr, end } => write!(
                f,
                "PT_LOAD segment [{:#x}, {:#x}) is outside the loadable window [{:#x}, {:#x})",
                vaddr, end, SEGMENT_WINDOW_BASE, SEGMENT_WINDOW_END
            ),
            LoaderError::OverlappingSegments { page } => {
                write!(f, "two PT_LOAD segments share the page at {:#x}", page)
            }
            LoaderError::EntryPointNotExecutable { entry } => write!(
                f,
                "entry point {:#x} is not inside an executable segment",
                entry
            ),
            LoaderError::MapFailed { va, reason } => {
                write!(f, "mapping {:#x} failed: {}", va, reason)
            }
        }
    }
}

/// What a loader needs from an address space: one fresh, zeroed, private
/// 4 KiB page at `va` with exactly `permissions` folded into its page
/// descriptor, returned as bytes the *kernel* can write immediately
/// (through its own identity mapping of the frame, not through the mapping
/// just created -- see `process.rs`'s `map_private_page` doc comment).
///
/// Implemented for `process::AddressSpace` in the binary half of this crate;
/// implemented in this module's tests by a fake that tracks pages in a map,
/// which is what makes the copy arithmetic below host-testable.
pub trait PrivatePageMapper {
    fn map_page(
        &mut self,
        va: u64,
        permissions: u64,
    ) -> Result<&'static mut [u8; 4096], LoaderError>;
}

/// Everything an eventual scheduler needs to actually run what was loaded,
/// plus the page counts, which exist for the proof/diagnostic output rather
/// than for execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedImage {
    /// `e_entry`, verified to sit inside a mapped executable segment.
    pub entry: u64,
    /// Initial `SP_EL0`: one past the last mapped stack byte.
    pub stack_top: u64,
    /// Lowest mapped stack VA.
    pub stack_base: u64,
    /// Pages mapped for `PT_LOAD` segments.
    pub segment_pages: usize,
    /// Pages mapped for the EL0 stack.
    pub stack_pages: usize,
}

/// Translates one segment's `p_flags` into the `extra` bits
/// `mmu::normal_4kib_page_descriptor` folds into a page descriptor.
///
/// | `PF_*` | `AP[2:1]` | `UXN` | `PXN` | meaning |
/// |--------|-----------|-------|-------|---------|
/// | `R`    | `0b11` ([`AP_EL0_RO`]) | set | set | EL0 read-only data, never executable |
/// | `R+X`  | `0b11` ([`AP_EL0_RO`]) | **clear** | set | EL0 code: fetchable at EL0, not writable by anyone, never executable at EL1 |
/// | `R+W`  | `0b01` ([`AP_EL0_RW`]) | set | set | EL0 data: writable, never executable |
/// | `R+W+X`| — | — | — | rejected, [`LoaderError::SegmentWritableAndExecutable`] |
///
/// The W^X property falls out of this directly: `UXN` is clear on exactly
/// one row, and that row is the only one without [`AP_EL0_RW`]. There is no
/// combination this function can return that is simultaneously writable and
/// executable.
///
/// `PXN` is set on *every* row, including the executable one. A
/// process-private page never contains anything EL1 is meant to execute, so
/// letting EL1 fetch from a page EL0 can influence would be a privilege-
/// escalation primitive for no benefit. (`mmu.rs` leaves `PXN` clear on
/// `el0.rs`'s demo code page, which predates any of this and is EL1's own
/// linked image, not process-private memory.)
///
/// Note `AP_EL0_RO` makes the page read-only for EL1 too; see its own doc
/// comment for why that does not stop this loader from writing content in.
pub fn page_permissions(flags: u32) -> Result<u64, LoaderError> {
    let readable = flags & PF_R != 0;
    let writable = flags & PF_W != 0;
    let executable = flags & PF_X != 0;
    match (readable, writable, executable) {
        (false, _, _) => Err(LoaderError::SegmentNotReadable),
        (true, true, true) => Err(LoaderError::SegmentWritableAndExecutable),
        (true, false, false) => Ok(AP_EL0_RO | UXN | PXN),
        (true, false, true) => Ok(AP_EL0_RO | PXN),
        (true, true, false) => Ok(AP_EL0_RW | UXN | PXN),
    }
}

/// Loads every `PT_LOAD` segment of `elf` into `space` with real
/// per-segment permissions, zero-fills each segment's BSS tail, and maps the
/// EL0 stack.
///
/// Segments need not be page-aligned or page-sized: each page is zeroed
/// first and then only the bytes that genuinely overlap
/// `[vaddr, vaddr + filesz)` are copied, so the `memsz`-beyond-`filesz` tail
/// *and* any sub-page slack at either end of a page are left as real zeroes
/// rather than as whatever the recycled physical frame previously held.
/// (`process.rs` happens to hand back `alloc_zeroed` memory today; the
/// explicit fill means this module's correctness does not depend on that
/// staying true, and the "frames get reused" leak is closed here, where the
/// knowledge of what should be zero actually lives.)
///
/// On error, pages already mapped into `space` stay mapped: there is no
/// unmapping primitive (and no `Drop`) in `process.rs` yet, by its own
/// documented choice, so the only safe thing a caller can do with a
/// partially loaded space is discard it -- which is what
/// `load_proof::prove_load` does, and what a scheduler must do too.
pub fn load<M: PrivatePageMapper>(
    elf: &Elf64<'_>,
    space: &mut M,
) -> Result<LoadedImage, LoaderError> {
    let entry = elf.entry_point();
    let mut mapped: BTreeSet<u64> = BTreeSet::new();
    let mut entry_is_executable = false;

    for segment in elf.segments() {
        // A zero-length PT_LOAD describes no memory; mapping a page for it
        // would hand the process an address the image never asked for.
        if segment.memsz == 0 {
            continue;
        }

        let permissions = page_permissions(segment.flags)?;

        // `elf.rs::parse` already proved this addition cannot overflow; the
        // `checked_add` is kept so this module does not depend on that
        // guarantee holding for every future caller.
        let end =
            segment
                .vaddr
                .checked_add(segment.memsz)
                .ok_or(LoaderError::SegmentOutsideWindow {
                    vaddr: segment.vaddr,
                    end: u64::MAX,
                })?;
        if segment.vaddr < SEGMENT_WINDOW_BASE || end > SEGMENT_WINDOW_END {
            return Err(LoaderError::SegmentOutsideWindow {
                vaddr: segment.vaddr,
                end,
            });
        }

        if segment.is_executable() && (segment.vaddr..end).contains(&entry) {
            entry_is_executable = true;
        }

        let content = elf.segment_bytes(&segment);
        let file_end = segment.vaddr + content.len() as u64;

        let first_page = align_down(segment.vaddr);
        let last_page = align_down(end - 1);
        let mut page_va = first_page;
        while page_va <= last_page {
            if !mapped.insert(page_va) {
                return Err(LoaderError::OverlappingSegments { page: page_va });
            }
            let page = space.map_page(page_va, permissions)?;
            // Everything not covered by real file content is zero: the BSS
            // tail and any sub-page slack before/after the segment.
            page.fill(0);

            let copy_start = page_va.max(segment.vaddr);
            let copy_end = (page_va + GRANULE_4KIB).min(file_end);
            if copy_start < copy_end {
                let into = (copy_start - page_va) as usize;
                let from = (copy_start - segment.vaddr) as usize;
                let len = (copy_end - copy_start) as usize;
                // Both ranges are in bounds by construction: `into + len`
                // <= 4096 because `copy_end <= page_va + 4096`, and
                // `from + len <= content.len()` because `copy_end <=
                // file_end`. Sliced (not `copy_from_slice` on raw
                // pointers) so a mistake here is a bounds check, not an
                // out-of-bounds write on a privileged path.
                page[into..into + len].copy_from_slice(&content[from..from + len]);
            }

            page_va += GRANULE_4KIB;
        }
    }

    if !entry_is_executable {
        return Err(LoaderError::EntryPointNotExecutable { entry });
    }

    // The EL0 stack: more private pages, read/write and execute-never at
    // both exception levels. No `PF_*` involved -- it is not an ELF
    // segment -- but the bits are exactly the `R+W` row of
    // [`page_permissions`]'s table, which is the point: a stack is data.
    let stack_pages = (STACK_SIZE / GRANULE_4KIB) as usize;
    for i in 0..stack_pages {
        let va = STACK_BASE + (i as u64) * GRANULE_4KIB;
        let page = space.map_page(va, AP_EL0_RW | UXN | PXN)?;
        page.fill(0);
    }

    Ok(LoadedImage {
        entry,
        stack_top: STACK_TOP,
        stack_base: STACK_BASE,
        segment_pages: mapped.len(),
        stack_pages,
    })
}

fn align_down(va: u64) -> u64 {
    va & !(GRANULE_4KIB - 1)
}

/// Host-side tests (`cargo test --lib`, no `--target`), the same
/// `#![cfg_attr(not(test), no_std)]` split `elf.rs` uses.
///
/// What is genuinely testable here without an MMU: the `PF_*` -> descriptor
/// translation (pure), and -- via a fake [`PrivatePageMapper`] backed by
/// leaked host allocations -- the page-count/copy/zero-fill arithmetic,
/// including segments that straddle a page boundary and BSS tails that
/// extend into a page with no file content at all. What is *not* testable
/// here, and is therefore what `load_proof::prove_load` does in real QEMU:
/// whether those descriptor bits mean what this module claims to actual
/// AArch64 translation hardware, read back through a real `TTBR0_EL1`
/// switch.
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A [`PrivatePageMapper`] over leaked host pages. Raw pointers, not
    /// `&'static mut`, because the trait hands the caller a `&'static mut`
    /// *and* this fake keeps the page around for the test to inspect
    /// afterwards -- two live mutable paths to the same bytes, which is only
    /// sound here because the test never uses both at once.
    struct FakeMapper {
        pages: BTreeMap<u64, *mut [u8; 4096]>,
        permissions: BTreeMap<u64, u64>,
        fail_at: Option<u64>,
    }

    impl FakeMapper {
        fn new() -> Self {
            FakeMapper {
                pages: BTreeMap::new(),
                permissions: BTreeMap::new(),
                fail_at: None,
            }
        }

        fn failing_at(va: u64) -> Self {
            let mut mapper = FakeMapper::new();
            mapper.fail_at = Some(va);
            mapper
        }

        fn bytes(&self, va: u64) -> Vec<u8> {
            let page = align_down(va);
            let ptr = *self.pages.get(&page).expect("page is not mapped");
            let offset = (va - page) as usize;
            // Explicit reference, not an implicit autoref of a raw
            // pointer deref (which `dangerous_implicit_autorefs` rightly
            // denies): the leaked page is live for the whole test.
            unsafe { (&(*ptr))[offset..].to_vec() }
        }

        fn byte(&self, va: u64) -> u8 {
            self.bytes(va)[0]
        }
    }

    impl PrivatePageMapper for FakeMapper {
        fn map_page(
            &mut self,
            va: u64,
            permissions: u64,
        ) -> Result<&'static mut [u8; 4096], LoaderError> {
            if self.fail_at == Some(va) {
                return Err(LoaderError::MapFailed {
                    va,
                    reason: "fake out of memory",
                });
            }
            let page: &'static mut [u8; 4096] =
                alloc::boxed::Box::leak(alloc::boxed::Box::new([0xCDu8; 4096]));
            self.pages.insert(va, page as *mut [u8; 4096]);
            self.permissions.insert(va, permissions);
            Ok(page)
        }
    }

    // --- the pure permission translation ---------------------------------

    #[test]
    fn read_only_segment_is_not_writable_and_not_executable() {
        let bits = page_permissions(PF_R).expect("R is a valid combination");
        assert_eq!(bits & AP_EL0_RW_MASK, AP_EL0_RO);
        assert_ne!(bits & UXN, 0);
        assert_ne!(bits & PXN, 0);
    }

    #[test]
    fn read_exec_segment_is_executable_at_el0_but_not_writable() {
        let bits = page_permissions(PF_R | PF_X).expect("R+X is a valid combination");
        // Read-only (so not writable from EL0), and UXN clear so EL0 can
        // fetch from it -- the W^X half that matters for .text.
        assert_eq!(bits & AP_EL0_RW_MASK, AP_EL0_RO);
        assert_eq!(bits & UXN, 0);
        // Still never executable at EL1.
        assert_ne!(bits & PXN, 0);
    }

    #[test]
    fn read_write_segment_is_writable_and_never_executable() {
        let bits = page_permissions(PF_R | PF_W).expect("R+W is a valid combination");
        assert_eq!(bits & AP_EL0_RW_MASK, AP_EL0_RW);
        assert_ne!(bits & UXN, 0);
        assert_ne!(bits & PXN, 0);
    }

    /// The actual W^X invariant, stated over every combination rather than
    /// per-case: nothing this function returns is both EL0-writable and
    /// EL0-executable.
    #[test]
    fn no_accepted_combination_is_both_writable_and_el0_executable() {
        for flags in 0u32..8 {
            if let Ok(bits) = page_permissions(flags) {
                let writable = bits & AP_EL0_RW_MASK == AP_EL0_RW;
                let el0_executable = bits & UXN == 0;
                assert!(
                    !(writable && el0_executable),
                    "flags {:#b} produced a W+X page ({:#x})",
                    flags,
                    bits
                );
            }
        }
    }

    #[test]
    fn rwx_segment_is_rejected() {
        assert_eq!(
            page_permissions(PF_R | PF_W | PF_X),
            Err(LoaderError::SegmentWritableAndExecutable)
        );
    }

    #[test]
    fn unreadable_segment_is_rejected() {
        assert_eq!(page_permissions(0), Err(LoaderError::SegmentNotReadable));
        assert_eq!(page_permissions(PF_W), Err(LoaderError::SegmentNotReadable));
        assert_eq!(page_permissions(PF_X), Err(LoaderError::SegmentNotReadable));
    }

    /// `AP[2:1]` is two bits; masking with just `AP_EL0_RW` would make
    /// `0b11` (read-only) look like it contained `0b01` (read/write).
    const AP_EL0_RW_MASK: u64 = 0b11 << 6;

    // --- the loading arithmetic, against the fake mapper -----------------

    const ELF_HEADER_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const PT_LOAD: u32 = 1;

    struct Phdr {
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    }

    /// Minimal valid AArch64 ELF64 image, same hand-assembly technique as
    /// `elf.rs`'s own tests (and `kernel/tests/elf_loader.rs` before them).
    fn build(entry: u64, phdrs: &[Phdr], payload_offset: usize, payload: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; ELF_HEADER_SIZE];
        image[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        image[4] = 2; // ELFCLASS64
        image[5] = 1; // ELFDATA2LSB
        image[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        image[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        image[24..32].copy_from_slice(&entry.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        image[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        image[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for phdr in phdrs {
            let mut entry = vec![0u8; PHDR_SIZE];
            entry[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
            entry[4..8].copy_from_slice(&phdr.flags.to_le_bytes());
            entry[8..16].copy_from_slice(&phdr.offset.to_le_bytes());
            entry[16..24].copy_from_slice(&phdr.vaddr.to_le_bytes());
            entry[32..40].copy_from_slice(&phdr.filesz.to_le_bytes());
            entry[40..48].copy_from_slice(&phdr.memsz.to_le_bytes());
            image.extend_from_slice(&entry);
        }
        if image.len() < payload_offset {
            image.resize(payload_offset, 0);
        }
        image.extend_from_slice(payload);
        image
    }

    const TEXT_VADDR: u64 = PRIVATE_REGION_BASE;
    const DATA_VADDR: u64 = PRIVATE_REGION_BASE + 0x1_0000;
    const TEXT: &[u8] = b"\x1f\x20\x03\xd5"; // `nop`
    const DATA: &[u8] = b"runix";
    const BSS_LEN: u64 = 16;

    fn two_segment_image() -> Vec<u8> {
        let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
        let mut payload = Vec::new();
        payload.extend_from_slice(TEXT);
        payload.extend_from_slice(DATA);
        build(
            TEXT_VADDR,
            &[
                Phdr {
                    flags: PF_R | PF_X,
                    offset: payload_offset as u64,
                    vaddr: TEXT_VADDR,
                    filesz: TEXT.len() as u64,
                    memsz: TEXT.len() as u64,
                },
                Phdr {
                    flags: PF_R | PF_W,
                    offset: (payload_offset + TEXT.len()) as u64,
                    vaddr: DATA_VADDR,
                    filesz: DATA.len() as u64,
                    memsz: DATA.len() as u64 + BSS_LEN,
                },
            ],
            payload_offset,
            &payload,
        )
    }

    #[test]
    fn loads_content_permissions_and_stack() {
        let image = two_segment_image();
        let elf = Elf64::parse(&image).expect("hand-built image must parse");
        let mut mapper = FakeMapper::new();
        let loaded = load(&elf, &mut mapper).expect("load must succeed");

        assert_eq!(loaded.entry, TEXT_VADDR);
        assert_eq!(loaded.stack_top, STACK_TOP);
        assert_eq!(loaded.stack_base, STACK_BASE);
        assert_eq!(loaded.segment_pages, 2);
        assert_eq!(loaded.stack_pages, 4);

        // Content landed at the right VAs.
        assert_eq!(&mapper.bytes(TEXT_VADDR)[..TEXT.len()], TEXT);
        assert_eq!(&mapper.bytes(DATA_VADDR)[..DATA.len()], DATA);

        // The BSS tail is zero, not the 0xCD the fake frame was filled with
        // to stand in for a recycled physical frame's stale contents.
        let tail = mapper.bytes(DATA_VADDR + DATA.len() as u64);
        assert!(tail[..BSS_LEN as usize].iter().all(|&b| b == 0));
        // ...and so is the sub-page slack after it.
        assert_eq!(mapper.byte(DATA_VADDR + DATA.len() as u64 + BSS_LEN), 0);
        // ...and before the segment's own start within its page.
        assert_eq!(mapper.byte(TEXT_VADDR + TEXT.len() as u64), 0);

        // Real W^X on the real pages, not just on the pure translation.
        let text_bits = mapper.permissions[&TEXT_VADDR];
        assert_eq!(text_bits & UXN, 0, "text must be fetchable at EL0");
        assert_eq!(text_bits & AP_EL0_RW_MASK, AP_EL0_RO);
        let data_bits = mapper.permissions[&DATA_VADDR];
        assert_ne!(data_bits & UXN, 0, "data must not be executable at EL0");
        assert_eq!(data_bits & AP_EL0_RW_MASK, AP_EL0_RW);

        // The stack: four pages, writable, never executable.
        for i in 0..4u64 {
            let va = STACK_BASE + i * GRANULE_4KIB;
            let bits = mapper.permissions[&va];
            assert_eq!(bits, AP_EL0_RW | UXN | PXN);
            assert_eq!(mapper.byte(va), 0);
        }
        // And nothing mapped in the guard gap below it.
        assert!(!mapper.pages.contains_key(&(STACK_BASE - GRANULE_4KIB)));
    }

    /// A segment that is neither page-aligned nor page-sized, straddling a
    /// page boundary -- the case the copy arithmetic is easiest to get
    /// wrong on, and the one `kernel/src/elf.rs` explicitly does not handle
    /// (it requires page-aligned `p_vaddr`).
    #[test]
    fn handles_unaligned_segment_straddling_a_page_boundary() {
        let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
        // Starts 8 bytes before a page boundary and runs 24 bytes, so 8
        // bytes land on the first page and 16 on the second.
        let straddle_vaddr = DATA_VADDR + GRANULE_4KIB - 8;
        let content: Vec<u8> = (0..24u8).collect();
        let mut payload = Vec::new();
        payload.extend_from_slice(TEXT);
        payload.extend_from_slice(&content);
        let image = build(
            TEXT_VADDR,
            &[
                Phdr {
                    flags: PF_R | PF_X,
                    offset: payload_offset as u64,
                    vaddr: TEXT_VADDR,
                    filesz: TEXT.len() as u64,
                    memsz: TEXT.len() as u64,
                },
                Phdr {
                    flags: PF_R | PF_W,
                    offset: (payload_offset + TEXT.len()) as u64,
                    vaddr: straddle_vaddr,
                    filesz: content.len() as u64,
                    // Plus a BSS tail that reaches into a third page.
                    memsz: content.len() as u64 + GRANULE_4KIB,
                },
            ],
            payload_offset,
            &payload,
        );
        let elf = Elf64::parse(&image).expect("hand-built image must parse");
        let mut mapper = FakeMapper::new();
        let loaded = load(&elf, &mut mapper).expect("load must succeed");

        // text (1) + three pages for a 24-byte segment whose memsz spans
        // into a third page.
        assert_eq!(loaded.segment_pages, 4);
        for (i, expected) in content.iter().enumerate() {
            assert_eq!(
                mapper.byte(straddle_vaddr + i as u64),
                *expected,
                "byte {} of the straddling segment",
                i
            );
        }
        // The byte just before the segment, on the same page, stays zero --
        // the copy must not have been offset to the page start.
        assert_eq!(mapper.byte(straddle_vaddr - 1), 0);
        // BSS, in the page after the content.
        assert_eq!(mapper.byte(straddle_vaddr + content.len() as u64), 0);
        assert_eq!(mapper.byte(straddle_vaddr + content.len() as u64 + 2048), 0);
    }

    #[test]
    fn rejects_a_segment_outside_the_loadable_window() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        // Identity-mapped kernel territory, not the private window.
        let image = build(
            0x4008_0000,
            &[Phdr {
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: 0x4008_0000,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
        );
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::new();
        assert_eq!(
            load(&elf, &mut mapper),
            Err(LoaderError::SegmentOutsideWindow {
                vaddr: 0x4008_0000,
                end: 0x4008_0000 + TEXT.len() as u64,
            })
        );
    }

    /// The stack region and its guard gap are not loadable, even though
    /// they are inside `process.rs`'s private window.
    #[test]
    fn rejects_a_segment_landing_in_the_stack_region() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build(
            STACK_BASE,
            &[Phdr {
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: STACK_BASE,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
        );
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::new();
        assert!(matches!(
            load(&elf, &mut mapper),
            Err(LoaderError::SegmentOutsideWindow { .. })
        ));
    }

    #[test]
    fn rejects_two_segments_sharing_a_page() {
        let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
        let mut payload = Vec::new();
        payload.extend_from_slice(TEXT);
        payload.extend_from_slice(DATA);
        let image = build(
            TEXT_VADDR,
            &[
                Phdr {
                    flags: PF_R | PF_X,
                    offset: payload_offset as u64,
                    vaddr: TEXT_VADDR,
                    filesz: TEXT.len() as u64,
                    memsz: TEXT.len() as u64,
                },
                Phdr {
                    flags: PF_R | PF_W,
                    offset: (payload_offset + TEXT.len()) as u64,
                    // Same page as the text segment, different permissions.
                    vaddr: TEXT_VADDR + 0x100,
                    filesz: DATA.len() as u64,
                    memsz: DATA.len() as u64,
                },
            ],
            payload_offset,
            &payload,
        );
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::new();
        assert_eq!(
            load(&elf, &mut mapper),
            Err(LoaderError::OverlappingSegments { page: TEXT_VADDR })
        );
    }

    #[test]
    fn rejects_an_entry_point_outside_every_executable_segment() {
        let image = two_segment_image();
        let mut image = image;
        // Point e_entry into the *data* segment.
        image[24..32].copy_from_slice(&DATA_VADDR.to_le_bytes());
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::new();
        assert_eq!(
            load(&elf, &mut mapper),
            Err(LoaderError::EntryPointNotExecutable { entry: DATA_VADDR })
        );
    }

    /// A mapping failure is propagated, not swallowed or panicked on --
    /// this crate is `panic = "abort"`.
    #[test]
    fn propagates_a_mapping_failure() {
        let image = two_segment_image();
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::failing_at(DATA_VADDR);
        assert_eq!(
            load(&elf, &mut mapper),
            Err(LoaderError::MapFailed {
                va: DATA_VADDR,
                reason: "fake out of memory",
            })
        );
    }

    /// The stack is mapped even for an image whose segments all fit in one
    /// page -- it is the loader's job, not the image's.
    #[test]
    fn stack_is_mapped_for_a_single_segment_image() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build(
            TEXT_VADDR,
            &[Phdr {
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: TEXT_VADDR,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
        );
        let elf = Elf64::parse(&image).expect("image itself is well-formed");
        let mut mapper = FakeMapper::new();
        let loaded = load(&elf, &mut mapper).expect("load must succeed");
        assert_eq!(loaded.segment_pages, 1);
        assert_eq!(loaded.stack_pages, 4);
        assert_eq!(loaded.stack_top - loaded.stack_base, STACK_SIZE);
    }

    /// Sanity-check the layout constants themselves: the stack must sit
    /// inside the private window, above the segment window, with a real gap.
    #[test]
    fn layout_constants_are_coherent() {
        assert!(SEGMENT_WINDOW_BASE >= PRIVATE_REGION_BASE);
        assert!(SEGMENT_WINDOW_END + STACK_GUARD_SIZE == STACK_BASE);
        assert!(STACK_TOP <= PRIVATE_REGION_END);
        assert_eq!(STACK_TOP % 16, 0, "SP_EL0 must be 16-byte aligned");
        assert_eq!(STACK_BASE % GRANULE_4KIB, 0);
    }
}
