//! Pure bookkeeping for freeing an address space's heap frames safely --
//! the host-testable half of `process::AddressSpace::destroy`.
//!
//! An address space owns three kinds of heap memory: translation tables,
//! private data pages, and physically contiguous blocks (virtqueue and
//! MARSHAL request/response regions). It also *maps* memory it does not own
//! (virtio-mmio device windows, the kernel's shared sub-tables). Freeing the
//! wrong one is a heap-corruption or device-register bug, and this crate is
//! `panic = "abort"`, so [`plan_frees`] validates the whole set before a
//! single byte is released:
//!
//! - every extent is 4 KiB-aligned and non-empty,
//! - every extent lies entirely inside the kernel heap (so a device MMIO
//!   address -- below the heap -- or a stray pointer can never be freed),
//! - no two extents overlap (which also rejects a double free: the same
//!   frame recorded twice).
//!
//! A failed plan frees nothing: leaking is the safe failure mode.

use alloc::vec::Vec;

/// 4 KiB, the granule everything here is measured in.
pub const FRAME_BYTES: u64 = 4096;

/// One contiguous heap extent to free, `Layout::from_size_align(bytes, 4096)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub addr: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// Address not 4 KiB-aligned.
    Misaligned(u64),
    /// Zero-length (or overflowing) extent.
    BadLength(u64),
    /// Extent not entirely inside the heap range.
    OutsideHeap(u64),
    /// Two extents overlap (includes the same frame recorded twice).
    Overlap(u64),
}

impl PlanError {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanError::Misaligned(_) => "extent is not 4 KiB-aligned",
            PlanError::BadLength(_) => "extent has zero or overflowing length",
            PlanError::OutsideHeap(_) => "extent is outside the kernel heap",
            PlanError::Overlap(_) => "two owned extents overlap (double free refused)",
        }
    }
}

/// Validates and sorts the extents to free. `tables` and `pages` are single
/// 4 KiB frames; `blocks` are `(base, page_count)` contiguous runs.
/// `heap_start..heap_end` is the allocator's range.
pub fn plan_frees(
    tables: impl Iterator<Item = u64>,
    pages: &[u64],
    blocks: &[(u64, u64)],
    heap_start: u64,
    heap_end: u64,
) -> Result<Vec<Extent>, PlanError> {
    let mut extents: Vec<Extent> = Vec::new();
    extents
        .try_reserve(pages.len() + blocks.len() + 8)
        .map_err(|_| PlanError::BadLength(0))?;
    for addr in tables.chain(pages.iter().copied()) {
        extents.push(Extent {
            addr,
            bytes: FRAME_BYTES,
        });
    }
    for &(addr, count) in blocks {
        let bytes = count
            .checked_mul(FRAME_BYTES)
            .ok_or(PlanError::BadLength(addr))?;
        extents.push(Extent { addr, bytes });
    }

    for e in &extents {
        if e.addr % FRAME_BYTES != 0 {
            return Err(PlanError::Misaligned(e.addr));
        }
        if e.bytes == 0 {
            return Err(PlanError::BadLength(e.addr));
        }
        let end = e
            .addr
            .checked_add(e.bytes)
            .ok_or(PlanError::BadLength(e.addr))?;
        if e.addr < heap_start || end > heap_end {
            return Err(PlanError::OutsideHeap(e.addr));
        }
    }

    extents.sort_unstable_by_key(|e| e.addr);
    for pair in extents.windows(2) {
        // Sorted by address: overlap iff the earlier one runs into the next.
        if pair[0].addr + pair[0].bytes > pair[1].addr {
            return Err(PlanError::Overlap(pair[1].addr));
        }
    }
    Ok(extents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const HS: u64 = 0x4100_0000;
    const HE: u64 = HS + 0x40_0000;

    #[test]
    fn plans_sorted_extents() {
        let plan = plan_frees(
            [HS + 0x3000, HS].into_iter(),
            &[HS + 0x1000],
            &[(HS + 0x10000, 3)],
            HS,
            HE,
        )
        .unwrap();
        assert_eq!(
            plan,
            vec![
                Extent {
                    addr: HS,
                    bytes: 4096
                },
                Extent {
                    addr: HS + 0x1000,
                    bytes: 4096
                },
                Extent {
                    addr: HS + 0x3000,
                    bytes: 4096
                },
                Extent {
                    addr: HS + 0x10000,
                    bytes: 3 * 4096
                },
            ]
        );
    }

    #[test]
    fn refuses_mmio_and_out_of_heap() {
        // The virtio-mmio page is below the heap.
        assert_eq!(
            plan_frees(core::iter::empty(), &[0x0a00_0000], &[], HS, HE),
            Err(PlanError::OutsideHeap(0x0a00_0000))
        );
        // One byte-page past the end.
        assert_eq!(
            plan_frees(core::iter::empty(), &[HE], &[], HS, HE),
            Err(PlanError::OutsideHeap(HE))
        );
        // A block that starts inside but runs past the end.
        assert_eq!(
            plan_frees(core::iter::empty(), &[], &[(HE - 4096, 2)], HS, HE),
            Err(PlanError::OutsideHeap(HE - 4096))
        );
        // Last valid page is fine.
        assert!(plan_frees(core::iter::empty(), &[HE - 4096], &[], HS, HE).is_ok());
    }

    #[test]
    fn refuses_misaligned_and_empty() {
        assert_eq!(
            plan_frees(core::iter::empty(), &[HS + 8], &[], HS, HE),
            Err(PlanError::Misaligned(HS + 8))
        );
        assert_eq!(
            plan_frees(core::iter::empty(), &[], &[(HS, 0)], HS, HE),
            Err(PlanError::BadLength(HS))
        );
        assert_eq!(
            plan_frees(core::iter::empty(), &[], &[(HS, u64::MAX)], HS, HE),
            Err(PlanError::BadLength(HS))
        );
    }

    #[test]
    fn refuses_double_free_and_overlap() {
        // Same frame as a table and as a page.
        assert_eq!(
            plan_frees([HS].into_iter(), &[HS], &[], HS, HE),
            Err(PlanError::Overlap(HS))
        );
        // A page inside a recorded block.
        assert_eq!(
            plan_frees(core::iter::empty(), &[HS + 0x1000], &[(HS, 4)], HS, HE),
            Err(PlanError::Overlap(HS + 0x1000))
        );
        // Adjacent but disjoint is fine.
        assert!(plan_frees(core::iter::empty(), &[HS + 0x3000], &[(HS, 3)], HS, HE).is_ok());
    }

    #[test]
    fn empty_plan_is_ok() {
        assert_eq!(
            plan_frees(core::iter::empty(), &[], &[], HS, HE),
            Ok(vec![])
        );
    }
}
