//! The AArch64 translation-descriptor bits and VA-layout constants that
//! both halves of this crate need: the hardware-side modules in the binary
//! (`mmu.rs`, `process.rs`) and the pure, host-testable logic in this
//! library (`loader.rs`).
//!
//! It exists for one reason: `loader.rs` translates a segment's
//! `PF_R`/`PF_W`/`PF_X` bits into real descriptor bits, and that
//! translation is the part of the loader most worth unit-testing on the
//! host -- but the bits themselves were defined in `mmu.rs`, which is
//! meaningless without real AArch64 system registers and therefore stays in
//! the `#![no_std] #![no_main]` binary. Re-declaring them here next to the
//! loader would mean two definitions of the same hardware encoding, free to
//! drift apart silently; moving them here instead keeps exactly one
//! definition that `mmu.rs`, `process.rs`, and `loader.rs` all use.
//!
//! Nothing here reads or writes any hardware state, which is why it can
//! live in the library at all. The prose explaining *why* the bits are what
//! they are stays attached to the constants, since that is the part a
//! reader actually needs; `mmu.rs`'s own doc comments cover how they are
//! combined into the boot-time identity map.

/// Granule sizes of the 4 KiB-granule AArch64 translation regime this
/// crate uses throughout (`TCR_EL1.TG0 = 0b00`, `T0SZ = 25` -- see
/// `mmu.rs`'s `install`): a level-1 entry covers 1 GiB, a level-3 entry one
/// 4 KiB page.
pub const GRANULE_1GIB: u64 = 1 << 30;
pub const GRANULE_4KIB: u64 = 1 << 12;

/// `UXN`/`PXN` (bits 54/53): Execute-Never for unprivileged (EL0) and
/// privileged (EL1) contexts respectively. Set on the Device block always,
/// on `EL0_STACK`'s pages, and on every process-private *data* page -- data,
/// never code. `loader.rs` is where a segment's real `PF_X` bit decides
/// whether `UXN` may be left clear; `PXN` is set on everything an EL0
/// process can reach regardless, because nothing EL1 executes ever lives in
/// a process-private page.
pub const UXN: u64 = 1 << 54;
pub const PXN: u64 = 1 << 53;

/// `AP[2:1]` (Access Permissions, bits `[7:6]`). The architecture encodes
/// EL1 and EL0 permission in the same two bits, so there is no
/// "EL0-writable, EL1-read-only" and no write-without-read state at all:
///
/// | `AP[2:1]` | EL1   | EL0  |
/// |-----------|-------|------|
/// | `0b00`    | RW    | none |
/// | `0b01`    | RW    | RW   |
/// | `0b10`    | RO    | none |
/// | `0b11`    | RO    | RO   |
///
/// Only the two EL0-accessible encodings are named here, since the
/// EL1-only default is `0` (no bits set) and `mmu.rs` writes it as such.
///
/// [`AP_EL0_RO`] makes a page read-only for *EL1 as well*, which is
/// deliberate and costs the loader nothing: `process.rs`'s
/// `map_private_page` hands back a `&mut [u8; 4096]` reached through the
/// kernel's own identity mapping of the heap frame, not through this
/// descriptor, so segment content is copied in before any EL0 mapping is
/// consulted.
pub const AP_EL0_RW: u64 = 0b01 << 6;
pub const AP_EL0_RO: u64 = 0b11 << 6;

/// Base of the process-private VA window -- level-1 index 2, which
/// `mmu.rs` never populates. See `process.rs`'s module doc comment for why
/// private mappings get their own level-1 slot rather than sharing one of
/// the kernel's: nothing this crate maps privately may share a translation
/// structure with code EL1 must keep fetching.
pub const PRIVATE_REGION_BASE: u64 = 2 * GRANULE_1GIB;
/// One past the end of the private window (exclusive) -- one level-1 slot,
/// 1 GiB.
pub const PRIVATE_REGION_END: u64 = PRIVATE_REGION_BASE + GRANULE_1GIB;
