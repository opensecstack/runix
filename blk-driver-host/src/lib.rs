//! Pure, hardware-independent FAT32 parsing logic — split out of `main.rs`
//! specifically so it can be property-tested on the host (`cargo test
//! --lib`, no `--target`), the same `#![cfg_attr(not(test), no_std)]`
//! split `net-driver-host/src/lib.rs` already uses for the same reason.
//!
//! Everything here is part of `docs/THREAT_MODEL.md`'s testing-rigor
//! commitment, applied from the moment this parser first exists rather
//! than retrofitted later: the boot sector, directory entries, and FAT
//! table this driver reads all originate from the block device — treated
//! as untrusted input the same way `net-driver-host`'s parsers treat
//! bytes from the emulated virtio-net device, not implicitly trusted just
//! because this is a "disk" interface rather than a network one. A
//! corrupted or hostile on-disk byte pattern must never cause a panic or
//! an out-of-bounds read here, the same property `validate_rx_completion`
//! exists to prove for virtio-net's device-reported fields.
//!
//! Scope: read-only FAT32. Short (8.3) and long (VFAT LFN, ASCII-only
//! matching) names are both supported; one level of subdirectory
//! traversal is proven (`kernel/tests/blk_fat32_read.rs`'s `SUBDIR` case).
//! No writes anywhere in this crate. See `docs/STATUS.md`'s
//! filesystem-driver section for the full scope statement and what's
//! still deferred.

#![cfg_attr(not(test), no_std)]

/// A parsed BIOS Parameter Block (BPB) — the FAT32 boot sector, always
/// sector 0. Only the fields this driver actually needs are kept; the BPB
/// has many more (media descriptor, geometry, volume label, ...) that are
/// either irrelevant to walking clusters/directories or not meaningful
/// once this driver negotiates nothing device-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSectorInfo {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sector_count: u16,
    pub num_fats: u8,
    /// FAT32-specific: FAT12/16 store this in a different (16-bit) field
    /// this parser never reads, since it only ever claims to understand
    /// FAT32 — see `parse`'s doc comment on why a FAT12/16 volume is
    /// rejected outright rather than partially misread.
    pub fat_size_32: u32,
    pub root_cluster: u32,
    /// Derived: the first sector of the first FAT (`reserved_sector_count`
    /// as an absolute sector number — the FAT region immediately follows
    /// the reserved sectors).
    pub fat_start_sector: u32,
    /// Derived: the first sector of the data region (cluster 2's sector),
    /// immediately after all `num_fats` copies of the FAT.
    pub data_start_sector: u32,
    /// The FAT32 FSInfo sector number (BPB offset 48, `u16`) — an absolute
    /// sector number on the volume (not relative to `reserved_sector_count`
    /// the way `fat_start_sector` is derived), almost always `1` in
    /// practice. Read but never validated by `parse` itself — a `0` or
    /// otherwise-implausible value just means [`FsInfoSector::parse`] will
    /// later reject whatever sector this points at, the same fail-soft
    /// posture the free-cluster-count hint update already needs (see that
    /// struct's own doc comment for why a missing/invalid FSInfo sector is
    /// not itself a reason to reject the whole volume — this driver's own
    /// correctness never depends on the hint being present or accurate).
    pub fsinfo_sector: u32,
}

/// Bytes-per-sector values FAT32 actually allows per spec — a device could
/// in principle report anything in a `u16`; only these four are ever
/// valid, so anything else is treated the same as a bad signature (an
/// unrecognized/corrupt volume), not an assumed-512 fallback that would
/// silently misinterpret every later offset.
const VALID_BYTES_PER_SECTOR: [u16; 4] = [512, 1024, 2048, 4096];

impl BootSectorInfo {
    /// Parses `sector` (sector 0 of the volume) as a FAT32 BPB. Returns
    /// `None` for anything that doesn't check out: missing `0x55AA`
    /// signature, an out-of-range `bytes_per_sector`, `sectors_per_cluster
    /// == 0` (would make every later cluster-to-sector arithmetic either
    /// divide by zero or silently alias every cluster to the same
    /// sector), `num_fats == 0` (a volume with no FAT can't be walked at
    /// all), or an on-disk arithmetic overflow computing
    /// `data_start_sector` (a hostile/corrupt `fat_size_32` making
    /// `reserved_sector_count + num_fats * fat_size_32` wrap is exactly
    /// the class of bug `validate_rx_completion` exists to catch for
    /// virtio-net's device-reported fields — checked arithmetic here,
    /// never a bare `+`/`*` on an on-disk value).
    ///
    /// This driver only ever claims to understand FAT32 specifically —
    /// it does not attempt to detect or partially support FAT12/16 (which
    /// use a different, 16-bit `fat_size_16` field and a fixed-size root
    /// directory area instead of a cluster chain). A FAT12/16 volume's
    /// `fat_size_32` field reads as `0`, which this function already
    /// rejects (see `num_fats == 0`-style reasoning above, applied to
    /// `fat_size_32` too) — not a special case, just a consequence of
    /// checking every field is actually usable.
    pub fn parse(sector: &[u8; 512]) -> Option<Self> {
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return None;
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if !VALID_BYTES_PER_SECTOR.contains(&bytes_per_sector) {
            return None;
        }

        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 {
            return None;
        }

        let reserved_sector_count = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        if num_fats == 0 {
            return None;
        }

        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        if fat_size_32 == 0 {
            return None;
        }

        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        let fsinfo_sector = u32::from(u16::from_le_bytes([sector[48], sector[49]]));

        let fat_start_sector = u32::from(reserved_sector_count);
        let fat_region_sectors = fat_size_32.checked_mul(u32::from(num_fats))?;
        let data_start_sector = fat_start_sector.checked_add(fat_region_sectors)?;

        Some(BootSectorInfo {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            num_fats,
            fat_size_32,
            root_cluster,
            fat_start_sector,
            data_start_sector,
            fsinfo_sector,
        })
    }

    /// The absolute sector number of `cluster`'s first sector — `None` if
    /// `cluster` is out of the valid range (clusters 0 and 1 are reserved;
    /// the spec's real cluster numbering starts at 2) or if the
    /// computation would overflow (same checked-arithmetic discipline as
    /// `parse`, applied to a cluster number that ultimately came from a
    /// FAT entry or directory entry — equally untrusted).
    pub fn cluster_to_sector(&self, cluster: u32) -> Option<u32> {
        if cluster < 2 {
            return None;
        }
        let cluster_index = cluster.checked_sub(2)?;
        let offset_sectors = cluster_index.checked_mul(u32::from(self.sectors_per_cluster))?;
        self.data_start_sector.checked_add(offset_sectors)
    }
}

/// The FAT32 FSInfo sector's free-cluster-count/next-free hint — real
/// on-disk fields (`docs/STATUS.md`'s filesystem-driver section names this
/// as a real, previously-named gap: this driver always scans the FAT from
/// cluster 2 itself, so its own correctness never depended on this hint,
/// but a real OS mounting this volume afterward would see a stale one).
/// Structural layout confirmed against `mkfs.fat -F 32`'s own output, not
/// assumed from the spec text alone: signature `0x41615252` at offset 0,
/// `free_count` at offset 488, `next_free` at offset 492, trailing
/// signature `0x61417272` at offset 484 and the same `0x55 0xAA` sector
/// signature every FAT32 sector ends with, at 510/511.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsInfoSector {
    pub free_count: u32,
    pub next_free: u32,
}

const FSINFO_SIG1: u32 = 0x4161_5252;
const FSINFO_SIG2: u32 = 0x6141_7272;
/// The on-disk sentinel meaning "this hint isn't maintained/known" — never
/// itself a valid count, so a caller must check for it before trusting
/// [`FsInfoSector::free_count`]/[`FsInfoSector::next_free`] as real numbers.
pub const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

impl FsInfoSector {
    /// Returns `None` for anything that doesn't check out: either
    /// signature missing, or the sector's own trailing `0x55 0xAA` missing
    /// — the same "don't trust a field from a sector that doesn't even
    /// look like the structure it's supposed to be" posture
    /// `BootSectorInfo::parse` already applies to the boot sector.
    pub fn parse(sector: &[u8; 512]) -> Option<Self> {
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return None;
        }
        let sig1 = u32::from_le_bytes([sector[0], sector[1], sector[2], sector[3]]);
        if sig1 != FSINFO_SIG1 {
            return None;
        }
        let sig2 = u32::from_le_bytes([sector[484], sector[485], sector[486], sector[487]]);
        if sig2 != FSINFO_SIG2 {
            return None;
        }
        let free_count = u32::from_le_bytes([sector[488], sector[489], sector[490], sector[491]]);
        let next_free = u32::from_le_bytes([sector[492], sector[493], sector[494], sector[495]]);
        Some(FsInfoSector {
            free_count,
            next_free,
        })
    }

    /// Patches just the `free_count`/`next_free` fields into `sector` in
    /// place — every other byte (both signatures, the trailing `0x55 0xAA`,
    /// and any reserved padding) is left exactly as it was, the same
    /// narrow read-modify-write discipline every other in-place patch in
    /// this module already uses (e.g. `run_partial_write_proof`'s
    /// `file_size` patch in `main.rs`).
    pub fn encode_into(&self, sector: &mut [u8; 512]) {
        sector[488..492].copy_from_slice(&self.free_count.to_le_bytes());
        sector[492..496].copy_from_slice(&self.next_free.to_le_bytes());
    }
}

/// Encodes a display-form ASCII filename (e.g. `"HELLO.TXT"`, `"BIG.TXT"`)
/// into the raw, space-padded 8.3 on-disk form
/// (`*b"HELLO   TXT"`/`*b"BIG     TXT"`) that [`parse_short_dir_entry`]'s
/// `name` field and every existing fixed-name lookup in `main.rs` already
/// compares against. Returns `None` for anything that doesn't fit 8.3
/// (base part longer than 8 characters, extension longer than 3, more
/// than one `.`-delimited extension, a space anywhere, or a non-ASCII
/// byte) — a dynamic filename arriving over IPC that doesn't fit gets
/// [`None`] here and falls back to a long-name lookup
/// (`find_entry_by_long_name`) instead of this function guessing at a
/// truncated/mangled short name, the same "fail closed on ambiguity, don't
/// guess" posture every other parser in this module already has.
pub fn encode_short_name(display: &[u8]) -> Option<[u8; 11]> {
    if display.is_empty() || display.len() > 12 {
        return None;
    }
    let (base, ext): (&[u8], &[u8]) = match display.iter().rposition(|&b| b == b'.') {
        Some(pos) => (&display[..pos], &display[pos + 1..]),
        None => (display, &[]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }
    let mut out = [b' '; 11];
    for (slot, &b) in out[..base.len()].iter_mut().zip(base) {
        if !b.is_ascii() || b == b' ' || b == b'.' {
            return None;
        }
        *slot = b.to_ascii_uppercase();
    }
    for (slot, &b) in out[8..8 + ext.len()].iter_mut().zip(ext) {
        if !b.is_ascii() || b == b' ' || b == b'.' {
            return None;
        }
        *slot = b.to_ascii_uppercase();
    }
    Some(out)
}

/// A parsed 8.3 short directory entry. `name` is the raw, space-padded
/// 11-byte on-disk form (e.g. `*b"HELLO   TXT"` for `HELLO.TXT`) — this
/// driver compares against a fixed expected name in that same raw form
/// rather than reconstructing a `"HELLO.TXT"`-style display string, since
/// nothing here needs to display a name, only match one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortDirEntry {
    pub name: [u8; 11],
    pub first_cluster: u32,
    pub file_size: u32,
    pub is_dir: bool,
}

const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LONG_NAME: u8 = 0x0F;
/// A directory attribute byte is a bitfield; a real LFN entry sets exactly
/// this combination (read-only|hidden|system|volume-label), checked as a
/// mask rather than exact equality since other bits in principle could
/// coexist — matching how every real FAT32 implementation recognizes an
/// LFN entry (`attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME`), not
/// `attr == ATTR_LONG_NAME` alone.
const ATTR_LONG_NAME_MASK: u8 = 0x3F;

/// Parses one 32-byte directory entry. Returns `None` for:
/// - the end-of-directory marker (`entry[0] == 0x00`) — the caller must
///   stop scanning entirely, not just skip this one (see the doc comment
///   on whatever caller loop uses this),
/// - a deleted entry (`entry[0] == 0xE5`),
/// - a long-file-name entry (parsed separately by [`parse_lfn_fragment`]
///   — this function only ever returns the *short* 8.3 form),
///
/// each collapsing to the same `None` here since a caller scanning for a
/// specific short name treats all three identically ("not a match, keep
/// scanning") — a caller that needs to tell "end of directory" apart from
/// "skip this one" (to know when to stop) checks `entry[0] == 0x00`
/// itself before calling this, the same split `net-driver-host`'s own
/// parsers leave to their callers where the distinction matters.
pub fn parse_short_dir_entry(entry: &[u8; 32]) -> Option<ShortDirEntry> {
    if entry[0] == 0x00 || entry[0] == 0xE5 {
        return None;
    }
    let attr = entry[11];
    if attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME {
        return None;
    }

    let mut name = [0u8; 11];
    name.copy_from_slice(&entry[0..11]);

    let cluster_hi = u16::from_le_bytes([entry[20], entry[21]]);
    let cluster_lo = u16::from_le_bytes([entry[26], entry[27]]);
    let first_cluster = (u32::from(cluster_hi) << 16) | u32::from(cluster_lo);

    let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

    Some(ShortDirEntry {
        name,
        first_cluster,
        file_size,
        is_dir: attr & ATTR_DIRECTORY != 0,
    })
}

/// One VFAT long-filename (LFN) directory entry — a normal 32-byte entry
/// with `attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME`, holding up to 13
/// UTF-16 code units of a name too long for the 8.3 short form. Several of
/// these precede the short entry they describe, stored in *descending*
/// sequence order (highest first) — reconstructing the real name means
/// concatenating them in *ascending* order instead (sequence 1 first),
/// the reverse of directory scan order. Confirmed against a real
/// `mkfs.fat`/`mcopy`-produced image, not just the spec text: for
/// `long-filename-test.txt`, the entry with `sequence == 2` (containing
/// `"-test.txt"`, the *end* of the name) is stored first in the
/// directory, immediately followed by `sequence == 1` (containing
/// `"long-filename"`, the *start*) and then the short entry
/// (`LONG-F~1.TXT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LfnFragment {
    /// 1-based chunk index (chunk `N` covers UTF-16 code units
    /// `(N-1)*13 .. N*13` of the full name) — the low 5 bits of the
    /// entry's first byte.
    pub sequence: u8,
    /// Set on the entry closest to the *end* of the name (the highest
    /// sequence number in the run) — the entry's first byte's `0x40` bit.
    pub is_last: bool,
    /// Checksum of the associated short entry's 11-byte name (see
    /// [`short_name_checksum`]) — every fragment in a run carries the
    /// same value, which must match the short entry that follows for the
    /// run to be trusted at all (an orphaned LFN run — e.g. left behind
    /// by a deletion that only removed the short entry — must never be
    /// silently accepted).
    pub checksum: u8,
    /// Up to 13 UTF-16 code units, in name order. `0x0000` marks the true
    /// end of the name (mid-fragment, if the name doesn't exactly fill
    /// every fragment); `0xFFFF` after that is unused padding, per spec.
    pub chars: [u16; 13],
}

const ATTR_LONG_NAME_SEQUENCE_MASK: u8 = 0x1F;
const ATTR_LONG_NAME_LAST_FLAG: u8 = 0x40;

/// Parses one 32-byte directory entry as an LFN fragment. Returns `None`
/// if it isn't one (`attr & ATTR_LONG_NAME_MASK != ATTR_LONG_NAME`) or if
/// its sequence number is `0` (the low 5 bits of a real LFN entry's first
/// byte are never zero — a zero here means either a deleted LFN entry
/// (first byte `0xE5`, whose low 5 bits happen to be `0x05`... still
/// nonzero, so this specifically catches a genuinely malformed/corrupt
/// entry, not the ordinary deleted case) or a hostile/corrupt byte
/// pattern, either way not a fragment this driver can trust enough to use
/// as an array index).
pub fn parse_lfn_fragment(entry: &[u8; 32]) -> Option<LfnFragment> {
    let attr = entry[11];
    if attr & ATTR_LONG_NAME_MASK != ATTR_LONG_NAME {
        return None;
    }
    let sequence = entry[0] & ATTR_LONG_NAME_SEQUENCE_MASK;
    if sequence == 0 {
        return None;
    }
    let is_last = entry[0] & ATTR_LONG_NAME_LAST_FLAG != 0;
    let checksum = entry[13];

    let mut chars = [0u16; 13];
    for i in 0..5 {
        chars[i] = u16::from_le_bytes([entry[1 + 2 * i], entry[2 + 2 * i]]);
    }
    for i in 0..6 {
        chars[5 + i] = u16::from_le_bytes([entry[14 + 2 * i], entry[15 + 2 * i]]);
    }
    for i in 0..2 {
        chars[11 + i] = u16::from_le_bytes([entry[28 + 2 * i], entry[29 + 2 * i]]);
    }

    Some(LfnFragment {
        sequence,
        is_last,
        checksum,
        chars,
    })
}

/// The standard VFAT short-name checksum — every LFN fragment in a run
/// carries this value, computed from the associated short entry's 11-byte
/// name, so a reader can confirm the run really belongs to the short
/// entry that follows it (not left behind by some earlier, unrelated
/// entry). Fixed algorithm, not invented — same one every real FAT32
/// implementation uses, verified here against a checksum actually read
/// back from a real `mkfs.fat`/`mcopy`-produced image (`0xd0`, for
/// `LONG-F~1.TXT`), not just trusted from the spec text.
pub fn short_name_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in name.iter() {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(byte);
    }
    sum
}

/// FAT32 end-of-chain markers are any value `>= 0x0FFF_FFF8` (the exact
/// value used varies by implementation — some write `0x0FFFFFFF`, others
/// `0x0FFFFFF8` — the spec requires readers to accept the whole range, not
/// match one specific value).
pub fn is_end_of_chain(fat_entry: u32) -> bool {
    fat_entry >= 0x0FFF_FFF8
}

/// Reads the 4-byte little-endian FAT32 entry for `cluster` out of
/// `fat_bytes` (one or more whole FAT sectors, concatenated) — masked to
/// the low 28 bits per spec (the top 4 bits are reserved, not part of the
/// cluster-chain value). Returns `None` if `cluster * 4` would land
/// partially or fully outside `fat_bytes` — a cluster number that reached
/// here came from a directory entry or a previous FAT entry, both
/// on-disk, both untrusted; indexing `fat_bytes` with an unchecked
/// device-reported offset is exactly the out-of-bounds-read bug class
/// `validate_rx_completion` was written to catch for virtio-net.
pub fn fat_entry_at(fat_bytes: &[u8], cluster: u32) -> Option<u32> {
    let byte_offset = (cluster as usize).checked_mul(4)?;
    let end = byte_offset.checked_add(4)?;
    if end > fat_bytes.len() {
        return None;
    }
    let raw = u32::from_le_bytes([
        fat_bytes[byte_offset],
        fat_bytes[byte_offset + 1],
        fat_bytes[byte_offset + 2],
        fat_bytes[byte_offset + 3],
    ]);
    Some(raw & 0x0FFF_FFFF)
}

/// Looks for the first directory-entry slot in `sector` (a whole on-disk
/// sector's worth of 32-byte entries, in on-disk order) that a `create`
/// caller can write a brand-new short entry into *without* growing the
/// directory: either a genuinely deleted slot (`entry[0] == 0xE5`) or the
/// first end-of-directory sentinel slot (`entry[0] == 0x00`) — reusing the
/// sentinel in place is safe because every slot after it is itself always
/// `0x00`/unused, the same invariant every reader (this crate's own
/// `find_entry_in_directory`-shaped scans) already relies on to know when
/// to stop scanning. Returns `None` if every entry in `sector` is live —
/// the caller must then check the *next* cluster in the chain, or (if
/// there is none) grow the directory before it can create anything.
///
/// Pure and hardware-independent, same "split out of `main.rs`
/// specifically so it's testable on the host" reasoning this whole module
/// exists for (see this file's own doc comment) — `main.rs`'s own
/// `find_or_grow_create_slot` is responsible for actually reading `sector`
/// off the real device and deciding what to do with `None`.
///
/// `sector.len()` need not be an exact multiple of 32 — any trailing
/// partial entry (never the case for a real on-disk sector, whose
/// `bytes_per_sector` is always itself a multiple of 32 for every value
/// [`VALID_BYTES_PER_SECTOR`] allows) is simply not examined, not a panic.
pub fn find_reusable_slot(sector: &[u8]) -> Option<usize> {
    for (index, chunk) in sector.chunks_exact(32).enumerate() {
        if chunk[0] == 0x00 || chunk[0] == 0xE5 {
            return Some(index);
        }
    }
    None
}

/// The fixed FAT32 end-of-chain value this driver writes whenever *it* is
/// the one marking a cluster as a chain's last one (reads still accept the
/// whole `>= 0x0FFF_FFF8` range via [`is_end_of_chain`] — a real
/// implementation elsewhere might have written a different value in that
/// range, but this driver only ever needs to write one consistent value of
/// its own).
pub const CHAIN_EOC_MARKER: u32 = 0x0FFF_FFFF;

/// Computes, for each cluster in `clusters` (a freshly-allocated,
/// not-yet-linked chain, in chain order), the FAT value it should be
/// written to: every cluster but the last points at its successor; the
/// last gets [`CHAIN_EOC_MARKER`]. Pure and hardware-independent — the
/// multi-cluster generalization of the single "new cluster's own EOC
/// marker, then the link" pair `main.rs`'s `run_grow_proof` already proved
/// safe for one cluster at a time; `main.rs`'s own `allocate_cluster_chain`
/// is responsible for actually reserving these cluster numbers and writing
/// each value via `write_fat_entry`, in whatever order it chooses (unlike
/// the single-cluster case, no two clusters in a *freshly allocated,
/// not-yet-externally-linked* chain can be observed by anything else mid-way,
/// so there is no "half-initialized" hazard to order against here — the
/// hazard `run_grow_proof` guards against is splicing this whole finished
/// chain onto the *existing* file/directory chain before it's fully built,
/// which `allocate_cluster_chain`'s own doc comment covers separately).
pub fn chain_link_values(clusters: &[u32]) -> impl Iterator<Item = (u32, u32)> + '_ {
    clusters.iter().enumerate().map(move |(i, &cluster)| {
        let value = clusters.get(i + 1).copied().unwrap_or(CHAIN_EOC_MARKER);
        (cluster, value)
    })
}

/// Scans one already-in-memory FAT sector's worth of bytes for the first
/// free (all-zero) entry, returning the *absolute* cluster number it
/// corresponds to — `None` if every entry in this sector is already in use
/// (or `sector`/`entries_per_sector` don't admit a valid cluster number at
/// all, via [`fat_entry_at`]'s own bounds check or a checked-arithmetic
/// overflow, same fail-closed posture as everything else in this module).
///
/// `fat_sector_index` is which physical FAT sector `sector`'s bytes came
/// from (0-based from the start of the FAT region) — needed to convert a
/// sector-local entry index into an absolute cluster number, the same
/// conversion `main.rs`'s own `allocate_free_cluster` used to do inline
/// before this was split out specifically so it's testable/fuzzable
/// without a real virtio-blk device: `allocate_free_cluster` is still the
/// one responsible for actually reading `sector` off the device, one
/// sector at a time, and now calls this pure helper per sector instead of
/// repeating the same loop body. Behavior is unchanged — this is a pure
/// extraction, not a new algorithm.
pub fn first_free_cluster_in_fat_sector(
    sector: &[u8],
    fat_sector_index: u32,
    entries_per_sector: u32,
) -> Option<u32> {
    for entry_in_sector in 0..entries_per_sector {
        let cluster = fat_sector_index
            .checked_mul(entries_per_sector)?
            .checked_add(entry_in_sector)?;
        if cluster < 2 {
            continue; // clusters 0/1 are reserved, never allocatable
        }
        if fat_entry_at(sector, entry_in_sector) == Some(0) {
            return Some(cluster);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A minimal, valid FAT32 BPB — every field this parser reads set to
    /// a plausible, self-consistent value, everything else left zeroed.
    /// `reserved_sector_count=32`, `num_fats=2`, `fat_size_32=1000` ->
    /// `fat_start_sector=32`, `data_start_sector=32+2*1000=2032`.
    fn valid_bpb() -> [u8; 512] {
        let mut s = [0u8; 512];
        s[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        s[13] = 4; // sectors_per_cluster
        s[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved_sector_count
        s[16] = 2; // num_fats
        s[36..40].copy_from_slice(&1000u32.to_le_bytes()); // fat_size_32
        s[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn parses_a_well_formed_bpb() {
        let sector = valid_bpb();
        let info = BootSectorInfo::parse(&sector).expect("valid BPB should parse");
        assert_eq!(info.bytes_per_sector, 512);
        assert_eq!(info.sectors_per_cluster, 4);
        assert_eq!(info.reserved_sector_count, 32);
        assert_eq!(info.num_fats, 2);
        assert_eq!(info.fat_size_32, 1000);
        assert_eq!(info.root_cluster, 2);
        assert_eq!(info.fat_start_sector, 32);
        assert_eq!(info.data_start_sector, 2032);
    }

    #[test]
    fn rejects_missing_signature() {
        let mut sector = valid_bpb();
        sector[511] = 0x00;
        assert_eq!(BootSectorInfo::parse(&sector), None);
    }

    #[test]
    fn rejects_bad_bytes_per_sector() {
        let mut sector = valid_bpb();
        sector[11..13].copy_from_slice(&513u16.to_le_bytes());
        assert_eq!(BootSectorInfo::parse(&sector), None);
    }

    #[test]
    fn rejects_zero_sectors_per_cluster() {
        let mut sector = valid_bpb();
        sector[13] = 0;
        assert_eq!(BootSectorInfo::parse(&sector), None);
    }

    #[test]
    fn rejects_zero_num_fats() {
        let mut sector = valid_bpb();
        sector[16] = 0;
        assert_eq!(BootSectorInfo::parse(&sector), None);
    }

    #[test]
    fn rejects_fat_region_overflow() {
        let mut sector = valid_bpb();
        // num_fats * fat_size_32 alone overflows u32, let alone the later
        // + reserved_sector_count -- must be rejected, not wrapped.
        sector[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        sector[16] = 2;
        assert_eq!(BootSectorInfo::parse(&sector), None);
    }

    #[test]
    fn well_formed_short_entry_is_recognized() {
        let mut entry = [0u8; 32];
        entry[0..11].copy_from_slice(b"HELLO   TXT");
        entry[11] = 0x20; // ARCHIVE, not a directory
        entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // cluster hi
        entry[26..28].copy_from_slice(&5u16.to_le_bytes()); // cluster lo
        entry[28..32].copy_from_slice(&70u32.to_le_bytes()); // file size

        let parsed = parse_short_dir_entry(&entry).expect("well-formed entry should parse");
        assert_eq!(&parsed.name, b"HELLO   TXT");
        assert_eq!(parsed.first_cluster, 5);
        assert_eq!(parsed.file_size, 70);
        assert!(!parsed.is_dir);
    }

    #[test]
    fn directory_attribute_is_recognized() {
        let mut entry = [0u8; 32];
        entry[0..11].copy_from_slice(b"SUBDIR     ");
        entry[11] = ATTR_DIRECTORY;
        let parsed = parse_short_dir_entry(&entry).expect("directory entry should parse");
        assert!(parsed.is_dir);
    }

    #[test]
    fn end_of_directory_marker_is_rejected() {
        let entry = [0u8; 32]; // entry[0] == 0x00
        assert_eq!(parse_short_dir_entry(&entry), None);
    }

    #[test]
    fn deleted_entry_is_rejected() {
        let mut entry = [0u8; 32];
        entry[0] = 0xE5;
        assert_eq!(parse_short_dir_entry(&entry), None);
    }

    #[test]
    fn lfn_entry_is_rejected() {
        let mut entry = [0u8; 32];
        entry[0] = 0x41; // a plausible LFN sequence-number byte, not 0x00/0xE5
        entry[11] = ATTR_LONG_NAME;
        assert_eq!(parse_short_dir_entry(&entry), None);
    }

    #[test]
    fn fat_entry_reads_known_value() {
        let mut fat = [0u8; 16];
        fat[8..12].copy_from_slice(&0xF123_4567u32.to_le_bytes()); // cluster 2
                                                                   // Top 4 bits (0xF) must be masked off per spec.
        assert_eq!(fat_entry_at(&fat, 2), Some(0x0123_4567));
    }

    #[test]
    fn fat_entry_rejects_out_of_range_cluster() {
        let fat = [0u8; 16]; // room for clusters 0..=3 only
        assert_eq!(fat_entry_at(&fat, 4), None);
        assert!(fat_entry_at(&fat, 3).is_some());
    }

    #[test]
    fn end_of_chain_boundaries() {
        assert!(!is_end_of_chain(0x0FFF_FFF7));
        assert!(is_end_of_chain(0x0FFF_FFF8));
        assert!(is_end_of_chain(0x0FFF_FFFF));
    }

    /// `0xd0` was read directly out of a real `mkfs.fat -F 32` +
    /// `mcopy`-produced image's `LONG-F~1.TXT` short entry, not assumed
    /// from the spec text — the actual ground truth this whole checksum
    /// exists to reproduce.
    #[test]
    fn short_name_checksum_matches_a_real_short_entry() {
        assert_eq!(short_name_checksum(b"LONG-F~1TXT"), 0xd0);
    }

    /// Built from the exact bytes of the two real LFN entries a
    /// `mkfs.fat`/`mcopy`-produced image wrote for `long-filename-test.txt`
    /// (dumped and hand-decoded from the actual fixture, not synthesized
    /// from the spec alone): `sequence == 1` holds `"long-filename"`
    /// (the *start* of the name, stored second in the directory,
    /// immediately before the short entry), `sequence == 2` (with
    /// `is_last` set) holds `"-test.txt"` (the *end*, stored first).
    #[test]
    fn parses_a_real_lfn_fragment_pair() {
        let seq1 = {
            let mut e = [0u8; 32];
            e[0] = 0x01;
            e[11] = 0x0F;
            e[13] = 0xd0;
            let text: [u16; 13] = [
                b'l' as u16,
                b'o' as u16,
                b'n' as u16,
                b'g' as u16,
                b'-' as u16,
                b'f' as u16,
                b'i' as u16,
                b'l' as u16,
                b'e' as u16,
                b'n' as u16,
                b'a' as u16,
                b'm' as u16,
                b'e' as u16,
            ];
            write_lfn_chars(&mut e, &text);
            e
        };
        let fragment = parse_lfn_fragment(&seq1).expect("valid LFN entry should parse");
        assert_eq!(fragment.sequence, 1);
        assert!(!fragment.is_last);
        assert_eq!(fragment.checksum, 0xd0);
        assert_eq!(fragment.chars[0], b'l' as u16);
        assert_eq!(fragment.chars[12], b'e' as u16);

        let seq2 = {
            let mut e = [0u8; 32];
            e[0] = 0x42; // sequence 2, last-entry flag set
            e[11] = 0x0F;
            e[13] = 0xd0;
            let mut text = [0xFFFFu16; 13];
            for (i, c) in b"-test.txt".iter().enumerate() {
                text[i] = *c as u16;
            }
            text[9] = 0x0000; // NUL terminator right after ".txt"
            write_lfn_chars(&mut e, &text);
            e
        };
        let fragment = parse_lfn_fragment(&seq2).expect("valid LFN entry should parse");
        assert_eq!(fragment.sequence, 2);
        assert!(fragment.is_last);
        assert_eq!(fragment.checksum, 0xd0);
        assert_eq!(fragment.chars[0], b'-' as u16);
        assert_eq!(fragment.chars[9], 0x0000);
    }

    #[test]
    fn non_lfn_entry_is_rejected() {
        let mut entry = [0u8; 32];
        entry[0..11].copy_from_slice(b"HELLO   TXT");
        entry[11] = 0x20; // ARCHIVE, not LFN
        assert_eq!(parse_lfn_fragment(&entry), None);
    }

    #[test]
    fn zero_sequence_lfn_entry_is_rejected() {
        let mut entry = [0u8; 32];
        entry[11] = 0x0F;
        entry[0] = 0x40; // last-flag set, but low 5 bits (sequence) are 0
        assert_eq!(parse_lfn_fragment(&entry), None);
    }

    /// Writes 13 UTF-16 code units into an LFN entry's three fragmented
    /// char regions — the inverse of `parse_lfn_fragment`'s own extraction,
    /// used only by these tests to build realistic fixtures without
    /// hand-writing every byte offset twice.
    fn write_lfn_chars(entry: &mut [u8; 32], chars: &[u16; 13]) {
        for i in 0..5 {
            entry[1 + 2 * i..3 + 2 * i].copy_from_slice(&chars[i].to_le_bytes());
        }
        for i in 0..6 {
            entry[14 + 2 * i..16 + 2 * i].copy_from_slice(&chars[5 + i].to_le_bytes());
        }
        for i in 0..2 {
            entry[28 + 2 * i..30 + 2 * i].copy_from_slice(&chars[11 + i].to_le_bytes());
        }
    }

    #[test]
    fn find_reusable_slot_prefers_the_first_deleted_or_sentinel_entry() {
        let mut sector = [0xFFu8; 512]; // never a valid first byte on its own
                                        // Slot 0: a live entry (first byte 0x41 is a plausible short-name
                                        // char, not 0x00/0xE5).
        sector[0] = 0x41;
        // Slot 1: deleted -- the first reusable slot, must win over slot 3's
        // sentinel even though it comes later in scan order.
        sector[32] = 0xE5;
        // Slot 3: the end-of-directory sentinel.
        sector[96] = 0x00;
        assert_eq!(find_reusable_slot(&sector), Some(1));
    }

    #[test]
    fn find_reusable_slot_finds_a_bare_sentinel_with_no_deleted_entry() {
        let mut sector = [0x41u8; 512]; // every slot "live"
        sector[64] = 0x00; // slot 2 is the end-of-directory sentinel
        assert_eq!(find_reusable_slot(&sector), Some(2));
    }

    #[test]
    fn find_reusable_slot_returns_none_when_every_entry_is_live() {
        let sector = [0x41u8; 512];
        assert_eq!(find_reusable_slot(&sector), None);
    }

    #[test]
    fn chain_link_values_points_every_cluster_at_its_successor_and_ends_in_eoc() {
        let clusters = [10u32, 11, 12];
        let links: Vec<(u32, u32)> = chain_link_values(&clusters).collect();
        assert_eq!(links, vec![(10, 11), (11, 12), (12, CHAIN_EOC_MARKER)]);
    }

    #[test]
    fn chain_link_values_of_a_single_cluster_is_just_its_own_eoc() {
        let clusters = [7u32];
        let links: Vec<(u32, u32)> = chain_link_values(&clusters).collect();
        assert_eq!(links, vec![(7, CHAIN_EOC_MARKER)]);
    }

    #[test]
    fn first_free_cluster_in_fat_sector_finds_the_first_zero_entry() {
        // 16 bytes = 4 entries; entries 0,1 are the reserved clusters,
        // entry 2 (cluster 2) is already in use, entry 3 (cluster 3) is
        // free -- must return 3, not 2.
        let mut sector = [0u8; 16];
        sector[8..12].copy_from_slice(&0x0000_0005u32.to_le_bytes()); // cluster 2: in use
        assert_eq!(
            first_free_cluster_in_fat_sector(&sector, 0, 4),
            Some(3)
        );
    }

    #[test]
    fn first_free_cluster_in_fat_sector_returns_none_when_all_in_use() {
        let mut sector = [0u8; 16];
        for chunk in sector.chunks_mut(4) {
            chunk.copy_from_slice(&0x0000_0001u32.to_le_bytes());
        }
        assert_eq!(first_free_cluster_in_fat_sector(&sector, 0, 4), None);
    }

    #[test]
    fn first_free_cluster_in_fat_sector_offsets_by_fat_sector_index() {
        // fat_sector_index=1, entries_per_sector=4 -> this sector covers
        // clusters 4..=7. Entry 0 in this sector (cluster 4) is free.
        let sector = [0u8; 16];
        assert_eq!(first_free_cluster_in_fat_sector(&sector, 1, 4), Some(4));
    }

    proptest! {
        // The actual regression class this whole module exists to catch:
        // no byte pattern, however malformed, may make any of these three
        // functions panic -- an index-out-of-bounds or slice-range panic
        // here would be reachable directly from on-disk, device-controlled
        // input, i.e. a remotely triggerable panic in a `panic = "abort"`
        // process (mounting a hostile/corrupt USB stick or disk image).
        #[test]
        fn boot_sector_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 512..=512)) {
            let mut sector = [0u8; 512];
            sector.copy_from_slice(&bytes);
            let _ = BootSectorInfo::parse(&sector);
        }

        #[test]
        fn dir_entry_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 32..=32)) {
            let mut entry = [0u8; 32];
            entry.copy_from_slice(&bytes);
            let _ = parse_short_dir_entry(&entry);
        }

        #[test]
        fn lfn_fragment_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 32..=32)) {
            let mut entry = [0u8; 32];
            entry.copy_from_slice(&bytes);
            let _ = parse_lfn_fragment(&entry);
        }

        // Same "no panic on arbitrary input" property as every other
        // parser here, applied to the one function that runs once per
        // *byte* of an 11-byte name rather than once per directory entry.
        #[test]
        fn short_name_checksum_never_panics(name in proptest::collection::vec(any::<u8>(), 11..=11)) {
            let mut buf = [0u8; 11];
            buf.copy_from_slice(&name);
            let _ = short_name_checksum(&buf);
        }

        // Pins the exact property a real cluster-chain walker depends on:
        // the returned offset (if any) must always be a valid index range
        // into whatever FAT bytes were actually supplied -- never past the
        // end, regardless of how the multiply/add could otherwise overflow
        // for a large `cluster`.
        #[test]
        fn fat_entry_at_never_panics_and_never_reads_past_the_buffer(
            fat_bytes in proptest::collection::vec(any::<u8>(), 0..600),
            cluster in any::<u32>(),
        ) {
            if let Some(_entry) = fat_entry_at(&fat_bytes, cluster) {
                let byte_offset = (cluster as usize) * 4;
                prop_assert!(byte_offset + 4 <= fat_bytes.len());
            }
        }

        // `find_reusable_slot` must never panic on arbitrary bytes,
        // regardless of length -- same "no byte pattern makes this crash"
        // property as every other parser in this module.
        #[test]
        fn find_reusable_slot_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let _ = find_reusable_slot(&bytes);
        }

        #[test]
        fn cluster_to_sector_never_panics(
            cluster in any::<u32>(),
            sectors_per_cluster in any::<u8>(),
            data_start_sector in any::<u32>(),
        ) {
            let info = BootSectorInfo {
                bytes_per_sector: 512,
                sectors_per_cluster,
                reserved_sector_count: 0,
                num_fats: 1,
                fat_size_32: 1,
                root_cluster: 2,
                fat_start_sector: 0,
                data_start_sector,
                fsinfo_sector: 1,
            };
            let _ = info.cluster_to_sector(cluster);
        }

        #[test]
        fn fsinfo_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 512..=512)) {
            let mut sector = [0u8; 512];
            sector.copy_from_slice(&bytes);
            let _ = FsInfoSector::parse(&sector);
        }

        #[test]
        fn encode_short_name_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..32)) {
            let _ = encode_short_name(&bytes);
        }

        // Same "no byte pattern makes this crash" property as every other
        // parser here, applied to the allocator's own scan-one-sector
        // decision logic -- plus the actual correctness invariant a real
        // allocator caller depends on: whatever cluster this returns must
        // genuinely be free (its own FAT entry reads back as zero) and must
        // be >= 2 (clusters 0/1 are reserved, never a valid allocation).
        #[test]
        fn first_free_cluster_in_fat_sector_never_panics_and_is_correct_when_found(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048),
            fat_sector_index in any::<u32>(),
            entries_per_sector in 0u32..2048,
        ) {
            let result = first_free_cluster_in_fat_sector(&bytes, fat_sector_index, entries_per_sector);
            if let Some(cluster) = result {
                prop_assert!(cluster >= 2);
                // Recompute which sector-local entry this cluster came
                // from and confirm it really does read as free -- the
                // property a caller (`allocate_free_cluster`) actually
                // relies on, not just "didn't panic."
                let entry_in_sector = cluster - fat_sector_index.wrapping_mul(entries_per_sector);
                prop_assert_eq!(fat_entry_at(&bytes, entry_in_sector), Some(0));
            }
        }
    }

    #[test]
    fn fsinfo_round_trips_through_encode_into() {
        let mut sector = [0u8; 512];
        sector[0..4].copy_from_slice(&FSINFO_SIG1.to_le_bytes());
        sector[484..488].copy_from_slice(&FSINFO_SIG2.to_le_bytes());
        sector[510] = 0x55;
        sector[511] = 0xAA;
        let info = FsInfoSector {
            free_count: 123,
            next_free: 456,
        };
        info.encode_into(&mut sector);
        let parsed = FsInfoSector::parse(&sector).expect("well-formed FSInfo should parse");
        assert_eq!(parsed, info);
        // Signatures/trailer must survive untouched -- the whole point of
        // patching only the two count fields.
        assert_eq!(sector[510], 0x55);
        assert_eq!(sector[511], 0xAA);
    }

    #[test]
    fn fsinfo_rejects_missing_signature() {
        let mut sector = [0u8; 512];
        sector[510] = 0x55;
        sector[511] = 0xAA;
        assert_eq!(FsInfoSector::parse(&sector), None);
    }

    #[test]
    fn encode_short_name_produces_expected_padded_form() {
        assert_eq!(encode_short_name(b"HELLO.TXT"), Some(*b"HELLO   TXT"));
        assert_eq!(encode_short_name(b"BIG.TXT"), Some(*b"BIG     TXT"));
        assert_eq!(encode_short_name(b"hello.txt"), Some(*b"HELLO   TXT"));
    }

    #[test]
    fn encode_short_name_rejects_names_that_do_not_fit_8_3() {
        assert_eq!(encode_short_name(b"WAY-TOO-LONG-NAME.TXT"), None);
        assert_eq!(encode_short_name(b"FILE.LONGEXT"), None);
        assert_eq!(encode_short_name(b""), None);
    }
}
