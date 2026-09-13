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
//! Scope: read-only FAT32, 8.3 short names only (no LFN reconstruction —
//! an LFN entry is recognized and skipped, never misread as a short
//! entry, but this driver never assembles a long name from one), no
//! subdirectory traversal (the caller only ever walks the root directory's
//! own entries). See `docs/STATUS.md`'s filesystem-driver section for the
//! full scope statement.

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
/// - a long-file-name entry (this driver never reconstructs LFNs — see
///   this module's doc comment),
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
            };
            let _ = info.cluster_to_sector(cluster);
        }
    }
}
