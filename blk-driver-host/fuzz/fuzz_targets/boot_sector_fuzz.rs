#![no_main]

// Fuzzes the one FAT32 boundary the other targets leave out: the BPB /
// boot sector (`BootSectorInfo::parse`) and everything that consumes its
// derived fields -- `cluster_to_sector`, the `FsInfoSector` parse/encode
// round trip, `find_reusable_slot` over a directory-cluster-sized slice,
// and `encode_short_name`.
//
// Input layout (fixed offsets, zero-padded / truncated, so a seed that is
// a real image's sector 0 followed by its FSInfo sector exercises both
// parsers at once):
//   data[0..512]    boot sector
//   data[512..1024] FSInfo sector
//   data[1024..]    directory-cluster bytes for `find_reusable_slot`; the
//                   whole of `data` is also reused as the candidate
//                   filename for `encode_short_name`.

use blk_driver_host::{encode_short_name, find_reusable_slot, BootSectorInfo, FsInfoSector};
use libfuzzer_sys::fuzz_target;

fn sector_at(data: &[u8], start: usize) -> [u8; 512] {
    let mut out = [0u8; 512];
    if start < data.len() {
        let end = data.len().min(start + 512);
        out[..end - start].copy_from_slice(&data[start..end]);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let boot = sector_at(data, 0);
    if let Some(info) = BootSectorInfo::parse(&boot) {
        // Parser guarantees: fields it rejects on must be non-zero, and
        // the derived values must equal the checked arithmetic.
        assert!(matches!(info.bytes_per_sector, 512 | 1024 | 2048 | 4096));
        assert!(info.sectors_per_cluster != 0);
        assert!(info.num_fats != 0);
        assert!(info.fat_size_32 != 0);
        assert_eq!(info.fat_start_sector, u32::from(info.reserved_sector_count));
        let fat_region = u64::from(info.fat_size_32) * u64::from(info.num_fats);
        assert_eq!(
            u64::from(info.data_start_sector),
            u64::from(info.fat_start_sector) + fat_region
        );
        assert!(info.data_start_sector >= info.fat_start_sector);
        assert!(info.data_start_sector > info.fat_start_sector); // fat_region >= 1

        let spc = u64::from(info.sectors_per_cluster);
        let probes = [
            0,
            1,
            2,
            3,
            info.root_cluster,
            info.root_cluster.wrapping_add(1),
            0x0FFF_FFF7,
            0x0FFF_FFF8,
            0x0FFF_FFFF,
            u32::MAX - 1,
            u32::MAX,
        ];
        for cluster in probes {
            match info.cluster_to_sector(cluster) {
                None => {
                    // None only for reserved clusters or u32 overflow.
                    let wide = u64::from(info.data_start_sector)
                        + u64::from(cluster.saturating_sub(2)) * spc;
                    assert!(cluster < 2 || wide > u64::from(u32::MAX));
                }
                Some(sector) => {
                    assert!(cluster >= 2);
                    let wide = u64::from(info.data_start_sector)
                        + u64::from(cluster - 2) * spc;
                    assert_eq!(u64::from(sector), wide);
                    assert!(sector >= info.data_start_sector);
                }
            }
        }
        // Cluster 2 is always exactly the data region start.
        assert_eq!(info.cluster_to_sector(2), Some(info.data_start_sector));
    }

    // FSInfo parse + encode round trip on a second sector.
    let mut fsinfo_raw = sector_at(data, 512);
    if let Some(fsinfo) = FsInfoSector::parse(&fsinfo_raw) {
        let original = fsinfo_raw;
        fsinfo.encode_into(&mut fsinfo_raw);
        // Re-encoding what was just parsed must change nothing.
        assert_eq!(fsinfo_raw, original);
        assert_eq!(FsInfoSector::parse(&fsinfo_raw), Some(fsinfo));
        // Encoding different values must keep the sector parseable and
        // touch only bytes 488..496.
        let flipped = FsInfoSector {
            free_count: !fsinfo.free_count,
            next_free: !fsinfo.next_free,
        };
        flipped.encode_into(&mut fsinfo_raw);
        assert_eq!(FsInfoSector::parse(&fsinfo_raw), Some(flipped));
        assert_eq!(fsinfo_raw[..488], original[..488]);
        assert_eq!(fsinfo_raw[496..], original[496..]);
    }

    // Directory-cluster-sized slice: result must index a whole in-bounds
    // entry that really is free/deleted, and be the first such one.
    let dir = if data.len() > 1024 { &data[1024..] } else { &[][..] };
    match find_reusable_slot(dir) {
        Some(index) => {
            assert!((index + 1) * 32 <= dir.len());
            assert!(dir[index * 32] == 0x00 || dir[index * 32] == 0xE5);
            assert!(dir
                .chunks_exact(32)
                .take(index)
                .all(|c| c[0] != 0x00 && c[0] != 0xE5));
        }
        None => assert!(dir
            .chunks_exact(32)
            .all(|c| c[0] != 0x00 && c[0] != 0xE5)),
    }

    // Arbitrary bytes as a display filename (also a short prefix, since
    // only <= 12-byte inputs can succeed).
    for candidate in [data, &data[..data.len().min(12)]] {
        if let Some(name) = encode_short_name(candidate) {
            assert_eq!(name.len(), 11);
            assert!(name.iter().all(|b| b.is_ascii() && !b.is_ascii_lowercase()));
            assert!(name[0] != b' ');
            // No '.' and no embedded space inside the base or extension
            // text; padding is trailing spaces only within each field.
            assert!(!name.contains(&b'.'));
            for field in [&name[..8], &name[8..]] {
                let used = field.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
                assert!(field[..used].iter().all(|&b| b != b' '));
            }
        }
    }
});
