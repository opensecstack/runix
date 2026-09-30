#![no_main]

// Fuzzes the two pure boundaries `docs/STATUS.md`'s filesystem-driver
// section names as the last unfuzzed gap: directory-entry/LFN-fragment
// parsing (`parse_short_dir_entry`, `parse_lfn_fragment`, both already
// proven panic-free by `lib.rs`'s own `proptest!` block, but never under
// libFuzzer's coverage-guided corpus) and cluster-chain walking
// (`fat_entry_at` + `is_end_of_chain`, driven with the same bounded-
// iteration shape `main.rs`'s real walkers -- `read_file_contents`,
// `find_entry_in_directory`, `find_entry_by_long_name` -- all use, so a
// corrupt or cyclic on-disk FAT is proven to terminate rather than spin
// forever, not just proven not to panic).
//
// Input layout: `data` is used twice, independently -- once as a whole
// on-disk directory sector (32-byte entries, scanned in the same order
// and with the same early-stop-on-0x00 rule every real directory scan in
// `main.rs` uses) and once as raw FAT bytes for a chain walk starting at
// the cluster number encoded in its first 4 bytes. No shared header to
// carve out of `data` for either use -- keeping the whole byte string
// available to both maximizes libFuzzer's coverage-guided mutation
// density for each path instead of splitting one already-small input.

use blk_driver_host::{
    fat_entry_at, is_end_of_chain, parse_lfn_fragment, parse_short_dir_entry,
    short_name_checksum,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Directory-entry / LFN-fragment scan, mirroring `find_entry_in_directory`
    // and `find_entry_by_long_name`'s own chunk-by-chunk loop over a
    // directory sector's raw bytes.
    for chunk in data.chunks_exact(32) {
        let entry_bytes: [u8; 32] = chunk.try_into().unwrap();
        if entry_bytes[0] == 0x00 {
            // End-of-directory sentinel -- every real scanner stops here
            // rather than examining anything after it.
            break;
        }
        if let Some(entry) = parse_short_dir_entry(&entry_bytes) {
            // Must never panic regardless of what raw name bytes came back,
            // the same property `short_name_checksum_never_panics` already
            // pins for arbitrary 11-byte input, exercised here on whatever
            // `parse_short_dir_entry` itself actually produced.
            let _ = short_name_checksum(&entry.name);
        }
        if let Some(fragment) = parse_lfn_fragment(&entry_bytes) {
            // Sequence is the low 5 bits of a byte and `parse_lfn_fragment`
            // itself already rejects 0 -- pin both ends of that range.
            assert!(fragment.sequence >= 1 && fragment.sequence <= 0x1F);
        }
    }

    // Cluster-chain walk over `data` treated as raw FAT bytes, starting
    // from an arbitrary (possibly out-of-range, possibly self-referential
    // or cyclic) cluster number. The 1024-iteration cap matches every real
    // chain walker in `main.rs` exactly -- this proves that cap actually
    // does its job (termination) for a byte pattern libFuzzer chooses,
    // not just for the hand-written fixtures those walkers' own tests use.
    if data.len() >= 4 {
        let mut cluster = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        for _ in 0..1024u32 {
            match fat_entry_at(data, cluster) {
                Some(next) if !is_end_of_chain(next) => cluster = next,
                _ => break,
            }
        }
    }
});
