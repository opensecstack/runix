#![no_main]

// Fuzzes `blk_driver_host::first_free_cluster_in_fat_sector` -- the pure
// decision logic `main.rs`'s own `allocate_free_cluster` was factored to
// delegate to specifically so it's fuzzable without a real virtio-blk
// device: "does this on-disk FAT sector contain a free entry, and if so,
// which absolute cluster number is it." `allocate_free_cluster` itself
// can't be fuzzed directly -- it takes a live `BlkDevice` doing real
// port-I/O-backed virtqueue reads, and there is no in-memory fake for that
// abstraction today (adding one would mean threading a new trait through
// every call site in `main.rs`, disproportionate to this one gap). This is
// the concrete, currently-uncovered pure boundary that abstraction would
// exist to expose, extracted with the smallest possible refactor instead.
//
// Input layout: first 4 bytes (little-endian) are `fat_sector_index`, next
// 4 are `entries_per_sector`, the rest is the FAT sector's raw bytes.

use blk_driver_host::{fat_entry_at, first_free_cluster_in_fat_sector};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let fat_sector_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let entries_per_sector = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let sector = &data[8..];

    let result = first_free_cluster_in_fat_sector(sector, fat_sector_index, entries_per_sector);

    // The real property a caller (`allocate_free_cluster`) depends on:
    // never a panic on arbitrary/corrupt bytes (the actual regression class
    // this driver's own FAT is untrusted, on-disk, device-controlled
    // input), and whenever a cluster comes back, it must be >= 2 (0/1 are
    // reserved) and its own FAT entry must genuinely read back as free
    // (0) -- not just "some plausible-looking number."
    if let Some(cluster) = result {
        assert!(cluster >= 2);
        let entry_in_sector = cluster - fat_sector_index.wrapping_mul(entries_per_sector);
        assert_eq!(fat_entry_at(sector, entry_in_sector), Some(0));
    }
});
