#![no_main]

// Fuzzes `blk_driver_host::chain_link_values` -- the pure, allocator-
// specific piece `main.rs`'s own `allocate_cluster_chain` doc comment names
// directly (the multi-cluster generalization of "new cluster's own EOC
// marker, then the link"). Unlike every other pure function in
// `blk-driver-host/src/lib.rs`, this one had only two fixed-value `#[test]`
// cases, no `proptest` arbitrary-input coverage at all and certainly no
// corpus-driven fuzzing -- this target closes that gap directly, rather
// than adding yet another harness for the boot-sector/dir-entry/LFN/
// checksum parsers `lib.rs`'s existing `proptest!` block already exercises.

use blk_driver_host::{chain_link_values, CHAIN_EOC_MARKER};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Reinterpret the raw fuzz bytes as a list of u32 cluster numbers --
    // libFuzzer hands us one byte slice, and this is the simplest lossless
    // way to get arbitrary-length, arbitrary-valued `&[u32]` input without
    // pulling in the `arbitrary` crate for a single call site.
    let clusters: Vec<u32> = data
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    let links: Vec<(u32, u32)> = chain_link_values(&clusters).collect();

    // The actual invariant this function exists to guarantee: every
    // cluster but the last points at its immediate successor in the same
    // order it was given, and the very last cluster's value is always the
    // fixed EOC marker -- never a panic, and never a value that would leave
    // a chain-walker landing somewhere other than intended or spinning
    // forever.
    assert_eq!(links.len(), clusters.len());
    for (i, &(cluster, value)) in links.iter().enumerate() {
        assert_eq!(cluster, clusters[i]);
        match clusters.get(i + 1) {
            Some(&next) => assert_eq!(value, next),
            None => assert_eq!(value, CHAIN_EOC_MARKER),
        }
    }
});
