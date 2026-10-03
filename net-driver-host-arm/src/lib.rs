//! Pure, hardware-independent parsing/validation logic for
//! `net-driver-host-arm` — split out of the binary for exactly the reason
//! `net-driver-host/src/lib.rs`'s own doc comment gives: `main.rs` is
//! `#![no_std] #![no_main]` on `aarch64-unknown-none` with no test harness
//! at all, so anything worth property-testing against arbitrary input has
//! to live somewhere that can also compile as an ordinary host library
//! (`cargo test --lib`, no `--target`).
//!
//! [`validate_rx_completion`] is ported byte-for-byte (same signature, same
//! bug class guarded against) from `net-driver-host`'s version — the
//! `(desc_id, len)` pair it checks comes from the emulated virtio device's
//! used-ring entry regardless of which transport (legacy PCI port I/O on
//! x86_64, MMIO version 2 here) produced it, so the same untrusted-input
//! discipline applies unchanged. The one constant that *does* differ
//! between the two transports is [`VIRTIO_NET_HDR_LEN`] — see its own doc
//! comment.

#![cfg_attr(not(test), no_std)]

/// `virtio_net_hdr_mrg_rxbuf` length: **12 bytes, not 10.** Negotiating
/// `VIRTIO_F_VERSION_1` (required for the MMIO version-2 transport this
/// crate's `virtio_net.rs` insists on — see that module's own doc comment)
/// makes QEMU/the virtio spec (5.1.6) force the `num_buffers` field present
/// on every buffer regardless of whether `VIRTIO_NET_F_MRG_RXBUF` was
/// separately negotiated. `net-driver-host`'s own constant of the same
/// name is 10 — that driver speaks the *legacy* virtio-pci transport (spec
/// 0.9.5), which has no `VIRTIO_F_VERSION_1` to negotiate at all. Confirmed
/// for real on the EL1 proof this ports from, not assumed: see
/// `kernel-arm/src/virtio_net.rs`'s module doc, "Feature negotiation"
/// section.
pub const VIRTIO_NET_HDR_LEN: usize = 12;

/// Every RX packet buffer this binary's (eventual) loader maps is exactly
/// one page — same reasoning as `net-driver-host`'s identical constant:
/// one physical page per buffer keeps "this buffer is one physically
/// contiguous frame" trivially true with no multi-page-contiguous
/// allocation needed.
pub const RX_BUFFER_SIZE: u32 = 4096;

/// Validates a completed RX descriptor's `(desc_id, len)` — both fields are
/// read from the device's used-ring entry, i.e. untrusted input from this
/// binary's point of view (the emulated virtio-net device, not a value this
/// code computed itself). Building a slice directly from an unchecked `len`
/// (which could exceed the buffer this driver actually posted) or indexing
/// buffer storage with an unchecked `desc_id` (which could be outside the
/// range of descriptors this driver ever posted) would be a real
/// out-of-bounds read reachable straight from device-controlled input —
/// exactly the bug class `net-driver-host`'s own doc comment on this
/// function records as having actually happened once, before this check
/// existed there. Returns the validated `(buffer_index, len)` pair, or
/// `None` if either field is out of range: the caller's job is to drop the
/// completion, not to guess a safe fallback for it.
pub fn validate_rx_completion(desc_id: u32, len: u32, buffer_count: usize) -> Option<(usize, u32)> {
    if len > RX_BUFFER_SIZE {
        return None;
    }
    let index = desc_id as usize;
    if index >= buffer_count {
        return None;
    }
    Some((index, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_a_well_formed_completion() {
        assert_eq!(validate_rx_completion(0, RX_BUFFER_SIZE, 4), Some((0, RX_BUFFER_SIZE)));
    }

    #[test]
    fn rejects_oversized_len() {
        assert_eq!(validate_rx_completion(0, RX_BUFFER_SIZE + 1, 4), None);
        assert!(validate_rx_completion(0, RX_BUFFER_SIZE, 4).is_some());
    }

    #[test]
    fn rejects_out_of_range_desc_id() {
        assert_eq!(validate_rx_completion(4, 100, 4), None);
        assert!(validate_rx_completion(3, 100, 4).is_some());
    }

    proptest! {
        // The real regression class this function exists to prevent: no
        // byte pattern or length the device reports, however malformed,
        // may make this function (or, transitively, whatever the caller
        // does with its output) panic — the same property
        // `net-driver-host`'s identical proptest guards, restated here
        // because it is this crate's own copy of the check, not a shared
        // dependency.
        #[test]
        fn never_panics_and_never_returns_out_of_range(
            desc_id in any::<u32>(),
            len in any::<u32>(),
            buffer_count in 1usize..16,
        ) {
            if let Some((index, validated_len)) = validate_rx_completion(desc_id, len, buffer_count) {
                prop_assert!(index < buffer_count);
                prop_assert!(validated_len <= RX_BUFFER_SIZE);
            }
        }

        #[test]
        fn rejects_every_desc_id_at_or_past_buffer_count(
            buffer_count in 1usize..16,
            len in 0u32..=RX_BUFFER_SIZE,
        ) {
            let desc_id = buffer_count as u32; // exactly one past the valid range
            prop_assert_eq!(validate_rx_completion(desc_id, len, buffer_count), None);
        }
    }
}
