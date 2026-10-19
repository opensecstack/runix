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
///
/// `len` is accepted only in `VIRTIO_NET_HDR_LEN..=RX_BUFFER_SIZE`: the
/// device always writes the full `virtio_net_hdr` before the frame, so a
/// shorter `len` is malformed, and the caller computes `len -
/// VIRTIO_NET_HDR_LEN` as the frame length (which would wrap to a huge
/// slice length for a shorter one). `len == VIRTIO_NET_HDR_LEN` is a valid
/// zero-length frame (same edge as `net-driver-host`).
pub fn validate_rx_completion(desc_id: u32, len: u32, buffer_count: usize) -> Option<(usize, u32)> {
    if len < VIRTIO_NET_HDR_LEN as u32 || len > RX_BUFFER_SIZE {
        return None;
    }
    let index = desc_id as usize;
    if index >= buffer_count {
        return None;
    }
    Some((index, len))
}

/// Largest virtqueue size this driver's fixed one-page-per-ring layout can
/// hold (16-byte descriptors, 256 per 4096-byte page). Same bound as
/// `net-driver-host`'s `MAX_QUEUE_SIZE`.
pub const MAX_QUEUE_SIZE: u16 = 256;

/// Whether `qsize` is a usable virtqueue size. `min_size` is the highest
/// descriptor index the driver ever posts on that queue plus one (the
/// buffer count: RX 8, TX 4). The size must be a power of two (virtio
/// split-ring rule; also excludes 0, which would make the ring's `% qsize`
/// abort) and at most [`MAX_QUEUE_SIZE`]. Mirrors
/// `net_driver_host::queue_size_is_valid`.
pub fn queue_size_is_valid(qsize: u16, min_size: u16) -> bool {
    qsize.is_power_of_two() && qsize >= min_size && qsize <= MAX_QUEUE_SIZE
}

/// Picks the queue size to program into `QueueNum`. Unlike the x86 legacy
/// transport (where the device dictates `QueueSize`), MMIO v2 lets the
/// driver write any `QueueNum <= QueueNumMax`, so rather than rejecting a
/// device whose `QueueNumMax` is merely not a power of two (e.g. 300), this
/// returns the largest power of two that is `<= min(device_max, requested,
/// MAX_QUEUE_SIZE)`. Returns `None` -- the caller must fail the driver --
/// only when no valid size exists, i.e. that cap is below `min_size`
/// (including a device reporting 0). Whenever `Some(n)` is returned,
/// `queue_size_is_valid(n, min_size)` holds.
pub fn choose_queue_size(device_max: u32, requested: u16, min_size: u16) -> Option<u16> {
    let cap = device_max
        .min(u32::from(requested))
        .min(u32::from(MAX_QUEUE_SIZE)) as u16;
    if cap == 0 {
        return None;
    }
    // Largest power of two <= cap.
    let size = 1u16 << (15 - cap.leading_zeros());
    if queue_size_is_valid(size, min_size) {
        Some(size)
    } else {
        None
    }
}

// F1 RX-servicing policy: compiled into the bin via `smoltcp_device`'s own
// `mod rx_policy;`, and included here under `cfg(test)` only so its tests run
// on the host (the bin has no test harness).
#[cfg(test)]
#[path = "smoltcp_device/rx_policy.rs"]
mod rx_policy;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RX_BUFFER_COUNT / TX_BUFFER_COUNT in smoltcp_device.rs (not visible
    /// to this lib crate).
    const RX_MIN: u16 = 8;
    const TX_MIN: u16 = 4;

    /// The pre-fix `VirtioNet::negotiate_queue_size` arithmetic, kept to
    /// show what it accepted.
    fn old_negotiate(max: u32, requested: u16) -> Option<u16> {
        let usable = max.min(u32::from(requested)).min(256);
        if usable == 0 {
            None
        } else {
            Some(usable as u16)
        }
    }

    #[test]
    fn queue_size_validation() {
        assert!(!queue_size_is_valid(0, RX_MIN));
        for s in 1..RX_MIN {
            assert!(!queue_size_is_valid(s, RX_MIN), "{s}");
        }
        assert!(!queue_size_is_valid(3, TX_MIN));
        assert!(!queue_size_is_valid(2, TX_MIN));
        assert!(!queue_size_is_valid(12, RX_MIN)); // not a power of two
        assert!(!queue_size_is_valid(255, RX_MIN));
        assert!(queue_size_is_valid(8, RX_MIN)); // boundary: == posted count
        assert!(queue_size_is_valid(4, TX_MIN));
        assert!(!queue_size_is_valid(4, RX_MIN)); // pow2 but below RX count
        assert!(queue_size_is_valid(128, RX_MIN));
        assert!(queue_size_is_valid(256, RX_MIN));
        assert!(!queue_size_is_valid(512, RX_MIN));
        assert!(!queue_size_is_valid(u16::MAX, RX_MIN));
    }

    #[test]
    fn choose_queue_size_boundaries() {
        assert_eq!(choose_queue_size(0, 256, RX_MIN), None);
        for m in 1..8 {
            assert_eq!(choose_queue_size(m, 256, RX_MIN), None, "max {m}");
        }
        assert_eq!(choose_queue_size(7, 256, TX_MIN), Some(4));
        assert_eq!(choose_queue_size(3, 256, TX_MIN), None);
        assert_eq!(choose_queue_size(8, 256, RX_MIN), Some(8));
        assert_eq!(choose_queue_size(12, 256, RX_MIN), Some(8));
        assert_eq!(choose_queue_size(255, 256, RX_MIN), Some(128));
        assert_eq!(choose_queue_size(256, 256, RX_MIN), Some(256));
        assert_eq!(choose_queue_size(300, 256, RX_MIN), Some(256));
        assert_eq!(choose_queue_size(u32::MAX, 256, RX_MIN), Some(256));
        assert_eq!(choose_queue_size(1024, 16, RX_MIN), Some(16));
        assert_eq!(choose_queue_size(1024, 4, RX_MIN), None);
        assert_eq!(choose_queue_size(1024, 0, RX_MIN), None);
    }

    #[test]
    fn old_negotiate_accepted_sizes_the_fix_rejects() {
        // The old behaviour returned Some(5)/Some(7)/Some(3)/Some(1), all
        // invalid (non-power-of-two or below the posted descriptor count).
        for (max, min) in [(5u32, RX_MIN), (7, RX_MIN), (3, TX_MIN), (1, TX_MIN)] {
            let old = old_negotiate(max, 256).unwrap();
            assert!(!queue_size_is_valid(old, min), "old accepted {old}");
            assert_eq!(choose_queue_size(max, 256, min), None);
        }
        // QueueNumMax 100 was accepted as 100 (not a power of two); now 64.
        assert_eq!(old_negotiate(100, 256), Some(100));
        assert!(!queue_size_is_valid(100, RX_MIN));
        assert_eq!(choose_queue_size(100, 256, RX_MIN), Some(64));
    }

    #[test]
    fn accepts_a_well_formed_completion() {
        assert_eq!(
            validate_rx_completion(0, RX_BUFFER_SIZE, 4),
            Some((0, RX_BUFFER_SIZE))
        );
    }

    #[test]
    fn rejects_oversized_len() {
        assert_eq!(validate_rx_completion(0, RX_BUFFER_SIZE + 1, 4), None);
        assert!(validate_rx_completion(0, RX_BUFFER_SIZE, 4).is_some());
    }

    #[test]
    fn rx_len_boundaries() {
        let hdr = VIRTIO_NET_HDR_LEN as u32;
        assert_eq!(validate_rx_completion(0, 0, 4), None);
        assert_eq!(validate_rx_completion(0, 1, 4), None);
        assert_eq!(validate_rx_completion(0, hdr - 1, 4), None);
        // Exactly the header: a valid zero-length frame (matches x86).
        assert_eq!(validate_rx_completion(0, hdr, 4), Some((0, hdr)));
        assert_eq!(
            validate_rx_completion(3, RX_BUFFER_SIZE, 4),
            Some((3, RX_BUFFER_SIZE))
        );
        assert_eq!(validate_rx_completion(0, RX_BUFFER_SIZE + 1, 4), None);
        assert_eq!(validate_rx_completion(0, u32::MAX, 4), None);
    }

    #[test]
    fn rejects_out_of_range_desc_id() {
        assert_eq!(validate_rx_completion(4, 100, 4), None);
        assert!(validate_rx_completion(3, 100, 4).is_some());
    }

    proptest! {
        #[test]
        fn choose_queue_size_result_is_always_valid(
            max in any::<u32>(),
            requested in any::<u16>(),
            min in 1u16..=64,
        ) {
            let cap = max.min(u32::from(requested)).min(256);
            if let Some(n) = choose_queue_size(max, requested, min) {
                prop_assert!(queue_size_is_valid(n, min));
                prop_assert!(u32::from(n) <= cap);
                // Largest such power of two: doubling would exceed the cap.
                prop_assert!(u32::from(n) * 2 > cap);
            } else {
                let mut s = 1u32;
                while s * 2 <= cap {
                    s *= 2;
                }
                prop_assert!(cap == 0 || s < u32::from(min));
            }
        }

        #[test]
        fn valid_size_keeps_ring_math_in_one_page(
            q in any::<u16>(),
            min in 1u16..=64,
        ) {
            if queue_size_is_valid(q, min) {
                let q = q as usize;
                prop_assert!(q >= min as usize);
                prop_assert!(q * 16 <= 4096);
                prop_assert!(6 + 2 * q <= 4096);
                prop_assert!(6 + 8 * q <= 4096);
            }
        }

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
                prop_assert!(validated_len >= VIRTIO_NET_HDR_LEN as u32);
            }
        }

        #[test]
        fn result_always_in_range_for_all_inputs(
            desc_id in any::<u32>(),
            len in any::<u32>(),
        ) {
            if let Some((index, l)) = validate_rx_completion(desc_id, len, 8) {
                prop_assert!(index < 8);
                prop_assert!(l >= VIRTIO_NET_HDR_LEN as u32 && l <= RX_BUFFER_SIZE);
            }
        }

        #[test]
        fn rejects_every_desc_id_at_or_past_buffer_count(
            buffer_count in 1usize..16,
            len in VIRTIO_NET_HDR_LEN as u32..=RX_BUFFER_SIZE,
        ) {
            let desc_id = buffer_count as u32; // exactly one past the valid range
            prop_assert_eq!(validate_rx_completion(desc_id, len, buffer_count), None);
        }
    }
}
