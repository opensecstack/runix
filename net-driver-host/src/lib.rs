//! Pure, hardware-independent parsing/validation logic for `net-driver-host`
//! — split out of `main.rs` specifically so it can be property-tested on
//! the host (`cargo test`, no `--target`), the same
//! `#![cfg_attr(not(test), no_std)]` split `capability-manager` already
//! uses for the same reason: `main.rs`'s `#![no_std] #![no_main]` binary
//! has no test harness at all (no `test`/panic-unwind runtime on
//! `x86_64-unknown-none`), so anything worth testing has to live somewhere
//! that can also compile as an ordinary host library.
//!
//! Everything here is part of docs/THREAT_MODEL.md's "testing rigor"
//! commitment: the bytes `is_arp_reply` inspects, and the `(desc_id, len)`
//! pair `validate_rx_completion` checks, both originate from the emulated
//! virtio-net *device* — treated as untrusted input in this driver's threat
//! model the same way a real NIC's DMA completions would be, not
//! implicitly trusted just because this is a "hardware" interface rather
//! than a network one.

#![cfg_attr(not(test), no_std)]

/// `virtio_net_hdr` length with no optional features negotiated (see
/// `virtio::VirtioNet::probe`'s doc comment: zero `GuestFeatures`) — no
/// `num_buffers` field, since that only exists when `VIRTIO_NET_F_MRG_RXBUF`
/// is negotiated.
pub const VIRTIO_NET_HDR_LEN: usize = 10;
pub const ETH_HEADER_LEN: usize = 14;
pub const ARP_PAYLOAD_LEN: usize = 28;

/// Every RX packet buffer `kernel/src/main.rs` maps is exactly one page —
/// see `load_and_run_net_driver_host`'s doc comment on why (each buffer
/// needs to be one contiguous physical page, so one page per buffer keeps
/// that trivially true without needing a physically-contiguous multi-page
/// allocation for buffers, unlike the virtqueue rings themselves).
pub const RX_BUFFER_SIZE: u32 = 4096;

/// Validates a completed RX descriptor's `(desc_id, len)` — both fields
/// come from the device's used-ring entry, so both are untrusted input
/// (see this module's doc comment). Constructing a slice directly from an
/// unchecked `len` (which could exceed the actual buffer size) or using an
/// unchecked `desc_id` as a buffer index (which could be outside the range
/// of buffers this driver actually posted) would be a real out-of-bounds
/// read — confirmed as a real bug, not a theoretical one: an earlier
/// version of `main.rs`'s poll loop did exactly this before this function
/// existed to gate it. Returns the validated `(buffer_index, len)` pair, or
/// `None` if either field is out of range — the caller's job is to drop
/// the completion rather than trust it, not to guess a safe fallback.
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

/// `buf` is a full RX buffer (`virtio_net_hdr` prefix + Ethernet frame) —
/// already validated by [`validate_rx_completion`] to be no longer than
/// [`RX_BUFFER_SIZE`], but this function makes no assumption about that;
/// it only trusts its own length check below. Checks Ethertype == ARP and
/// ARP opcode == reply — the specific, falsifiable proof Phase 1 exists to
/// produce, not "some bytes arrived".
pub fn is_arp_reply(buf: &[u8]) -> bool {
    if buf.len() < VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + ARP_PAYLOAD_LEN {
        return false;
    }
    let eth = &buf[VIRTIO_NET_HDR_LEN..];
    let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
    if ethertype != 0x0806 {
        return false;
    }
    let arp = &eth[ETH_HEADER_LEN..ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
    let oper = u16::from_be_bytes([arp[6], arp[7]]);
    oper == 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_buffer_is_not_an_arp_reply() {
        assert!(!is_arp_reply(&[]));
    }

    #[test]
    fn a_well_formed_arp_reply_is_recognized() {
        let mut buf = [0u8; VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
        let eth = &mut buf[VIRTIO_NET_HDR_LEN..];
        eth[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let arp = &mut eth[ETH_HEADER_LEN..ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
        arp[6..8].copy_from_slice(&2u16.to_be_bytes()); // oper: reply
        assert!(is_arp_reply(&buf));
    }

    #[test]
    fn wrong_ethertype_is_rejected() {
        let mut buf = [0u8; VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
        let eth = &mut buf[VIRTIO_NET_HDR_LEN..];
        eth[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not ARP
        assert!(!is_arp_reply(&buf));
    }

    #[test]
    fn arp_request_not_reply_is_rejected() {
        let mut buf = [0u8; VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
        let eth = &mut buf[VIRTIO_NET_HDR_LEN..];
        eth[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let arp = &mut eth[ETH_HEADER_LEN..ETH_HEADER_LEN + ARP_PAYLOAD_LEN];
        arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // oper: request, not reply
        assert!(!is_arp_reply(&buf));
    }

    #[test]
    fn validate_rx_completion_rejects_oversized_len() {
        assert_eq!(validate_rx_completion(0, RX_BUFFER_SIZE + 1, 4), None);
        assert!(validate_rx_completion(0, RX_BUFFER_SIZE, 4).is_some());
    }

    #[test]
    fn validate_rx_completion_rejects_out_of_range_desc_id() {
        assert_eq!(validate_rx_completion(4, 100, 4), None);
        assert!(validate_rx_completion(3, 100, 4).is_some());
    }

    proptest! {
        // The actual regression class this whole module exists to catch:
        // no byte pattern or length, however malformed, may make either
        // function panic (an index-out-of-bounds or slice-range panic here
        // would be reachable directly from device-controlled input, i.e. a
        // remotely triggerable panic in a `panic = "abort"` process).
        #[test]
        fn is_arp_reply_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = is_arp_reply(&buf);
        }

        #[test]
        fn validate_rx_completion_never_panics_and_never_returns_out_of_range(
            desc_id in any::<u32>(),
            len in any::<u32>(),
            buffer_count in 1usize..16,
        ) {
            if let Some((index, validated_len)) = validate_rx_completion(desc_id, len, buffer_count) {
                prop_assert!(index < buffer_count);
                prop_assert!(validated_len <= RX_BUFFER_SIZE);
            }
        }

        // The buffer-index a caller would actually use to build a slice
        // (`NET_RXBUF_VA + index * 4096`) must never come from an
        // unvalidated `desc_id` — this pins the exact property the real
        // bug violated: `desc_id` alone was trusted as an index with no
        // range check at all.
        #[test]
        fn validate_rx_completion_rejects_every_desc_id_at_or_past_buffer_count(
            buffer_count in 1usize..16,
            len in 0u32..=RX_BUFFER_SIZE,
        ) {
            let desc_id = buffer_count as u32; // exactly one past the valid range
            prop_assert_eq!(validate_rx_completion(desc_id, len, buffer_count), None);
        }
    }
}
