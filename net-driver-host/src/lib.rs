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
#[cfg(test)]
extern crate alloc;

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

/// Property-tests the actual boundary this driver owns: does feeding
/// arbitrary/malformed bytes into the exact path `net-driver-host` uses to
/// hand smoltcp a received frame ever panic. Deliberately NOT a test of
/// smoltcp's own parser internals (a third-party, independently-maintained
/// crate — forking/fuzzing it directly is out of scope). See
/// docs/THREAT_MODEL.md's testing-rigor section: Phase 2's real
/// Ethernet/IP/TCP header parsing is done by smoltcp, not by any in-house
/// parser this codebase wrote, so there's no in-house parser to point a
/// property test at directly the way `is_arp_reply`/`validate_rx_completion`
/// could be — this is the closest equivalent, one layer up the stack, at
/// the integration boundary `net-driver-host` actually owns.
#[cfg(test)]
mod smoltcp_fuzz {
    use alloc::vec::Vec;
    use proptest::prelude::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::{icmp, tcp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

    /// Mirrors `net-driver-host/src/main.rs`'s real bring-up exactly (same
    /// static IP/gateway, same one-ICMP-one-TCP socket set) so this test
    /// exercises the same parsing/state-machine surface the real driver
    /// actually reaches, not a stripped-down stand-in that happens to avoid
    /// the interesting code paths.
    const LOCAL_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
    const GATEWAY_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);
    const FUZZ_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// A `smoltcp::phy::Device` standing in for `RunixNetDevice`, with no
    /// real hardware underneath: holds at most one queued "arbitrary bytes
    /// just arrived on the wire" frame, handed out (and cleared) exactly
    /// once by `receive()` — the same one-shot-per-poll shape the real
    /// device has when nothing new has arrived. `transmit()` always
    /// succeeds and its content is discarded: this test only cares about
    /// the RX-parsing panic surface, not what smoltcp chooses to send back.
    struct FuzzDevice {
        next_rx: Option<Vec<u8>>,
    }

    struct FuzzRxToken(Vec<u8>);
    struct FuzzTxToken;

    impl RxToken for FuzzRxToken {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.0)
        }
    }

    impl TxToken for FuzzTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buf = alloc::vec![0u8; len];
            f(&mut buf)
        }
    }

    impl Device for FuzzDevice {
        type RxToken<'a> = FuzzRxToken;
        type TxToken<'a> = FuzzTxToken;

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.next_rx.take()?;
            Some((FuzzRxToken(frame), FuzzTxToken))
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            Some(FuzzTxToken)
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.medium = Medium::Ethernet;
            caps
        }
    }

    /// Builds an `Interface` + `SocketSet` matching `main.rs`'s real
    /// construction (one ICMP socket, one TCP socket) so this test reaches
    /// the same code paths the real driver does.
    fn build_iface_and_sockets(device: &mut FuzzDevice) -> (Interface, SocketSet<'static>) {
        let config = Config::new(EthernetAddress(FUZZ_MAC).into());
        let mut iface = Interface::new(config, device, Instant::from_millis(0));
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::Ipv4(LOCAL_IP), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY_IP)
            .unwrap();

        let icmp_rx_buffer = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY],
            alloc::vec![0; 256],
        );
        let icmp_tx_buffer = icmp::PacketBuffer::new(
            alloc::vec![icmp::PacketMetadata::EMPTY],
            alloc::vec![0; 256],
        );
        let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);

        let tcp_rx_buffer = tcp::SocketBuffer::new(alloc::vec![0; 256]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(alloc::vec![0; 256]);
        let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

        let mut sockets = SocketSet::new(Vec::new());
        let _ = sockets.add(icmp_socket);
        let _ = sockets.add(tcp_socket);

        (iface, sockets)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The regression class this test exists to catch: no sequence of
        /// arbitrary, possibly-malformed frames — however short, however
        /// garbled — may make `Interface::poll` panic. `frames` models
        /// several separate "packets arrived" events (1..8 of them, each
        /// 0..1500 bytes — covering everything from empty/too-short-to-be-
        /// a-header garbage up to a full-size plausible frame), each polled
        /// several times so a multi-frame sequence can build partial
        /// connection state (e.g. a half-open TCP handshake) rather than
        /// only ever exercising a single cold poll.
        #[test]
        fn smoltcp_never_panics_on_arbitrary_frames(
            frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..1500), 1..8),
        ) {
            let mut device = FuzzDevice { next_rx: None };
            let (mut iface, mut sockets) = build_iface_and_sockets(&mut device);

            let mut ms: i64 = 0;
            for frame in frames {
                device.next_rx = Some(frame);
                // A few polls per frame: the first one consumes the queued
                // RX frame, later ones (with `next_rx` now empty) still
                // exercise any timer-driven state the first poll started
                // (retransmits, TCP timeouts) — the same reason the real
                // driver's own poll loops in main.rs poll repeatedly rather
                // than once.
                for _ in 0..4 {
                    ms += 1;
                    iface.poll(Instant::from_millis(ms), &mut device, &mut sockets);
                }
            }
        }
    }
}
