#![no_main]

// Harness duplicated from net-driver-host/src/lib.rs's `#[cfg(test)] mod
// smoltcp_fuzz` (FuzzDevice / build_iface_and_sockets), which is proptest-
// driven and `#[cfg(test)]`-private — not exposed from the library on
// purpose, since it exists only to give the property test something to
// drive. Duplicated here rather than changing lib.rs's visibility: this is
// the smallest way to get libFuzzer/corpus-driven coverage of the same
// boundary (raw bytes -> smoltcp::iface::Interface::poll) without turning a
// test-only harness into part of the crate's public surface.
//
// See net-driver-host/src/lib.rs's `smoltcp_fuzz` module doc comment for
// why this boundary (not smoltcp's own parser internals) is the one
// net-driver-host actually owns and is responsible for fuzzing.

use libfuzzer_sys::fuzz_target;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{icmp, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

const LOCAL_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const GATEWAY_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);
const FUZZ_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

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
        let mut buf = vec![0u8; len];
        f(&mut buf)
    }
}

impl Device for FuzzDevice {
    type RxToken<'a> = FuzzRxToken;
    type TxToken<'a> = FuzzTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
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

    let icmp_rx_buffer =
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer =
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut sockets = SocketSet::new(Vec::new());
    let _ = sockets.add(icmp_socket);
    let _ = sockets.add(tcp_socket);

    (iface, sockets)
}

// libFuzzer hands us one raw byte slice per iteration, not a sequence of
// frames the way the proptest version generates — split on a 0xff byte
// (vanishingly unlikely to matter for header parsing either way) to still
// get multi-frame sequences, since the real regression class here is
// panics from *state* built across several polls (e.g. a half-open TCP
// handshake), not just a single cold poll of one frame.
fuzz_target!(|data: &[u8]| {
    let frames: Vec<Vec<u8>> = data
        .split(|&b| b == 0xff)
        .take(8)
        .map(|chunk| chunk.to_vec())
        .collect();
    if frames.is_empty() {
        return;
    }

    let mut device = FuzzDevice { next_rx: None };
    let (mut iface, mut sockets) = build_iface_and_sockets(&mut device);

    let mut ms: i64 = 0;
    for frame in frames {
        device.next_rx = Some(frame);
        for _ in 0..4 {
            ms += 1;
            iface.poll(Instant::from_millis(ms), &mut device, &mut sockets);
        }
    }
});
