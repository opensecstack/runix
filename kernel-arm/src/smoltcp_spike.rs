//! SPIKE, not real functionality -- see `docs/BETA_MOBILE_PROGRESS.md`
//! Item 2 / section 2.3. The real Stage 2 networking work needs `smoltcp`
//! working in this crate, and this repo has a documented history of bare
//! metal target dependencies hitting real codegen crashes (see
//! `docs/STATUS.md`'s `curve25519-dalek` / `kernel/`'s x86_64 account).
//! `aarch64-unknown-none` + stable is a different target/toolchain than
//! where that bug was found, so this forces real codegen of a minimal
//! `smoltcp` feature set (`medium-ethernet, proto-ipv4, socket-icmp,
//! alloc`) to check it before committing to the design.
//!
//! Never called from `main.rs`'s boot sequence -- it doesn't need to run
//! correctly, only to compile, since a codegen crash (if one exists) would
//! surface at compile time, not at runtime.

use alloc::vec;

#[allow(dead_code)]
fn smoltcp_spike() {
    let mac = smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let _config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(mac));

    let rx_buffer = smoltcp::socket::icmp::PacketBuffer::new(
        vec![smoltcp::socket::icmp::PacketMetadata::EMPTY],
        vec![0u8; 256],
    );
    let tx_buffer = smoltcp::socket::icmp::PacketBuffer::new(
        vec![smoltcp::socket::icmp::PacketMetadata::EMPTY],
        vec![0u8; 256],
    );
    let _socket = smoltcp::socket::icmp::Socket::new(rx_buffer, tx_buffer);
}
