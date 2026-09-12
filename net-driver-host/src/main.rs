//! Network driver host, Phase 2a+2b: brings up `smoltcp`'s `Interface` on
//! top of the virtqueue transport Phase 1 proved works, verifies it with a
//! real ICMP echo round-trip against QEMU/SLIRP's own gateway (10.0.2.2) —
//! which SLIRP answers out of the box, needing no new QEMU/CI
//! infrastructure — and then, only if the kernel says to (`NetBootInfo::attempt_tcp`),
//! a real TCP client round-trip against a `guestfwd`-bridged host listener.
//! See docs/STATUS.md's network-stack section for why ICMP and TCP are
//! proven as two separate, sequential phases in the same binary rather than
//! one combined attempt: a `Device`/`Interface` bring-up bug is a different
//! failure class than TCP's much larger stateful protocol correctness, and
//! ICMP already exercises the IPv4 header path (checksums, addressing, and
//! — transparently, via smoltcp's own ARP cache resolving the gateway's MAC
//! before it can send anything — the exact ARP round-trip Phase 1 proved
//! by hand) without touching TCP at all. `attempt_tcp` exists specifically
//! so `kernel/tests/net_driver_icmp.rs` (no `guestfwd`, no host listener)
//! can skip the TCP attempt entirely — without it, a TCP connect to an
//! unreachable address would sit in SYN-SENT for the whole poll bound
//! before giving up, adding real wall-clock time to a test that's supposed
//! to stay fast.
//!
//! Phase 1's hand-built ARP-request-and-poll flow (`kernel/tests/net_driver_arp.rs`,
//! now retired) is superseded here, not run alongside it: `smoltcp_device::RunixNetDevice`
//! owns the RX/TX virtqueues exclusively from `_start` onward, and smoltcp's
//! own neighbor-discovery cache performs the equivalent ARP resolution
//! automatically as a prerequisite to routing the ICMP echo — a strictly
//! stronger proof (it now also exercises real IPv4/ICMP checksums) of the
//! same underlying virtqueue mechanism, not a weaker or different one.
//!
//! This process never gets raw port-I/O privilege itself — every register
//! access goes through the capability-gated `SYS_PORT_IN`/`SYS_PORT_OUT`
//! syscalls (`syscall.rs`), scoped by the kernel to exactly this device's
//! BAR0 register range at spawn time (`kernel/src/main.rs`'s
//! `load_and_run_net_driver_host`). The virtqueue rings and packet buffers
//! themselves are plain memory the kernel mapped directly into this
//! process's address space (no syscall needed to read/write them) — but
//! this process has no way to learn its own *physical* memory addresses
//! (by design: `AddressSpace::map_private_page` intentionally doesn't
//! expose that), and virtio's `QueueAddress`/descriptor `addr` fields need
//! real physical addresses. The kernel resolves that gap by computing every
//! physical address itself at map time and handing them over in
//! [`NetBootInfo`], a fixed, pre-agreed memory page — see that struct's
//! doc comment.

#![no_std]
#![no_main]

extern crate alloc;

mod smoltcp_device;
mod syscall;
mod virtio;

use alloc::vec;
use linked_list_allocator::LockedHeap;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{icmp, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};
use smoltcp_device::{RunixNetDevice, RX_BUFFER_COUNT, TX_BUFFER_COUNT};
use syscall::{write_all, write_byte, yield_now};

/// Must match `kernel/src/main.rs`'s own `NET_HEAP_START`/`NET_HEAP_SIZE` —
/// same "the loader sets this up, this binary has no privilege to map its
/// own memory" split `grid-sandbox-host` already documents. Unchanged from
/// Phase 1 — smoltcp's footprint for one interface and one ICMP socket
/// comfortably fits the existing 256 KiB.
pub const HEAP_START: usize = 0x_1111_1111_0000;
pub const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// One fixed page the kernel writes before spawning this process and this
/// process only ever reads — the physical addresses `AddressSpace::map_private_page`
/// deliberately doesn't hand back to a ring 3 process. Must match
/// `kernel/src/main.rs`'s own `NetBootInfo` definition exactly (`repr(C)`,
/// same field order) — the only contract connecting the two independently
/// compiled crates for this struct, the same way the syscall ABI itself
/// (not a shared type) is what connects `syscall.rs` to the kernel.
#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    /// Physical base of a `3 * QUEUE_ALIGN`-byte region: descriptor table,
    /// then avail ring, then used ring (see `virtio::Virtqueue`'s doc
    /// comment). The matching *virtual* address is the fixed constant
    /// [`NET_RXQ_VA`] below — the kernel mapped both to point at the same
    /// memory.
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    /// Physical addresses of individually-mapped, page-sized RX packet
    /// buffers — matching virtual base [`NET_RXBUF_VA`], one page apart.
    /// Grown from Phase 1's 4 to `RX_BUFFER_COUNT` (8) for a more usable
    /// receive window under smoltcp.
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    /// Physical addresses of individually-mapped TX packet buffers —
    /// matching virtual base [`NET_TXBUF_VA`]. Grown from Phase 1's single
    /// buffer (always descriptor 0) to `TX_BUFFER_COUNT` (4): smoltcp needs
    /// more than one in-flight TX buffer at once (e.g. an ARP reply/request
    /// interleaved with the ICMP packet it's routing), unlike Phase 1's one
    /// hand-built frame at a time.
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    /// Whether this run should attempt the Phase 2b TCP proof after the
    /// ICMP one — see the module doc comment for why this can't just
    /// always be attempted. Set by whichever test/boot path builds this
    /// page (`0` in `kernel/src/main.rs`'s real boot sequence and
    /// `kernel/tests/net_driver_icmp.rs`; `1` only in
    /// `kernel/tests/net_driver_tcp.rs`, which alone configures the
    /// `guestfwd` route and host listener this needs).
    attempt_tcp: u8,
}

const NET_INFO_VA: usize = 0x_1111_3333_0000;
const NET_RXQ_VA: usize = 0x_1111_4444_0000;
const NET_TXQ_VA: usize = 0x_1111_5555_0000;
const NET_RXBUF_VA: usize = 0x_1111_6666_0000;
const NET_TXBUF_VA: usize = 0x_1111_7777_0000;

/// SLIRP's own fixed defaults (see `docs/STATUS.md`'s network-stack
/// section) — no DHCP negotiated, matching Phase 1's same hardcoded
/// addresses.
const LOCAL_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const GATEWAY_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);
const ICMP_IDENT: u16 = 0x22b;
const ICMP_PAYLOAD: &[u8] = b"RUNIX-ICMP-PROOF";

/// The `guestfwd` target `kernel/tests/net_driver_tcp.rs` configures QEMU
/// with (see that test's own doc comment) — a guest-visible address in
/// SLIRP's `10.0.2.0/24` subnet that doesn't collide with the gateway
/// (`.2`) or this driver's own static address (`.15`).
const TCP_REMOTE_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 100);
const TCP_REMOTE_PORT: u16 = 9000;
/// Arbitrary ephemeral port, matching smoltcp's own documented example.
const TCP_LOCAL_PORT: u16 = 49152;
const TCP_PING: &[u8] = b"RUNIX-TCP-PROOF-PING";
const TCP_PONG: &[u8] = b"RUNIX-TCP-PROOF-PONG";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let info = unsafe { &*(NET_INFO_VA as *const NetBootInfo) };
    let net = virtio::VirtioNet::probe(info.io_base);
    let mac = net.mac;

    write_all(b"net-driver-host: virtio-net probed, MAC=");
    for (i, byte) in mac.iter().enumerate() {
        write_hex_byte(*byte);
        if i != 5 {
            write_byte(b':');
        }
    }
    write_byte(b'\n');

    let rx_size = net.queue_size(0);
    net.set_queue_address(0, info.rx_queue_phys);
    let tx_size = net.queue_size(1);
    net.set_queue_address(1, info.tx_queue_phys);

    let mut device = unsafe {
        RunixNetDevice::new(
            info.io_base,
            NET_RXQ_VA,
            rx_size,
            NET_TXQ_VA,
            tx_size,
            NET_RXBUF_VA,
            info.rx_buffer_phys,
            NET_TXBUF_VA,
            info.tx_buffer_phys,
        )
    };
    net.mark_ready();
    device.notify_rx();

    let config = Config::new(EthernetAddress(mac).into());
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::Ipv4(LOCAL_IP), 24))
            .unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY_IP)
        .unwrap();

    let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
    let mut sockets = SocketSet::new(vec![]);
    let icmp_handle = sockets.add(icmp_socket);

    let device_checksum_caps = smoltcp::phy::Device::capabilities(&device).checksum;

    let mut sent = false;
    let mut found = false;
    let mut final_iteration = 0u32;
    // Same bound (2,000,000 iterations, yield every 10,000) and reasoning
    // as Phase 1's poll loop: a real reply from QEMU/SLIRP arrives promptly
    // in practice, so this bound exists purely to make a genuinely broken
    // driver report failure instead of hanging the boot forever.
    'poll: for iteration in 0..2_000_000u32 {
        final_iteration = iteration;
        let timestamp = Instant::from_millis(iteration as i64);
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<icmp::Socket>(icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(ICMP_IDENT)).unwrap();
        }

        if socket.can_send() && !sent {
            let repr = Icmpv4Repr::EchoRequest {
                ident: ICMP_IDENT,
                seq_no: 0,
                data: ICMP_PAYLOAD,
            };
            let payload = socket
                .send(repr.buffer_len(), IpAddress::Ipv4(GATEWAY_IP))
                .unwrap();
            let mut packet = Icmpv4Packet::new_unchecked(payload);
            repr.emit(&mut packet, &device_checksum_caps);
            sent = true;
        }

        if socket.can_recv() {
            let (payload, _) = socket.recv().unwrap();
            if let Ok(packet) = Icmpv4Packet::new_checked(payload) {
                if let Ok(Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }) = Icmpv4Repr::parse(&packet, &device_checksum_caps)
                {
                    // Exact bytes checked, not just "got a reply" -- the
                    // same discipline Phase 1's `is_arp_reply` already
                    // applied to opcodes.
                    if ident == ICMP_IDENT && seq_no == 0 && data == ICMP_PAYLOAD {
                        found = true;
                        break 'poll;
                    }
                }
            }
        }

        if iteration % 10_000 == 0 {
            yield_now();
        }
    }

    if found {
        write_all(b"net-driver-host: ICMP echo reply received (Phase 2a OK)\n");
    } else {
        write_all(b"net-driver-host: no ICMP echo reply within poll bound (Phase 2a FAILED)\n");
    }

    // Beyond the human-readable serial output above, `kernel/tests/net_driver_icmp.rs`
    // needs a way to tell PASS from FAIL that doesn't depend on grepping
    // text -- reaching this point without a fault only proves nothing
    // *crashed*, not that the ICMP round-trip actually succeeded. Same
    // convention Phase 1 established: write a real result code into the
    // shared `NetBootInfo` page at a fixed offset well past that struct's
    // own fields.
    unsafe {
        core::ptr::write_volatile(
            (NET_INFO_VA + NET_RESULT_OFFSET) as *mut u8,
            if found {
                NET_RESULT_PASS
            } else {
                NET_RESULT_FAIL
            },
        );
    }

    if info.attempt_tcp != 0 {
        // `+ 1`, not `0`: smoltcp's `Interface` remembers the last
        // `Instant` it was polled with internally (retransmit/backoff
        // timers are computed relative to it) -- restarting the TCP
        // phase's own timestamp counter from 0 would hand it a timestamp
        // *earlier* than what it already saw during the ICMP phase above,
        // silently stalling every timer-driven part of the TCP state
        // machine (confirmed for real: with a reset-to-0 counter, packet
        // capture showed the guest never even sent an ARP request for the
        // TCP remote, let alone a SYN). One shared, always-increasing
        // counter across both phases avoids this.
        run_tcp_proof(&mut iface, &mut device, final_iteration + 1);
    }

    loop {
        yield_now();
    }
}

/// Phase 2b: connect out to `TCP_REMOTE_IP:TCP_REMOTE_PORT` (a `guestfwd`
/// route `kernel/tests/net_driver_tcp.rs` configures QEMU with, bridging
/// to a real host-run listener via `nc` — see that test's own doc
/// comment), send a fixed payload, and check the exact reply — the same
/// "real round-trip, exact bytes checked" discipline every prior phase in
/// this codebase already applies. Runs strictly after the ICMP proof
/// above, on the same `iface`/`device` (a fresh `SocketSet` per phase,
/// matching the existing per-phase-loop style this file already uses).
fn run_tcp_proof(iface: &mut Interface, device: &mut RunixNetDevice, start_iteration: u32) {
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let mut tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    // Nagle + delayed ACK can add ~200ms of first-byte latency for a
    // connection this short-lived -- disabling it avoids that being
    // mistaken for a hang while this poll loop's bound is being tuned.
    tcp_socket.set_nagle_enabled(false);

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp_socket);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(TCP_REMOTE_IP), TCP_REMOTE_PORT),
            TCP_LOCAL_PORT,
        )
        .unwrap();

    let mut sent = false;
    let mut received = [0u8; 32];
    let mut received_len = 0usize;
    let mut pass = false;
    let mut done = false;

    // Same bound and reasoning as the ICMP loop above. `start_iteration +
    // offset`, not a fresh `0..`, keeps `iface`'s internal timestamp
    // strictly increasing across both phases -- see the caller's comment.
    for offset in 0..2_000_000u32 {
        let timestamp = Instant::from_millis((start_iteration + offset) as i64);
        iface.poll(timestamp, device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        if socket.can_send() && !sent && socket.send_slice(TCP_PING).is_ok() {
            sent = true;
        }

        if socket.can_recv() && received_len < TCP_PONG.len() {
            if let Ok(n) = socket.recv_slice(&mut received[received_len..TCP_PONG.len()]) {
                received_len += n;
            }
        }

        if received_len >= TCP_PONG.len() {
            // Exact bytes checked, not just "received something" -- the
            // same discipline `is_arp_reply`/the ICMP check above already
            // apply.
            pass = received[..TCP_PONG.len()] == *TCP_PONG;
            done = true;
        }
        // The host listener closes its end right after replying -- once
        // that's visible here, there's nothing left to wait for either way.
        if sent && !socket.is_open() {
            done = true;
        }
        if done {
            break;
        }

        if offset % 10_000 == 0 {
            yield_now();
        }
    }

    if pass {
        write_all(b"net-driver-host: TCP echo reply received (Phase 2b OK)\n");
    } else {
        write_all(
            b"net-driver-host: TCP echo reply missing/wrong within poll bound (Phase 2b FAILED)\n",
        );
    }

    unsafe {
        core::ptr::write_volatile(
            (NET_INFO_VA + NET_TCP_RESULT_OFFSET) as *mut u8,
            if pass {
                NET_RESULT_PASS
            } else {
                NET_RESULT_FAIL
            },
        );
    }
}

/// Offset into the `NetBootInfo` page reserved for this process's own
/// PASS/FAIL result byte — past `NetBootInfo`'s own fields with room to
/// spare, so a future field added to that struct can't collide with it.
/// Must match whatever reads this byte back (`kernel/tests/net_driver_icmp.rs`).
/// Unchanged from Phase 1 (same offset, same convention).
pub const NET_RESULT_OFFSET: usize = 128;
/// Phase 2b's own result byte, one past the ICMP one above -- read only by
/// `kernel/tests/net_driver_tcp.rs`; `net_driver_icmp.rs` never looks at
/// this offset, so it needs no changes for this to coexist.
pub const NET_TCP_RESULT_OFFSET: usize = 129;
pub const NET_RESULT_PASS: u8 = 1;
pub const NET_RESULT_FAIL: u8 = 2;

fn write_hex_byte(byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    write_byte(HEX[(byte >> 4) as usize]);
    write_byte(HEX[(byte & 0xF) as usize]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No `hlt` here — that's a privileged instruction; executing it from
    // ring 3 would general-protection-fault instead of halting anything.
    write_byte(b'?');
    loop {
        core::hint::spin_loop();
    }
}
