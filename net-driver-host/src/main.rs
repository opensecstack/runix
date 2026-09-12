//! Network driver host, Phase 1: proves the legacy virtio-net virtqueue
//! mechanism works at all — transmit one hand-built ARP request, poll for
//! QEMU/SLIRP's reply — before any TCP/IP stack (smoltcp, Phase 2) gets
//! built on top of it. See docs/STATUS.md's network-stack section for why
//! this is split into two phases: the virtqueue/physical-addressing
//! mechanics here have zero prior art in this codebase and are a different
//! class of bug than TCP/IP protocol correctness, best diagnosed
//! separately.
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

mod syscall;
mod virtio;

use linked_list_allocator::LockedHeap;
use syscall::{write_all, write_byte, yield_now};
use virtio::Virtqueue;

/// Must match `kernel/src/main.rs`'s own `NET_HEAP_START`/`NET_HEAP_SIZE` —
/// same "the loader sets this up, this binary has no privilege to map its
/// own memory" split `grid-sandbox-host` already documents.
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
    /// Physical addresses of 4 individually-mapped, page-sized RX packet
    /// buffers — matching virtual base [`NET_RXBUF_VA`], one page apart.
    rx_buffer_phys: [u64; 4],
    /// Physical address of the one TX packet buffer — matching virtual
    /// address [`NET_TXBUF_VA`].
    tx_buffer_phys: u64,
}

const NET_INFO_VA: usize = 0x_1111_3333_0000;
const NET_RXQ_VA: usize = 0x_1111_4444_0000;
const NET_TXQ_VA: usize = 0x_1111_5555_0000;
const NET_RXBUF_VA: usize = 0x_1111_6666_0000;
const NET_TXBUF_VA: usize = 0x_1111_7777_0000;

const RX_QUEUE_INDEX: u16 = 0;
const TX_QUEUE_INDEX: u16 = 1;
const RX_BUFFER_COUNT: usize = 4;
/// `virtio_net_hdr` with no optional features negotiated (see
/// `VirtioNet::probe`'s doc comment: zero `GuestFeatures`) — no
/// `num_buffers` field, since that only exists when `VIRTIO_NET_F_MRG_RXBUF`
/// is negotiated. Every field is zero for a packet needing no
/// offload/segmentation help, which every packet here is.
const VIRTIO_NET_HDR_LEN: usize = 10;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let info = unsafe { &*(NET_INFO_VA as *const NetBootInfo) };
    let net = virtio::VirtioNet::probe(info.io_base);

    let rx_size = net.queue_size(RX_QUEUE_INDEX);
    net.set_queue_address(RX_QUEUE_INDEX, info.rx_queue_phys);
    let tx_size = net.queue_size(TX_QUEUE_INDEX);
    net.set_queue_address(TX_QUEUE_INDEX, info.tx_queue_phys);

    let mut rx_queue = unsafe { Virtqueue::new(NET_RXQ_VA, rx_size) };
    let mut tx_queue = unsafe { Virtqueue::new(NET_TXQ_VA, tx_size) };
    rx_queue.init_avail_flags();
    tx_queue.init_avail_flags();

    // Pre-fill every RX descriptor before DRIVER_OK — the device must never
    // see itself as "ready" with nowhere to write an incoming frame.
    for i in 0..RX_BUFFER_COUNT {
        unsafe {
            rx_queue.post(i as u16, info.rx_buffer_phys[i], 4096, true);
        }
    }
    net.mark_ready();
    net.notify(RX_QUEUE_INDEX);

    write_all(b"net-driver-host: virtio-net probed, MAC=");
    for (i, byte) in net.mac.iter().enumerate() {
        write_hex_byte(*byte);
        if i != 5 {
            write_byte(b':');
        }
    }
    write_byte(b'\n');

    send_arp_request(&net, &mut tx_queue, info.tx_buffer_phys, net.mac);

    // Bounded poll: a real reply from QEMU/SLIRP arrives promptly (well
    // under a second in practice) — this bound exists so a genuinely broken
    // driver reports failure instead of hanging the boot forever.
    let mut found = false;
    'poll: for iteration in 0..2_000_000u32 {
        if let Some((desc_id, len)) = rx_queue.poll_used() {
            let buf = unsafe {
                core::slice::from_raw_parts(
                    (NET_RXBUF_VA + desc_id as usize * 4096) as *const u8,
                    len as usize,
                )
            };
            if is_arp_reply(buf) {
                found = true;
                break 'poll;
            }
            // Not what we were looking for (could be unrelated broadcast
            // traffic SLIRP itself generates) — repost the same buffer and
            // keep waiting.
            unsafe {
                rx_queue.post(
                    desc_id as u16,
                    info.rx_buffer_phys[desc_id as usize],
                    4096,
                    true,
                );
            }
            net.notify(RX_QUEUE_INDEX);
        }
        if iteration % 10_000 == 0 {
            yield_now();
        }
    }

    if found {
        write_all(b"net-driver-host: ARP reply received (Phase 1 OK)\n");
    } else {
        write_all(b"net-driver-host: no ARP reply within poll bound (Phase 1 FAILED)\n");
    }

    // Beyond the human-readable serial output above, `kernel/tests/net_driver_arp.rs`
    // needs a way to tell PASS from FAIL that doesn't depend on grepping
    // text -- reaching this point without a fault only proves nothing
    // *crashed*, not that the ARP round-trip actually succeeded (a silent
    // "no reply, poll bound exceeded" would print FAILED but never fault).
    // Write a real result code into the shared `NetBootInfo` page at a
    // fixed offset well past that struct's own fields, matching the same
    // repr(C)-by-convention contract already connecting these two
    // independently compiled crates for `NetBootInfo` itself. The kernel
    // (or a test) can read this page's content directly since it stayed
    // mapped in this process's `AddressSpace` throughout.
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

    loop {
        yield_now();
    }
}

/// Offset into the `NetBootInfo` page reserved for this process's own
/// PASS/FAIL result byte — past `NetBootInfo`'s own ~60 bytes with room to
/// spare, so a future field added to that struct can't collide with it.
/// Must match whatever reads this byte back (`kernel/tests/net_driver_arp.rs`).
pub const NET_RESULT_OFFSET: usize = 128;
pub const NET_RESULT_PASS: u8 = 1;
pub const NET_RESULT_FAIL: u8 = 2;

fn write_hex_byte(byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    write_byte(HEX[(byte >> 4) as usize]);
    write_byte(HEX[(byte & 0xF) as usize]);
}

/// Builds a gratuitous-ish ARP request ("who has 10.0.2.2? tell 10.0.2.15")
/// straight into the TX buffer and hands it to the device. `10.0.2.2` is
/// QEMU SLIRP's built-in gateway address, and `10.0.2.15` its default first
/// guest lease — both fixed by SLIRP's own defaults (no DHCP negotiated
/// here, see the module doc comment), so SLIRP is expected to answer this
/// exact query regardless of what IP this driver actually ends up with in a
/// later phase.
fn send_arp_request(
    net: &virtio::VirtioNet,
    tx_queue: &mut Virtqueue,
    tx_buf_phys: u64,
    mac: [u8; 6],
) {
    let buf = unsafe { core::slice::from_raw_parts_mut(NET_TXBUF_VA as *mut u8, 4096) };
    buf[..VIRTIO_NET_HDR_LEN].fill(0);

    let eth = &mut buf[VIRTIO_NET_HDR_LEN..];
    eth[0..6].fill(0xFF); // broadcast destination
    eth[6..12].copy_from_slice(&mac);
    eth[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // Ethertype: ARP

    let arp = &mut eth[14..14 + 28];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    arp[4] = 6; // hlen
    arp[5] = 4; // plen
    arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // oper: request
    arp[8..14].copy_from_slice(&mac); // sha
    arp[14..18].copy_from_slice(&[10, 0, 2, 15]); // spa
    arp[18..24].fill(0); // tha: unknown
    arp[24..28].copy_from_slice(&[10, 0, 2, 2]); // tpa: SLIRP's gateway

    let frame_len = VIRTIO_NET_HDR_LEN + 14 + 28;
    unsafe {
        tx_queue.post(0, tx_buf_phys, frame_len as u32, false);
    }
    net.notify(TX_QUEUE_INDEX);
}

/// `buf` is a full RX buffer (`virtio_net_hdr` prefix + Ethernet frame).
/// Checks Ethertype == ARP and ARP opcode == reply — the specific,
/// falsifiable proof this phase exists to produce, not "some bytes arrived".
fn is_arp_reply(buf: &[u8]) -> bool {
    if buf.len() < VIRTIO_NET_HDR_LEN + 14 + 28 {
        return false;
    }
    let eth = &buf[VIRTIO_NET_HDR_LEN..];
    let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
    if ethertype != 0x0806 {
        return false;
    }
    let arp = &eth[14..14 + 28];
    let oper = u16::from_be_bytes([arp[6], arp[7]]);
    oper == 2
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
