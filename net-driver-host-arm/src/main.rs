//! Network driver host, ARM: Beta mobile item 2.5 "Stage 3: real outbound
//! TCP at EL0" — the AArch64 analogue of `net-driver-host`'s x86_64 binary,
//! brought up against `kernel-arm`'s virtio-mmio network device instead of
//! legacy virtio-pci, and scoped to exactly one proof: bring up
//! `smoltcp`'s `Interface` over a real virtqueue transport, with a static
//! SLIRP address, and complete a real TCP round trip against
//! `kernel/tests/support/tcp_proof_listener.py` through the same
//! `guestfwd` bridge `net-driver-host`'s own `run_tcp_proof` already
//! proves against on x86_64. No ICMP phase (unlike `net-driver-host`'s
//! Phase 2a/2b split) and no DHCP/DNS/sockets-IPC surface — those are
//! `net-driver-host`'s *later* phases, out of scope for this slice (see
//! that crate's own module doc comment for why ICMP and TCP are sequenced
//! separately there; there is no equivalent sequencing need here with only
//! one phase to run).
//!
//! # Scope: this binary alone, not a loaded/running process
//!
//! This crate is new, standalone, and builds and lints clean for
//! `aarch64-unknown-none` on its own — but **nothing in this codebase
//! loads it yet**. `kernel-arm` already has every prerequisite this binary
//! needs *from the kernel side* (a per-process address space, an ELF
//! loader, a scheduler that can `eret` into a loaded image — see
//! `kernel-arm/src/process.rs`/`loader.rs`/`scheduler.rs`/`el0_proof.rs`),
//! but nothing yet (a) discovers the virtio-net device and computes the
//! physical addresses [`NetBootInfo`] below needs, (b) maps this binary's
//! segments plus a [`NetBootInfo`] page into a fresh `AddressSpace`, or (c)
//! schedules a thread to `eret` into it. That three-part job is
//! `net-driver-host-arm`'s own loader-integration follow-up slice, deliberately
//! not done here — see this module's `TODO(loader integration)` comments
//! (one on [`NetBootInfo`] itself, one at [`run_tcp_proof`]'s end) for
//! the exact contract the next slice needs to satisfy.
//!
//! # Why a `NetBootInfo` page at all
//!
//! Identical reasoning to `net-driver-host/src/main.rs`'s own `NetBootInfo`
//! doc comment, restated for the ARM side: this process never gets raw
//! MMIO-mapping privilege of its own (by the same `AddressSpace`-level
//! design `process.rs` already applies to physical addresses in general —
//! see `virtio_net.rs`'s module doc for where that gap actually bites),
//! and it has no way to learn the physical addresses virtio's
//! `QueueDesc`/`QueueDriver`/`QueueDevice` registers need. Whatever loader
//! eventually maps this process's address space is expected to compute
//! those physical addresses itself (the same way
//! `kernel/src/main.rs::load_and_run_net_driver_host` does for
//! `net-driver-host` on x86_64) and hand them over in this fixed page.

#![no_std]
#![no_main]

extern crate alloc;

mod smoltcp_device;
mod syscall;
mod virtio_mmio;
mod virtio_net;

use alloc::vec;
use linked_list_allocator::LockedHeap;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use smoltcp_device::RunixNetDevice;
use syscall::{write_all, write_byte, write_decimal, write_hex_byte};

/// A private heap for this process — same role and same allocator crate as
/// `net-driver-host`'s own `HEAP_START`/`HEAP_SIZE` and `kernel-arm`'s own
/// EL1 `heap.rs`. **Provisional**: this VA is chosen to sit well inside
/// `kernel-arm::vm::PRIVATE_REGION_BASE..PRIVATE_REGION_END`
/// (`0x8000_0000..0xC000_0000` as of this writing) and clear of where this
/// binary's own loaded ELF segments and the other fixed VAs below could
/// plausibly land, but no loader exists yet to enforce that any of these
/// addresses are actually mapped — see this module's doc comment's
/// "Scope" section. Whichever agent writes the loader integration must
/// either map exactly these VAs or update them here to match whatever
/// layout it actually uses; this file is the single source of truth for
/// that layout until then.
pub const HEAP_START: usize = 0x_8800_0000;
pub const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// One fixed page the (future) loader writes before scheduling this
/// process and this process only ever reads — the AArch64/MMIO-v2
/// counterpart of `net-driver-host/src/main.rs`'s own `NetBootInfo`. See
/// this module's doc comment for why this process cannot compute any of
/// these values itself.
///
/// `#[repr(C)]`, matching `net-driver-host`'s convention for the same
/// kernel/user-space boundary struct — the wire format binding whichever
/// future kernel-side code builds this page to this binary's own
/// definition of it. There is no shared `ipc` crate type for this today
/// (`net-driver-host`'s own `NetBootInfo` is likewise a private,
/// one-sided contract, not an `ipc::` type) — a boot-time, one-shot,
/// one-direction handoff page is a different shape than the bidirectional
/// typed-message traffic `ipc::sockets` exists for, and duplicating that
/// precedent here rather than inventing a third shape is the point.
///
/// TODO(loader integration): the agent that writes
/// `kernel-arm`'s net-driver-host-arm loader integration must:
///   1. Discover the virtio-net device (`virtio_mmio`-style scan, like
///      `kernel-arm::virtio_mmio::probe`, but over EL1's own identity-
///      mapped window) and compute its MMIO register window's *physical*
///      base.
///   2. Build a fresh `process::AddressSpace`, map that physical window
///      into it (the "MMIO-window capability type" referenced in this
///      repo's recent `kernel-arm` history) at the VA [`NET_INFO_VA`] +
///      friends below expect, and map a `NetBootInfo`-sized page at
///      [`NET_INFO_VA`] itself with this struct's fields filled in.
///   3. Map `3 * virtio_net::QUEUE_ALIGN`-byte regions at [`NET_RXQ_VA`]/
///      [`NET_TXQ_VA`] and `RX_BUFFER_COUNT`/`TX_BUFFER_COUNT` individual
///      pages at [`NET_RXBUF_VA`]/[`NET_TXBUF_VA`], recording each one's
///      *physical* address into the corresponding `NetBootInfo` field —
///      exactly the job `kernel/src/main.rs::load_and_run_net_driver_host`
///      already does for `net-driver-host` on x86_64.
///   4. Load this binary's ELF segments and spawn/schedule a thread that
///      `eret`s into its entry point, the same mechanism
///      `el0_proof.rs::prove_el0_process` already proves end to end for a
///      hand-built image — this binary is a real compiled ELF rather than
///      a `global_asm!` payload, which is the only thing that differs.
#[repr(C)]
struct NetBootInfo {
    /// VA of this device's virtio-mmio register window, already mapped
    /// into this process by the loader — handed to
    /// [`virtio_mmio::probe`]/[`virtio_net::VirtioNet`] exactly as given,
    /// never computed or assumed by this binary. See `virtio_mmio.rs`'s
    /// module doc comment for why this must be a boot-info field rather
    /// than a baked-in constant.
    mmio_base: u64,
    /// Physical base of a `3 * virtio_net::QUEUE_ALIGN`-byte region
    /// (descriptor table, then avail ring, then used ring — see
    /// `virtio_net::Virtqueue`'s doc comment). The matching *virtual*
    /// address is the fixed constant [`NET_RXQ_VA`] below.
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    /// Physical addresses of individually-mapped, page-sized RX packet
    /// buffers — matching virtual base [`NET_RXBUF_VA`], one page apart.
    rx_buffer_phys: [u64; smoltcp_device::RX_BUFFER_COUNT],
    /// Physical addresses of individually-mapped TX packet buffers —
    /// matching virtual base [`NET_TXBUF_VA`].
    tx_buffer_phys: [u64; smoltcp_device::TX_BUFFER_COUNT],
}

const NET_INFO_VA: usize = 0x_8810_0000;
const NET_RXQ_VA: usize = 0x_8820_0000;
const NET_TXQ_VA: usize = 0x_8830_0000;
const NET_RXBUF_VA: usize = 0x_8840_0000;
const NET_TXBUF_VA: usize = 0x_8850_0000;

/// Requested queue size for both RX and TX — the device's own
/// `QueueNumMax` may cap this lower; see
/// `virtio_net::VirtioNet::negotiate_queue_size`. [`virtio_net::MAX_SUPPORTED_QUEUE_SIZE`]
/// (256) is the ceiling this driver's fixed one-page descriptor table can
/// hold at all, so asking for exactly that leaves the actual choice to
/// whatever the device reports, same as `net-driver-host/src/main.rs`'s
/// own `net.queue_size(..)` calls do on x86_64.
const REQUESTED_QUEUE_SIZE: u16 = virtio_net::MAX_SUPPORTED_QUEUE_SIZE;

/// SLIRP's own fixed defaults (see `docs/STATUS.md`'s network-stack
/// section, and `docs/BETA_MOBILE_PROGRESS.md` item 2.2's real QEMU
/// output) — no DHCP negotiated, matching
/// `kernel-arm::virtio_net::{SELF_IP, GATEWAY_IP}` and
/// `net-driver-host`'s own `LOCAL_IP`/`GATEWAY_IP` exactly.
const LOCAL_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const GATEWAY_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);

/// The `guestfwd` target `kernel/tests/net_driver_tcp.rs` configures QEMU
/// with, reached through SLIRP's `10.0.2.0/24` subnet — same constants
/// `net-driver-host/src/main.rs` already uses and
/// `kernel/tests/support/tcp_proof_listener.py` already answers, reused
/// unchanged rather than inventing a parallel proof target.
const TCP_REMOTE_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 100);
const TCP_REMOTE_PORT: u16 = 9000;
/// Arbitrary ephemeral port, matching smoltcp's own documented example and
/// `net-driver-host`'s own `TCP_LOCAL_PORT`.
const TCP_LOCAL_PORT: u16 = 49152;
const TCP_PING: &[u8] = b"RUNIX-TCP-PROOF-PING";
const TCP_PONG: &[u8] = b"RUNIX-TCP-PROOF-PONG";

/// Every way this proof can conclude, reported as the `u64` `main` computes
/// — see [`run_tcp_proof`]'s own `TODO(loader integration)` comment for
/// where this value is meant to go once there is an EL1 side able to read
/// it. `0` is the only passing value; every other value names a specific,
/// distinguishable failure reason, matching this codebase's "a boot log
/// alone should be enough to diagnose it" convention
/// (`kernel-arm::virtio_net::ArpError`'s own doc comment states the same
/// goal for its enum).
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofResult {
    Pass = 0,
    DeviceProbeFailed = 1,
    FeatureNegotiationFailed = 2,
    QueueSetupFailed = 3,
    TcpConnectTimedOut = 4,
    TcpReplyMismatch = 5,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let info = unsafe { &*(NET_INFO_VA as *const NetBootInfo) };
    let result = run(info);

    write_all(b"net-driver-host-arm: result=");
    write_decimal(result as u64);
    write_byte(b'\n');

    // "This EL0 excursion is finished; resume my EL1 continuation" --
    // `kernel-arm/src/svc.rs`'s `SYS_NET_PROOF_DONE`, following
    // `el0_proof.rs::finish`'s own payload convention exactly: `x0` =
    // syscall number, `x1` = this `result as u64`, `svc #0`. Only one
    // register of payload (unlike `SYS_EL0_PROOF_DONE`'s three), since this
    // proof's whole verdict is the single flat `ProofResult` code, not
    // several separately observed bytes. `SYS_NET_PROOF_DONE` is duplicated
    // here by hand rather than shared from a crate, matching
    // `SYS_WRITE`'s own duplication above (see `syscall.rs`'s module doc
    // comment on why this binary and `kernel-arm` stay two independently
    // compiled programs that agree on syscall numbers by convention, not by
    // a shared dependency) -- it must match `kernel-arm/src/svc.rs`'s
    // `SYS_NET_PROOF_DONE` exactly.
    const SYS_NET_PROOF_DONE: u64 = 14;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x0") SYS_NET_PROOF_DONE,
            in("x1") result as u64,
            options(nostack),
        );
    }

    // `finish` on the EL1 side never resumes this process once it has
    // claimed the continuation -- reaching here would mean either no
    // continuation was live (this binary wasn't actually launched through
    // `tcp_proof.rs`'s mechanism) or the syscall number above doesn't match
    // `svc.rs`'s dispatch table. Either way there is nothing left to do but
    // spin, same as `el0_proof.rs`'s payload's own trailing `wfe` loop for
    // the identical "should never actually be reached" reason.
    loop {
        unsafe {
            core::arch::asm!("wfe", options(nostack, preserves_flags));
        }
    }
}

/// The whole proof: probe the device, bring up virtqueues, build the
/// `smoltcp` interface with the static SLIRP address, and run the TCP
/// round trip. Returns a [`ProofResult`] rather than panicking on any
/// failure — this process is `panic = "abort"`, and every failure mode
/// below is an ordinary, expected-to-sometimes-happen outcome (a
/// misconfigured QEMU command line, an unreachable listener), not a bug in
/// this code reaching an invariant violation.
fn run(info: &NetBootInfo) -> ProofResult {
    let dev = match virtio_mmio::probe(info.mmio_base as usize) {
        Ok(dev) => dev,
        Err(err) => {
            write_all(b"net-driver-host-arm: virtio-mmio probe failed: ");
            write_all(err_to_bytes(&err));
            write_byte(b'\n');
            return ProofResult::DeviceProbeFailed;
        }
    };
    write_all(b"net-driver-host-arm: virtio-net probed, version=");
    write_decimal(dev.version as u64);
    write_all(b" vendor_id=");
    write_decimal(dev.vendor_id as u64);
    write_all(b" MAC=");
    for (i, byte) in dev.mac.iter().enumerate() {
        write_hex_byte(*byte);
        if i != 5 {
            write_byte(b':');
        }
    }
    write_byte(b'\n');

    let net = match virtio_net::VirtioNet::negotiate(&dev) {
        Ok(net) => net,
        Err(_) => {
            write_all(b"net-driver-host-arm: feature negotiation failed\n");
            return ProofResult::FeatureNegotiationFailed;
        }
    };

    let rx_size = match net.negotiate_queue_size(virtio_net::QUEUE_RX, REQUESTED_QUEUE_SIZE) {
        Ok(size) => size,
        Err(_) => return ProofResult::QueueSetupFailed,
    };
    let tx_size = match net.negotiate_queue_size(virtio_net::QUEUE_TX, REQUESTED_QUEUE_SIZE) {
        Ok(size) => size,
        Err(_) => return ProofResult::QueueSetupFailed,
    };
    if net
        .setup_queue(virtio_net::QUEUE_RX, rx_size, info.rx_queue_phys)
        .is_err()
    {
        return ProofResult::QueueSetupFailed;
    }
    if net
        .setup_queue(virtio_net::QUEUE_TX, tx_size, info.tx_queue_phys)
        .is_err()
    {
        return ProofResult::QueueSetupFailed;
    }

    let mut device = unsafe {
        RunixNetDevice::new(
            info.mmio_base as usize,
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

    let config = Config::new(EthernetAddress(net.mac).into());
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv4(LOCAL_IP), 24));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY_IP);

    run_tcp_proof(&mut iface, &mut device)
}

/// One real TCP round trip against `tcp_proof_listener.py`, through the
/// same `guestfwd` bridge `net-driver-host`'s own `run_tcp_proof` already
/// proves on x86_64 — connect, send [`TCP_PING`], poll (bounded) for
/// exactly [`TCP_PONG`], compare exactly. Ported from that function
/// directly: same bound and reasoning (a real reply from a reachable
/// listener arrives promptly in practice, so the bound exists purely to
/// turn a genuinely broken/unreachable path into a reported failure
/// instead of an unbounded hang), same Nagle-disabled tweak, same "the
/// listener closes right after replying, so seeing that is also a
/// legitimate reason to stop polling" exit condition.
fn run_tcp_proof(iface: &mut Interface, device: &mut RunixNetDevice) -> ProofResult {
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 256]);
    let mut tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    tcp_socket.set_nagle_enabled(false);

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp_socket);
    if sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(TCP_REMOTE_IP), TCP_REMOTE_PORT),
            TCP_LOCAL_PORT,
        )
        .is_err()
    {
        return ProofResult::TcpConnectTimedOut;
    }

    let mut sent = false;
    let mut received = [0u8; 32];
    let mut received_len = 0usize;
    let mut outcome: Option<ProofResult> = None;

    // Same bound (2,000,000 iterations, 1ms apart) as
    // `net-driver-host/src/main.rs::run_tcp_proof`'s identical loop.
    for offset in 0..2_000_000u32 {
        let timestamp = Instant::from_millis(offset as i64);
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
            // Exact bytes checked, not just "received something" -- same
            // discipline `net-driver-host`'s own proof and
            // `kernel-arm::virtio_net::parse_arp_reply` both already apply.
            outcome = Some(if received[..TCP_PONG.len()] == *TCP_PONG {
                ProofResult::Pass
            } else {
                ProofResult::TcpReplyMismatch
            });
        }
        // The host listener closes its end right after replying -- once
        // that's visible here with no reply ever having matched, there is
        // nothing left to wait for either way.
        if sent && !socket.is_open() && outcome.is_none() {
            outcome = Some(ProofResult::TcpReplyMismatch);
        }
        if let Some(outcome) = outcome {
            return outcome;
        }

        // No `yield_now()` call here, unlike `net-driver-host`'s x86_64
        // loop: that call exists there to give other ring 3 threads a
        // chance to run under that kernel's scheduler. `kernel-arm` has no
        // equivalent syscall yet (see `syscall.rs`'s own doc comment on
        // what this binary's ABI surface is limited to today) -- a plain
        // busy-poll loop is exactly what `kernel-arm::virtio_net::arp_round_trip`
        // already does for the same reason, and is sound here for the
        // same reason: there is nothing else this single-threaded process
        // needs to let run concurrently with it yet.
    }

    ProofResult::TcpConnectTimedOut
}

/// Renders a [`virtio_mmio::ProbeError`] without pulling in `core::fmt`'s
/// heavier machinery at a call site that already has a plain byte-sink
/// (`write_all`) -- this binary has no formatted-`Display`-to-serial
/// bridge the way `kernel-arm::serial_println!` does, so error values are
/// rendered by hand at their one call site instead.
fn err_to_bytes(err: &virtio_mmio::ProbeError) -> &'static [u8] {
    match err {
        virtio_mmio::ProbeError::BadMagic(_) => b"bad magic (wrong VA, or not virtio-mmio)",
        virtio_mmio::ProbeError::NoDevice => b"no device in this slot",
        virtio_mmio::ProbeError::WrongDeviceId(_) => b"wrong device id (not network)",
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No `wfi`/privileged halt here -- same reasoning
    // `net-driver-host/src/main.rs`'s own panic handler gives for avoiding
    // `hlt`: this runs at EL0, and a privileged halt instruction here would
    // fault instead of halting anything. `wfe` is unprivileged at EL0.
    write_byte(b'?');
    loop {
        unsafe {
            core::arch::asm!("wfe", options(nostack, preserves_flags));
        }
    }
}
