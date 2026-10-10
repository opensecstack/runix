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
///
/// # `mode` and the second use this binary is growing (Beta item 2.6)
///
/// This struct, and this binary, originally had exactly one job: the
/// fixed PING/PONG [`ProofResult`] round trip described above
/// ([`Mode::TcpProof`], `mode == 0`). `kernel-arm/src/marshal_transport.rs`
/// (a parallel, independent slice) is wiring `esim_marshal::evaluate` to a
/// real transport by loading this *same compiled binary* a second way —
/// into a fresh process, same as `tcp_proof.rs` already does, but asking
/// it to relay an arbitrary caller-supplied byte buffer to a configurable
/// remote address instead of running the fixed demo exchange
/// ([`Mode::MarshalRequest`], `mode == 1`). The fields below `mode` itself
/// are only meaningful in that second mode; `Mode::TcpProof` ignores them
/// and behaves exactly as it always has, reading [`TCP_REMOTE_IP`]/
/// [`TCP_REMOTE_PORT`] the same way it always did — this is an addition,
/// not a rewrite, of the existing proof.
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
    /// `0` = [`Mode::TcpProof`] (the original, still-default behavior —
    /// every field below this one is ignored in this mode), `1` =
    /// [`Mode::MarshalRequest`] (see this struct's own doc comment
    /// section above). Any other value is treated the same as `0` — see
    /// `_start`'s dispatch for why defaulting to the long-proven behavior
    /// rather than failing closed is the right call for a value this
    /// binary cannot itself validate against anything.
    mode: u64,
    /// `Mode::MarshalRequest`-only: the remote host to connect to, as four
    /// octets in the same order `Ipv4Address::new`'s own arguments take
    /// (`[a, b, c, d]` for `a.b.c.d`) — replacing the role [`TCP_REMOTE_IP`]
    /// plays for `Mode::TcpProof`. `Mode::TcpProof` ignores this field and
    /// keeps using that constant unchanged.
    remote_ip: [u8; 4],
    /// `Mode::MarshalRequest`-only: the remote TCP port, replacing the role
    /// [`TCP_REMOTE_PORT`] plays for `Mode::TcpProof`.
    remote_port: u16,
    /// `Mode::MarshalRequest`-only: the local (source) TCP port to connect
    /// from. Every MARSHAL evaluation is a fresh process on a fresh smoltcp
    /// stack (same deterministic ISN, same 10.0.2.15) that never gets to
    /// tear its flow down on the SLIRP side, so reusing one fixed source
    /// port makes every evaluation after the first present a SYN whose
    /// 4-tuple SLIRP still holds -- the caller therefore passes a distinct
    /// port per evaluation. `0` (an unset/legacy value) falls back to
    /// [`TCP_LOCAL_PORT`]. Occupies what was previously `repr(C)` padding
    /// between `remote_port` and `request_len`, so no other offset and not
    /// the struct's size changes. `Mode::TcpProof` ignores it.
    local_port: u16,
    /// `Mode::MarshalRequest`-only: how many bytes at [`MARSHAL_REQUEST_VA`]
    /// are valid — the loader writes the encoded `MarshalRequest` there
    /// before `eret`ing and records its exact length here, since the
    /// buffer itself carries no length prefix of its own. Clamped to
    /// [`MARSHAL_REQUEST_CAPACITY`] before use (see `run_marshal_request`)
    /// rather than trusted outright — a value larger than the loader
    /// actually mapped must not turn into an out-of-bounds read just
    /// because this struct's own producer made a mistake.
    request_len: u64,
}

/// See [`NetBootInfo::mode`]'s own doc comment — kept as a small enum here
/// purely for `_start`'s `match` to read, not part of the wire struct
/// itself (the wire field is the plain `u64` above, same reasoning
/// `ProofResult`'s own `#[repr(u64)]` gives for why the wire shape and the
/// Rust-side match target can be the same representation without needing
/// two separate types).
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    TcpProof = 0,
    MarshalRequest = 1,
}

impl Mode {
    /// Any value this binary does not recognize defaults to
    /// [`Mode::TcpProof`] — see [`NetBootInfo::mode`]'s doc comment for why
    /// defaulting to the long-proven behavior, rather than failing closed,
    /// is the right call for a field this binary has no independent way to
    /// validate.
    fn from_u64(value: u64) -> Mode {
        match value {
            1 => Mode::MarshalRequest,
            _ => Mode::TcpProof,
        }
    }
}

const NET_INFO_VA: usize = 0x_8810_0000;
const NET_RXQ_VA: usize = 0x_8820_0000;
const NET_TXQ_VA: usize = 0x_8830_0000;
const NET_RXBUF_VA: usize = 0x_8840_0000;
const NET_TXBUF_VA: usize = 0x_8850_0000;
/// `Mode::MarshalRequest`-only: VA of the encoded `MarshalRequest` bytes
/// the loader writes before `eret`ing — see [`NetBootInfo::request_len`]
/// for the matching length field. Chosen clear of every VA above and of
/// [`MARSHAL_RESPONSE_VA`] below.
const MARSHAL_REQUEST_VA: usize = 0x_8860_0000;
/// `Mode::MarshalRequest`-only: how many bytes the loader is expected to
/// have mapped at [`MARSHAL_REQUEST_VA`] — [`NetBootInfo::request_len`] is
/// clamped to this before any read, so a bogus/oversized `request_len`
/// turns into a truncated send rather than a read past what is actually
/// mapped. 8 KiB, matching [`MARSHAL_RESPONSE_CAPACITY`]'s own reasoning
/// below (comfortably larger than a `MarshalRequest`'s encoded JSON is
/// ever expected to be).
const MARSHAL_REQUEST_CAPACITY: usize = 8192;
/// `Mode::MarshalRequest`-only: VA of a fixed-capacity buffer this binary
/// writes reply bytes into as they arrive — EL1 reads `request_len`-many
/// bytes back out starting here after this process reports completion
/// (see `SYS_MARSHAL_PROOF_DONE`'s own doc comment at its call site for
/// how the actual byte count is reported — not through this struct, since
/// `NetBootInfo` is otherwise a one-direction, EL1-writes/EL0-reads-only
/// contract, and adding a write-back field to it would be the one
/// exception).
const MARSHAL_RESPONSE_VA: usize = 0x_8870_0000;
/// `Mode::MarshalRequest`-only: fixed capacity of the buffer at
/// [`MARSHAL_RESPONSE_VA`]. 8 KiB: comfortably larger than twice
/// `runix_ipc::marshal`'s `MAX_JSON_LEN` would need for a full
/// decodable `MarshalResponse` with headroom, picked as a generous round
/// number rather than by pulling in the `runix-ipc` crate as a dependency
/// of this `no_std`/`aarch64-unknown-none` binary just to read one
/// constant — the response is truncated (never overrun) if a reply
/// somehow exceeds this, which `run_marshal_request` reports honestly via
/// the byte count it hands back rather than silently.
const MARSHAL_RESPONSE_CAPACITY: usize = 8192;

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

    match Mode::from_u64(info.mode) {
        Mode::TcpProof => {
            let result = run_tcp_proof_mode(info);

            write_all(b"net-driver-host-arm: result=");
            write_decimal(result as u64);
            write_byte(b'\n');

            // "This EL0 excursion is finished; resume my EL1 continuation" --
            // `kernel-arm/src/svc.rs`'s `SYS_NET_PROOF_DONE`, following
            // `el0_proof.rs::finish`'s own payload convention exactly: `x0` =
            // syscall number, `x1` = this `result as u64`, `svc #0`. Only one
            // register of payload (unlike `SYS_EL0_PROOF_DONE`'s three), since
            // this proof's whole verdict is the single flat `ProofResult`
            // code, not several separately observed bytes. `SYS_NET_PROOF_DONE`
            // is duplicated here by hand rather than shared from a crate,
            // matching `SYS_WRITE`'s own duplication above (see `syscall.rs`'s
            // module doc comment on why this binary and `kernel-arm` stay two
            // independently compiled programs that agree on syscall numbers
            // by convention, not by a shared dependency) -- it must match
            // `kernel-arm/src/svc.rs`'s `SYS_NET_PROOF_DONE` exactly.
            const SYS_NET_PROOF_DONE: u64 = 14;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    in("x0") SYS_NET_PROOF_DONE,
                    in("x1") result as u64,
                    options(nostack),
                );
            }
        }
        Mode::MarshalRequest => {
            let (status, response_len) = run_marshal_request_mode(info);

            write_all(b"net-driver-host-arm: marshal-request status=");
            write_decimal(status as u64);
            write_all(b" response_len=");
            write_decimal(response_len);
            write_byte(b'\n');

            // "This EL0 excursion is finished; resume my EL1 continuation" --
            // the `Mode::MarshalRequest` counterpart of `SYS_NET_PROOF_DONE`
            // above, newly allocated for this mode rather than reusing `14`
            // because the payload shape is different: `x1` = status (`0` =
            // at least one reply byte was received and copied into
            // [`MARSHAL_RESPONSE_VA`]; `1` = the connect attempt failed or
            // timed out with nothing ever received, and `response_len` is
            // `0`), `x2` = the number of bytes actually written at
            // [`MARSHAL_RESPONSE_VA`] (always `<= MARSHAL_RESPONSE_CAPACITY`,
            // never a silent truncation the caller can't detect — EL1 reads
            // exactly this many bytes back, no more). Not wired into
            // `kernel-arm/src/svc.rs::dispatch` by this slice — that is
            // `marshal_transport.rs`'s own follow-up job, same as this
            // file's existing `TODO(loader integration)` convention left
            // `SYS_NET_PROOF_DONE`'s dispatch arm for a later slice. Must
            // match whatever `kernel-arm/src/svc.rs` defines for
            // `SYS_MARSHAL_PROOF_DONE` once that side lands.
            const SYS_MARSHAL_PROOF_DONE: u64 = 15;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    in("x0") SYS_MARSHAL_PROOF_DONE,
                    in("x1") status as u64,
                    in("x2") response_len,
                    options(nostack),
                );
            }
        }
    }

    // `finish` on the EL1 side never resumes this process once it has
    // claimed the continuation -- reaching here would mean either no
    // continuation was live (this binary wasn't actually launched through
    // `tcp_proof.rs`'s/`marshal_transport.rs`'s mechanism) or the syscall
    // number above doesn't match `svc.rs`'s dispatch table. Either way
    // there is nothing left to do but spin, same as `el0_proof.rs`'s
    // payload's own trailing `wfe` loop for the identical "should never
    // actually be reached" reason.
    loop {
        unsafe {
            core::arch::asm!("wfe", options(nostack, preserves_flags));
        }
    }
}

/// `Mode::TcpProof` entry point: shares every bring-up step with
/// `Mode::MarshalRequest` via [`bring_up_interface`], branching only at
/// "what do we do with the open interface" by calling [`run_tcp_proof`] —
/// this function, and [`ProofResult`]'s possible values, are unchanged
/// from before `Mode::MarshalRequest` existed.
fn run_tcp_proof_mode(info: &NetBootInfo) -> ProofResult {
    match bring_up_interface(info) {
        Ok((mut iface, mut device)) => run_tcp_proof(&mut iface, &mut device),
        Err(result) => result,
    }
}

/// `Mode::MarshalRequest` entry point: identical bring-up to
/// [`run_tcp_proof_mode`] via [`bring_up_interface`], then
/// [`run_marshal_request`] in place of [`run_tcp_proof`]. Returns `(status,
/// response_len)` exactly as `_start` reports them via
/// `SYS_MARSHAL_PROOF_DONE` — see that call site's own doc comment for the
/// convention. Bring-up failure (device probe/feature negotiation/queue
/// setup) is reported the same way a connect failure is: status `1`,
/// `response_len` `0` — from `marshal_transport.rs`'s point of view both
/// are simply "no reply came back", and `ProofResult`'s finer-grained
/// distinction is already written to the serial console by
/// [`bring_up_interface`]'s own failure branches for human diagnosis.
fn run_marshal_request_mode(info: &NetBootInfo) -> (u8, u64) {
    match bring_up_interface(info) {
        Ok((mut iface, mut device)) => run_marshal_request(&mut iface, &mut device, info),
        Err(_) => (1, 0),
    }
}

/// Every step both modes share: probe the device, negotiate features,
/// stand up the virtqueues, and build the `smoltcp` interface with the
/// static SLIRP address. Returns the live `(Interface, RunixNetDevice)`
/// pair on success, or the specific [`ProofResult`] naming what failed —
/// callers that don't need that granularity (`run_marshal_request_mode`)
/// are free to collapse it. This is a straight extraction of what used to
/// be the first half of the old, single-mode `run` function; no bring-up
/// behavior changed.
fn bring_up_interface(info: &NetBootInfo) -> Result<(Interface, RunixNetDevice), ProofResult> {
    let dev = match virtio_mmio::probe(info.mmio_base as usize) {
        Ok(dev) => dev,
        Err(err) => {
            write_all(b"net-driver-host-arm: virtio-mmio probe failed: ");
            write_all(err_to_bytes(&err));
            write_byte(b'\n');
            return Err(ProofResult::DeviceProbeFailed);
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
            return Err(ProofResult::FeatureNegotiationFailed);
        }
    };

    let rx_size = match net.negotiate_queue_size(virtio_net::QUEUE_RX, REQUESTED_QUEUE_SIZE) {
        Ok(size) => size,
        Err(_) => return Err(ProofResult::QueueSetupFailed),
    };
    let tx_size = match net.negotiate_queue_size(virtio_net::QUEUE_TX, REQUESTED_QUEUE_SIZE) {
        Ok(size) => size,
        Err(_) => return Err(ProofResult::QueueSetupFailed),
    };
    if net
        .setup_queue(virtio_net::QUEUE_RX, rx_size, info.rx_queue_phys)
        .is_err()
    {
        return Err(ProofResult::QueueSetupFailed);
    }
    if net
        .setup_queue(virtio_net::QUEUE_TX, tx_size, info.tx_queue_phys)
        .is_err()
    {
        return Err(ProofResult::QueueSetupFailed);
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

    Ok((iface, device))
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

/// The `Mode::MarshalRequest` counterpart of [`run_tcp_proof`]: same
/// connect-then-poll shape (same iteration bound, same Nagle-disabled
/// socket setup, same "the listener closing is also a legitimate reason
/// to stop polling" exit condition), but relaying an arbitrary
/// caller-supplied buffer instead of the fixed [`TCP_PING`]/[`TCP_PONG`]
/// demo exchange: connect to `info.remote_ip`/`info.remote_port`, send
/// `info.request_len` bytes read from [`MARSHAL_REQUEST_VA`] (clamped to
/// [`MARSHAL_REQUEST_CAPACITY`]), and accumulate whatever reply bytes
/// arrive into [`MARSHAL_RESPONSE_VA`] (clamped to
/// [`MARSHAL_RESPONSE_CAPACITY`] — never written past it) until the
/// connection closes, the response buffer fills, or the iteration bound
/// is hit. Returns `(status, response_len)` exactly as `_start` reports
/// them via `SYS_MARSHAL_PROOF_DONE`: status `0` with `response_len > 0`
/// means at least one reply byte was received and copied back; status `1`
/// with `response_len == 0` covers both "never connected" and "connected
/// but nothing came back before the bound" — `marshal_transport.rs`'s own
/// caller (`esim_marshal::evaluate`) treats both the same way (no decodable
/// `MarshalResponse`), so collapsing them here rather than inventing a
/// third status is the point.
fn run_marshal_request(
    iface: &mut Interface,
    device: &mut RunixNetDevice,
    info: &NetBootInfo,
) -> (u8, u64) {
    let remote_ip = Ipv4Address::new(
        info.remote_ip[0],
        info.remote_ip[1],
        info.remote_ip[2],
        info.remote_ip[3],
    );

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; MARSHAL_RESPONSE_CAPACITY]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; MARSHAL_REQUEST_CAPACITY]);
    let mut tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
    tcp_socket.set_nagle_enabled(false);

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp_socket);
    if sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(remote_ip), info.remote_port),
            if info.local_port == 0 {
                TCP_LOCAL_PORT
            } else {
                info.local_port
            },
        )
        .is_err()
    {
        return (1, 0);
    }

    // Clamped, not trusted outright -- see [`MARSHAL_REQUEST_CAPACITY`]'s
    // own doc comment for why a bogus/oversized `request_len` must turn
    // into a truncated send rather than a read past what the loader
    // actually mapped.
    let request_len = (info.request_len as usize).min(MARSHAL_REQUEST_CAPACITY);
    // SAFETY: the loader contract (see `NetBootInfo`'s own doc comment)
    // is that it maps at least `MARSHAL_REQUEST_CAPACITY` bytes at
    // `MARSHAL_REQUEST_VA` before `eret`ing into this process, and
    // `request_len` is clamped to that same capacity immediately above --
    // this read never reaches past what is guaranteed mapped.
    let request: &[u8] =
        unsafe { core::slice::from_raw_parts(MARSHAL_REQUEST_VA as *const u8, request_len) };

    let response_ptr = MARSHAL_RESPONSE_VA as *mut u8;
    let mut sent = 0usize;
    let mut received_len = 0usize;

    // Same bound (2,000,000 iterations, 1ms apart) as
    // [`run_tcp_proof`]'s identical loop, and the same reasoning: a real
    // reply from a reachable listener arrives promptly in practice, so
    // the bound exists purely to turn a genuinely broken/unreachable path
    // into a reported failure instead of an unbounded hang.
    for offset in 0..2_000_000u32 {
        let timestamp = Instant::from_millis(offset as i64);
        iface.poll(timestamp, device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        if socket.can_send() && sent < request.len() {
            if let Ok(n) = socket.send_slice(&request[sent..]) {
                sent += n;
            }
        }

        if socket.can_recv() && received_len < MARSHAL_RESPONSE_CAPACITY {
            // SAFETY: `response_ptr` points at a `MARSHAL_RESPONSE_CAPACITY`-
            // byte buffer the loader mapped (same contract as the request
            // buffer above); `received_len` only ever grows up to that same
            // capacity across iterations, so this slice never extends past
            // it -- no silent truncation past the buffer's own bounds, only
            // the documented, honestly-reported truncation at capacity.
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    response_ptr.add(received_len),
                    MARSHAL_RESPONSE_CAPACITY - received_len,
                )
            };
            if let Ok(n) = socket.recv_slice(dst) {
                received_len += n;
            }
        }

        let response_buffer_full = received_len >= MARSHAL_RESPONSE_CAPACITY;
        // The listener closing its end once the request has been fully
        // sent is also a legitimate reason to stop polling -- same
        // discipline [`run_tcp_proof`] applies to `TCP_PONG`.
        let remote_closed = sent >= request.len() && !socket.is_open();
        if response_buffer_full || remote_closed {
            break;
        }
    }

    // Graceful close: send a FIN and keep polling (bounded) until the
    // socket reaches Closed/TimeWait, so SLIRP sees the teardown instead
    // of a flow that is silently abandoned when this process is destroyed.
    // The poll clock continues past the main loop's last timestamp.
    sockets.get_mut::<tcp::Socket>(handle).close();
    for offset in 0..CLOSE_POLL_BUDGET {
        let timestamp = Instant::from_millis(2_000_000 + offset as i64);
        iface.poll(timestamp, device, &mut sockets);
        let state = sockets.get_mut::<tcp::Socket>(handle).state();
        if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
            break;
        }
    }

    if received_len == 0 {
        (1, 0)
    } else {
        (0, received_len as u64)
    }
}

/// Upper bound on the post-response polls spent waiting for the TCP close
/// handshake to finish in [`run_marshal_request`]. Generous relative to a
/// local SLIRP round trip, small relative to the 2,000,000 main-loop bound.
const CLOSE_POLL_BUDGET: u32 = 200_000;

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
