//! virtio-net **virtqueue bring-up and one real ARP round trip** -- Stage 1
//! of giving this crate real networking (see
//! `docs/BETA_MOBILE_PROGRESS.md` item 2.2). Builds directly on
//! `virtio_mmio.rs`'s Stage 0 discovery (which only *reads* registers and
//! deliberately leaves the device untouched): takes the [`NetDevice`] that
//! probe found, runs the virtio initialization handshake, sets up one RX
//! and one TX virtqueue, transmits a hand-built Ethernet/ARP request, and
//! polls for the reply.
//!
//! Nothing more than that. No smoltcp (`smoltcp_spike.rs` is still a
//! compile-only spike, untouched by this), no IP, no TCP, no interrupts --
//! the single thing this proves is that the virtqueue mechanism works end
//! to end against a real device.
//!
//! # Transport: MMIO version 2, not legacy
//!
//! Stage 0 found this device reporting `Version` = 1 (legacy) by default,
//! and that `-global virtio-mmio.force-legacy=false` makes the same device
//! report `Version` = 2. This module requires version 2 and refuses to run
//! on legacy, on purpose: legacy's single `QueueAddress` register (a
//! *page frame number*, see `net-driver-host/src/virtio.rs` for the
//! x86_64 legacy-PCI equivalent) forces the three ring regions to be
//! contiguous and page-aligned relative to each other, whereas version 2
//! has separate 64-bit `QueueDesc`/`QueueDriver`/`QueueDevice` address
//! registers per queue and so lets each ring live wherever the compiler
//! placed it. That removes a whole class of layout bug for the cost of one
//! QEMU command-line flag.
//!
//! Register offsets below are the virtio 1.1 spec's MMIO transport
//! ("MMIO Device Register Layout"), continuing the set `virtio_mmio.rs`
//! already defined for discovery. The version-2-only registers are the
//! six ring-address ones at `0x080`-`0x0a4` plus `QueueReady` at `0x044`;
//! `QueuePFN`/`QueueAlign`/`GuestPageSize` (legacy-only) are deliberately
//! absent.
//!
//! # Feature negotiation: exactly one bit
//!
//! `VIRTIO_F_VERSION_1` (bit 32) and nothing else. It isn't optional --
//! a non-transitional modern device will not accept `FEATURES_OK` without
//! it -- and everything else (checksum offload, TSO/GSO, `VIRTIO_NET_F_MAC`,
//! `VIRTIO_NET_F_MRG_RXBUF`) is left off, keeping packet layout the
//! simplest possible case. Note the MAC is still readable from config
//! space without negotiating `VIRTIO_NET_F_MAC` (Stage 0 already did
//! exactly that), so there is nothing to gain by asking for it.
//!
//! One consequence that is easy to get wrong and *was* the thing to get
//! right here: negotiating `VIRTIO_F_VERSION_1` makes the `virtio_net_hdr`
//! prefix on every buffer **12 bytes**, not 10. Per spec 5.1.6, the
//! `num_buffers` field is present whenever `VIRTIO_NET_F_MRG_RXBUF` *or*
//! `VIRTIO_F_VERSION_1` is negotiated -- and QEMU implements exactly that
//! (its `virtio_net_set_mrg_rx_bufs` forces `mergeable_rx_bufs` on and
//! `guest_hdr_len` to `sizeof(virtio_net_hdr_mrg_rxbuf)` = 12 when
//! version 1 is set, regardless of whether the driver asked for
//! `MRG_RXBUF`). A 10-byte header here would shift every frame by two
//! bytes in both directions. See [`NET_HDR_LEN`].
//!
//! # Memory: no DMA translation problem at all
//!
//! Unlike x86_64's equivalent work, this needs no address translation and
//! no physical-contiguity dance: this crate's address space is
//! identity-mapped (VA == PA, see `mmu.rs`), so a statically-allocated
//! `.bss` array's address *is* the physical address handed to the device.
//! And `mmu.rs` maps the Normal region **non-cacheable**, so there is no
//! cache-maintenance requirement between these writes and the device's
//! reads either. Ring memory is therefore just page-aligned `static mut`
//! storage, same pattern as `el0.rs`'s `EL0_STACK`.
//!
//! # Memory ordering: `dsb sy`, not `dmb ishst`
//!
//! QEMU runs this under TCG (software emulation -- this project doesn't
//! use KVM), where memory ordering between the emulated CPU and QEMU's own
//! I/O thread can be elided. There is documented upstream history of
//! virtio-ring staleness on aarch64 specifically, fixed by a full system
//! barrier rather than the weaker store-only inner-shareable one. So
//! [`notify`] issues an explicit `dsb sy` between publishing the avail
//! ring and writing `QueueNotify`, and [`poll_used`] issues one before
//! each read of the used index. This is in place from the start by
//! decision, not added after chasing a "the ring looks right but the
//! device never responds" stall.
//!
//! # Privilege
//!
//! Still EL1, still explicitly throwaway scaffolding per the staged plan
//! in `docs/BETA_MOBILE_PROGRESS.md`. Unlike Stage 0 this *does* parse
//! bytes a device wrote, so it is the first thing here that would want to
//! be at EL0 -- which is exactly why item 2.4 (this crate's EL0 process
//! model) is sequenced before Stage 3, the first stage handling genuinely
//! external data. The parsing below is bounds-checked against the length
//! the device reported *and* against the buffer's own size, and never
//! indexes past either.

use crate::virtio_mmio::NetDevice;

// ---------------------------------------------------------------------------
// MMIO register offsets (virtio 1.1, MMIO transport). `virtio_mmio.rs`
// defines the discovery-only subset; these are the ones initialization and
// queue setup need.
// ---------------------------------------------------------------------------

const REG_DEVICE_FEATURES: usize = 0x010;
const REG_DEVICE_FEATURES_SEL: usize = 0x014;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
/// Version-2 only. Legacy uses `QueuePFN` at `0x040` instead.
const REG_QUEUE_READY: usize = 0x044;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_STATUS: usize = 0x070;
/// Version-2 only, and the whole reason for preferring v2: six separate
/// 32-bit halves giving each of the three ring regions its own independent
/// 64-bit physical address.
const REG_QUEUE_DESC_LOW: usize = 0x080;
const REG_QUEUE_DESC_HIGH: usize = 0x084;
const REG_QUEUE_DRIVER_LOW: usize = 0x090;
const REG_QUEUE_DRIVER_HIGH: usize = 0x094;
const REG_QUEUE_DEVICE_LOW: usize = 0x0a0;
const REG_QUEUE_DEVICE_HIGH: usize = 0x0a4;

// Device status bits (virtio 1.1, 2.1).
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

/// `VIRTIO_F_VERSION_1` is feature bit 32, i.e. bit 0 of the *high* word
/// selected by writing 1 to `DeviceFeaturesSel`/`DriverFeaturesSel`.
const FEATURE_VERSION_1_HIGH_BIT: u32 = 1;

/// MMIO transport version this module requires -- see the module doc.
const REQUIRED_MMIO_VERSION: u32 = 2;

/// virtio-net's queue 0 is receive, queue 1 is transmit (spec 5.1.2).
const QUEUE_RX: u32 = 0;
const QUEUE_TX: u32 = 1;

/// Descriptors per queue. A power of two, as the spec requires, and
/// deliberately tiny: this module posts exactly one buffer per queue.
const QUEUE_SIZE: u16 = 8;

/// `struct virtio_net_hdr_mrg_rxbuf` -- 12 bytes, *not* 10. See the module
/// doc's feature-negotiation section for why this follows from negotiating
/// `VIRTIO_F_VERSION_1` alone.
const NET_HDR_LEN: usize = 12;

const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Bound on the used-ring poll. SLIRP answers an ARP request essentially
/// immediately, so this is a "something is wrong" ceiling, not a tuned
/// timeout -- exhausting it is a failure to report, never a hang.
const POLL_ATTEMPTS: u32 = 2_000_000;

/// Extra bounded polls spent on the *TX* used ring once the RX reply has
/// already arrived -- see the call site for why.
const TX_DRAIN_ATTEMPTS: u32 = 100_000;

// ---------------------------------------------------------------------------
// Ring and buffer memory
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct AvailRing {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct UsedRing {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QUEUE_SIZE as usize],
    avail_event: u16,
}

/// One virtqueue's three regions in one page-aligned allocation.
///
/// The spec's alignment requirements are 16 (descriptor table), 2 (avail
/// ring) and 4 (used ring); `repr(C)` on fields of those natural
/// alignments inside a 4 KiB-aligned struct satisfies all three. The
/// device is told each region's address from `addr_of_mut!` on the real
/// field rather than from hand-computed offsets, so `repr(C)`'s own
/// padding decisions can't desynchronize this driver's view of the rings
/// from the device's.
///
/// `repr(align(4096))` for the same reason `el0.rs`'s `El0Stack` uses it:
/// it keeps this device-visible memory from sharing a page with unrelated
/// statics.
#[repr(C, align(4096))]
struct QueueMem {
    desc: [VirtqDesc; QUEUE_SIZE as usize],
    avail: AvailRing,
    used: UsedRing,
}

const EMPTY_QUEUE_MEM: QueueMem = QueueMem {
    desc: [VirtqDesc {
        addr: 0,
        len: 0,
        flags: 0,
        next: 0,
    }; QUEUE_SIZE as usize],
    avail: AvailRing {
        flags: 0,
        idx: 0,
        ring: [0; QUEUE_SIZE as usize],
        used_event: 0,
    },
    used: UsedRing {
        flags: 0,
        idx: 0,
        ring: [UsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize],
        avail_event: 0,
    },
};

static mut RX_QUEUE: QueueMem = EMPTY_QUEUE_MEM;
static mut TX_QUEUE: QueueMem = EMPTY_QUEUE_MEM;

/// One frame's worth of buffer, header included. 2 KiB is the conventional
/// virtio-net RX buffer size (comfortably over a 1514-byte Ethernet frame
/// plus the 12-byte header) and the same buffer type is reused for TX so
/// there is only one size to reason about.
const FRAME_BUF_LEN: usize = 2048;

#[repr(C, align(4096))]
struct FrameBuf([u8; FRAME_BUF_LEN]);

static mut RX_BUF: FrameBuf = FrameBuf([0; FRAME_BUF_LEN]);
static mut TX_BUF: FrameBuf = FrameBuf([0; FRAME_BUF_LEN]);

// ---------------------------------------------------------------------------
// Raw MMIO access -- same shape as `virtio_mmio.rs`/`gic.rs`
// ---------------------------------------------------------------------------

fn read32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn write32(addr: usize, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

/// Full system barrier. Used at exactly the two points the module doc
/// describes -- see that section for why this and not `dmb ishst`.
fn dsb_sy() {
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// ARP / Ethernet constants
// ---------------------------------------------------------------------------

/// SLIRP's gateway, the address being resolved.
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// The address SLIRP's built-in DHCP would hand out first; used here as a
/// plausible sender address without actually running DHCP.
const SELF_IP: [u8; 4] = [10, 0, 2, 15];

const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;

/// 14-byte Ethernet header + 28-byte ARP payload.
const ARP_FRAME_LEN: usize = 42;

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// A verified ARP reply.
pub struct ArpReply {
    /// The MAC the gateway answered with.
    pub sender_mac: [u8; 6],
    /// The IPv4 address it claimed (checked to be [`GATEWAY_IP`]).
    pub sender_ip: [u8; 4],
    /// Bytes the device reported writing, header included -- diagnostic.
    pub used_len: u32,
    /// Whether a TX completion was also observed. Not required for success
    /// (the reply arriving proves the frame went out), but reported
    /// because a reply *without* one would mean something odd.
    pub tx_completed: bool,
}

/// Every way this can fail, each carrying the value that made it fail so a
/// boot log is enough to diagnose it without a debugger.
pub enum ArpError {
    /// Device reported MMIO transport version N, not 2 -- almost certainly
    /// a missing `-global virtio-mmio.force-legacy=false`.
    UnsupportedTransport(u32),
    /// Writing 0 to `Status` didn't take.
    ResetFailed(u32),
    /// The device doesn't offer `VIRTIO_F_VERSION_1`.
    NoVersion1(u32),
    /// `FEATURES_OK` was written but read back clear -- the device
    /// rejected the feature set.
    FeaturesRejected(u32),
    /// `QueueNumMax` for this queue is smaller than [`QUEUE_SIZE`].
    QueueTooSmall { queue: u32, max: u32 },
    /// `QueueReady` was written but read back clear.
    QueueNotReady(u32),
    /// Poll loop exhausted. `tx_completed` distinguishes "the device never
    /// looked at our TX ring at all" from "it sent the frame but nothing
    /// came back".
    Timeout { tx_completed: bool },
    /// Something arrived but isn't the ARP reply being looked for.
    NotArpReply {
        used_len: u32,
        ethertype: u16,
        opcode: u16,
    },
}

impl core::fmt::Display for ArpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ArpError::UnsupportedTransport(v) => write!(
                f,
                "MMIO transport version {v}, need {REQUIRED_MMIO_VERSION} \
                 (add `-global virtio-mmio.force-legacy=false`)"
            ),
            ArpError::ResetFailed(s) => write!(f, "device reset failed, Status={s:#x}"),
            ArpError::NoVersion1(hi) => write!(
                f,
                "device does not offer VIRTIO_F_VERSION_1 (DeviceFeatures[63:32]={hi:#x})"
            ),
            ArpError::FeaturesRejected(s) => {
                write!(f, "device rejected FEATURES_OK, Status={s:#x}")
            }
            ArpError::QueueTooSmall { queue, max } => write!(
                f,
                "queue {queue} QueueNumMax={max}, need at least {QUEUE_SIZE}"
            ),
            ArpError::QueueNotReady(q) => write!(f, "queue {q} QueueReady read back clear"),
            ArpError::Timeout { tx_completed } => write!(
                f,
                "no ARP reply after {POLL_ATTEMPTS} polls (tx_completed={tx_completed})"
            ),
            ArpError::NotArpReply {
                used_len,
                ethertype,
                opcode,
            } => write!(
                f,
                "received {used_len} bytes but not an ARP reply \
                 (ethertype={ethertype:#06x}, opcode={opcode})"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Virtqueue operations
// ---------------------------------------------------------------------------

/// Points at one queue's three ring regions. Raw pointers rather than
/// references, because this memory is concurrently written by the device:
/// a `&mut` to it would be a lie the compiler is entitled to optimize
/// against.
struct Queue {
    desc: *mut VirtqDesc,
    avail: *mut AvailRing,
    used: *const UsedRing,
    index: u32,
    base: usize,
    last_used_seen: u16,
}

impl Queue {
    /// Writes descriptor 0 and publishes it in the avail ring.
    ///
    /// The descriptor write is ordered before the avail-ring entry, and
    /// that before the `idx` bump, by compiler fences: the device must
    /// never observe an avail-ring entry pointing at a half-written
    /// descriptor. The *hardware* ordering that matters (ring writes
    /// before the `QueueNotify` store) is [`notify`]'s `dsb sy`.
    fn post(&mut self, buf_addr: u64, buf_len: u32, writable: bool) {
        unsafe {
            core::ptr::write_volatile(
                self.desc,
                VirtqDesc {
                    addr: buf_addr,
                    len: buf_len,
                    flags: if writable { VIRTQ_DESC_F_WRITE } else { 0 },
                    next: 0,
                },
            );
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            let idx_ptr = core::ptr::addr_of_mut!((*self.avail).idx);
            let idx = core::ptr::read_volatile(idx_ptr);
            let slot = core::ptr::addr_of_mut!((*self.avail).ring[(idx % QUEUE_SIZE) as usize]);
            core::ptr::write_volatile(slot, 0); // descriptor 0, the only one in use
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(idx_ptr, idx.wrapping_add(1));
        }
    }

    /// `dsb sy`, *then* the `QueueNotify` write -- see the module doc.
    fn notify(&self) {
        dsb_sy();
        write32(self.base + REG_QUEUE_NOTIFY, self.index);
    }

    /// One non-blocking check of the used ring. The `dsb sy` is here for
    /// the same TCG reason as in [`Queue::notify`], in the other
    /// direction: without it the emulated CPU can keep reading a stale
    /// `used.idx` indefinitely.
    fn poll_used(&mut self) -> Option<UsedElem> {
        dsb_sy();
        let idx = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.used).idx)) };
        if idx == self.last_used_seen {
            return None;
        }
        let elem = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                (*self.used).ring[(self.last_used_seen % QUEUE_SIZE) as usize]
            ))
        };
        self.last_used_seen = self.last_used_seen.wrapping_add(1);
        Some(elem)
    }
}

/// Tells the device where `mem`'s three rings live and marks the queue
/// ready. Must be called after `FEATURES_OK` and before `DRIVER_OK`.
fn setup_queue(base: usize, index: u32, mem: *mut QueueMem) -> Result<Queue, ArpError> {
    write32(base + REG_QUEUE_SEL, index);

    let max = read32(base + REG_QUEUE_NUM_MAX);
    if max < u32::from(QUEUE_SIZE) {
        return Err(ArpError::QueueTooSmall { queue: index, max });
    }
    write32(base + REG_QUEUE_NUM, u32::from(QUEUE_SIZE));

    // Identity-mapped: these virtual addresses *are* the physical
    // addresses the device will DMA to/from. See the module doc.
    let desc = unsafe { core::ptr::addr_of_mut!((*mem).desc[0]) };
    let avail = unsafe { core::ptr::addr_of_mut!((*mem).avail) };
    let used = unsafe { core::ptr::addr_of_mut!((*mem).used) };

    let write_addr = |low: usize, high: usize, addr: u64| {
        write32(base + low, addr as u32);
        write32(base + high, (addr >> 32) as u32);
    };
    write_addr(REG_QUEUE_DESC_LOW, REG_QUEUE_DESC_HIGH, desc as u64);
    write_addr(REG_QUEUE_DRIVER_LOW, REG_QUEUE_DRIVER_HIGH, avail as u64);
    write_addr(REG_QUEUE_DEVICE_LOW, REG_QUEUE_DEVICE_HIGH, used as u64);

    write32(base + REG_QUEUE_READY, 1);
    if read32(base + REG_QUEUE_READY) != 1 {
        return Err(ArpError::QueueNotReady(index));
    }

    Ok(Queue {
        desc,
        avail,
        used: used as *const UsedRing,
        index,
        base,
        last_used_seen: 0,
    })
}

// ---------------------------------------------------------------------------
// Frame construction / parsing
// ---------------------------------------------------------------------------

/// Writes `virtio_net_hdr` (all-zero: no checksum offload, no GSO, and
/// `num_buffers` is device-written on RX / ignored on TX) followed by an
/// Ethernet-framed ARP request into `buf`. Returns the total descriptor
/// length, header included.
fn build_arp_request(buf: *mut u8, src_mac: [u8; 6]) -> u32 {
    let mut frame = [0u8; ARP_FRAME_LEN];

    // Ethernet header.
    frame[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // ARP payload (RFC 826 field order).
    frame[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    frame[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    frame[18] = 6; // hardware address length
    frame[19] = 4; // protocol address length
    frame[20..22].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    frame[22..28].copy_from_slice(&src_mac); // sender hardware address
    frame[28..32].copy_from_slice(&SELF_IP); // sender protocol address
                                             // 32..38: target hardware address stays all-zero -- that is the
                                             // unknown being asked about.
    frame[38..42].copy_from_slice(&GATEWAY_IP); // target protocol address

    unsafe {
        core::ptr::write_bytes(buf, 0, NET_HDR_LEN);
        core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HDR_LEN), ARP_FRAME_LEN);
    }
    (NET_HDR_LEN + ARP_FRAME_LEN) as u32
}

/// Checks a received buffer really is an ARP *reply* for [`GATEWAY_IP`]
/// with a usable sender MAC.
///
/// Every offset is validated against both the length the device reported
/// and the buffer's own size before being read -- the device-reported
/// length is the first thing here that isn't this code's own invariant.
fn parse_arp_reply(buf: *const u8, used_len: u32) -> Result<ArpReply, ArpError> {
    let min_len = (NET_HDR_LEN + ARP_FRAME_LEN) as u32;
    if used_len < min_len || used_len as usize > FRAME_BUF_LEN {
        return Err(ArpError::NotArpReply {
            used_len,
            ethertype: 0,
            opcode: 0,
        });
    }

    let mut frame = [0u8; ARP_FRAME_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(buf.add(NET_HDR_LEN), frame.as_mut_ptr(), ARP_FRAME_LEN);
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let opcode = u16::from_be_bytes([frame[20], frame[21]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&frame[28..32]);

    // An all-zero sender MAC would mean the "reply" carries no resolution
    // at all, and a sender IP other than the address asked about means
    // this is some other conversation on the broadcast domain, not the
    // answer. Both are rejected rather than reported as success.
    if ethertype != ETHERTYPE_ARP
        || opcode != ARP_OP_REPLY
        || sender_mac == [0u8; 6]
        || sender_ip != GATEWAY_IP
    {
        return Err(ArpError::NotArpReply {
            used_len,
            ethertype,
            opcode,
        });
    }

    Ok(ArpReply {
        sender_mac,
        sender_ip,
        used_len,
        tx_completed: false,
    })
}

// ---------------------------------------------------------------------------
// The whole round trip
// ---------------------------------------------------------------------------

/// Initializes `dev`'s virtqueues, sends one ARP request for
/// [`GATEWAY_IP`], and polls for the reply. Printing is the caller's job
/// (`nonsecure.rs`'s EL1 bring-up), matching every other hardware
/// bring-up step in this crate.
///
/// Writes device state, unlike `virtio_mmio::probe` -- call it once, after
/// the MMU is up.
pub fn arp_round_trip(dev: &NetDevice) -> Result<ArpReply, ArpError> {
    let base = dev.base();

    if dev.version != REQUIRED_MMIO_VERSION {
        return Err(ArpError::UnsupportedTransport(dev.version));
    }

    // --- Initialization handshake (virtio 1.1, 3.1.1) ---

    write32(base + REG_STATUS, 0); // reset
    let after_reset = read32(base + REG_STATUS);
    if after_reset != 0 {
        return Err(ArpError::ResetFailed(after_reset));
    }

    let mut status = STATUS_ACKNOWLEDGE;
    write32(base + REG_STATUS, status);
    status |= STATUS_DRIVER;
    write32(base + REG_STATUS, status);

    // Feature bits 63:32 -- the half `VIRTIO_F_VERSION_1` lives in.
    write32(base + REG_DEVICE_FEATURES_SEL, 1);
    let features_high = read32(base + REG_DEVICE_FEATURES);
    if features_high & FEATURE_VERSION_1_HIGH_BIT == 0 {
        return Err(ArpError::NoVersion1(features_high));
    }
    // Bits 31:0 read but not used: nothing in the low half is needed, and
    // the read is kept so the sequence matches the spec's "read, then
    // write the subset you accept" shape for both halves.
    write32(base + REG_DEVICE_FEATURES_SEL, 0);
    let _features_low = read32(base + REG_DEVICE_FEATURES);

    write32(base + REG_DRIVER_FEATURES_SEL, 0);
    write32(base + REG_DRIVER_FEATURES, 0);
    write32(base + REG_DRIVER_FEATURES_SEL, 1);
    write32(base + REG_DRIVER_FEATURES, FEATURE_VERSION_1_HIGH_BIT);

    status |= STATUS_FEATURES_OK;
    write32(base + REG_STATUS, status);
    let confirmed = read32(base + REG_STATUS);
    if confirmed & STATUS_FEATURES_OK == 0 {
        return Err(ArpError::FeaturesRejected(confirmed));
    }

    let mut rx = setup_queue(base, QUEUE_RX, core::ptr::addr_of_mut!(RX_QUEUE))?;
    let mut tx = setup_queue(base, QUEUE_TX, core::ptr::addr_of_mut!(TX_QUEUE))?;

    status |= STATUS_DRIVER_OK;
    write32(base + REG_STATUS, status);

    // --- Post an RX buffer first: the device needs somewhere to write an
    // incoming frame before there is any chance of one arriving. ---

    // `addr_of_mut!` on the whole static, not on `.0` -- a field
    // projection on a mutable static needs an `unsafe` block, while the
    // static's own address doesn't, and `FrameBuf` is a `repr(C)`
    // single-field newtype so the two addresses are identical anyway.
    let rx_buf = core::ptr::addr_of_mut!(RX_BUF) as *mut u8;
    rx.post(rx_buf as u64, FRAME_BUF_LEN as u32, true);
    rx.notify();

    // --- Transmit the ARP request. ---

    let tx_buf = core::ptr::addr_of_mut!(TX_BUF) as *mut u8;
    let tx_len = build_arp_request(tx_buf, dev.mac);
    tx.post(tx_buf as u64, tx_len, false);
    tx.notify();

    // --- Poll both used rings. ---

    let mut tx_completed = false;
    for _ in 0..POLL_ATTEMPTS {
        if !tx_completed && tx.poll_used().is_some() {
            tx_completed = true;
        }
        if let Some(elem) = rx.poll_used() {
            let mut reply = parse_arp_reply(rx_buf as *const u8, elem.len)?;
            // The reply arriving already proves the request went out, so
            // TX completion is diagnostic only -- but QEMU retires the TX
            // descriptor from a deferred bottom half, which can land
            // *after* the reply is already in the RX ring. Give it a
            // short bounded window so the reported value reflects
            // reality rather than just which half of the loop won a
            // race.
            for _ in 0..TX_DRAIN_ATTEMPTS {
                if tx_completed {
                    break;
                }
                tx_completed = tx.poll_used().is_some();
            }
            reply.tx_completed = tx_completed;
            return Ok(reply);
        }
    }

    Err(ArpError::Timeout { tx_completed })
}
