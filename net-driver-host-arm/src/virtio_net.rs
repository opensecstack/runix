//! virtio-net virtqueue bring-up — ported from
//! `kernel-arm/src/virtio_net.rs`'s initialization handshake, feature
//! negotiation, and queue setup (the parts of that module that are
//! genuinely EL-agnostic: register reads/writes, status-bit sequencing,
//! and the MMIO-version-2 six-register ring-address scheme), combined with
//! `net-driver-host/src/virtio.rs`'s region-based `Virtqueue` layout (one
//! contiguous `3 * QUEUE_ALIGN`-byte allocation per queue: descriptor
//! table, then avail ring, then used ring) rather than
//! `kernel-arm::virtio_net`'s three independently-placed `QueueMem`
//! statics.
//!
//! # Why the x86_64 region layout, not the EL1 original's three statics
//!
//! `kernel-arm::virtio_net::QueueMem`/`setup_queue` hands the device three
//! *independent* addresses per queue (`QueueDesc`/`QueueDriver`/
//! `QueueDevice`), each the address of a plain Rust `static` — sound there
//! because that code runs at EL1 under an identity map, where "the address
//! of a static" and "the physical address to hand the device" are the same
//! number. Neither half of that holds here: this binary runs at EL0 in its
//! own process-private address space (no identity map — see `vm.rs`'s own
//! "QEMU/TCG `AP[1]`" doc comment on `process.rs`, referenced from
//! `loader.rs`), and more fundamentally, a ring 3/EL0 process in this
//! codebase is never told its own physical addresses at all (see
//! `net-driver-host/src/main.rs`'s module doc comment on exactly this gap
//! on the x86_64 side, and [`crate::NetBootInfo`]'s own doc comment for how
//! this binary expects the same gap to be closed: the loader computes
//! every physical address itself and hands them over in a fixed boot-info
//! page). One `region_phys: u64` per queue — handed in externally, never
//! computed by this process — is therefore the natural unit, exactly
//! matching `net-driver-host/src/virtio.rs::Virtqueue`'s own shape. This
//! module ports that shape rather than inventing a third one.
//!
//! # Register offsets and the version-2 requirement
//!
//! Unchanged from `kernel-arm/src/virtio_net.rs` — these are virtio 1.1
//! MMIO-transport facts, not EL1-specific ones. Still MMIO version 2 only,
//! for the same reason that module's doc comment gives: version 2's six
//! independent 64-bit `QueueDesc`/`QueueDriver`/`QueueDevice` registers let
//! each ring live at whatever address this binary's loader chose, with no
//! page-frame-number/contiguity constraint the way legacy's single
//! `QueuePFN` register would impose.
//!
//! # Feature negotiation and the 12-byte header
//!
//! Also unchanged: exactly `VIRTIO_F_VERSION_1` (bit 32) and nothing else.
//! See [`crate::VIRTIO_NET_HDR_LEN`] (defined in `lib.rs`, where it can be
//! host-tested alongside [`crate::validate_rx_completion`]) for why that
//! makes every buffer's header 12 bytes, not 10.
//!
//! # Memory ordering
//!
//! `kernel-arm/src/virtio_net.rs`'s module doc documents real, upstream-
//! confirmed virtio-ring staleness on aarch64 under TCG, fixed by `dsb sy`
//! (not the weaker `dmb ishst`) between a ring write and `QueueNotify`, and
//! before every read of the used index. Both barriers are reproduced here
//! at the identical points: [`notify`] and [`Virtqueue::poll_used`].

use core::sync::atomic::{compiler_fence, Ordering};

use crate::virtio_mmio::NetDevice;

// ---------------------------------------------------------------------------
// MMIO register offsets (virtio 1.1, MMIO transport) -- identical to
// kernel-arm/src/virtio_net.rs's own table.
// ---------------------------------------------------------------------------

const REG_DEVICE_FEATURES: usize = 0x010;
const REG_DEVICE_FEATURES_SEL: usize = 0x014;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_READY: usize = 0x044;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_STATUS: usize = 0x070;
const REG_QUEUE_DESC_LOW: usize = 0x080;
const REG_QUEUE_DESC_HIGH: usize = 0x084;
const REG_QUEUE_DRIVER_LOW: usize = 0x090;
const REG_QUEUE_DRIVER_HIGH: usize = 0x094;
const REG_QUEUE_DEVICE_LOW: usize = 0x0a0;
const REG_QUEUE_DEVICE_HIGH: usize = 0x0a4;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

/// `VIRTIO_F_VERSION_1` is feature bit 32, i.e. bit 0 of the *high* word
/// selected by writing 1 to `*FeaturesSel`.
const FEATURE_VERSION_1_HIGH_BIT: u32 = 1;

/// MMIO transport version this module requires — see the module doc.
const REQUIRED_MMIO_VERSION: u32 = 2;

/// virtio-net's queue 0 is receive, queue 1 is transmit (spec 5.1.2).
pub const QUEUE_RX: u32 = 0;
pub const QUEUE_TX: u32 = 1;

/// Legacy virtio-pci's queue alignment, reused here for the same per-region
/// layout `net-driver-host/src/virtio.rs::Virtqueue` uses: descriptor
/// table, then avail ring, then used ring, each `QUEUE_ALIGN`-aligned —
/// see this module's doc comment on why this crate ports that layout
/// rather than `kernel-arm::virtio_net`'s three-static one. Nothing about
/// this value is legacy-transport-specific; it is simply "one page", a
/// convenient and sufficient alignment for every ring region regardless of
/// transport version.
pub const QUEUE_ALIGN: usize = 4096;

/// One page of 16-byte descriptors is 256 — the same bound
/// `net-driver-host/src/virtio.rs::MAX_SUPPORTED_QUEUE_SIZE` enforces, for
/// the identical reason: a `QueueNumMax` larger than this would not fit
/// this driver's fixed one-page descriptor table.
pub const MAX_SUPPORTED_QUEUE_SIZE: u16 = 256;

const VIRTQ_DESC_F_WRITE: u16 = 2;

fn read32(addr: usize) -> u32 {
    // SAFETY: see virtio_mmio.rs's `read32` — same contract, same caller
    // obligation (a loader-mapped MMIO-window VA).
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn write32(addr: usize, value: u32) {
    // SAFETY: as above, for a write.
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

/// Full system barrier — see the module doc's "Memory ordering" section for
/// why this and not `dmb ishst`.
fn dsb_sy() {
    // SAFETY: a barrier instruction with no memory operand of its own;
    // ordering-only.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Every way bringing a device up can fail, each carrying the value that
/// made it fail — same shape as `kernel-arm::virtio_net::ArpError`'s
/// initialization-handshake variants, minus the ones specific to that
/// module's one-shot ARP proof (`Timeout`/`NotArpReply`), which have no
/// equivalent here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    /// `dev.version()` is not [`REQUIRED_MMIO_VERSION`].
    UnsupportedTransport(u32),
    /// Writing 0 to `Status` didn't take.
    ResetFailed(u32),
    /// The device doesn't offer `VIRTIO_F_VERSION_1`.
    NoVersion1(u32),
    /// `FEATURES_OK` was written but read back clear.
    FeaturesRejected(u32),
    /// `QueueNumMax` for this queue is smaller than the queue size this
    /// driver asked to use, or larger than [`MAX_SUPPORTED_QUEUE_SIZE`]
    /// (would not fit this driver's fixed one-page descriptor table).
    QueueSizeUnsupported { queue: u32, requested: u16, max: u32 },
    /// `QueueReady` was written but read back clear.
    QueueNotReady(u32),
}

impl core::fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VirtioNetError::UnsupportedTransport(v) => write!(
                f,
                "MMIO transport version {v}, need {REQUIRED_MMIO_VERSION}"
            ),
            VirtioNetError::ResetFailed(s) => write!(f, "device reset failed, Status={s:#x}"),
            VirtioNetError::NoVersion1(hi) => write!(
                f,
                "device does not offer VIRTIO_F_VERSION_1 (DeviceFeatures[63:32]={hi:#x})"
            ),
            VirtioNetError::FeaturesRejected(s) => {
                write!(f, "device rejected FEATURES_OK, Status={s:#x}")
            }
            VirtioNetError::QueueSizeUnsupported { queue, requested, max } => write!(
                f,
                "queue {queue} QueueNumMax={max}, need between 1 and \
                 min(requested {requested}, {MAX_SUPPORTED_QUEUE_SIZE})"
            ),
            VirtioNetError::QueueNotReady(q) => write!(f, "queue {q} QueueReady read back clear"),
        }
    }
}

/// A virtio-net device past the initialization handshake and feature
/// negotiation, ready for [`VirtioNet::setup_queue`] calls — the AArch64/
/// MMIO-v2 counterpart of `net-driver-host/src/virtio.rs::VirtioNet`.
pub struct VirtioNet {
    base: usize,
    pub mac: [u8; 6],
}

impl VirtioNet {
    /// Runs the version-2 initialization handshake (reset, ACKNOWLEDGE,
    /// DRIVER, negotiate `VIRTIO_F_VERSION_1` alone, FEATURES_OK) against
    /// an already-[`crate::virtio_mmio::probe`]d device. Does *not* set
    /// `DRIVER_OK` yet — call [`Self::setup_queue`] for both queues first,
    /// then [`Self::mark_ready`].
    pub fn negotiate(dev: &NetDevice) -> Result<Self, VirtioNetError> {
        if dev.version != REQUIRED_MMIO_VERSION {
            return Err(VirtioNetError::UnsupportedTransport(dev.version));
        }
        let base = dev.base();

        write32(base + REG_STATUS, 0); // reset
        let after_reset = read32(base + REG_STATUS);
        if after_reset != 0 {
            return Err(VirtioNetError::ResetFailed(after_reset));
        }

        let mut status = STATUS_ACKNOWLEDGE;
        write32(base + REG_STATUS, status);
        status |= STATUS_DRIVER;
        write32(base + REG_STATUS, status);

        // Feature bits 63:32 -- the half VIRTIO_F_VERSION_1 lives in.
        write32(base + REG_DEVICE_FEATURES_SEL, 1);
        let features_high = read32(base + REG_DEVICE_FEATURES);
        if features_high & FEATURE_VERSION_1_HIGH_BIT == 0 {
            return Err(VirtioNetError::NoVersion1(features_high));
        }
        // Bits 31:0: nothing in the low half is needed, but the
        // read-then-write-the-accepted-subset sequence is kept symmetric
        // for both halves, same as the EL1 original.
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
            return Err(VirtioNetError::FeaturesRejected(confirmed));
        }

        Ok(VirtioNet { base, mac: dev.mac })
    }

    /// Reads `queue_index`'s `QueueNumMax`.
    fn queue_num_max(&self, queue_index: u32) -> u32 {
        write32(self.base + REG_QUEUE_SEL, queue_index);
        read32(self.base + REG_QUEUE_NUM_MAX)
    }

    /// Picks a queue size for `queue_index`: the smaller of `requested` and
    /// the device's own `QueueNumMax`, rejected outright if that would
    /// exceed [`MAX_SUPPORTED_QUEUE_SIZE`] (would not fit this driver's
    /// fixed one-page descriptor table) or be zero (the device has no
    /// usable queue here at all).
    pub fn negotiate_queue_size(
        &self,
        queue_index: u32,
        requested: u16,
    ) -> Result<u16, VirtioNetError> {
        let max = self.queue_num_max(queue_index);
        let usable = max.min(u32::from(requested)).min(u32::from(MAX_SUPPORTED_QUEUE_SIZE));
        if usable == 0 {
            return Err(VirtioNetError::QueueSizeUnsupported {
                queue: queue_index,
                requested,
                max,
            });
        }
        Ok(usable as u16)
    }

    /// Tells the device where `queue_index`'s three ring regions live
    /// (`region_phys`, `region_phys + QUEUE_ALIGN`, `region_phys +
    /// 2*QUEUE_ALIGN` — see the module doc comment on why one contiguous
    /// region replaces the EL1 original's three independent statics) and
    /// marks the queue ready. Must be called after [`Self::negotiate`] and
    /// before [`Self::mark_ready`], once per queue.
    pub fn setup_queue(
        &self,
        queue_index: u32,
        qsize: u16,
        region_phys: u64,
    ) -> Result<(), VirtioNetError> {
        write32(self.base + REG_QUEUE_SEL, queue_index);
        write32(self.base + REG_QUEUE_NUM, u32::from(qsize));

        let desc_phys = region_phys;
        let avail_phys = region_phys + QUEUE_ALIGN as u64;
        let used_phys = region_phys + 2 * QUEUE_ALIGN as u64;

        let write_addr = |low: usize, high: usize, addr: u64| {
            write32(self.base + low, addr as u32);
            write32(self.base + high, (addr >> 32) as u32);
        };
        write_addr(REG_QUEUE_DESC_LOW, REG_QUEUE_DESC_HIGH, desc_phys);
        write_addr(REG_QUEUE_DRIVER_LOW, REG_QUEUE_DRIVER_HIGH, avail_phys);
        write_addr(REG_QUEUE_DEVICE_LOW, REG_QUEUE_DEVICE_HIGH, used_phys);

        write32(self.base + REG_QUEUE_READY, 1);
        if read32(self.base + REG_QUEUE_READY) != 1 {
            return Err(VirtioNetError::QueueNotReady(queue_index));
        }
        Ok(())
    }

    /// Sets `DRIVER_OK` — from this point the device may process whatever
    /// is already posted to each queue's avail ring. Call only after both
    /// queues are set up.
    pub fn mark_ready(&self) {
        write32(
            self.base + REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
    }
}

/// `QueueNotify` write, as a free function taking a bare `base`/`queue_index`
/// rather than a `&VirtioNet` method — same reasoning as
/// `net-driver-host/src/virtio.rs::notify`'s identical design: every caller
/// that needs this (`smoltcp_device.rs`'s tokens) only ever has `base` in
/// scope, not a whole borrowed `VirtioNet`, to avoid entangling its
/// lifetime with smoltcp's own token borrows. `dsb sy` *before* the write —
/// see the module doc's "Memory ordering" section.
pub fn notify(base: usize, queue_index: u32) {
    dsb_sy();
    write32(base + REG_QUEUE_NOTIFY, queue_index);
}

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct UsedElem {
    id: u32,
    len: u32,
}

/// One virtqueue's ring memory, laid out across 3 `QUEUE_ALIGN`-sized
/// regions starting at `region_va` — a *virtual* address this process can
/// read/write directly (the loader is expected to have mapped it
/// `USER_ACCESSIBLE | WRITABLE`, same contract
/// `net-driver-host/src/virtio.rs::Virtqueue`'s doc comment states for its
/// own `region_va`): descriptor table at `region_va + 0`, avail ring at
/// `region_va + QUEUE_ALIGN`, used ring at `region_va + 2*QUEUE_ALIGN`.
/// `region_phys` (handed to the device via [`VirtioNet::setup_queue`]) is
/// the matching *physical* base — this process has no way to compute that
/// itself; see [`crate::NetBootInfo`]'s doc comment.
pub struct Virtqueue {
    desc: *mut VirtqDesc,
    avail_flags: *mut u16,
    avail_idx: *mut u16,
    avail_ring: *mut u16,
    used_idx: *const u16,
    used_ring: *const UsedElem,
    qsize: u16,
    last_used_seen: u16,
}

impl Virtqueue {
    /// # Safety
    /// `region_va` must point to `3 * QUEUE_ALIGN` bytes of readable/
    /// writable memory this process exclusively owns, zeroed before this is
    /// called — a stale used/avail index left over from whatever
    /// previously occupied this memory would desynchronize the ring from
    /// the device's own idea of it.
    pub unsafe fn new(region_va: usize, qsize: u16) -> Self {
        let desc = region_va as *mut VirtqDesc;
        let avail_base = region_va + QUEUE_ALIGN;
        let used_base = region_va + 2 * QUEUE_ALIGN;
        Virtqueue {
            desc,
            avail_flags: avail_base as *mut u16,
            avail_idx: (avail_base + 2) as *mut u16,
            avail_ring: (avail_base + 4) as *mut u16,
            used_idx: (used_base + 2) as *const u16,
            used_ring: (used_base + 4) as *const UsedElem,
            qsize,
            last_used_seen: 0,
        }
    }

    pub fn init_avail_flags(&mut self) {
        unsafe {
            core::ptr::write_volatile(self.avail_flags, 0);
            core::ptr::write_volatile(self.avail_idx, 0);
        }
    }

    /// Writes descriptor `index` and appends it to the avail ring —
    /// `writable` is `true` for an RX buffer, `false` for TX. The
    /// descriptor write happens before the avail-ring/idx writes that
    /// publish it, with a compiler fence between: the device (QEMU,
    /// reading this same memory concurrently) must never observe an
    /// avail-ring entry pointing at a not-yet-fully-written descriptor.
    /// The *hardware* ordering that matters (ring writes before the
    /// `QueueNotify` store) is [`notify`]'s `dsb sy`, not this fence.
    ///
    /// # Safety
    /// `buf_phys`/`buf_len` must describe memory this process actually
    /// owns and that outlives the device's use of it (until the
    /// corresponding used-ring entry appears) — same contract as handing a
    /// raw pointer to any DMA-capable device.
    pub unsafe fn post(&mut self, index: u16, buf_phys: u64, buf_len: u32, writable: bool) {
        unsafe {
            let desc_ptr = self.desc.add(index as usize);
            core::ptr::write_volatile(
                desc_ptr,
                VirtqDesc {
                    addr: buf_phys,
                    len: buf_len,
                    flags: if writable { VIRTQ_DESC_F_WRITE } else { 0 },
                    next: 0,
                },
            );
            compiler_fence(Ordering::SeqCst);

            let idx = core::ptr::read_volatile(self.avail_idx);
            let slot = self.avail_ring.add((idx % self.qsize) as usize);
            core::ptr::write_volatile(slot, index);
            compiler_fence(Ordering::SeqCst);
            core::ptr::write_volatile(self.avail_idx, idx.wrapping_add(1));
        }
    }

    /// Polls for one new completion. Returns `(descriptor_id, byte_length)`
    /// the device reported — for an RX buffer, `byte_length` is how many
    /// bytes the device actually wrote (including the `virtio_net_hdr`
    /// prefix); for TX, it's conventionally 0. `dsb sy` before the read —
    /// see the module doc's "Memory ordering" section; without it the
    /// emulated CPU can keep reading a stale `used.idx` indefinitely under
    /// TCG.
    pub fn poll_used(&mut self) -> Option<(u32, u32)> {
        dsb_sy();
        let idx = unsafe { core::ptr::read_volatile(self.used_idx) };
        if idx == self.last_used_seen {
            return None;
        }
        let elem = unsafe {
            core::ptr::read_volatile(
                self.used_ring
                    .add((self.last_used_seen % self.qsize) as usize),
            )
        };
        self.last_used_seen = self.last_used_seen.wrapping_add(1);
        Some((elem.id, elem.len))
    }
}
