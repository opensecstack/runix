//! Legacy virtio-pci transport (spec 0.9.5) for virtio-blk — same transport
//! `net-driver-host/src/virtio.rs` already proved for virtio-net (legacy
//! only, I/O-port BAR reachable through the capability-gated
//! `SYS_PORT_IN`/`SYS_PORT_OUT` syscalls, polling instead of interrupts —
//! see that file's doc comment for the full reasoning, unchanged here).
//! This is its own copy, not a shared dependency: each ring-3 binary in
//! this codebase is independently compiled and linked
//! (`net-driver-host`/`grid-sandbox-host` already established this
//! convention for their own `syscall.rs`).
//!
//! What's actually new relative to the virtio-net copy: **descriptor
//! chaining**. Virtio-net's RX/TX buffers are always exactly one
//! descriptor each; virtio-blk's request format needs three linked
//! descriptors (header, data, device-written status) submitted as a single
//! chain via `next`/`VIRTQ_DESC_F_NEXT` — see [`Virtqueue::post_chain`].
//!
//! Register layout (offsets from the I/O-port BAR base) — identical to
//! every legacy virtio-pci device, virtio-blk included:
//! `0x00` DeviceFeatures (u32 RO), `0x04` GuestFeatures (u32 RW),
//! `0x08` QueueAddress (u32 RW — physical *page number*), `0x0C` QueueSize
//! (u16 RO), `0x0E` QueueSelect (u16 RW), `0x10` QueueNotify (u16 RW),
//! `0x12` DeviceStatus (u8 RW), `0x13` ISRStatus (u8 RO), `0x14`
//! device-specific config — for virtio-blk, an 8-byte little-endian
//! `capacity` (sector count) first, before other optional fields this
//! driver doesn't read (it negotiates zero features, so nothing past
//! `capacity` is guaranteed present anyway).

use crate::syscall::{port_in, port_out};

const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_ADDRESS: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;
const REG_CAPACITY: u16 = 0x14;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

/// Same fixed one-page-per-part layout `net-driver-host/src/virtio.rs`
/// already uses (descriptor table, avail ring, used ring, each rounded up
/// to this).
pub const QUEUE_ALIGN: usize = 4096;
/// Same reasoning as `net-driver-host`'s own constant of this name — one
/// page of 16-byte descriptors is exactly 256, QEMU's legacy default.
pub const MAX_SUPPORTED_QUEUE_SIZE: u16 = 256;

fn read_reg(io_base: u16, offset: u16, width: u8) -> u32 {
    port_in(io_base + offset, width).expect("port I/O denied reading a virtio-blk register")
}

fn write_reg(io_base: u16, offset: u16, width: u8, value: u32) {
    let ok = port_out(io_base + offset, width, value);
    assert!(ok, "port I/O denied writing a virtio-blk register");
}

pub struct VirtioBlk {
    pub io_base: u16,
    /// Sector count (512-byte sectors) — read once at probe time, not
    /// re-read anywhere else; this Phase 1 slice only ever touches sector
    /// 0, but capacity is cheap to have and worth logging for a real
    /// device sanity check.
    pub capacity_sectors: u64,
}

impl VirtioBlk {
    /// Same legacy status handshake as `net-driver-host`'s `VirtioNet::probe`
    /// (ACKNOWLEDGE, then ACKNOWLEDGE|DRIVER, negotiate zero features) —
    /// generic to every legacy virtio-pci device, not net-specific. Reads
    /// `capacity` instead of a MAC, one byte at a time (same per-byte
    /// pattern `VirtioNet::probe` uses, avoiding any assumption about
    /// register-width alignment support).
    pub fn probe(io_base: u16) -> Self {
        write_reg(io_base, REG_DEVICE_STATUS, 1, 0); // reset
        write_reg(io_base, REG_DEVICE_STATUS, 1, u32::from(STATUS_ACKNOWLEDGE));
        write_reg(
            io_base,
            REG_DEVICE_STATUS,
            1,
            u32::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER),
        );

        // Negotiate nothing — same reasoning as virtio-net: keeps every
        // optional feature (e.g. multi-queue, discard/write-zeroes,
        // topology hints) off, so this Phase 1 slice only ever deals with
        // one queue and the plain capacity field.
        let _device_features = read_reg(io_base, REG_DEVICE_FEATURES, 4);
        write_reg(io_base, REG_GUEST_FEATURES, 4, 0);

        let mut capacity_bytes = [0u8; 8];
        for (i, byte) in capacity_bytes.iter_mut().enumerate() {
            *byte = read_reg(io_base, REG_CAPACITY + i as u16, 1) as u8;
        }

        VirtioBlk {
            io_base,
            capacity_sectors: u64::from_le_bytes(capacity_bytes),
        }
    }

    /// Reads the (one, for virtio-blk) request queue's `QueueSize` and
    /// asserts it fits this driver's fixed one-page descriptor table —
    /// same contract as `net-driver-host`'s `VirtioNet::queue_size`.
    pub fn queue_size(&self, queue_index: u16) -> u16 {
        write_reg(self.io_base, REG_QUEUE_SELECT, 2, u32::from(queue_index));
        let size = read_reg(self.io_base, REG_QUEUE_SIZE, 2) as u16;
        assert!(
            size <= MAX_SUPPORTED_QUEUE_SIZE,
            "virtio-blk queue {queue_index} reports size {size}, past this driver's fixed one-page descriptor table"
        );
        size
    }

    pub fn set_queue_address(&self, queue_index: u16, region_phys: u64) {
        write_reg(self.io_base, REG_QUEUE_SELECT, 2, u32::from(queue_index));
        let pfn = (region_phys / QUEUE_ALIGN as u64) as u32;
        write_reg(self.io_base, REG_QUEUE_ADDRESS, 4, pfn);
    }

    /// Sets `DRIVER_OK` — from this point the device may start processing
    /// whatever's already posted to the request queue's avail ring.
    pub fn mark_ready(&self) {
        write_reg(
            self.io_base,
            REG_DEVICE_STATUS,
            1,
            u32::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK),
        );
    }
}

pub fn notify(io_base: u16, queue_index: u16) {
    write_reg(io_base, REG_QUEUE_NOTIFY, 2, u32::from(queue_index));
}

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
struct UsedElem {
    id: u32,
    len: u32,
}

/// One virtqueue's ring memory — identical layout and safety contract to
/// `net-driver-host/src/virtio.rs`'s `Virtqueue` (descriptor table at
/// `region_va + 0`, avail ring at `+ QUEUE_ALIGN`, used ring at
/// `+ 2*QUEUE_ALIGN`). Only one instance needed here (virtio-blk legacy has
/// exactly one request queue, unlike virtio-net's separate RX/TX pair).
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
    /// Same contract as `net-driver-host`'s `Virtqueue::new`: `region_va`
    /// must point to `3 * QUEUE_ALIGN` bytes this process exclusively owns,
    /// zeroed before this is called.
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

    /// Writes a chain of descriptors starting at fixed index `0` (this
    /// driver only ever has one request in flight at a time — post, poll
    /// to completion, then post the next — so reusing indices `0..len` for
    /// every request is safe: the previous chain's completion has already
    /// been consumed via [`Self::poll_used`] before this is called again),
    /// linking each to the next via `next`/`VIRTQ_DESC_F_NEXT`, then
    /// publishes only the head (index 0) to the avail ring — the device
    /// walks the rest of the chain itself via each descriptor's `next`
    /// field, the same way it would for a driver using a real free-list
    /// allocator across many in-flight requests.
    ///
    /// `descriptors` is `(phys_addr, len, writable)` per part of the
    /// request, in chain order (e.g. virtio-blk's header, then data, then
    /// status) — `writable` is `true` exactly where the *device* writes
    /// into this process's buffer (virtio-blk's status byte always;
    /// virtio-blk's data buffer too, but only for a read request).
    ///
    /// # Safety
    /// Same contract as `net-driver-host`'s `Virtqueue::post`, for every
    /// descriptor in the chain: each `phys_addr`/`len` must describe memory
    /// this process actually owns and that outlives the device's use of it.
    pub unsafe fn post_chain(&mut self, descriptors: &[(u64, u32, bool)]) {
        assert!(
            !descriptors.is_empty(),
            "post_chain requires at least one descriptor"
        );
        unsafe {
            for (i, &(phys, len, writable)) in descriptors.iter().enumerate() {
                let is_last = i + 1 == descriptors.len();
                let mut flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
                if !is_last {
                    flags |= VIRTQ_DESC_F_NEXT;
                }
                let desc_ptr = self.desc.add(i);
                core::ptr::write_volatile(
                    desc_ptr,
                    VirtqDesc {
                        addr: phys,
                        len,
                        flags,
                        next: if is_last { 0 } else { (i + 1) as u16 },
                    },
                );
            }
            // Same fence-before-publish discipline as `post`: the device
            // (QEMU, reading this same memory concurrently once notified)
            // must never observe an avail-ring entry pointing at a
            // not-yet-fully-written chain.
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            let idx = core::ptr::read_volatile(self.avail_idx);
            let slot = self.avail_ring.add((idx % self.qsize) as usize);
            core::ptr::write_volatile(slot, 0); // head index — always 0, see doc comment above
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(self.avail_idx, idx.wrapping_add(1));
        }
    }

    /// Polls for one new completion. Returns `(head_descriptor_id, byte_length)`
    /// — for a chained request, `byte_length` is the device's own
    /// `written` byte count for the whole chain (virtio-blk devices
    /// commonly report the data+status bytes actually written), which this
    /// driver doesn't rely on: it reads the request's own status byte
    /// directly out of the request buffer instead of trusting this count.
    pub fn poll_used(&mut self) -> Option<(u32, u32)> {
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
