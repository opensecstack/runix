//! Legacy virtio-pci transport (spec 0.9.5) for virtio-net — deliberately
//! only the "legacy" transport, not "modern" (virtio 1.0+): legacy exposes
//! its control interface via an I/O-port BAR, which this process can reach
//! through the capability-gated `SYS_PORT_IN`/`SYS_PORT_OUT` syscalls with
//! no MMIO-mapping support needed anywhere in the kernel (see
//! `kernel/src/pci.rs::read_bar0_io_port`'s doc comment). Interrupts are
//! never used — polling the used ring is spec-valid and used in production
//! (DPDK's poll-mode virtio driver) — sidestepping the fact that this
//! kernel has no MSI-X/IOAPIC support at all yet.
//!
//! Register layout (offsets from the I/O-port BAR base):
//! `0x00` DeviceFeatures (u32 RO), `0x04` GuestFeatures (u32 RW),
//! `0x08` QueueAddress (u32 RW — physical *page number*, not a byte
//! address), `0x0C` QueueSize (u16 RO), `0x0E` QueueSelect (u16 RW),
//! `0x10` QueueNotify (u16 RW), `0x12` DeviceStatus (u8 RW),
//! `0x13` ISRStatus (u8 RO), `0x14` device-specific config (virtio-net's
//! MAC address, 6 bytes).

use crate::syscall::{port_in, port_out};

const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_ADDRESS: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;
const REG_MAC: u16 = 0x14;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

/// Legacy virtio-pci's queue alignment — descriptor table, avail ring, and
/// used ring are each rounded up to this before the next part starts. Also
/// exactly one page, which is why a fixed "3 pages per queue" allocation
/// (desc, avail, used) works regardless of the device's actual `QueueSize`,
/// as long as that size fits one page's worth of descriptors — see
/// `MAX_SUPPORTED_QUEUE_SIZE` below.
pub const QUEUE_ALIGN: usize = 4096;

/// One page of 16-byte descriptors is exactly 256 — QEMU's virtio-net-pci
/// legacy default. A `QueueSize` larger than this wouldn't fit the fixed
/// one-page descriptor table this driver's fixed page layout assumes; fail
/// loudly rather than silently truncate or corrupt adjacent memory.
pub const MAX_SUPPORTED_QUEUE_SIZE: u16 = 256;

fn read_reg(io_base: u16, offset: u16, width: u8) -> u32 {
    port_in(io_base + offset, width).expect("port I/O denied reading a virtio-net register")
}

fn write_reg(io_base: u16, offset: u16, width: u8, value: u32) {
    let ok = port_out(io_base + offset, width, value);
    assert!(ok, "port I/O denied writing a virtio-net register");
}

pub struct VirtioNet {
    pub io_base: u16,
    pub mac: [u8; 6],
}

impl VirtioNet {
    /// Runs the legacy status handshake through `DRIVER` (ACKNOWLEDGE this
    /// is a virtio device, then ACKNOWLEDGE|DRIVER — a driver exists for
    /// it), negotiates zero optional features (no checksum offload, no
    /// merged RX buffers — keeps every packet's layout the simplest
    /// possible case for this first slice), and reads the device's MAC.
    /// Does *not* yet set `DRIVER_OK` — that happens once queues are
    /// configured, via [`Self::mark_ready`].
    pub fn probe(io_base: u16) -> Self {
        write_reg(io_base, REG_DEVICE_STATUS, 1, 0); // reset
        write_reg(io_base, REG_DEVICE_STATUS, 1, u32::from(STATUS_ACKNOWLEDGE));
        write_reg(
            io_base,
            REG_DEVICE_STATUS,
            1,
            u32::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER),
        );

        // Negotiate nothing — a zero GuestFeatures write is always valid
        // (it's a subset of whatever DeviceFeatures advertises) and keeps
        // every optional feature (checksum offload, merged RX buffers,
        // TSO/GSO) off, so packet buffers need no feature-dependent header
        // variants for this first slice.
        let _device_features = read_reg(io_base, REG_DEVICE_FEATURES, 4);
        write_reg(io_base, REG_GUEST_FEATURES, 4, 0);

        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = read_reg(io_base, REG_MAC + i as u16, 1) as u8;
        }

        VirtioNet { io_base, mac }
    }

    /// Reads `queue_index`'s `QueueSize` and asserts it fits this driver's
    /// fixed one-page descriptor table — see `MAX_SUPPORTED_QUEUE_SIZE`.
    pub fn queue_size(&self, queue_index: u16) -> u16 {
        write_reg(self.io_base, REG_QUEUE_SELECT, 2, u32::from(queue_index));
        let size = read_reg(self.io_base, REG_QUEUE_SIZE, 2) as u16;
        assert!(
            size <= MAX_SUPPORTED_QUEUE_SIZE,
            "virtio-net queue {queue_index} reports size {size}, past this driver's fixed one-page descriptor table"
        );
        size
    }

    /// Tells the device where `queue_index`'s ring memory lives — `region_phys`
    /// must be the start of a `3 * QUEUE_ALIGN`-byte region (desc table, then
    /// avail ring, then used ring, each `QUEUE_ALIGN`-aligned), already
    /// selected via [`Self::queue_size`]'s `QueueSelect` write.
    pub fn set_queue_address(&self, queue_index: u16, region_phys: u64) {
        write_reg(self.io_base, REG_QUEUE_SELECT, 2, u32::from(queue_index));
        let pfn = (region_phys / QUEUE_ALIGN as u64) as u32;
        write_reg(self.io_base, REG_QUEUE_ADDRESS, 4, pfn);
    }

    /// Sets `DRIVER_OK` — from this point the device may start processing
    /// whatever's already posted to each queue's avail ring.
    pub fn mark_ready(&self) {
        write_reg(
            self.io_base,
            REG_DEVICE_STATUS,
            1,
            u32::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK),
        );
    }
}

/// `QueueNotify` write, as a free function rather than a `VirtioNet`
/// method: every caller that needs this (`smoltcp_device.rs`'s
/// `RunixNetDevice`/token types) only ever has an `io_base` value in scope,
/// not a whole borrowed `VirtioNet` — plumbing one through would mean
/// either holding a long-lived `&VirtioNet` borrow across smoltcp's own
/// token borrows (awkward lifetime entanglement) or copying the two-field
/// struct around for no benefit over just copying the `u16` it actually
/// needs.
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

const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
struct UsedElem {
    id: u32,
    len: u32,
}

/// One virtqueue's ring memory, laid out across 3 `QUEUE_ALIGN`-sized pages
/// starting at `region_va` (a *virtual* address this process can read/write
/// directly — the kernel mapped it `USER_ACCESSIBLE | WRITABLE` before
/// spawning this process, see `kernel/src/main.rs`'s `load_and_run_net_driver_host`):
/// descriptor table at `region_va + 0`, avail ring at `region_va + QUEUE_ALIGN`,
/// used ring at `region_va + 2*QUEUE_ALIGN`. `region_phys` is the matching
/// *physical* base, already told to the device via [`VirtioNet::set_queue_address`]
/// — this process has no way to compute that itself (it never gets a raw
/// physical address, only what the kernel handed it in `NetBootInfo`).
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
    /// called (a stale used/avail index from whatever previously occupied
    /// this memory would desynchronize the ring from the device's own idea
    /// of it).
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

    /// Writes descriptor `index` and appends it to the avail ring —
    /// `writable` is `true` for an RX buffer (the device writes into it),
    /// `false` for TX (the device only reads it). Descriptor writes happen
    /// before the avail-ring/idx writes that publish it, with a compiler
    /// fence between them: the device (QEMU, reading this same memory
    /// concurrently) must never observe an avail-ring entry pointing at a
    /// not-yet-fully-written descriptor.
    ///
    /// # Safety
    /// `buf_phys`/`buf_len` must describe memory this process actually owns
    /// and that outlives the device's use of it (until the corresponding
    /// used-ring entry appears) — same contract as handing a raw pointer to
    /// any DMA-capable device.
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
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            let idx = core::ptr::read_volatile(self.avail_idx);
            let slot = self.avail_ring.add((idx % self.qsize) as usize);
            core::ptr::write_volatile(slot, index);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(self.avail_idx, idx.wrapping_add(1));
        }
    }

    pub fn init_avail_flags(&mut self) {
        unsafe {
            core::ptr::write_volatile(self.avail_flags, 0);
            core::ptr::write_volatile(self.avail_idx, 0);
        }
    }

    /// Polls for one new completion. Returns `(descriptor_id, byte_length)`
    /// the device reported — for an RX buffer, `byte_length` is how many
    /// bytes the device actually wrote (including the `virtio_net_hdr`
    /// prefix); for TX, it's conventionally 0 and only the fact that a
    /// completion appeared at all matters.
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
