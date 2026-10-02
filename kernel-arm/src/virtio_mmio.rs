//! virtio-mmio device *discovery* -- Stage 0 of giving this crate real
//! networking (see `docs/BETA_MOBILE_PROGRESS.md` item 2.1). Finds QEMU's
//! `virtio-net-device` on the `virt` machine's MMIO transport and reads its
//! MAC address. Nothing else: no virtqueue setup, no feature negotiation,
//! no packet I/O, no interrupts -- those are Stages 1-3, deliberately kept
//! out of here.
//!
//! # Transport, and why MMIO rather than PCI
//!
//! QEMU's `virt` machine exposes virtio over **virtio-mmio**, a flat
//! register window with no bus enumeration at all: 32 fixed slots starting
//! at `0x0a00_0000`, each `0x200` bytes wide, so slot N's base is
//! `0x0a00_0000 + N * 0x200` (slot 0 = `0x0a00_0000`, slot 31 =
//! `0x0a00_0000 + 31 * 0x200` = `0x0a00_3e00`, the window ending at
//! `0x0a00_4000`). Every slot's `MagicValue` register reads correctly
//! whether or not a device is attached to it; an *empty* slot is
//! distinguished by `DeviceID` reading 0. There is no PCIe bus in play
//! here, hence `virtio-net-device` (transport-agnostic, lands on MMIO on
//! this machine) rather than `virtio-net-pci` on the QEMU command line.
//!
//! The whole window falls inside `mmu.rs`'s flat 1 GiB Device-nGnRnE block
//! (`0x0000_0000`-`0x3FFF_FFFF`, the same mapping the GIC at `0x0800_0000`
//! and UART0 at `0x0900_0000` already use), so this needs no new MMU work
//! -- it is readable both before and after `mmu::install`.
//!
//! # Why scan all 32 slots instead of stopping early
//!
//! [`probe`] walks every slot 0..32 even though today's QEMU command line
//! attaches exactly one network device, and reports how many slots were
//! populated alongside the device it found. Reason: QEMU does *not*
//! populate these slots from index 0 upward (it assigns them from the top
//! of the window downward), so a scan that stopped at the first *empty*
//! slot would find nothing at all, and one that stopped at the first
//! *populated* slot would silently hide the case where the device landed
//! somewhere other than where this code assumed. Scanning everything and
//! reporting the real slot count makes "no device attached" and "device
//! attached at an unexpected index" distinguishable in the boot log, which
//! is the entire point of a discovery phase.
//!
//! # Privilege
//!
//! This runs at EL1 and is explicitly throwaway scaffolding per the staged
//! plan: it parses no attacker-controlled data (a boot-time read of a MAC
//! address from an emulated register window), so EL1 is acceptable for
//! now. Real networking moves to EL0 in a later stage, once this crate has
//! a process model at all.

/// Base of the `virt` machine's virtio-mmio register window.
const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;
/// Bytes per slot -- slot N is at `VIRTIO_MMIO_BASE + N * SLOT_STRIDE`.
const SLOT_STRIDE: usize = 0x200;
/// Number of slots `virt` provides.
const SLOT_COUNT: usize = 32;

// Register offsets from a slot's base, straight from the virtio 1.x spec's
// MMIO transport section. `+ 0x000` on the first one is arithmetically a
// no-op, kept so every register's real offset is visible at a glance --
// same convention as `gic.rs`.
#[allow(clippy::identity_op)]
const REG_MAGIC_VALUE: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_VENDOR_ID: usize = 0x00c;
/// Start of device-specific config space for the MMIO transport. For
/// `virtio-net`, `config[0]..config[5]` are the MAC address.
const REG_CONFIG: usize = 0x100;

/// `MagicValue` must read this: ASCII `"virt"` little-endian.
const MAGIC: u32 = 0x7472_6976;
/// virtio device ID 1 = network card. 0 means "no device in this slot".
const DEVICE_ID_NET: u32 = 1;

fn read32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn read8(addr: usize) -> u8 {
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// A discovered virtio-mmio network device.
pub struct NetDevice {
    /// Slot index within the `virt` machine's 32-slot MMIO window.
    pub slot: usize,
    /// `Version` register: 2 = modern MMIO transport, 1 = legacy.
    pub version: u32,
    /// `VendorID` register -- diagnostic only (QEMU reports its own).
    pub vendor_id: u32,
    /// The device's MAC, `config[0]..config[5]`.
    pub mac: [u8; 6],
}

/// Result of one full scan of the MMIO window.
pub struct Scan {
    /// How many slots held *any* device (non-zero `DeviceID`) -- lets the
    /// caller tell "nothing attached" apart from "something attached, but
    /// not a network device".
    pub populated_slots: usize,
    /// The first network device found, if any.
    pub net: Option<NetDevice>,
}

/// Scans all 32 virtio-mmio slots and reports what is there. Reads only --
/// no device state is written, so this is safe to call at any point after
/// boot and cannot disturb a device a later stage will initialize properly.
/// Printing is the caller's job (`nonsecure.rs`'s EL1 bring-up), matching
/// how every other hardware bring-up step in this crate is structured.
pub fn probe() -> Scan {
    let mut populated_slots = 0;
    let mut net = None;

    for slot in 0..SLOT_COUNT {
        let base = VIRTIO_MMIO_BASE + slot * SLOT_STRIDE;

        // A slot that doesn't even answer with the right magic isn't a
        // virtio transport at all -- skip it without touching anything
        // else in its window.
        if read32(base + REG_MAGIC_VALUE) != MAGIC {
            continue;
        }

        let device_id = read32(base + REG_DEVICE_ID);
        if device_id == 0 {
            continue; // valid transport, empty slot
        }
        populated_slots += 1;

        if device_id != DEVICE_ID_NET || net.is_some() {
            continue;
        }

        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = read8(base + REG_CONFIG + i);
        }

        net = Some(NetDevice {
            slot,
            version: read32(base + REG_VERSION),
            vendor_id: read32(base + REG_VENDOR_ID),
            mac,
        });
    }

    Scan {
        populated_slots,
        net,
    }
}
