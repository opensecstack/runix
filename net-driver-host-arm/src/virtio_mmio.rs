//! virtio-mmio device *discovery* — ported from
//! `kernel-arm/src/virtio_mmio.rs`'s `probe()`/`NetDevice`, with the one
//! change this binary's execution context forces: that module runs at EL1
//! under `kernel-arm`'s flat identity map (`mmu.rs`), so `VIRTIO_MMIO_BASE`
//! (`0x0a00_0000`, the `virt` machine's fixed physical window) *is* a valid
//! virtual address to read directly. This binary runs at EL0, inside its
//! own process-private address space, where that is simply not true —
//! there is no identity mapping, and the VA this device's register window
//! ends up mapped at is a decision the (not yet written) loader makes, not
//! a machine-wide constant this code is entitled to assume. [`probe`]
//! therefore takes that VA as an explicit `base: usize` parameter and
//! performs no arithmetic against any baked-in physical address.
//!
//! Narrower in scope than the EL1 original for a second reason, independent
//! of the VA question: `kernel-arm::virtio_mmio::probe` scans all 32
//! slots of the `virt` machine's MMIO window because, at the point it runs,
//! nothing has yet decided which slot holds the network device — discovery
//! *is* its job. By the time this binary runs, that job is expected to
//! already be done: the loader is expected to have identified the one
//! virtio-net-device slot and mapped exactly its `0x200`-byte register
//! window into this process (see `main.rs`'s `NetBootInfo` doc comment for
//! the contract this assumes but does not itself implement). [`probe`]
//! therefore checks the one `base` it's handed, not a 32-slot window.
//!
//! Register offsets, `MAGIC`, and `DEVICE_ID_NET` are unchanged from the
//! EL1 original — those are properties of the virtio-mmio transport itself,
//! not of which exception level is reading them.

/// `MagicValue` register offset, relative to `base`.
#[allow(clippy::identity_op)]
const REG_MAGIC_VALUE: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_VENDOR_ID: usize = 0x00c;
/// Start of device-specific config space. For `virtio-net`,
/// `config[0]..config[5]` are the MAC address — same as the EL1 original.
const REG_CONFIG: usize = 0x100;

/// `MagicValue` must read this: ASCII `"virt"` little-endian.
const MAGIC: u32 = 0x7472_6976;
/// virtio device ID 1 = network card. 0 means "no device here".
const DEVICE_ID_NET: u32 = 1;

fn read32(addr: usize) -> u32 {
    // SAFETY: `addr` is a caller-supplied VA the loader is expected to have
    // mapped as this process's MMIO-window capability (see this module's
    // doc comment) — a plain 32-bit MMIO register read, no side effect
    // beyond whatever the device itself defines for reading this register.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn read8(addr: usize) -> u8 {
    // SAFETY: as above.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// A discovered virtio-mmio network device, at the VA `base` was given as.
pub struct NetDevice {
    base: usize,
    /// `Version` register: 2 = modern MMIO transport, 1 = legacy.
    /// `virtio_net.rs` requires 2 and refuses to run on 1 — see its own
    /// module doc comment for why.
    pub version: u32,
    /// `VendorID` register — diagnostic only.
    pub vendor_id: u32,
    /// The device's MAC, `config[0]..config[5]`.
    pub mac: [u8; 6],
}

impl NetDevice {
    /// The VA this device's register window starts at — the same `base`
    /// [`probe`] was called with. Exposed so `virtio_net.rs` can drive the
    /// same device without this module handing back anything it can't
    /// also be asked for again.
    pub fn base(&self) -> usize {
        self.base
    }
}

/// Every way [`probe`] can fail to find a usable network device at `base`,
/// each carrying the value that made it fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// `MagicValue` didn't read `"virt"` — `base` is not a virtio-mmio
    /// transport at all (wrong VA, or the loader mapped something else
    /// here).
    BadMagic(u32),
    /// `DeviceID` read 0 — a valid transport, but no device attached to
    /// this slot.
    NoDevice,
    /// `DeviceID` read something other than 1 (network) — a valid,
    /// populated transport, just not the device this binary wants.
    WrongDeviceId(u32),
}

impl core::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProbeError::BadMagic(magic) => {
                write!(
                    f,
                    "MagicValue read {magic:#x}, expected {MAGIC:#x} (\"virt\")"
                )
            }
            ProbeError::NoDevice => f.write_str("DeviceID read 0 -- no device in this slot"),
            ProbeError::WrongDeviceId(id) => {
                write!(f, "DeviceID read {id}, expected {DEVICE_ID_NET} (network)")
            }
        }
    }
}

/// Checks that a virtio-net device is really mapped at `base`, and reads
/// its MAC. Reads only — no device state is written, matching the EL1
/// original's own "safe to call at any point, cannot disturb a device a
/// later stage will initialize properly" property.
pub fn probe(base: usize) -> Result<NetDevice, ProbeError> {
    let magic = read32(base + REG_MAGIC_VALUE);
    if magic != MAGIC {
        return Err(ProbeError::BadMagic(magic));
    }

    let device_id = read32(base + REG_DEVICE_ID);
    if device_id == 0 {
        return Err(ProbeError::NoDevice);
    }
    if device_id != DEVICE_ID_NET {
        return Err(ProbeError::WrongDeviceId(device_id));
    }

    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = read8(base + REG_CONFIG + i);
    }

    Ok(NetDevice {
        base,
        version: read32(base + REG_VERSION),
        vendor_id: read32(base + REG_VENDOR_ID),
        mac,
    })
}
