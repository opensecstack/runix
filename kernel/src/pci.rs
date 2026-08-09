//! PCI configuration-space enumeration — the first slice of network stack
//! work (see the top-level README's roadmap: PCI enumeration ->
//! virtio-net driver -> smoltcp, built as a real ring 3 process, not
//! in-kernel first). This module is deliberately kernel-side and
//! deliberately small: finding *what hardware exists* needs the raw
//! `0xCF8`/`0xCFC` I/O ports, which only ring 0 can touch, but nothing
//! here parses a single byte that came from outside the machine — every
//! value read is whatever QEMU/real firmware put in PCI config space, not
//! attacker-controlled network input. That distinction matters: this is
//! exactly the code that does *not* need the fuzzing/property-testing
//! rigor the eventual packet-parsing code will — see the README's network
//! stack section for where that starts to apply.
//!
//! Legacy mechanism #1 (`CONFIG_ADDRESS`/`CONFIG_DATA`, ports `0xCF8`/
//! `0xCFC`) — the original, universally-supported PCI config access method
//! (https://wiki.osdev.org/PCI#Configuration_Space_Access_Mechanism_.231).
//! PCIe's memory-mapped ECAM is faster and exposes the extended config
//! space, but needs the MCFG ACPI table to find its base address, which
//! this kernel doesn't parse ACPI tables for yet — out of scope until
//! something here actually needs config space past the first 256 bytes.

use alloc::vec::Vec;
use x86_64::instructions::port::Port;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

/// Set bit enables config-space access; bits 23-16/15-11/10-8 select
/// bus/device/function; bits 7-2 select the dword-aligned register (the low
/// 2 bits are dropped — config space is only ever addressed a dword at a
/// time through this mechanism).
fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset & 0xFC)
}

/// Reads one dword from `(bus, device, function)`'s config space at
/// `offset` (rounded down to the nearest dword — see [`config_address`]).
///
/// # Safety
/// Port I/O is inherently a side effect on real (or emulated) hardware
/// state — safe to call at any time on real PCI config space (reads here
/// have no destructive effect, unlike some device MMIO), but still unsafe
/// because the compiler can't verify these ports mean what this function
/// assumes they mean.
unsafe fn read_config_dword(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe {
        let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(CONFIG_DATA);
        address_port.write(config_address(bus, device, function, offset));
        data_port.read()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    /// Class/subclass/prog-if from offset 0x08 — enough to recognize a
    /// device's general kind (e.g. class 0x02 = network controller)
    /// without needing a vendor-specific ID table for every possible NIC.
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

/// Brute-force scans every (bus, device, function) slot PCI defines
/// (256 x 32 x 8) and returns every slot that responds with something
/// other than the "nothing here" sentinel (`vendor_id == 0xFFFF` — real
/// hardware and QEMU alike leave an unpopulated slot's config space
/// reading back as all-ones). Slow in the abstract (65,536 config reads in
/// the worst case) but each read is a single port I/O round-trip and this
/// runs once at boot, not on any hot path — not worth a smarter topology
/// walk (following bridges' secondary bus numbers instead of scanning
/// every bus number blindly) until it actually shows up as boot-time cost
/// worth caring about.
pub fn scan() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let dword0 = unsafe { read_config_dword(bus, device, function, 0x00) };
                let vendor_id = (dword0 & 0xFFFF) as u16;
                if vendor_id == 0xFFFF {
                    // Function 0 reporting nothing means this device slot
                    // is entirely empty — skip the other 7 functions
                    // rather than probing slots that can't be populated
                    // (a multi-function device always populates function 0).
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                let device_id = (dword0 >> 16) as u16;
                let dword2 = unsafe { read_config_dword(bus, device, function, 0x08) };
                devices.push(PciDevice {
                    bus,
                    device,
                    function,
                    vendor_id,
                    device_id,
                    class: (dword2 >> 24) as u8,
                    subclass: (dword2 >> 16) as u8,
                    prog_if: (dword2 >> 8) as u8,
                });
            }
        }
    }
    devices
}

/// Red Hat/Qumranet's PCI vendor ID — every virtio device, including
/// virtio-net, is registered under this vendor regardless of which
/// specific virtio device it implements.
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// virtio-net's "transitional" device ID (supports both the legacy and
/// modern virtio interface) — what QEMU's `-device virtio-net-pci` exposes
/// by default, which is what `xtask` boots every kernel/test instance
/// with. A modern-only virtio-net (`disable-legacy=on`) would instead
/// present 0x1041; not matched here since nothing in this kernel assumes
/// modern-only virtio yet.
const VIRTIO_NET_DEVICE_ID: u16 = 0x1000;

/// Finds the virtio-net device among already-scanned `devices`, if present.
/// Takes a slice rather than re-scanning so callers that already have a
/// `scan()` result (or want to look for more than one device kind) don't
/// pay for the bus walk twice.
pub fn find_virtio_net(devices: &[PciDevice]) -> Option<PciDevice> {
    devices
        .iter()
        .copied()
        .find(|d| d.vendor_id == VIRTIO_VENDOR_ID && d.device_id == VIRTIO_NET_DEVICE_ID)
}
