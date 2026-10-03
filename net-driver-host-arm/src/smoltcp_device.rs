//! `smoltcp::phy::Device` adapter over [`virtio_net::Virtqueue`] — ported
//! directly from `net-driver-host/src/smoltcp_device.rs`'s
//! `RunixNetDevice`/`RunixRxToken`/`RunixTxToken`, which this module
//! mirrors field-for-field and method-for-method. The only substantive
//! differences from the x86_64 original: the notify/header-length calls go
//! through this crate's own `virtio_net` module (MMIO, not legacy
//! virtio-pci port I/O), and [`crate::VIRTIO_NET_HDR_LEN`] is 12, not 10 —
//! see that constant's own doc comment in `lib.rs`.

use crate::virtio_net::{self, Virtqueue};
use net_driver_host_arm::validate_rx_completion;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

const RX_QUEUE_INDEX: u32 = virtio_net::QUEUE_RX;
const TX_QUEUE_INDEX: u32 = virtio_net::QUEUE_TX;
pub const RX_BUFFER_COUNT: usize = 8;
pub const TX_BUFFER_COUNT: usize = 4;

const VIRTIO_NET_HDR_LEN: usize = net_driver_host_arm::VIRTIO_NET_HDR_LEN;
const RX_BUFFER_SIZE: u32 = net_driver_host_arm::RX_BUFFER_SIZE;

pub struct RunixNetDevice {
    mmio_base: usize,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    rx_buffer_va: usize,
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    tx_buffer_va: usize,
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    /// Which TX slots are currently posted to the device and not yet
    /// reclaimed — same linear-scan-is-plenty reasoning as the x86_64
    /// original (`TX_BUFFER_COUNT` is small enough that no free-list
    /// structure is worth it).
    tx_in_use: [bool; TX_BUFFER_COUNT],
}

impl RunixNetDevice {
    /// # Safety
    /// Same contract as `virtio_net::Virtqueue::new` for both
    /// `rx_queue`/`tx_queue`: `rx_queue_va`/`tx_queue_va` must each point
    /// to `3 * virtio_net::QUEUE_ALIGN` zeroed bytes this process
    /// exclusively owns. `rx_buffer_va`/`tx_buffer_va` must each point to
    /// `RX_BUFFER_COUNT`/`TX_BUFFER_COUNT` individually page-mapped,
    /// physically-backed buffers matching `rx_buffer_phys`/`tx_buffer_phys`.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        mmio_base: usize,
        rx_queue_va: usize,
        rx_queue_size: u16,
        tx_queue_va: usize,
        tx_queue_size: u16,
        rx_buffer_va: usize,
        rx_buffer_phys: [u64; RX_BUFFER_COUNT],
        tx_buffer_va: usize,
        tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    ) -> Self {
        let mut rx_queue = unsafe { Virtqueue::new(rx_queue_va, rx_queue_size) };
        let mut tx_queue = unsafe { Virtqueue::new(tx_queue_va, tx_queue_size) };
        rx_queue.init_avail_flags();
        tx_queue.init_avail_flags();

        // Pre-fill every RX descriptor before the caller marks the device
        // ready -- it must never see itself as "ready" with nowhere to
        // write an incoming frame.
        for (i, &phys) in rx_buffer_phys.iter().enumerate() {
            unsafe {
                rx_queue.post(i as u16, phys, RX_BUFFER_SIZE, true);
            }
        }

        RunixNetDevice {
            mmio_base,
            rx_queue,
            tx_queue,
            rx_buffer_va,
            rx_buffer_phys,
            tx_buffer_va,
            tx_buffer_phys,
            tx_in_use: [false; TX_BUFFER_COUNT],
        }
    }

    pub fn notify_rx(&self) {
        virtio_net::notify(self.mmio_base, RX_QUEUE_INDEX);
    }

    fn free_tx_slot(&mut self) -> Option<usize> {
        self.reap_tx_completions();
        self.tx_in_use.iter().position(|&used| !used)
    }

    /// Frees any TX slot the device has finished reading — must run before
    /// handing out a "free" slot, or a slot still in flight could be
    /// overwritten while the device is still reading it. Same "don't trust
    /// a device-reported index past what we actually posted" stance as
    /// the x86_64 original: an out-of-range `desc_id` is silently ignored,
    /// not trusted.
    fn reap_tx_completions(&mut self) {
        while let Some((desc_id, _len)) = self.tx_queue.poll_used() {
            let index = desc_id as usize;
            if index < TX_BUFFER_COUNT {
                self.tx_in_use[index] = false;
            }
        }
    }
}

// Each token borrows only its own queue, not the whole device -- `receive()`
// needs to hand back *two* tokens at once (RX and TX), which a shared
// `&mut RunixNetDevice` in both can't do. Identical reasoning to the
// x86_64 original's own comment here.
pub struct RunixRxToken<'a> {
    rx_queue: &'a mut Virtqueue,
    mmio_base: usize,
    rx_buffer_va: usize,
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    index: usize,
    len: usize,
}

pub struct RunixTxToken<'a> {
    tx_queue: &'a mut Virtqueue,
    /// This slot's own in-use flag, marked `true` only inside
    /// [`Self::consume`] -- see `receive`/`transmit`'s doc comments for why
    /// it must NOT be marked at token-construction time.
    tx_in_use: &'a mut bool,
    mmio_base: usize,
    tx_buffer_va: usize,
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    slot: usize,
}

impl Device for RunixNetDevice {
    type RxToken<'a> = RunixRxToken<'a>;
    type TxToken<'a> = RunixTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Deliberately does NOT mark the paired TX slot in-use here -- see
        // the x86_64 original's identical comment on the real TX-slot-leak
        // bug this ordering avoids (most inbound packets need no reply at
        // all, and smoltcp simply drops an unused TxToken without ever
        // calling consume() on it).
        let (desc_id, len) = self.rx_queue.poll_used()?;
        let (index, len) = validate_rx_completion(desc_id, len, RX_BUFFER_COUNT)?;
        let tx_slot = self.free_tx_slot()?;

        let mmio_base = self.mmio_base;
        let rx_buffer_va = self.rx_buffer_va;
        let rx_buffer_phys = self.rx_buffer_phys;
        let tx_buffer_va = self.tx_buffer_va;
        let tx_buffer_phys = self.tx_buffer_phys;

        Some((
            RunixRxToken {
                rx_queue: &mut self.rx_queue,
                mmio_base,
                rx_buffer_va,
                rx_buffer_phys,
                index,
                len: len as usize,
            },
            RunixTxToken {
                tx_queue: &mut self.tx_queue,
                tx_in_use: &mut self.tx_in_use[tx_slot],
                mmio_base,
                tx_buffer_va,
                tx_buffer_phys,
                slot: tx_slot,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let slot = self.free_tx_slot()?;
        Some(RunixTxToken {
            tx_queue: &mut self.tx_queue,
            tx_in_use: &mut self.tx_in_use[slot],
            mmio_base: self.mmio_base,
            tx_buffer_va: self.tx_buffer_va,
            tx_buffer_phys: self.tx_buffer_phys,
            slot,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ethernet;
        // Deliberately NOT `ChecksumCapabilities::ignored()` -- this
        // driver negotiated zero virtio-net offload features (see
        // `virtio_net::VirtioNet::negotiate`'s doc comment), so nothing
        // computes or verifies checksums except smoltcp itself.
        caps
    }
}

impl smoltcp::phy::RxToken for RunixRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let buf = unsafe {
            core::slice::from_raw_parts(
                (self.rx_buffer_va + self.index * 4096 + VIRTIO_NET_HDR_LEN) as *const u8,
                self.len - VIRTIO_NET_HDR_LEN,
            )
        };
        let result = f(buf);
        // Re-post this descriptor as RX before returning -- the buffer's
        // content has already been consumed by `f` above.
        unsafe {
            self.rx_queue.post(
                self.index as u16,
                self.rx_buffer_phys[self.index],
                RX_BUFFER_SIZE,
                true,
            );
        }
        virtio_net::notify(self.mmio_base, RX_QUEUE_INDEX);
        result
    }
}

impl smoltcp::phy::TxToken for RunixTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let buf = unsafe {
            core::slice::from_raw_parts_mut((self.tx_buffer_va + self.slot * 4096) as *mut u8, 4096)
        };
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        let result = f(&mut buf[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + len]);
        unsafe {
            self.tx_queue.post(
                self.slot as u16,
                self.tx_buffer_phys[self.slot],
                (VIRTIO_NET_HDR_LEN + len) as u32,
                false,
            );
        }
        // Marked in-use only now that the slot is actually posted to the
        // device -- see `receive`/`transmit`'s doc comments for why.
        *self.tx_in_use = true;
        virtio_net::notify(self.mmio_base, TX_QUEUE_INDEX);
        result
    }
}
