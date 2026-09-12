//! `smoltcp::phy::Device` adapter over `virtio::Virtqueue`/`VirtioNet` —
//! Phase 2a's whole reason for existing: everything below is glue between
//! smoltcp's token-based transmit/receive contract and the virtqueue
//! primitives Phase 1 already proved correct (`docs/STATUS.md`'s
//! network-stack section). Deliberately its own module, not folded into
//! `virtio.rs`: that file is pure hand-rolled virtqueue/register mechanics
//! with zero smoltcp awareness, and it stays that way — this module is the
//! only thing that knows both worlds exist.

use crate::virtio::{self, Virtqueue};
use net_driver_host::validate_rx_completion;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

const RX_QUEUE_INDEX: u16 = 0;
const TX_QUEUE_INDEX: u16 = 1;
pub const RX_BUFFER_COUNT: usize = 8;
pub const TX_BUFFER_COUNT: usize = 4;

/// `virtio_net_hdr` length with no optional features negotiated — same
/// constant `net_driver_host::VIRTIO_NET_HDR_LEN` in `lib.rs`, duplicated
/// here only because this module lives in the bin crate, not the lib (see
/// `main.rs`'s `use net_driver_host::...` for the shared one it uses
/// directly; this one exists so `smoltcp_device.rs` doesn't need to depend
/// on the lib crate just for one constant it could trivially restate).
const VIRTIO_NET_HDR_LEN: usize = net_driver_host::VIRTIO_NET_HDR_LEN;
const RX_BUFFER_SIZE: u32 = net_driver_host::RX_BUFFER_SIZE;

pub struct RunixNetDevice {
    net_io_base: u16,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    rx_buffer_va: usize,
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    tx_buffer_va: usize,
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    /// Which TX slots are currently posted to the device and not yet
    /// reclaimed. No `Vec`/free-list crate needed for `TX_BUFFER_COUNT`
    /// this small — a linear scan for the first `false` is plenty.
    tx_in_use: [bool; TX_BUFFER_COUNT],
}

impl RunixNetDevice {
    /// # Safety
    /// Same contract as `Virtqueue::new` for both `rx_queue`/`tx_queue`:
    /// `rx_queue_va`/`tx_queue_va` must each point to `3 * QUEUE_ALIGN`
    /// zeroed bytes this process exclusively owns. `rx_buffer_va`/
    /// `tx_buffer_va` must each point to `RX_BUFFER_COUNT`/`TX_BUFFER_COUNT`
    /// individually page-mapped, physically-backed buffers matching
    /// `rx_buffer_phys`/`tx_buffer_phys`.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        net_io_base: u16,
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
        // write an incoming frame, same requirement Phase 1's `_start`
        // already documents.
        for (i, &phys) in rx_buffer_phys.iter().enumerate() {
            unsafe {
                rx_queue.post(i as u16, phys, RX_BUFFER_SIZE, true);
            }
        }

        RunixNetDevice {
            net_io_base,
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
        virtio::notify(self.net_io_base, RX_QUEUE_INDEX);
    }

    fn free_tx_slot(&mut self) -> Option<usize> {
        self.reap_tx_completions();
        self.tx_in_use.iter().position(|&used| !used)
    }

    /// Frees any TX slot the device has finished reading — must run before
    /// handing out a "free" slot, or a slot still in flight could be
    /// overwritten while the device is still reading it. Not
    /// `validate_rx_completion` reused here (that function's bounds are
    /// specifically documented in terms of RX buffer semantics) — this is
    /// the same "don't trust a device-reported index past what we
    /// actually posted" stance, just plain-inlined for TX, where an
    /// out-of-range `desc_id` is silently ignored rather than trusted.
    fn reap_tx_completions(&mut self) {
        while let Some((desc_id, _len)) = self.tx_queue.poll_used() {
            let index = desc_id as usize;
            if index < TX_BUFFER_COUNT {
                self.tx_in_use[index] = false;
            }
        }
    }
}

// Each token borrows only its own queue (a disjoint field of
// `RunixNetDevice`), not the whole device -- `receive()` needs to hand back
// *two* tokens at once (RX and TX), which a shared `&mut RunixNetDevice` in
// both can't do (two simultaneous mutable borrows of the same value). Every
// other value a token needs (`net_io_base`, buffer VAs/physical addresses)
// is `Copy` and small enough to just copy into the token directly instead
// of borrowing it.
pub struct RunixRxToken<'a> {
    rx_queue: &'a mut Virtqueue,
    net_io_base: u16,
    rx_buffer_va: usize,
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    index: usize,
    len: usize,
}

pub struct RunixTxToken<'a> {
    tx_queue: &'a mut Virtqueue,
    /// This slot's own in-use flag, marked `true` only inside [`Self::consume`]
    /// -- see `receive`/`transmit`'s doc comments for why it must NOT be
    /// marked at token-construction time.
    tx_in_use: &'a mut bool,
    net_io_base: u16,
    tx_buffer_va: usize,
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    slot: usize,
}

impl Device for RunixNetDevice {
    type RxToken<'a> = RunixRxToken<'a>;
    type TxToken<'a> = RunixTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // smoltcp's own contract: `receive()` must hand back both tokens
        // together (it may need to reply, e.g. to an ARP request, while
        // processing the frame that prompted it) -- no RX without spare TX
        // capacity, matching smoltcp's own `Loopback`/real-device examples.
        //
        // Deliberately does NOT mark the paired TX slot in-use here: most
        // inbound packets (e.g. a plain ARP *reply*, not a request) need no
        // reply at all, and smoltcp simply drops an unused `TxToken`
        // without ever calling `consume()` on it. Marking the slot in-use
        // at this point, unconditionally, leaked one TX slot per such
        // packet in an earlier version -- confirmed for real, not
        // theoretical: with only `TX_BUFFER_COUNT` (4) slots total, this
        // silently exhausted all of them after a handful of inbound ARP/
        // ICMP replies, after which `receive()` could never again find a
        // free slot to pair with -- the exact symptom observed (the guest
        // kept re-sending ARP requests for the TCP peer forever, each one
        // answered, but never progressing to an actual TCP SYN). Only
        // `TxToken::consume` marks a slot in-use now, at the point it's
        // actually posted to the device.
        let (desc_id, len) = self.rx_queue.poll_used()?;
        let (index, len) = validate_rx_completion(desc_id, len, RX_BUFFER_COUNT)?;
        let tx_slot = self.free_tx_slot()?;

        let net_io_base = self.net_io_base;
        let rx_buffer_va = self.rx_buffer_va;
        let rx_buffer_phys = self.rx_buffer_phys;
        let tx_buffer_va = self.tx_buffer_va;
        let tx_buffer_phys = self.tx_buffer_phys;

        Some((
            RunixRxToken {
                rx_queue: &mut self.rx_queue,
                net_io_base,
                rx_buffer_va,
                rx_buffer_phys,
                index,
                len: len as usize,
            },
            RunixTxToken {
                tx_queue: &mut self.tx_queue,
                tx_in_use: &mut self.tx_in_use[tx_slot],
                net_io_base,
                tx_buffer_va,
                tx_buffer_phys,
                slot: tx_slot,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // Same reasoning as `receive()` above: the slot isn't marked
        // in-use until `TxToken::consume` actually posts it.
        let slot = self.free_tx_slot()?;
        Some(RunixTxToken {
            tx_queue: &mut self.tx_queue,
            tx_in_use: &mut self.tx_in_use[slot],
            net_io_base: self.net_io_base,
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
        // `virtio::VirtioNet::probe`'s doc comment), so nothing computes or
        // verifies checksums except smoltcp itself. The real network stack
        // on the other end of QEMU/SLIRP checks them for real.
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
        // content has already been consumed by `f` above, so it's safe to
        // hand back to the device immediately.
        unsafe {
            self.rx_queue.post(
                self.index as u16,
                self.rx_buffer_phys[self.index],
                RX_BUFFER_SIZE,
                true,
            );
        }
        virtio::notify(self.net_io_base, RX_QUEUE_INDEX);
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
        virtio::notify(self.net_io_base, TX_QUEUE_INDEX);
        result
    }
}
