//! `smoltcp::phy::Device` adapter over [`virtio_net::Virtqueue`] — ported
//! directly from `net-driver-host/src/smoltcp_device.rs`'s
//! `RunixNetDevice`/`RunixRxToken`/`RunixTxToken`, which this module
//! mirrors field-for-field and method-for-method. The only substantive
//! differences from the x86_64 original: the notify/header-length calls go
//! through this crate's own `virtio_net` module (MMIO, not legacy
//! virtio-pci port I/O), and [`crate::VIRTIO_NET_HDR_LEN`] is 12, not 10 —
//! see that constant's own doc comment in `lib.rs`.

use crate::syscall::write_all;
use crate::virtio_net::{self, Virtqueue};
use net_driver_host_arm::validate_rx_completion;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

mod rx_policy;
use rx_policy::{post_rx_buffer, service_rx, RxPosted, RxRing, TxPort};

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
    /// Count of used-ring entries whose `desc_id` was out of range (device
    /// lied about buffer ownership). See `rx_policy` rule 3.
    rx_unidentified: u32,
    /// Count of used-ring entries for an in-range buffer the device does not
    /// own (not posted). See `rx_policy` rule 4.
    rx_not_owned: u32,
    /// Driver-side ownership: bit per RX buffer, set while it is in the avail
    /// ring. See `rx_policy` rules 4-6.
    rx_posted: RxPosted,
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
        // SAFETY: forwarded from this fn's own `# Safety` contract: the
        // `rx_queue_va` region is `3 * QUEUE_ALIGN` zeroed bytes, RW, owned
        // exclusively by this process, and aligned for `VirtqDesc` (8). This
        // function checks none of that; the caller establishes it (the sole
        // caller, `main.rs`, passes the fixed page-aligned VA `NET_RXQ_VA`
        // that the loader maps). `rx_queue_size` comes from
        // `negotiate_queue_size(.., min = RX_BUFFER_COUNT)`, so it is a power
        // of two in `RX_BUFFER_COUNT..=256` and every ring access stays
        // inside its own page (descriptor table: 16 * 256 = 4096 bytes).
        let mut rx_queue = unsafe { Virtqueue::new(rx_queue_va, rx_queue_size) };
        // SAFETY: as above, for `tx_queue_va`/`tx_queue_size` (`NET_TXQ_VA`,
        // `min = TX_BUFFER_COUNT`); the TX region is distinct from the RX
        // region (separate fixed VAs in `main.rs`), so the two queues never
        // alias.
        let mut tx_queue = unsafe { Virtqueue::new(tx_queue_va, tx_queue_size) };
        rx_queue.init_avail_flags();
        tx_queue.init_avail_flags();

        // Pre-fill every RX descriptor before the caller marks the device
        // ready -- it must never see itself as "ready" with nowhere to
        // write an incoming frame.
        let mut rx_posted = RxPosted::none();
        for (i, &phys) in rx_buffer_phys.iter().enumerate() {
            // SAFETY: `i < RX_BUFFER_COUNT` (8) satisfies `post`'s `index <
            // 256` and, since `rx_queue_size >= RX_BUFFER_COUNT` (see above),
            // is also below the queue size, so the 8 entries occupy distinct
            // avail-ring slots. `phys` is the physical address of RX buffer
            // `i`, a `RX_BUFFER_SIZE`-byte (one-page) buffer this process
            // owns for its whole lifetime (this fn's contract), so it
            // outlives the device's use of it. `rx_queue` is a local, so this
            // is the only access to it. The device is not yet marked ready
            // (`main.rs` calls `mark_ready` only after this fn returns, and
            // `init_avail_flags` above has already zeroed the avail
            // flags/idx), so nothing is consuming the ring concurrently. Each
            // buffer is posted once: `post_rx_buffer` refuses a buffer whose
            // posted bit is already set.
            post_rx_buffer(&mut rx_posted, i, || unsafe {
                rx_queue.post(i as u16, phys, RX_BUFFER_SIZE, true);
            });
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
            rx_unidentified: 0,
            rx_not_owned: 0,
            rx_posted,
        }
    }

    pub fn notify_rx(&self) {
        virtio_net::notify(self.mmio_base, RX_QUEUE_INDEX);
    }
}

/// Borrowed view of the TX queue and slot flags for `rx_policy::service_rx`
/// (and `transmit`).
struct TxSlots<'a> {
    tx_queue: &'a mut Virtqueue,
    tx_in_use: &'a mut [bool; TX_BUFFER_COUNT],
}

impl TxPort for TxSlots<'_> {
    /// Frees any TX slot the device has finished reading -- this must run
    /// before handing out a "free" slot, or a slot still in flight could be
    /// overwritten while the device is still reading it -- then returns the
    /// first free slot. Same "don't trust a device-reported index past what
    /// we actually posted" stance as for RX: an out-of-range `desc_id` is
    /// silently ignored, not trusted.
    fn free_tx_slot(&mut self) -> Option<usize> {
        while let Some((desc_id, _len)) = self.tx_queue.poll_used() {
            let index = desc_id as usize;
            if index < TX_BUFFER_COUNT {
                self.tx_in_use[index] = false;
            }
        }
        self.tx_in_use.iter().position(|&used| !used)
    }
}

// Each token borrows only its own queue, not the whole device -- `receive()`
// needs to hand back *two* tokens at once (RX and TX), which a shared
// `&mut RunixNetDevice` in both can't do. Identical reasoning to the
// x86_64 original's own comment here.
pub struct RunixRxToken<'a> {
    rx_queue: &'a mut Virtqueue,
    rx_posted: &'a mut RxPosted,
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

/// Borrowed view of the RX queue for `rx_policy::next_rx_frame`.
struct RxPort<'a> {
    rx_queue: &'a mut Virtqueue,
    mmio_base: usize,
    rx_buffer_phys: &'a [u64; RX_BUFFER_COUNT],
    posted: &'a mut RxPosted,
    unidentified: &'a mut u32,
    not_owned: &'a mut u32,
}

impl RxRing for RxPort<'_> {
    fn poll_used(&mut self) -> Option<(u32, u32)> {
        self.rx_queue.poll_used()
    }

    fn posted(&self) -> RxPosted {
        *self.posted
    }

    fn release(&mut self, index: usize) {
        self.posted.release(index);
    }

    fn repost(&mut self, index: usize) {
        // Defense in depth: `rx_policy` only asks for `index < RX_BUFFER_COUNT`.
        if index >= RX_BUFFER_COUNT {
            return;
        }
        let (posted, rx_queue, phys) = (
            &mut *self.posted,
            &mut *self.rx_queue,
            self.rx_buffer_phys[index],
        );
        // SAFETY: `index < RX_BUFFER_COUNT` (checked
        // above) satisfies `post`'s `index < 256`; `rx_buffer_phys[index]` is
        // that RX buffer's physical address, a one-page buffer owned for the
        // process's lifetime. No slice into the buffer is live: slices are
        // only created inside `RunixRxToken::consume`, which has returned (a
        // token needs the `&mut RunixNetDevice` that `receive()` holds, and
        // none is outstanding), and the frame is being dropped unread. The
        // avail ring never gets a second entry for this buffer: the driver
        // tracks ownership itself (`RxPosted`), `post_rx_buffer` writes only
        // on a not-posted -> posted transition and refuses otherwise, and the
        // bit was cleared when the device's used entry for it was accepted, so
        // this no longer rests on the device being honest about which ids it
        // completes. STILL ASSUMED: the device does not write the buffer's
        // memory after it has returned it through the used ring (until it is
        // posted again). This is the unique `&mut` to the queue.
        let wrote = post_rx_buffer(posted, index, || unsafe {
            rx_queue.post(index as u16, phys, RX_BUFFER_SIZE, true);
        });
        if wrote {
            virtio_net::notify(self.mmio_base, RX_QUEUE_INDEX);
        }
    }

    fn note_unidentified(&mut self) {
        if *self.unidentified == 0 {
            write_all(
                b"net-driver: device returned out-of-range RX desc id; ignored
",
            );
        }
        *self.unidentified = self.unidentified.saturating_add(1);
    }

    fn note_not_owned(&mut self) {
        if *self.not_owned == 0 {
            write_all(
                b"net-driver: device completed an RX buffer it does not own; ignored
",
            );
        }
        *self.not_owned = self.not_owned.saturating_add(1);
    }
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
        //
        // Order matters (F1): the TX slot is checked BEFORE any used entry is
        // consumed, and an invalid completion re-posts its buffer -- see
        // `rx_policy`'s module doc.
        //
        // The ordering (TX slot first, RX ring untouched when none) lives in
        // `rx_policy::service_rx`, which is host-tested with call-order mocks;
        // nothing is duplicated here.
        let mut tx_port = TxSlots {
            tx_queue: &mut self.tx_queue,
            tx_in_use: &mut self.tx_in_use,
        };
        let mut rx_port = RxPort {
            rx_queue: &mut self.rx_queue,
            mmio_base: self.mmio_base,
            rx_buffer_phys: &self.rx_buffer_phys,
            posted: &mut self.rx_posted,
            unidentified: &mut self.rx_unidentified,
            not_owned: &mut self.rx_not_owned,
        };
        let service = service_rx(&mut rx_port, &mut tx_port, RX_BUFFER_COUNT)?;
        let (tx_slot, index, len) = (service.tx_slot, service.index, service.len);

        let mmio_base = self.mmio_base;
        let rx_buffer_va = self.rx_buffer_va;
        let rx_buffer_phys = self.rx_buffer_phys;
        let tx_buffer_va = self.tx_buffer_va;
        let tx_buffer_phys = self.tx_buffer_phys;

        Some((
            RunixRxToken {
                rx_queue: &mut self.rx_queue,
                rx_posted: &mut self.rx_posted,
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
        let slot = TxSlots {
            tx_queue: &mut self.tx_queue,
            tx_in_use: &mut self.tx_in_use,
        }
        .free_tx_slot()?;
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
        // SAFETY: `index < RX_BUFFER_COUNT` and `VIRTIO_NET_HDR_LEN <= len <=
        // RX_BUFFER_SIZE` were enforced by `validate_rx_completion`, which
        // `rx_policy::classify_rx_completion` calls (reached via
        // `next_rx_frame`, from `service_rx`, from `receive()`); only a
        // `Deliver` verdict builds this token, so the slice lies inside RX
        // buffer `index`'s page. As defense in depth the length uses
        // `saturating_sub`, so even a bypassed validator yields an empty
        // slice, not a wrapped, huge one.
        let buf = unsafe {
            core::slice::from_raw_parts(
                (self.rx_buffer_va + self.index * 4096 + VIRTIO_NET_HDR_LEN) as *const u8,
                self.len.saturating_sub(VIRTIO_NET_HDR_LEN),
            )
        };
        let result = f(buf);
        // Re-post this descriptor as RX before returning -- the buffer's
        // content has already been consumed by `f` above.
        let RunixRxToken {
            rx_queue,
            rx_posted,
            rx_buffer_phys,
            index,
            mmio_base,
            ..
        } = self;
        // SAFETY: `index < RX_BUFFER_COUNT`
        // (validated by `classify_rx_completion`, see above) satisfies `post`'s `index < 256`;
        // `rx_buffer_phys[index]` is that same RX buffer's physical address, a
        // one-page buffer owned for the process's lifetime, and nothing
        // borrows its contents any more (`buf` is out of use). `self.rx_queue`
        // is the unique `&mut` to the queue held by this token. `receive()`
        // cleared this buffer's posted bit when it accepted the device's used
        // entry, so `post_rx_buffer` writes exactly one avail entry here (it
        // refuses, writing nothing, if the buffer were somehow already
        // posted); a drop of the token without `consume` never re-posts.
        let wrote = post_rx_buffer(rx_posted, index, || unsafe {
            rx_queue.post(index as u16, rx_buffer_phys[index], RX_BUFFER_SIZE, true);
        });
        if wrote {
            virtio_net::notify(mmio_base, RX_QUEUE_INDEX);
        }
        result
    }
}

impl smoltcp::phy::TxToken for RunixTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // SAFETY: `slot < TX_BUFFER_COUNT` (4) because it came from
        // `free_tx_slot`'s position in the `tx_in_use` array (directly in
        // `transmit`, via `service_rx` in `receive`), so `tx_buffer_va + slot
        // * 4096` .. `+ 4096` is exactly TX buffer `slot`'s own page
        // (`RunixNetDevice::new`'s contract), valid RW for the process's
        // lifetime; `u8` has alignment 1 and any byte is valid. Exclusivity:
        // `free_tx_slot` only returns a slot whose `tx_in_use` flag is clear
        // (never posted, or reaped from a used-ring entry), and the flag is
        // set only after the `post` below. Each token holds the device's
        // `&mut` TX queue borrow, so there is at most one live `TxToken`, and
        // no other slice over this page exists (RX slices are over a distinct
        // region). This slice is dead once `f` returns. ASSUMPTION: the
        // device does not read a slot it has already returned through the
        // used ring. `free_tx_slot` clears the flag from the device-reported
        // `desc_id` without checking the slot was in flight, so a lying
        // device can at worst make us send a torn frame; it cannot make this
        // slice alias another Rust reference.
        let buf = unsafe {
            core::slice::from_raw_parts_mut((self.tx_buffer_va + self.slot * 4096) as *mut u8, 4096)
        };
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        let result = f(&mut buf[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + len]);
        // SAFETY: `slot < 4` satisfies `post`'s `index < 256` and is below
        // `tx_queue_size` (`>= TX_BUFFER_COUNT`, see `new`). The
        // `buf[..VIRTIO_NET_HDR_LEN + len]` slicing above already panicked
        // (not UB) if `len` exceeded the page, so `12 + len <= 4096` bytes at
        // `tx_buffer_phys[slot]` are inside that slot's page, a buffer this
        // process owns for its lifetime (so it outlives the device's use of
        // it). `buf` is not touched again, and the slot is not handed out
        // again until the device returns it through the used ring
        // (`tx_in_use` is set right after this post, with no other access to
        // the token's queue in between). `self.tx_queue` is the unique `&mut`
        // to the queue held by this token.
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
