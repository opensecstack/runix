//! `smoltcp::phy::Device` adapter over `virtio::Virtqueue`/`VirtioNet` —
//! Phase 2a's whole reason for existing: everything below is glue between
//! smoltcp's token-based transmit/receive contract and the virtqueue
//! primitives Phase 1 already proved correct (`docs/STATUS.md`'s
//! network-stack section). Deliberately its own module, not folded into
//! `virtio.rs`: that file is pure hand-rolled virtqueue/register mechanics
//! with zero smoltcp awareness, and it stays that way — this module is the
//! only thing that knows both worlds exist.

use crate::syscall::write_all;
use crate::virtio::{self, Virtqueue};
use net_driver_host::validate_rx_completion;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

mod rx_policy;
use rx_policy::{post_rx_buffer, service_rx, RxPosted, RxRing, TxPort};

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
    /// Same contract as `Virtqueue::new` for both `rx_queue`/`tx_queue`:
    /// `rx_queue_va`/`tx_queue_va` must each point to `3 * QUEUE_ALIGN`
    /// zeroed bytes this process exclusively owns. `rx_buffer_va`/
    /// `tx_buffer_va` must each point to `RX_BUFFER_COUNT`/`TX_BUFFER_COUNT`
    /// individually page-mapped, physically-backed buffers matching
    /// `rx_buffer_phys`/`tx_buffer_phys`: buffer `i` occupies the 4096 bytes
    /// at `*_buffer_va + i * 4096` (the `RxToken`/`TxToken` `consume` bodies
    /// compute that address unchecked, with `i` bounded by the
    /// `*_BUFFER_COUNT` consts) and is exclusively owned, RW, and mapped for
    /// the process's lifetime. `rx_queue_size`/`tx_queue_size` must
    /// satisfy `net_driver_host::queue_size_is_valid` (see `Virtqueue::new`).
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
        // SAFETY: forwarded from this fn's own `# Safety` contract
        // (`rx_queue_va` region, zeroed, exclusively owned, page-aligned,
        // size in range).
        let mut rx_queue = unsafe { Virtqueue::new(rx_queue_va, rx_queue_size) };
        // SAFETY: as above, for `tx_queue_va`/`tx_queue_size`; the TX region
        // is distinct from the RX region, so the two queues never alias.
        let mut tx_queue = unsafe { Virtqueue::new(tx_queue_va, tx_queue_size) };
        rx_queue.init_avail_flags();
        tx_queue.init_avail_flags();

        // Pre-fill every RX descriptor before the caller marks the device
        // ready -- it must never see itself as "ready" with nowhere to
        // write an incoming frame, same requirement Phase 1's `_start`
        // already documents.
        let mut rx_posted = RxPosted::none();
        for (i, &phys) in rx_buffer_phys.iter().enumerate() {
            // SAFETY: `i < RX_BUFFER_COUNT` (8) satisfies `post`'s `index <
            // 256`; `phys` is the physical address of RX buffer `i`, a
            // `RX_BUFFER_SIZE`-byte (one-page) buffer this process owns for
            // its whole lifetime (this fn's contract), so it outlives the
            // device's use of it. The device is not yet marked ready, so
            // nothing is consuming the ring concurrently.
            post_rx_buffer(&mut rx_posted, i, || unsafe {
                rx_queue.post(i as u16, phys, RX_BUFFER_SIZE, true);
            });
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
            rx_unidentified: 0,
            rx_not_owned: 0,
            rx_posted,
        }
    }

    pub fn notify_rx(&self) {
        virtio::notify(self.net_io_base, RX_QUEUE_INDEX);
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

// Each token borrows only its own queue (a disjoint field of
// `RunixNetDevice`), not the whole device -- `receive()` needs to hand back
// *two* tokens at once (RX and TX), which a shared `&mut RunixNetDevice` in
// both can't do (two simultaneous mutable borrows of the same value). Every
// other value a token needs (`net_io_base`, buffer VAs/physical addresses)
// is `Copy` and small enough to just copy into the token directly instead
// of borrowing it.
pub struct RunixRxToken<'a> {
    rx_queue: &'a mut Virtqueue,
    rx_posted: &'a mut RxPosted,
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

/// Borrowed view of the RX queue for `rx_policy::next_rx_frame`.
struct RxPort<'a> {
    rx_queue: &'a mut Virtqueue,
    net_io_base: u16,
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
            virtio::notify(self.net_io_base, RX_QUEUE_INDEX);
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
            net_io_base: self.net_io_base,
            rx_buffer_phys: &self.rx_buffer_phys,
            posted: &mut self.rx_posted,
            unidentified: &mut self.rx_unidentified,
            not_owned: &mut self.rx_not_owned,
        };
        let service = service_rx(&mut rx_port, &mut tx_port, RX_BUFFER_COUNT)?;
        let (tx_slot, index, len) = (service.tx_slot, service.index, service.len);

        let net_io_base = self.net_io_base;
        let rx_buffer_va = self.rx_buffer_va;
        let rx_buffer_phys = self.rx_buffer_phys;
        let tx_buffer_va = self.tx_buffer_va;
        let tx_buffer_phys = self.tx_buffer_phys;

        Some((
            RunixRxToken {
                rx_queue: &mut self.rx_queue,
                rx_posted: &mut self.rx_posted,
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
        let slot = TxSlots {
            tx_queue: &mut self.tx_queue,
            tx_in_use: &mut self.tx_in_use,
        }
        .free_tx_slot()?;
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
        // SAFETY: `index < RX_BUFFER_COUNT` and `VIRTIO_NET_HDR_LEN <= len <=
        // RX_BUFFER_SIZE` (4096) were enforced by `validate_rx_completion`,
        // which `rx_policy::classify_rx_completion` calls (reached via
        // `next_rx_frame`, from `service_rx`, from `receive()`); only a
        // `Deliver` verdict builds this token, so the range `rx_buffer_va + index * 4096 + 10 ..` of
        // length `len - 10` lies inside RX buffer `index`'s page
        // (`RunixNetDevice::new`'s contract). As defense in depth the length
        // uses `saturating_sub`, so even a bypassed validator yields an
        // empty slice rather than a wrapped, huge one. `u8` has alignment 1
        // and any byte is valid. The device handed this buffer back through
        // the used ring, so the driver owns it until the `post` below; the
        // slice is dead before then (`f` has returned, and `R` cannot borrow
        // from the higher-ranked `&[u8]`). Also assumes the device does not
        // write this buffer while the slice is live (it only does so for
        // descriptors in the avail ring, and this one is re-posted only
        // after `f`).
        let buf = unsafe {
            core::slice::from_raw_parts(
                (self.rx_buffer_va + self.index * 4096 + VIRTIO_NET_HDR_LEN) as *const u8,
                self.len.saturating_sub(VIRTIO_NET_HDR_LEN),
            )
        };
        let result = f(buf);
        // Re-post this descriptor as RX before returning -- the buffer's
        // content has already been consumed by `f` above, so it's safe to
        // hand back to the device immediately.
        let RunixRxToken {
            rx_queue,
            rx_posted,
            rx_buffer_phys,
            index,
            net_io_base,
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
            virtio::notify(net_io_base, RX_QUEUE_INDEX);
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
        // `free_tx_slot`'s position in the `tx_in_use` array, so `tx_buffer_va
        // + slot * 4096` .. `+ 4096` is exactly TX buffer `slot`'s own page
        // (`RunixNetDevice::new`'s contract), valid RW for the process's
        // lifetime; `u8` alignment 1. Exclusivity: `free_tx_slot` only
        // returns a slot whose `tx_in_use` flag is clear (never posted, or
        // reaped from a used-ring entry by its `poll_used` loop), and this
        // token holds the device's only `&mut` TX queue borrow, so there is
        // at most one live `TxToken` and no other slice over this page. ASSUMPTION: the device does not
        // read a slot it has already returned through the used ring.
        let buf = unsafe {
            core::slice::from_raw_parts_mut((self.tx_buffer_va + self.slot * 4096) as *mut u8, 4096)
        };
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        let result = f(&mut buf[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + len]);
        // SAFETY: `slot < 4` satisfies `post`'s `index < 256`. The
        // `buf[..VIRTIO_NET_HDR_LEN + len]` slicing above already panicked
        // (not UB) if `len` exceeded the page, so `10 + len <= 4096` bytes at
        // `tx_buffer_phys[slot]` are inside that slot's page. The buffer is
        // not touched again, and the slot is not handed out again until the
        // device returns it (`tx_in_use` is set right after this post, with no
        // other access to the token's queue in between).
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
