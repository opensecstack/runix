//! Pure RX-completion servicing policy for `RunixNetDevice::receive`,
//! split out so it can be tested on the host (the bin crate has no test
//! harness; `lib.rs` includes this file under `cfg(test)` with `#[path]`).
//!
//! Threat model F1 (docs/THREAT_MODEL.md, "Unsafe review"): a used-ring
//! entry that is consumed but neither delivered nor re-posted permanently
//! removes one of the `RX_BUFFER_COUNT` buffers from the device's pool. The
//! rules enforced here:
//!
//! 1. Nothing is consumed unless it can be serviced: with no free TX slot
//!    the used ring is not touched at all (a transient shortage loses
//!    nothing; the entries are still there on the next call). This order is
//!    structural: [`service_rx`] is the single function `receive()` calls
//!    and it takes the TX slot before it ever touches the RX ring.
//! 2. A completion whose `desc_id` names a real buffer but whose `len` is
//!    invalid is dropped and *that same buffer is re-posted*.
//! 3. A completion whose `desc_id` is out of range names no buffer we own.
//!    Nothing can be re-posted for it; it is counted/logged by the ring and
//!    skipped. Every buffer stays posted, so a hostile id cannot drain more
//!    buffers than it names (it names none).
//!
//! Driver-side buffer ownership (F4): [`RxPosted`] has one bit per RX buffer,
//! set while the buffer is in the avail ring (posted) and cleared the moment
//! a used entry for it is accepted.
//!
//! 4. A used entry whose id is in range but whose buffer is not marked posted
//!    names a buffer the driver currently holds (a repeated completion, or a
//!    completion for a frame still being serviced). The device does not own
//!    it, so it is counted/logged, not delivered and not re-posted.
//! 5. A re-post of a buffer already marked posted is refused
//!    ([`post_rx_buffer`]): a second avail entry is never written.
//! 6. Re-posts for dropped (bad `len`) buffers are deferred to the end of the
//!    batch, so a second completion for the same id inside one batch finds
//!    the bit clear (rule 4) instead of a freshly re-posted buffer.
//!
//! Limit (not detectable from the driver side): a forged completion that
//! reaches the head of the used ring only after the driver has legitimately
//! re-posted that buffer is indistinguishable from the device having consumed
//! the re-post, and is accepted.

// Resolved via the parent module: `smoltcp_device` in the bin crate (which
// imports it from the lib) and the lib's crate root when `lib.rs` includes this
// file for host tests.
use super::validate_rx_completion;

/// Driver-side ownership of the RX buffers: bit `i` set means buffer `i` is
/// posted (in the avail ring, owned by the device).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxPosted(u32);

impl RxPosted {
    /// No buffer posted.
    pub const fn none() -> Self {
        RxPosted(0)
    }

    fn bit(index: usize) -> u32 {
        match u32::try_from(index) {
            Ok(i) if i < u32::BITS => 1u32 << i,
            _ => 0,
        }
    }

    /// True if buffer `index` is posted. Indices beyond the mask are never
    /// posted.
    pub fn is_posted(&self, index: usize) -> bool {
        self.0 & Self::bit(index) != 0
    }

    /// Marks `index` posted. Returns false (and changes nothing) if it was
    /// already posted or is not representable.
    pub fn try_post(&mut self, index: usize) -> bool {
        let bit = Self::bit(index);
        if bit == 0 || self.0 & bit != 0 {
            return false;
        }
        self.0 |= bit;
        true
    }

    /// Clears `index`: a used entry for it was accepted.
    pub fn release(&mut self, index: usize) {
        self.0 &= !Self::bit(index);
    }

    /// Number of posted buffers.
    #[cfg(test)]
    pub fn count(&self) -> u32 {
        self.0.count_ones()
    }
}

/// Marks `index` posted and runs `write` (the actual avail-ring write), or,
/// if the buffer is already marked posted, refuses: `debug_assert` in debug
/// builds, a silent skip in release. Never writes a second avail entry.
/// Returns whether `write` ran.
pub fn post_rx_buffer<F: FnOnce()>(posted: &mut RxPosted, index: usize, write: F) -> bool {
    if !posted.try_post(index) {
        debug_assert!(
            false,
            "refused re-post of RX buffer {index}: already posted"
        );
        return false;
    }
    write();
    true
}

/// What to do with one used-ring completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAction {
    /// Valid: hand buffer `index` (`len` bytes written) to smoltcp. The RX
    /// token re-posts it after the frame has been consumed.
    Deliver { index: usize, len: u32 },
    /// Invalid `len`, valid `desc_id`: drop the frame, re-post `index`.
    DropAndRepost { index: usize },
    /// `desc_id` out of range: nothing identifiable; count and skip.
    DropUnidentified,
    /// `desc_id` in range but the buffer is not posted (the driver holds it):
    /// the device does not own it; count and skip, re-post nothing.
    DropNotOwned,
}

/// Classifies a device-reported `(desc_id, len)`. Validation itself is
/// `validate_rx_completion` (unchanged); this decides what a failure means
/// for buffer ownership and rejects completions for buffers not posted.
pub fn classify_rx_completion(
    desc_id: u32,
    len: u32,
    buffer_count: usize,
    posted: &RxPosted,
) -> RxAction {
    let index = desc_id as usize;
    if index >= buffer_count {
        return RxAction::DropUnidentified;
    }
    if !posted.is_posted(index) {
        return RxAction::DropNotOwned;
    }
    match validate_rx_completion(desc_id, len, buffer_count) {
        Some((index, len)) => RxAction::Deliver { index, len },
        None => RxAction::DropAndRepost { index },
    }
}

/// The RX virtqueue as `next_rx_frame` needs it.
pub trait RxRing {
    /// Consumes and returns the next used entry `(desc_id, len)`.
    fn poll_used(&mut self) -> Option<(u32, u32)>;
    /// Which buffers are currently posted.
    fn posted(&self) -> RxPosted;
    /// A used entry for `index` was accepted: clear its posted bit.
    fn release(&mut self, index: usize);
    /// Re-posts RX buffer `index` (`index < buffer_count`) to the device
    /// through [`post_rx_buffer`] (refused if already posted).
    fn repost(&mut self, index: usize);
    /// Records (and, the first time, logs) an out-of-range `desc_id`.
    fn note_unidentified(&mut self);
    /// Records (and, the first time, logs) a completion for a buffer the
    /// device does not own.
    fn note_not_owned(&mut self);
}

/// Upper bound on used entries examined per `receive()` call, so a device
/// that keeps producing garbage cannot monopolise the polling loop.
pub const MAX_ENTRIES_PER_CALL: usize = 16;

/// Returns the next deliverable `(buffer_index, len)`, or `None`. Dropped
/// buffers are re-posted at the end of the batch (rule 6). The caller must
/// have secured a TX slot first; use [`service_rx`].
pub fn next_rx_frame<R: RxRing>(ring: &mut R, buffer_count: usize) -> Option<(usize, u32)> {
    debug_assert!(buffer_count <= u32::BITS as usize);
    let mut pending: u32 = 0;
    let mut found = None;
    for _ in 0..MAX_ENTRIES_PER_CALL {
        let Some((desc_id, len)) = ring.poll_used() else {
            break;
        };
        match classify_rx_completion(desc_id, len, buffer_count, &ring.posted()) {
            RxAction::Deliver { index, len } => {
                ring.release(index);
                found = Some((index, len));
                break;
            }
            RxAction::DropAndRepost { index } => {
                ring.release(index);
                pending |= RxPosted::bit(index);
            }
            RxAction::DropUnidentified => ring.note_unidentified(),
            RxAction::DropNotOwned => ring.note_not_owned(),
        }
    }
    for index in 0..buffer_count {
        if pending & RxPosted::bit(index) != 0 {
            ring.repost(index);
        }
    }
    found
}

/// The TX side as `service_rx` needs it.
pub trait TxPort {
    /// Reaps finished TX completions, then returns a free TX slot.
    fn free_tx_slot(&mut self) -> Option<usize>;
}

/// A serviced receive: the TX slot to pair, and the RX frame to deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxService {
    pub tx_slot: usize,
    pub index: usize,
    pub len: u32,
}

/// Everything `receive()` must do, in order: reap TX completions and take a
/// free TX slot FIRST; with none, return without touching the RX ring (rule
/// 1); only then service the RX ring.
pub fn service_rx<R: RxRing, T: TxPort>(
    rx: &mut R,
    tx: &mut T,
    buffer_count: usize,
) -> Option<RxService> {
    let tx_slot = tx.free_tx_slot()?;
    let (index, len) = next_rx_frame(rx, buffer_count)?;
    Some(RxService {
        tx_slot,
        index,
        len,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{RX_BUFFER_SIZE, VIRTIO_NET_HDR_LEN};
    use super::*;
    use proptest::prelude::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    const N: usize = 8;
    const GOOD: u32 = 64;

    /// Device + ring model. `avail` is the avail ring as the device sees it
    /// (entries written by the driver and not yet consumed by the device);
    /// `used` is the used ring, each entry tagged `honest` when the device
    /// really took the buffer from `avail`.
    struct Model {
        posted: RxPosted,
        avail: Vec<usize>,
        used: VecDeque<(u32, u32, bool)>,
        unidentified: u32,
        not_owned: u32,
        releases: u32,
        pushes: u32,
        refused: u32,
        dup_writes: u32,
        forged_accepted: u32,
    }

    impl Model {
        fn new() -> Self {
            let mut m = Model {
                posted: RxPosted::none(),
                avail: Vec::new(),
                used: VecDeque::new(),
                unidentified: 0,
                not_owned: 0,
                releases: 0,
                pushes: 0,
                refused: 0,
                dup_writes: 0,
                forged_accepted: 0,
            };
            for i in 0..N {
                assert!(post_rx_buffer(&mut m.posted, i, || m.avail.push(i)));
            }
            m
        }
        /// Honest device: takes a buffer from the avail ring and completes it.
        fn device_completes(&mut self, id: usize, len: u32) -> bool {
            match self.avail.iter().position(|&i| i == id) {
                Some(pos) => {
                    self.avail.remove(pos);
                    self.used.push_back((id as u32, len, true));
                    true
                }
                None => false,
            }
        }
        /// Lying device: an arbitrary used entry it did not take from avail.
        fn device_lies(&mut self, id: u32, len: u32) {
            self.used.push_back((id, len, false));
        }
        fn posted_count(&self) -> usize {
            self.posted.count() as usize
        }
    }

    impl RxRing for Model {
        fn poll_used(&mut self) -> Option<(u32, u32)> {
            let (id, len, honest) = self.used.pop_front()?;
            if !honest && (id as usize) < N && self.posted.is_posted(id as usize) {
                // Forged, but indistinguishable from a real completion.
                self.forged_accepted += 1;
            }
            Some((id, len))
        }
        fn posted(&self) -> RxPosted {
            self.posted
        }
        fn release(&mut self, index: usize) {
            self.posted.release(index);
            self.releases += 1;
        }
        fn repost(&mut self, index: usize) {
            // post_rx_buffer would debug_assert on a refusal; the proptest
            // wants to count refusals, so go through try_post here and use
            // the real helper for the write.
            if self.posted.is_posted(index) {
                self.refused += 1;
                return;
            }
            let (posted, avail) = (&mut self.posted, &mut self.avail);
            let dup = avail.contains(&index);
            if post_rx_buffer(posted, index, || avail.push(index)) {
                self.pushes += 1;
                if dup {
                    self.dup_writes += 1;
                }
            }
        }
        fn note_unidentified(&mut self) {
            self.unidentified += 1;
        }
        fn note_not_owned(&mut self) {
            self.not_owned += 1;
        }
    }

    struct Gate(bool);
    impl TxPort for Gate {
        fn free_tx_slot(&mut self) -> Option<usize> {
            self.0.then_some(0)
        }
    }

    /// What `RunixRxToken::consume` does after smoltcp reads the frame.
    fn consume(m: &mut Model, index: usize) {
        m.repost(index);
    }

    /// Drains the used ring the way the poll loop does.
    fn drain(m: &mut Model, tx_free: bool) -> usize {
        let mut delivered = 0;
        let mut tx = Gate(tx_free);
        while !m.used.is_empty() {
            match service_rx(m, &mut tx, N) {
                Some(s) => {
                    consume(m, s.index);
                    delivered += 1;
                }
                None if !tx_free => break,
                None => {}
            }
        }
        delivered
    }

    fn assert_avail_unique(m: &Model) {
        let mut seen = [false; N];
        for &i in &m.avail {
            assert!(!seen[i], "duplicate avail entry for buffer {i}");
            seen[i] = true;
        }
    }

    #[test]
    fn bad_len_completions_never_shrink_the_pool() {
        let mut m = Model::new();
        let bad = [
            0u32,
            1,
            VIRTIO_NET_HDR_LEN as u32 - 1,
            RX_BUFFER_SIZE + 1,
            u32::MAX,
        ];
        // Far more bad completions than there are buffers.
        for round in 0..200 {
            for id in 0..N {
                assert!(m.device_completes(id, bad[(round + id) % bad.len()]));
            }
            assert_eq!(drain(&mut m, true), 0);
            assert_eq!(m.posted_count(), N, "round {round}");
            assert_avail_unique(&m);
        }
    }

    #[test]
    fn tx_full_burst_loses_nothing() {
        let mut m = Model::new();
        for id in 0..N {
            m.device_completes(id, 64);
        }
        // All TX slots busy: nothing may be consumed.
        assert_eq!(drain(&mut m, false), 0);
        assert_eq!(m.used.len(), N, "entries must stay in the used ring");
        // TX frees up: every frame is still deliverable.
        assert_eq!(drain(&mut m, true), N);
        assert_eq!(m.posted_count(), N);
    }

    #[test]
    fn out_of_range_id_is_counted_and_drains_nothing() {
        let mut m = Model::new();
        for k in 0..100u32 {
            m.device_lies(N as u32 + k, 64);
            m.device_lies(u32::MAX - k, 0);
        }
        assert_eq!(drain(&mut m, true), 0);
        assert_eq!(m.unidentified, 200);
        assert_eq!(m.posted_count(), N);
    }

    #[test]
    fn valid_frames_still_delivered_between_garbage() {
        let mut m = Model::new();
        m.device_completes(2, 0); // bad len
        m.device_lies(99, 64); // unidentified
        m.device_completes(5, 100); // good
        let mut tx = Gate(true);
        let s = service_rx(&mut m, &mut tx, N).unwrap();
        assert_eq!((s.index, s.len), (5, 100));
        assert!(m.posted.is_posted(2), "bad-len buffer re-posted");
        assert!(
            !m.posted.is_posted(5),
            "delivered buffer owned until consume"
        );
        consume(&mut m, 5);
        assert_eq!(m.posted_count(), N);
        assert_avail_unique(&m);
    }

    #[test]
    fn classification() {
        let all = {
            let mut p = RxPosted::none();
            for i in 0..N {
                assert!(p.try_post(i));
            }
            p
        };
        assert_eq!(
            classify_rx_completion(3, 4, 8, &all),
            RxAction::DropAndRepost { index: 3 }
        );
        assert_eq!(
            classify_rx_completion(8, 100, 8, &all),
            RxAction::DropUnidentified
        );
        assert_eq!(
            classify_rx_completion(7, RX_BUFFER_SIZE, 8, &all),
            RxAction::Deliver {
                index: 7,
                len: RX_BUFFER_SIZE
            }
        );
        let mut p = all;
        p.release(3);
        assert_eq!(classify_rx_completion(3, 64, 8, &p), RxAction::DropNotOwned);
        assert_eq!(classify_rx_completion(3, 4, 8, &p), RxAction::DropNotOwned);
    }

    #[test]
    fn posted_bits() {
        let mut p = RxPosted::none();
        assert!(p.try_post(2));
        assert!(!p.try_post(2), "second post refused");
        assert!(
            !p.try_post(32) && !p.try_post(usize::MAX),
            "unrepresentable"
        );
        assert!(!p.is_posted(32) && !p.is_posted(usize::MAX));
        p.release(2);
        assert!(!p.is_posted(2) && p.count() == 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "refused re-post")]
    fn double_post_trips_debug_assert() {
        let mut p = RxPosted::none();
        let mut writes = 0;
        post_rx_buffer(&mut p, 1, || writes += 1);
        post_rx_buffer(&mut p, 1, || writes += 1);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn double_post_is_skipped_in_release() {
        let mut p = RxPosted::none();
        let mut writes = 0;
        assert!(post_rx_buffer(&mut p, 1, || writes += 1));
        assert!(!post_rx_buffer(&mut p, 1, || writes += 1));
        assert_eq!(writes, 1);
    }

    #[test]
    fn same_id_completed_twice_in_one_batch() {
        // First completion has a bad len (dropped, buffer 3 pending re-post);
        // the repeat names a buffer the driver holds: not delivered, not
        // re-posted, so exactly one avail entry for 3.
        let mut m = Model::new();
        assert!(m.device_completes(3, 0));
        m.device_lies(3, GOOD);
        assert_eq!(drain(&mut m, true), 0);
        assert_eq!(m.not_owned, 1);
        assert_eq!(m.pushes, 1);
        assert_eq!(m.refused, 0);
        assert_eq!(m.posted_count(), N);
        assert_avail_unique(&m);
    }

    #[test]
    fn id_completed_while_driver_holds_it() {
        let mut m = Model::new();
        assert!(m.device_completes(3, GOOD));
        let mut tx = Gate(true);
        let s = service_rx(&mut m, &mut tx, N).unwrap();
        assert_eq!(s.index, 3);
        // Frame 3 is being serviced (token live, not yet consumed): another
        // completion for 3 must not be delivered or re-posted.
        m.device_lies(3, GOOD);
        assert_eq!(service_rx(&mut m, &mut tx, N), None);
        assert_eq!(m.not_owned, 1);
        assert!(!m.posted.is_posted(3));
        consume(&mut m, 3);
        assert_eq!(m.posted_count(), N);
        assert_eq!(m.refused, 0);
        assert_avail_unique(&m);
    }

    #[test]
    fn completed_reposted_and_completed_again_legitimately() {
        let mut m = Model::new();
        for round in 0..50 {
            assert!(m.device_completes(3, GOOD), "round {round}");
            assert_eq!(drain(&mut m, true), 1);
            // consume re-posted it, so the device owns it again.
            assert!(m.posted.is_posted(3));
        }
        assert_eq!(m.not_owned, 0);
        assert_eq!(m.refused, 0);
        assert_avail_unique(&m);
    }

    #[test]
    fn long_honest_run_delivers_every_frame() {
        let mut m = Model::new();
        let mut sent = 0;
        let mut delivered = 0;
        for round in 0..2000usize {
            // A burst of 1..=N frames on distinct buffers.
            for k in 0..=(round % N) {
                if m.device_completes((round + k) % N, GOOD) {
                    sent += 1;
                }
            }
            delivered += drain(&mut m, true);
            assert_eq!(m.posted_count(), N);
        }
        assert_eq!(delivered, sent);
        assert!(sent > 2000);
        assert_eq!(m.not_owned + m.unidentified + m.refused, 0);
        assert_avail_unique(&m);
    }

    // ---- service_rx ordering (call-sequence mocks) ----

    type Log = Rc<RefCell<Vec<&'static str>>>;

    struct MockRx {
        log: Log,
        used: VecDeque<(u32, u32)>,
        posted: RxPosted,
    }
    impl RxRing for MockRx {
        fn poll_used(&mut self) -> Option<(u32, u32)> {
            self.log.borrow_mut().push("poll_used");
            self.used.pop_front()
        }
        fn posted(&self) -> RxPosted {
            self.posted
        }
        fn release(&mut self, index: usize) {
            self.posted.release(index);
        }
        fn repost(&mut self, index: usize) {
            self.log.borrow_mut().push("repost");
            self.posted.try_post(index);
        }
        fn note_unidentified(&mut self) {}
        fn note_not_owned(&mut self) {}
    }

    struct MockTx {
        log: Log,
        slot: Option<usize>,
    }
    impl TxPort for MockTx {
        fn free_tx_slot(&mut self) -> Option<usize> {
            self.log.borrow_mut().push("free_tx_slot");
            self.slot
        }
    }

    fn mocks(slot: Option<usize>, entries: &[(u32, u32)]) -> (MockRx, MockTx, Log) {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut posted = RxPosted::none();
        for i in 0..N {
            posted.try_post(i);
        }
        (
            MockRx {
                log: log.clone(),
                used: entries.iter().copied().collect(),
                posted,
            },
            MockTx {
                log: log.clone(),
                slot,
            },
            log,
        )
    }

    #[test]
    fn tx_full_never_polls_the_used_ring() {
        let (mut rx, mut tx, log) = mocks(None, &[(1, GOOD), (2, GOOD)]);
        assert_eq!(service_rx(&mut rx, &mut tx, N), None);
        assert_eq!(*log.borrow(), vec!["free_tx_slot"]);
        assert_eq!(rx.used.len(), 2, "entries untouched");
    }

    #[test]
    fn tx_check_precedes_the_first_poll() {
        let (mut rx, mut tx, log) = mocks(Some(2), &[(1, GOOD)]);
        let s = service_rx(&mut rx, &mut tx, N).unwrap();
        assert_eq!((s.tx_slot, s.index, s.len), (2, 1, GOOD));
        assert_eq!(*log.borrow(), vec!["free_tx_slot", "poll_used"]);
    }

    #[test]
    fn tx_free_empty_ring_still_checks_tx_first() {
        let (mut rx, mut tx, log) = mocks(Some(0), &[]);
        assert_eq!(service_rx(&mut rx, &mut tx, N), None);
        assert_eq!(*log.borrow(), vec!["free_tx_slot", "poll_used"]);
    }

    #[test]
    fn drops_are_reposted_after_the_tx_check() {
        let (mut rx, mut tx, log) = mocks(Some(0), &[(4, 0), (5, GOOD)]);
        let s = service_rx(&mut rx, &mut tx, N).unwrap();
        assert_eq!(s.index, 5);
        assert_eq!(
            *log.borrow(),
            vec!["free_tx_slot", "poll_used", "poll_used", "repost"]
        );
    }

    /// Calls the REAL `post_rx_buffer`, returning (result, writes made). A
    /// refusal is a `debug_assert` panic in debug builds (caught here and
    /// reported as `false`) and a silent skip in release builds, so the same
    /// refusal path is exercised and checked under both profiles.
    fn real_post(posted: &mut RxPosted, index: usize, expect_refusal: bool) -> (bool, u32) {
        let mut writes = 0u32;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            post_rx_buffer(posted, index, || writes += 1)
        }));
        let ran = match outcome {
            Ok(ran) => {
                assert!(
                    !cfg!(debug_assertions) || !expect_refusal,
                    "debug build must trip the assert on a refusal (index {index})"
                );
                ran
            }
            Err(_) => {
                assert!(
                    cfg!(debug_assertions) && expect_refusal,
                    "unexpected panic posting index {index}"
                );
                false
            }
        };
        (ran, writes)
    }

    proptest! {
        /// Unconditional `post_rx_buffer` calls (no pre-check of `is_posted`)
        /// with in-range, unrepresentable and huge indices, interleaved with
        /// releases. The avail write runs exactly once per not-posted ->
        /// posted transition, never for an already-posted or unrepresentable
        /// index, and the posted mask always equals an independent model.
        #[test]
        fn post_rx_buffer_refusal_path(
            ops in proptest::collection::vec(
                (any::<bool>(), prop_oneof![
                    8 => 0usize..12,
                    2 => 12usize..40,
                    1 => Just(usize::MAX),
                ]),
                0..400,
            )
        ) {
            let mut posted = RxPosted::none();
            let mut model = [false; 32];
            let mut total_writes = 0u32;
            let mut expected_writes = 0u32;
            for (is_post, index) in ops {
                if is_post {
                    let legal = index < 32 && !model[index];
                    let (ran, writes) = real_post(&mut posted, index, !legal);
                    prop_assert_eq!(ran, legal, "index {}", index);
                    prop_assert_eq!(writes, u32::from(legal), "index {}", index);
                    total_writes += writes;
                    if legal {
                        model[index] = true;
                        expected_writes += 1;
                    }
                } else {
                    posted.release(index);
                    if index < 32 {
                        model[index] = false;
                    }
                }
                for (i, &set) in model.iter().enumerate() {
                    prop_assert_eq!(posted.is_posted(i), set, "bit {}", i);
                }
                prop_assert_eq!(
                    posted.count() as usize,
                    model.iter().filter(|&&b| b).count()
                );
                prop_assert!(!posted.is_posted(usize::MAX));
                prop_assert_eq!(total_writes, expected_writes);
            }
        }

        /// Any interleaving of honest completions (ids 0..8, any len), forged
        /// entries (in-range ids, whether or not posted, repeats, and
        /// out-of-range ids) and TX-full/free phases. Invariants hold at every
        /// step, not just at the end.
        #[test]
        fn pool_never_shrinks(
            ops in proptest::collection::vec(
                (0u8..4, 0u32..8, 0usize..7, 0u32..64, any::<bool>(), any::<bool>()),
                0..300,
            )
        ) {
            const LENS: [u32; 7] = [0, 5, 10, 64, 4096, 4097, u32::MAX];
            let mut m = Model::new();
            for (kind, id, len_sel, oor, tx_free, do_drain) in ops {
                let len = LENS[len_sel];
                match kind {
                    0 => { m.device_completes(id as usize, len); }
                    1 => m.device_lies(id, len),             // in range, posted or not
                    2 => m.device_lies(N as u32 + oor, len), // out of range
                    _ => {
                        // Repeat the last queued entry.
                        if let Some(&(i, l, _)) = m.used.back() {
                            m.device_lies(i, l);
                        }
                    }
                }
                if do_drain {
                    drain(&mut m, tx_free);
                }
                // Never more posted than buffers.
                prop_assert!(m.posted_count() <= N);
                // Every buffer the device still holds (not completed) is
                // marked posted: the count never drops below them.
                for &i in &m.avail {
                    prop_assert!(m.posted.is_posted(i));
                }
                let mut distinct = m.avail.clone();
                distinct.sort_unstable();
                distinct.dedup();
                prop_assert!(m.posted_count() >= distinct.len());
                // No re-post of an already posted buffer was ever attempted.
                prop_assert_eq!(m.refused, 0);
                // A duplicate avail entry can only originate from a forged entry
                // that was indistinguishable from a real completion (its
                // leftover duplicate can then cause later ones).
                prop_assert!(m.forged_accepted > 0 || m.dup_writes == 0);
                if m.forged_accepted == 0 {
                    assert_avail_unique(&m);
                }
            }
            drain(&mut m, true);
            // Every accepted entry was re-posted exactly once.
            prop_assert_eq!(m.pushes, m.releases);
            prop_assert_eq!(m.posted_count(), N);
        }
    }
}
