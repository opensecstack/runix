//! A bounded, still hash-chained WORM audit log for `kernel-arm` (Beta gap
//! closure A2/A3; `docs/adrs/0009-bounded-worm-chain-and-denial-auditing.md`).
//!
//! # The problem
//!
//! `svc.rs` used to append every audited decision to one unbounded
//! `citadel_integration::WormLog`. A caller holding a data, session or eSIM
//! capability could repeat a call and grow that chain without limit (threat
//! model gap 18), and the only way to avoid giving a caller that power was to
//! leave denials out of the chain entirely (gap 7). This module is the bound
//! that lets denials be audited without handing every caller a heap-exhaustion
//! lever.
//!
//! # The bound
//!
//! The chain is still append-only and still verified by
//! `WormLog::verify_chain`: nothing is ever deleted, edited or re-linked, so
//! the hash chain stays meaningful for every entry it holds. What is bounded is
//! how many entries each *class* of event may append:
//!
//! - Every [`AuditClass`] has its own fixed `quota` of individual entries.
//!   Classes do not borrow from each other, so a flood in one class cannot
//!   consume another's room. In particular the [`AuditClass::Applied`] class
//!   (governed state changes) has headroom no denial, rejection, metering or
//!   reconciler class can touch.
//! - Once a class has used its quota, a further event of that class is
//!   **coalesced**, never silently dropped: a per-class counter (`dropped`) and
//!   the most recent reason are kept in memory, and a *summary entry* is
//!   committed to the chain when `dropped` first reaches 1 and again each time
//!   it quadruples (1, 4, 16, 64, ...), at most [`MAX_SUMMARY_COMMITS`] times
//!   per class. Summary entries come out of their own reserved room (not the
//!   class quota), so a saturated class can always say that it is saturated.
//! - The total is therefore a compile-time constant, [`TOTAL_CAPACITY`] =
//!   sum of quotas + `CLASS_COUNT * MAX_SUMMARY_COMMITS`, and
//!   [`BoundedAudit::verify`] checks it together with the hash chain.
//!
//! What this does **not** do: it keeps the *first* `quota` events of a class,
//! not the most recent, so a caller can use up a class's quota with harmless
//! events and leave a later, genuine one visible only as a count and a last
//! reason (that is why the classes are split by what a caller can reach, and
//! why `GateBlocked` -- governance verdicts -- is not shared with the
//! fail-closed class). It also cannot tell the chain's reader which dropped
//! events differed from each other beyond the last reason.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use runix_citadel_integration::WormLog;

/// What kind of event an entry is. The class decides which quota it draws on,
/// and is what a coalesced summary is counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditClass {
    /// A governed state change that happened (eSIM transition, MVNO bind /
    /// suspend / reactivate, forced disable, unbind, applied usage reset).
    /// Reserved room no denial, rejection, metering or reconciler class can
    /// use.
    Applied,
    /// An authorized data-layer event that is not a governed state change:
    /// usage feeds, advisory requests, session open / close, the billing
    /// period request. High frequency, so it is kept out of `Applied`.
    DataActivity,
    /// A reachable MARSHAL said `Refuse` or `HardStop`.
    GateBlocked,
    /// The gate blocked without a remote verdict: local evaluation failure,
    /// unreachable under a fail-closed action, or a faulty reply.
    GateFailClosed,
    /// Capability denial on an eSIM syscall.
    CapDenialEsim,
    /// Capability denial on an MVNO syscall.
    CapDenialMvno,
    /// Capability denial on a data syscall.
    CapDenialData,
    /// A request refused after the capability check passed (state-machine or
    /// registry error, the MVNO enable gate, a data-layer refusal).
    Rejected,
    /// Reconciler evidence (an incident observed), deduplicated by the caller
    /// via [`ReconcileMemory`].
    Incident,
    /// "A reconcile pass ran clean", recorded on a state change only.
    CleanPass,
}

/// Number of classes; the index of a class is its position in [`AuditClass::ALL`].
pub const CLASS_COUNT: usize = 10;

/// Per-class individual-entry quotas, indexed by [`AuditClass::index`].
const QUOTAS: [usize; CLASS_COUNT] = [128, 64, 24, 24, 16, 16, 16, 48, 32, 8];

/// How many summary entries one class may ever commit.
pub const MAX_SUMMARY_COMMITS: u32 = 8;

/// A class commits its next summary when `dropped` reaches this multiple of
/// the previous commit's threshold (1, 4, 16, ...).
const SUMMARY_GROWTH: u64 = 4;

/// Longest `last_reason` kept (bytes, cut on a char boundary).
const REASON_LIMIT: usize = 120;

const fn total_capacity() -> usize {
    let mut i = 0;
    let mut sum = 0;
    while i < CLASS_COUNT {
        sum += QUOTAS[i] + MAX_SUMMARY_COMMITS as usize;
        i += 1;
    }
    sum
}

/// The most entries the chain can ever hold.
pub const TOTAL_CAPACITY: usize = total_capacity();

/// Prefix of the `module_id` (subject) of every summary entry.
pub const SUMMARY_SUBJECT_PREFIX: &str = "audit:summary:";

impl AuditClass {
    pub const ALL: [AuditClass; CLASS_COUNT] = [
        AuditClass::Applied,
        AuditClass::DataActivity,
        AuditClass::GateBlocked,
        AuditClass::GateFailClosed,
        AuditClass::CapDenialEsim,
        AuditClass::CapDenialMvno,
        AuditClass::CapDenialData,
        AuditClass::Rejected,
        AuditClass::Incident,
        AuditClass::CleanPass,
    ];

    pub const fn index(self) -> usize {
        match self {
            AuditClass::Applied => 0,
            AuditClass::DataActivity => 1,
            AuditClass::GateBlocked => 2,
            AuditClass::GateFailClosed => 3,
            AuditClass::CapDenialEsim => 4,
            AuditClass::CapDenialMvno => 5,
            AuditClass::CapDenialData => 6,
            AuditClass::Rejected => 7,
            AuditClass::Incident => 8,
            AuditClass::CleanPass => 9,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            AuditClass::Applied => "applied",
            AuditClass::DataActivity => "data-activity",
            AuditClass::GateBlocked => "gate-blocked",
            AuditClass::GateFailClosed => "gate-fail-closed",
            AuditClass::CapDenialEsim => "cap-denial.esim",
            AuditClass::CapDenialMvno => "cap-denial.mvno",
            AuditClass::CapDenialData => "cap-denial.data",
            AuditClass::Rejected => "rejected",
            AuditClass::Incident => "incident",
            AuditClass::CleanPass => "clean-pass",
        }
    }

    pub const fn quota(self) -> usize {
        QUOTAS[self.index()]
    }
}

/// What [`BoundedAudit::record`] / [`BoundedAudit::note_coalesced`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOutcome {
    /// One individual entry was appended.
    Recorded { class: AuditClass },
    /// No individual entry: the event was counted. `summary_committed` says
    /// whether this event also caused a summary entry to be appended.
    Coalesced {
        class: AuditClass,
        /// Events coalesced in this class so far, including this one.
        dropped: u64,
        summary_committed: bool,
        last_reason: String,
    },
}

/// Read-only view of one class's counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassStats {
    pub class: AuditClass,
    pub quota: usize,
    /// Individual entries appended.
    pub recorded: usize,
    /// Events coalesced instead of appended.
    pub dropped: u64,
    /// Summary entries committed.
    pub summaries: u32,
    pub last_reason: String,
}

#[derive(Debug, Clone)]
struct ClassState {
    recorded: usize,
    dropped: u64,
    summaries: u32,
    next_commit_at: u64,
    last_reason: String,
}

impl ClassState {
    fn new() -> Self {
        Self {
            recorded: 0,
            dropped: 0,
            summaries: 0,
            next_commit_at: 1,
            last_reason: String::new(),
        }
    }
}

fn truncate(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return String::from(s);
    }
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// A `WormLog` with a hard size bound; see the module documentation.
pub struct BoundedAudit {
    log: WormLog,
    classes: [ClassState; CLASS_COUNT],
}

impl Default for BoundedAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedAudit {
    pub fn new() -> Self {
        Self {
            log: WormLog::new(),
            classes: core::array::from_fn(|_| ClassState::new()),
        }
    }

    /// Appends one lifecycle-transition entry if `class` still has quota,
    /// otherwise coalesces it (counted, last reason kept, summary committed on
    /// the 1 / 4 / 16 ... boundary). Never fails and never drops an event
    /// without counting it.
    pub fn record(
        &mut self,
        class: AuditClass,
        subject: &str,
        from: &str,
        to: &str,
        authorized: bool,
        reason: Option<String>,
    ) -> AuditOutcome {
        let i = class.index();
        if self.classes[i].recorded < class.quota() && self.log.entries().len() < TOTAL_CAPACITY {
            self.log
                .record_lifecycle_transition(subject, from, to, authorized, reason);
            self.classes[i].recorded += 1;
            return AuditOutcome::Recorded { class };
        }
        let summary = match &reason {
            Some(r) => format!("{subject} [{from} -> {to}]: {r}"),
            None => format!("{subject} [{from} -> {to}]"),
        };
        self.coalesce(class, &summary)
    }

    /// Counts an event of `class` that the caller has decided not to append
    /// (for example a repeated clean reconcile pass), with the same counted,
    /// summary-committing behaviour as a quota overflow. Nothing is appended
    /// for the event itself.
    pub fn note_coalesced(&mut self, class: AuditClass, reason: &str) -> AuditOutcome {
        self.coalesce(class, reason)
    }

    fn coalesce(&mut self, class: AuditClass, reason: &str) -> AuditOutcome {
        let i = class.index();
        let st = &mut self.classes[i];
        st.dropped = st.dropped.saturating_add(1);
        st.last_reason = truncate(reason, REASON_LIMIT);
        let mut summary_committed = false;
        if st.summaries < MAX_SUMMARY_COMMITS && st.dropped >= st.next_commit_at {
            let subject = format!("{SUMMARY_SUBJECT_PREFIX}{}", class.name());
            let text = format!(
                "class {} coalesced {} event(s), not individually recorded (quota {}, recorded {}); last: {}",
                class.name(),
                st.dropped,
                class.quota(),
                st.recorded,
                st.last_reason
            );
            st.summaries += 1;
            st.next_commit_at = st.next_commit_at.saturating_mul(SUMMARY_GROWTH);
            let dropped = st.dropped;
            self.log.record_lifecycle_transition(
                &subject,
                "individual entries",
                &format!("coalesced ({dropped})"),
                false,
                Some(text),
            );
            summary_committed = true;
        }
        let st = &self.classes[i];
        AuditOutcome::Coalesced {
            class,
            dropped: st.dropped,
            summary_committed,
            last_reason: st.last_reason.clone(),
        }
    }

    /// Entries currently in the chain (individual plus summary).
    pub fn len(&self) -> usize {
        self.log.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.entries().is_empty()
    }

    /// `(authorized, reason)` of the newest entry, read from the chain.
    pub fn last_entry(&self) -> Option<(bool, Option<String>)> {
        let e = self.log.entries().last()?;
        Some((e.authorized, e.reason.clone()))
    }

    /// The underlying chain, for inspection.
    pub fn log(&self) -> &WormLog {
        &self.log
    }

    pub fn stats(&self, class: AuditClass) -> ClassStats {
        let st = &self.classes[class.index()];
        ClassStats {
            class,
            quota: class.quota(),
            recorded: st.recorded,
            dropped: st.dropped,
            summaries: st.summaries,
            last_reason: st.last_reason.clone(),
        }
    }

    /// Events coalesced across all classes.
    pub fn total_dropped(&self) -> u64 {
        self.classes
            .iter()
            .fold(0u64, |a, c| a.saturating_add(c.dropped))
    }

    /// The hash chain verifies AND the bound's own books balance: the chain
    /// holds exactly the entries the counters say were appended, no class is
    /// over quota, no class committed more summaries than allowed, every
    /// committed summary is in the chain, and the total is within
    /// [`TOTAL_CAPACITY`].
    pub fn verify(&self) -> bool {
        if !self.log.verify_chain() {
            return false;
        }
        let mut appended = 0usize;
        let mut summaries = 0usize;
        for class in AuditClass::ALL {
            let st = &self.classes[class.index()];
            if st.recorded > class.quota() || st.summaries > MAX_SUMMARY_COMMITS {
                return false;
            }
            appended += st.recorded + st.summaries as usize;
            summaries += st.summaries as usize;
        }
        let in_chain = self.log.entries();
        let summary_entries = in_chain
            .iter()
            .filter(|e| e.module_id.starts_with(SUMMARY_SUBJECT_PREFIX))
            .count();
        in_chain.len() == appended
            && in_chain.len() <= TOTAL_CAPACITY
            && summary_entries == summaries
    }
}

/// What a clean reconcile pass should do to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanPass {
    /// The previous pass was not clean (or none ran): append one entry.
    Record { clean_passes: u64 },
    /// Consecutive clean pass: count it, append nothing.
    Coalesce { clean_passes: u64 },
}

/// Which of one reconcile pass's findings are new, and what to do if it was
/// clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassPlan {
    /// `fresh[i]` is true when `keys[i]` was not reported by the previous
    /// pass (and is the first occurrence within this one): record it.
    pub fresh: Vec<bool>,
    /// `Some` iff the pass had no findings.
    pub clean: Option<CleanPass>,
}

/// The reconciler's memory of its previous pass, so that a persistent finding
/// is recorded when first seen (and again if it goes away and comes back)
/// rather than on every call, and so that a run of clean passes is one entry
/// plus a counter. The memory is the previous pass's key set only, so it is
/// bounded by what one pass can report.
#[derive(Debug, Default)]
pub struct ReconcileMemory {
    prev: BTreeSet<String>,
    last_clean: bool,
    passes: u64,
    clean_passes: u64,
}

impl ReconcileMemory {
    pub const fn new() -> Self {
        Self {
            prev: BTreeSet::new(),
            last_clean: false,
            passes: 0,
            clean_passes: 0,
        }
    }

    /// Total passes observed.
    pub fn passes(&self) -> u64 {
        self.passes
    }

    /// Total clean passes observed (recorded or coalesced).
    pub fn clean_passes(&self) -> u64 {
        self.clean_passes
    }

    /// Feed one pass's finding keys (one per incident, in report order; a key
    /// must contain what identifies the finding and omit what merely changes
    /// from call to call, such as the current tick).
    pub fn observe(&mut self, keys: &[String]) -> PassPlan {
        self.passes = self.passes.saturating_add(1);
        let mut current: BTreeSet<String> = BTreeSet::new();
        let mut fresh = Vec::with_capacity(keys.len());
        for key in keys {
            let new = !self.prev.contains(key);
            let first_here = current.insert(key.clone());
            fresh.push(new && first_here);
        }
        let clean = if keys.is_empty() {
            self.clean_passes = self.clean_passes.saturating_add(1);
            let plan = if self.last_clean {
                CleanPass::Coalesce {
                    clean_passes: self.clean_passes,
                }
            } else {
                CleanPass::Record {
                    clean_passes: self.clean_passes,
                }
            };
            Some(plan)
        } else {
            None
        };
        self.last_clean = keys.is_empty();
        self.prev = current;
        PassPlan { fresh, clean }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(a: &mut BoundedAudit, class: AuditClass, n: usize) -> AuditOutcome {
        a.record(
            class,
            "subject",
            "from",
            "to",
            false,
            Some(format!("event {n}")),
        )
    }

    #[test]
    fn quotas_are_positive_and_capacity_is_their_sum_plus_summary_room() {
        let mut q = 0;
        for c in AuditClass::ALL {
            assert!(c.quota() > 0, "{}", c.name());
            assert_eq!(AuditClass::ALL[c.index()], c);
            q += c.quota() + MAX_SUMMARY_COMMITS as usize;
        }
        assert_eq!(q, TOTAL_CAPACITY);
        // distinct names (a summary subject must identify its class)
        for (i, a) in AuditClass::ALL.iter().enumerate() {
            for b in &AuditClass::ALL[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn a_class_stops_at_its_quota_and_the_rest_are_counted() {
        let mut a = BoundedAudit::new();
        let q = AuditClass::CapDenialEsim.quota();
        for n in 0..q {
            assert_eq!(
                rec(&mut a, AuditClass::CapDenialEsim, n),
                AuditOutcome::Recorded {
                    class: AuditClass::CapDenialEsim
                }
            );
        }
        assert_eq!(a.len(), q);
        let out = rec(&mut a, AuditClass::CapDenialEsim, q);
        match out {
            AuditOutcome::Coalesced {
                dropped,
                summary_committed,
                last_reason,
                ..
            } => {
                assert_eq!(dropped, 1);
                assert!(summary_committed, "first overflow commits a summary");
                assert!(last_reason.contains(&format!("event {q}")));
            }
            other => panic!("expected coalesced, got {other:?}"),
        }
        assert_eq!(a.len(), q + 1);
        assert!(a.verify());
    }

    #[test]
    fn a_flood_of_one_class_grows_the_chain_by_a_constant_and_loses_nothing_silently() {
        let mut a = BoundedAudit::new();
        let events = 5_000usize;
        for n in 0..events {
            rec(&mut a, AuditClass::Rejected, n);
        }
        let s = a.stats(AuditClass::Rejected);
        assert_eq!(s.recorded, AuditClass::Rejected.quota());
        // every event is either an entry or counted
        assert_eq!(s.recorded as u64 + s.dropped, events as u64);
        // last reason is the newest event
        assert!(s.last_reason.contains(&format!("event {}", events - 1)));
        // 1, 4, 16, 64, 256, 1024, 4096 -> 7 commits for ~4950 dropped
        assert_eq!(s.summaries, 7);
        assert_eq!(a.len(), s.recorded + s.summaries as usize);
        assert!(a.verify());
    }

    #[test]
    fn summary_commits_follow_the_geometric_schedule_and_stop_at_the_cap() {
        let mut a = BoundedAudit::new();
        let class = AuditClass::GateFailClosed;
        for n in 0..class.quota() {
            rec(&mut a, class, n);
        }
        let mut committed_at = Vec::new();
        for n in 0..100_000usize {
            if let AuditOutcome::Coalesced {
                dropped,
                summary_committed: true,
                ..
            } = rec(&mut a, class, n)
            {
                committed_at.push(dropped);
            }
        }
        assert_eq!(
            committed_at,
            vec![1, 4, 16, 64, 256, 1024, 4096, 16384],
            "geometric, capped at MAX_SUMMARY_COMMITS"
        );
        assert_eq!(a.stats(class).summaries, MAX_SUMMARY_COMMITS);
        assert_eq!(a.stats(class).dropped, 100_000);
        assert!(a.verify());
    }

    #[test]
    fn a_summary_entry_in_the_chain_states_class_count_and_last_reason() {
        let mut a = BoundedAudit::new();
        let class = AuditClass::CapDenialData;
        for n in 0..class.quota() + 4 {
            rec(&mut a, class, n);
        }
        // dropped = 4 -> summaries committed at 1 and 4
        let summaries: Vec<_> = a
            .log()
            .entries()
            .iter()
            .filter(|e| e.module_id == "audit:summary:cap-denial.data")
            .collect();
        assert_eq!(summaries.len(), 2);
        let last = summaries[1];
        assert!(!last.authorized);
        let reason = last.reason.as_deref().unwrap_or("");
        assert!(reason.contains("coalesced 4 event(s)"), "{reason}");
        assert!(
            reason.contains(&format!("event {}", class.quota() + 3)),
            "{reason}"
        );
        assert!(a.verify());
    }

    #[test]
    fn applied_headroom_survives_a_flood_of_every_other_class() {
        let mut a = BoundedAudit::new();
        for class in AuditClass::ALL {
            if class == AuditClass::Applied {
                continue;
            }
            for n in 0..2_000usize {
                rec(&mut a, class, n);
            }
        }
        // Every other class is saturated; Applied can still take its whole quota.
        for n in 0..AuditClass::Applied.quota() {
            assert_eq!(
                rec(&mut a, AuditClass::Applied, n),
                AuditOutcome::Recorded {
                    class: AuditClass::Applied
                },
                "applied entry {n} must still be appended"
            );
        }
        assert!(a.len() <= TOTAL_CAPACITY);
        assert!(a.verify());
    }

    #[test]
    fn a_flood_of_every_class_stays_within_the_hard_total_and_verifies() {
        let mut a = BoundedAudit::new();
        for n in 0..3_000usize {
            for class in AuditClass::ALL {
                rec(&mut a, class, n);
            }
        }
        assert!(
            a.len() <= TOTAL_CAPACITY,
            "{} > {}",
            a.len(),
            TOTAL_CAPACITY
        );
        assert!(a.verify());
        for class in AuditClass::ALL {
            let s = a.stats(class);
            assert_eq!(s.recorded, class.quota());
            assert_eq!(s.recorded as u64 + s.dropped, 3_000, "{}", class.name());
        }
        assert_eq!(
            a.total_dropped(),
            AuditClass::ALL
                .iter()
                .map(|c| 3_000 - c.quota() as u64)
                .sum::<u64>()
        );
    }

    #[test]
    fn verify_chain_holds_on_a_saturated_log_and_entries_are_linked() {
        let mut a = BoundedAudit::new();
        for n in 0..1_000usize {
            rec(&mut a, AuditClass::Incident, n);
            rec(&mut a, AuditClass::CapDenialMvno, n);
        }
        assert!(a.log().verify_chain());
        let e = a.log().entries();
        for w in e.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
            assert_eq!(w[1].seq, w[0].seq + 1);
        }
        assert!(a.verify());
    }

    #[test]
    fn last_reason_is_truncated_on_a_char_boundary() {
        let mut a = BoundedAudit::new();
        let class = AuditClass::CleanPass;
        let long = "é".repeat(500);
        let out = a.note_coalesced(class, &long);
        match out {
            AuditOutcome::Coalesced { last_reason, .. } => {
                assert!(last_reason.len() <= REASON_LIMIT + 3);
                assert!(last_reason.ends_with("..."));
            }
            other => panic!("{other:?}"),
        }
        assert!(a.verify());
    }

    #[test]
    fn note_coalesced_counts_without_appending_the_event_itself() {
        let mut a = BoundedAudit::new();
        let out = a.note_coalesced(AuditClass::CleanPass, "clean pass 2");
        // the first coalesced event commits a summary (1), the next two do not
        assert!(matches!(
            out,
            AuditOutcome::Coalesced {
                dropped: 1,
                summary_committed: true,
                ..
            }
        ));
        for _ in 0..2 {
            assert!(matches!(
                a.note_coalesced(AuditClass::CleanPass, "clean pass"),
                AuditOutcome::Coalesced {
                    summary_committed: false,
                    ..
                }
            ));
        }
        assert_eq!(a.len(), 1);
        assert_eq!(a.stats(AuditClass::CleanPass).dropped, 3);
        assert!(a.verify());
    }

    #[test]
    fn last_entry_reads_the_newest_chain_entry() {
        let mut a = BoundedAudit::new();
        assert!(a.last_entry().is_none());
        a.record(
            AuditClass::Applied,
            "s",
            "a",
            "b",
            true,
            Some(String::from("ok")),
        );
        let (auth, reason) = a.last_entry().unwrap();
        assert!(auth);
        assert!(reason.unwrap().contains("ok"));
    }

    #[test]
    fn dedupe_records_a_persistent_finding_once() {
        let mut m = ReconcileMemory::new();
        let keys = vec![String::from("a"), String::from("b")];
        assert_eq!(m.observe(&keys).fresh, vec![true, true]);
        for _ in 0..50 {
            let plan = m.observe(&keys);
            assert_eq!(plan.fresh, vec![false, false]);
            assert!(plan.clean.is_none());
        }
    }

    #[test]
    fn dedupe_records_again_when_the_set_changes_or_a_finding_returns() {
        let mut m = ReconcileMemory::new();
        let ab = vec![String::from("a"), String::from("b")];
        let b = vec![String::from("b")];
        let bc = vec![String::from("b"), String::from("c")];
        m.observe(&ab);
        // a disappears: b is not new
        assert_eq!(m.observe(&b).fresh, vec![false]);
        // c is new, b is not
        assert_eq!(m.observe(&bc).fresh, vec![false, true]);
        // a returns after having been absent: new again
        assert_eq!(m.observe(&ab).fresh, vec![true, false]);
    }

    #[test]
    fn dedupe_treats_duplicate_keys_in_one_pass_as_one_finding() {
        let mut m = ReconcileMemory::new();
        let keys = vec![String::from("a"), String::from("a")];
        assert_eq!(m.observe(&keys).fresh, vec![true, false]);
    }

    #[test]
    fn clean_passes_record_on_a_state_change_and_coalesce_otherwise() {
        let mut m = ReconcileMemory::new();
        // never ran: the first clean pass is a state change
        assert_eq!(
            m.observe(&[]).clean,
            Some(CleanPass::Record { clean_passes: 1 })
        );
        assert_eq!(
            m.observe(&[]).clean,
            Some(CleanPass::Coalesce { clean_passes: 2 })
        );
        assert_eq!(
            m.observe(&[]).clean,
            Some(CleanPass::Coalesce { clean_passes: 3 })
        );
        // an incident breaks the run; the next clean pass is recorded again
        assert!(m.observe(&[String::from("x")]).clean.is_none());
        assert_eq!(
            m.observe(&[]).clean,
            Some(CleanPass::Record { clean_passes: 4 })
        );
        assert_eq!(m.passes(), 5);
        assert_eq!(m.clean_passes(), 4);
    }

    /// The reconciler driven the way `svc.rs` drives it, for many passes:
    /// persistent drift, then a long clean run. The chain stays tiny.
    #[test]
    fn repeated_reconcile_passes_do_not_grow_the_chain() {
        let mut audit = BoundedAudit::new();
        let mut mem = ReconcileMemory::new();
        let drift = vec![String::from("usage-over-cap|account:0")];
        for _ in 0..10_000 {
            let plan = mem.observe(&drift);
            for fresh in plan.fresh {
                if fresh {
                    audit.record(AuditClass::Incident, "r", "e", "o", false, None);
                }
            }
        }
        assert_eq!(audit.len(), 1, "one incident entry for 10k passes");

        for _ in 0..10_000 {
            match mem.observe(&[]).clean {
                Some(CleanPass::Record { .. }) => {
                    audit.record(AuditClass::CleanPass, "r", "a", "b", true, None);
                }
                Some(CleanPass::Coalesce { .. }) => {
                    audit.note_coalesced(AuditClass::CleanPass, "clean");
                }
                None => unreachable!(),
            }
        }
        // 1 incident + 1 clean-pass entry + summaries at 1,4,16,...: <= 8
        assert!(audit.len() <= 1 + 1 + MAX_SUMMARY_COMMITS as usize);
        assert_eq!(audit.stats(AuditClass::CleanPass).dropped, 9_999);
        assert!(audit.verify());
    }
}
