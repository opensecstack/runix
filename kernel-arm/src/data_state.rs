//! Bounded in-kernel state for the data policy syscalls (Beta item 4.3): the
//! per-account usage counters and the open data-session table. Pure data
//! structure, no hardware and no locking of its own, so `cargo test --lib`
//! covers the bounds and the idempotent-open semantics; `data.rs` (binary
//! side) owns the one `spin::Mutex<DataState>` that wraps it.
//!
//! # What lives here, and what deliberately does not
//!
//! - Usage counters (`runix_mobile::policy::DataUsage` per account id) and,
//!   next to each, `last_used` -- the value the previous reconciliation saw,
//!   which is the reconciler's `last_used_bytes` input for its regression
//!   check. The counter only ever goes up (`apply_usage` saturates), so a
//!   regression incident can only mean the state was tampered with; it is a
//!   tripwire, not an expected event. The one legitimate way it goes back down
//!   is [`DataState::reset_usage`] (the governed `SYS_DATA_RESET`), which clears
//!   `last_used` in the same critical section so the reconciler reads the reset
//!   as a new period, not as tampering (see
//!   `reconcile::ObservedAccount::last_used_bytes`).
//! - The open-session table the reconciler snapshots. A session is recorded
//!   only when the policy engine allowed it.
//! - NOT here: entitlements (`data_codes::demo_entitlement`), account
//!   standing and profile lifecycle (owned by `mvno.rs` / `sim.rs`; copied in
//!   by the caller), capabilities, WORM audit.
//! - Billing periods (`runix_mobile::period::BillingPeriod` per account id) and,
//!   next to each, `reset_requested_since` -- the tick at which the kernel first
//!   told a caller "this period is over, please reset". A period is DATA: the
//!   only things that ever start one are [`DataState::set_period`] (boot-time
//!   demo data) and [`DataState::start_next_period`] (the governed reset's
//!   success path); nothing here reads a clock, resets on a schedule, or acts on
//!   an elapsed period. `now` is always an explicit argument the caller read
//!   from the generic timer at the moment it asked.
//!
//! # Lock order: this state is a LEAF
//!
//! `data.rs` holds the lock around a `DataState` only for the duration of one
//! method here, and every method is pure (no call out of this module). So the
//! data lock is never held while calling into `mvno`, `sim` or the `svc.rs`
//! audit, and none of those call back into data: whatever order the registry
//! -> sim rule (see `mvno.rs`) imposes among themselves, the data lock sits
//! below all of them and cannot take part in a cycle. The syscall handlers
//! copy what they need out of this state before they audit.

use alloc::vec::Vec;

use runix_mobile::period::{
    assess_period, next_period, period_request, BillingPeriod, ObservedPeriod, PeriodAssessment,
    PeriodError, PeriodRequest,
};
use runix_mobile::policy::{
    apply_usage, evaluate_usage, reset_usage, AccountStandingForData, DataEntitlement, DataUsage,
    NetworkClass, PolicyDecisionRecord, ProfileLifecycleForData, SessionDecision, SessionRequest,
};

/// Most accounts the usage table tracks. Equals the account registry's own
/// bound (`runix_mobile::account::MAX_ACCOUNTS`), so every account that can
/// exist can also be metered.
pub const MAX_DATA_ACCOUNTS: usize = 16;

/// Most data sessions open at once. One per (account, slot, profile); the
/// registry bounds profiles at 4 per account, so 16 is demo-scale headroom.
pub const MAX_DATA_SESSIONS: usize = 16;

/// A table was full; nothing was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableFull;

/// One account's usage counter plus the reconciler's bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageEntry {
    pub account: u64,
    pub usage: DataUsage,
    /// `used_bytes` at the previous reconciliation; `None` before the first.
    pub last_used: Option<u64>,
}

/// One open data session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSession {
    pub account: u64,
    pub slot: usize,
    pub profile: u8,
    pub roaming: bool,
}

/// One account's billing period plus the request bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodEntry {
    pub account: u64,
    pub period: BillingPeriod,
    /// Tick at which a reset request was FIRST issued for the current period
    /// (`None` before any, and again after a governed reset starts the next
    /// period). The reconciler reads it to measure how long a request stayed
    /// unactioned (`period::check_periods`); it is evidence, never authority.
    pub reset_requested_since: Option<u64>,
}

/// What [`DataState::advise_period`] found. ADVICE ONLY: `request` is the
/// pure model's statement that a reset is due, not a reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodAdvice {
    pub assessment: PeriodAssessment,
    /// `Some(ResetUsage)` iff the period has elapsed (never for a rewound
    /// clock -- see `period::period_request`).
    pub request: Option<PeriodRequest>,
    /// `true` only on the call that recorded `reset_requested_since` (the first
    /// request for this period). The caller audits that one transition rather
    /// than every poll, so polling cannot grow the WORM chain without bound.
    pub first_request: bool,
}

/// What [`DataState::start_next_period`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodStarted {
    /// The account has no period (nothing to start; behaves as before periods
    /// existed).
    NoPeriod,
    /// The next period is installed and the request marker cleared.
    Started(BillingPeriod),
    /// `next_period` refused (the reset tick is before the old period's start:
    /// a rewound clock). The OLD period and marker are left exactly as they
    /// were, so the anomaly stays visible to the reconciler
    /// (`ClockBeforeStart`) instead of being papered over.
    Rejected(PeriodError),
}

/// What `decide_and_open` did with the session table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRecorded {
    /// The engine denied: the table was not touched (and an already-open
    /// session is NOT closed -- closing is the caller's act, never ours).
    NotRecorded,
    /// Allowed; a new row was added.
    Opened,
    /// Allowed; the (account, slot, profile) session was already open and its
    /// roaming flag was refreshed. No second row.
    Refreshed,
    /// Allowed by policy but the table is full, so it could not be recorded.
    TableFull,
}

/// Result of [`DataState::decide_and_open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOutcome {
    pub record: PolicyDecisionRecord,
    pub recorded: SessionRecorded,
}

#[derive(Debug, Default)]
pub struct DataState {
    usage: Vec<UsageEntry>,
    sessions: Vec<DataSession>,
    periods: Vec<PeriodEntry>,
}

impl DataState {
    pub const fn new() -> Self {
        Self {
            usage: Vec::new(),
            sessions: Vec::new(),
            periods: Vec::new(),
        }
    }

    /// The counter for `account`; an account never fed has used nothing.
    pub fn usage_of(&self, account: u64) -> DataUsage {
        self.usage
            .iter()
            .find(|e| e.account == account)
            .map(|e| e.usage)
            .unwrap_or(DataUsage { used_bytes: 0 })
    }

    /// Add `bytes` to `account`'s counter (saturating, via the engine's own
    /// `apply_usage`). Returns `(before, after)`. A first-ever feed for a new
    /// account needs a free row; a full table refuses rather than evicting.
    pub fn feed_usage(
        &mut self,
        account: u64,
        bytes: u64,
    ) -> Result<(DataUsage, DataUsage), TableFull> {
        if let Some(e) = self.usage.iter_mut().find(|e| e.account == account) {
            let before = e.usage;
            e.usage = apply_usage(before, bytes);
            return Ok((before, e.usage));
        }
        if self.usage.len() >= MAX_DATA_ACCOUNTS {
            return Err(TableFull);
        }
        let before = DataUsage { used_bytes: 0 };
        let after = apply_usage(before, bytes);
        self.usage.push(UsageEntry {
            account,
            usage: after,
            last_used: None,
        });
        Ok((before, after))
    }

    /// Start a new usage period for `account`: set its counter to the engine's
    /// `reset_usage()` and clear `last_used` (the reconciler's memory), in this
    /// one critical section. Clearing `last_used` is what tells the reconciler a
    /// legitimate period reset happened; without it its `UsageRegression` check
    /// would report the reset as counter tampering. Returns `(before, after)`.
    ///
    /// Touches nothing else: no session is closed, no standing or profile
    /// changes (the caller lifts the cap, it does not also tear down or
    /// restore anything). An account that was never fed has no row and nothing
    /// to reset (`(0, 0)`); no row is created for it.
    pub fn reset_usage(&mut self, account: u64) -> (DataUsage, DataUsage) {
        match self.usage.iter_mut().find(|e| e.account == account) {
            Some(e) => {
                let before = e.usage;
                e.usage = reset_usage();
                e.last_used = None;
                (before, e.usage)
            }
            None => (DataUsage { used_bytes: 0 }, reset_usage()),
        }
    }

    /// Install `period` as `account`'s current billing period and clear any
    /// outstanding request marker (a replaced period is a fresh one). DEMO
    /// DATA ONLY at boot; the runtime path is [`Self::start_next_period`]. A
    /// first period for a new account needs a free row (same bound as the usage
    /// table); a full table refuses rather than evicting.
    pub fn set_period(&mut self, account: u64, period: BillingPeriod) -> Result<(), TableFull> {
        if let Some(e) = self.periods.iter_mut().find(|e| e.account == account) {
            e.period = period;
            e.reset_requested_since = None;
            return Ok(());
        }
        if self.periods.len() >= MAX_DATA_ACCOUNTS {
            return Err(TableFull);
        }
        self.periods.push(PeriodEntry {
            account,
            period,
            reset_requested_since: None,
        });
        Ok(())
    }

    /// `account`'s current period, if it has one.
    pub fn period_of(&self, account: u64) -> Option<BillingPeriod> {
        self.periods
            .iter()
            .find(|e| e.account == account)
            .map(|e| e.period)
    }

    /// Assess `account`'s period at the caller-supplied `now` and, if a reset
    /// is due, remember WHEN it was first requested. `None`: no period.
    ///
    /// READ-ONLY ADVICE. The one write is `reset_requested_since`, set the first
    /// time a request is issued and never moved afterwards (a later poll must
    /// not make an old request look young -- the reconciler's grace runs from
    /// the first one). Nothing is reset, restricted or closed here.
    pub fn advise_period(&mut self, account: u64, now: u64) -> Option<PeriodAdvice> {
        let e = self.periods.iter_mut().find(|e| e.account == account)?;
        let assessment = assess_period(&e.period, now);
        let request = period_request(&e.period, now);
        let first_request = request.is_some() && e.reset_requested_since.is_none();
        if first_request {
            e.reset_requested_since = Some(now);
        }
        Some(PeriodAdvice {
            assessment,
            request,
            first_request,
        })
    }

    /// The governed reset took effect at tick `now`: install
    /// `next_period(old, now)` (start = `now`, same length) and clear the
    /// request marker. Called ONLY from the reset's success path, after its
    /// capability check and MARSHAL gate; a denied reset never reaches it, so a
    /// denied reset starts no period and leaves the request outstanding.
    pub fn start_next_period(&mut self, account: u64, now: u64) -> PeriodStarted {
        let Some(e) = self.periods.iter_mut().find(|e| e.account == account) else {
            return PeriodStarted::NoPeriod;
        };
        match next_period(&e.period, now) {
            Ok(next) => {
                e.period = next;
                e.reset_requested_since = None;
                PeriodStarted::Started(next)
            }
            Err(err) => PeriodStarted::Rejected(err),
        }
    }

    /// The governed reset in ONE critical section: usage back to zero
    /// ([`Self::reset_usage`]) and the next period started at `now`
    /// ([`Self::start_next_period`]). One section, so no reader sees a zeroed
    /// counter inside an old, elapsed period (or the reverse).
    pub fn reset_usage_and_period(
        &mut self,
        account: u64,
        now: u64,
    ) -> (DataUsage, DataUsage, PeriodStarted) {
        let (before, after) = self.reset_usage(account);
        let started = self.start_next_period(account, now);
        (before, after, started)
    }

    /// The reconciler's view of every period: copies, in table order
    /// (`check_periods` is order-independent).
    pub fn period_snapshot(&self) -> Vec<ObservedPeriod> {
        self.periods
            .iter()
            .map(|e| ObservedPeriod {
                account: e.account,
                period: e.period,
                reset_requested_since: e.reset_requested_since,
            })
            .collect()
    }

    /// Evaluate a session request against the CURRENT usage and, only if the
    /// engine allows it, record the session. One critical section, so the
    /// usage the decision saw is the usage in force when the row is written.
    /// The decision is the engine's, unmodified; this function adds nothing to
    /// it and takes nothing away (a deny leaves every row alone).
    #[allow(clippy::too_many_arguments)]
    pub fn decide_and_open(
        &mut self,
        account: u64,
        slot: usize,
        profile: u8,
        roaming: bool,
        standing: AccountStandingForData,
        lifecycle: ProfileLifecycleForData,
        entitlement: DataEntitlement,
    ) -> OpenOutcome {
        let record = PolicyDecisionRecord::decide(SessionRequest {
            standing,
            lifecycle,
            entitlement,
            usage: self.usage_of(account),
            network: if roaming {
                NetworkClass::Roaming
            } else {
                NetworkClass::Home
            },
        });
        let recorded = match record.decision {
            SessionDecision::Deny(_) => SessionRecorded::NotRecorded,
            SessionDecision::Allow | SessionDecision::AllowThrottled => {
                self.record_session(DataSession {
                    account,
                    slot,
                    profile,
                    roaming,
                })
            }
        };
        OpenOutcome { record, recorded }
    }

    fn record_session(&mut self, s: DataSession) -> SessionRecorded {
        if let Some(existing) = self
            .sessions
            .iter_mut()
            .find(|e| e.account == s.account && e.slot == s.slot && e.profile == s.profile)
        {
            existing.roaming = s.roaming;
            return SessionRecorded::Refreshed;
        }
        if self.sessions.len() >= MAX_DATA_SESSIONS {
            return SessionRecorded::TableFull;
        }
        self.sessions.push(s);
        SessionRecorded::Opened
    }

    /// Remove one session; `true` if it was open. The CALLER carrying out a
    /// restriction (or finishing normally) -- nothing in the policy path calls
    /// this on its own.
    pub fn close_session(&mut self, account: u64, slot: usize, profile: u8) -> bool {
        let before = self.sessions.len();
        self.sessions
            .retain(|e| !(e.account == account && e.slot == slot && e.profile == profile));
        self.sessions.len() != before
    }

    /// Copies of both tables for the reconciler's snapshot.
    pub fn snapshot(&self) -> (Vec<UsageEntry>, Vec<DataSession>) {
        (self.usage.clone(), self.sessions.clone())
    }

    /// Record that `observed` is what the reconciler just saw: sets each
    /// matching row's `last_used` to the OBSERVED value (not to the live one,
    /// which could have moved) -- the only mutation the reconcile syscall
    /// can make to this state, and bookkeeping only.
    pub fn mark_observed(&mut self, observed: &[UsageEntry]) {
        for o in observed {
            if let Some(e) = self.usage.iter_mut().find(|e| e.account == o.account) {
                e.last_used = Some(o.usage.used_bytes);
            }
        }
    }

    /// Band of `account`'s current usage under `entitlement` (what the usage
    /// feed's assessment is computed from).
    pub fn assess(
        &self,
        account: u64,
        entitlement: &DataEntitlement,
    ) -> runix_mobile::policy::UsageAssessment {
        evaluate_usage(entitlement, &self.usage_of(account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runix_mobile::policy::{ActionRequest, DenyReason, UsageBand};

    fn ent() -> DataEntitlement {
        DataEntitlement::new(Some(1000), 80, false, 150).unwrap()
    }

    fn open(s: &mut DataState, account: u64, roaming: bool) -> OpenOutcome {
        s.decide_and_open(
            account,
            0,
            0,
            roaming,
            AccountStandingForData::Active,
            ProfileLifecycleForData::Enabled,
            ent(),
        )
    }

    #[test]
    fn unfed_account_has_used_nothing() {
        assert_eq!(DataState::new().usage_of(7).used_bytes, 0);
    }

    #[test]
    fn feed_accumulates_and_saturates() {
        let mut s = DataState::new();
        assert_eq!(s.feed_usage(0, 900).unwrap().1.used_bytes, 900);
        let (b, a) = s.feed_usage(0, 700).unwrap();
        assert_eq!((b.used_bytes, a.used_bytes), (900, 1600));
        let (_, a) = s.feed_usage(0, u64::MAX).unwrap();
        assert_eq!(a.used_bytes, u64::MAX);
        // Still saturated, never wraps back to a small number.
        assert_eq!(s.feed_usage(0, 5).unwrap().1.used_bytes, u64::MAX);
    }

    #[test]
    fn usage_table_is_bounded_and_refuses_rather_than_evicts() {
        let mut s = DataState::new();
        for a in 0..MAX_DATA_ACCOUNTS as u64 {
            s.feed_usage(a, 1).unwrap();
        }
        assert_eq!(s.feed_usage(MAX_DATA_ACCOUNTS as u64, 1), Err(TableFull));
        // Existing accounts can still be fed when full.
        assert!(s.feed_usage(0, 1).is_ok());
        assert_eq!(s.usage_of(0).used_bytes, 2);
    }

    #[test]
    fn allow_records_and_reopen_refreshes_instead_of_duplicating() {
        let mut s = DataState::new();
        let o = open(&mut s, 0, false);
        assert_eq!(o.record.decision, SessionDecision::Allow);
        assert_eq!(o.recorded, SessionRecorded::Opened);
        let o = open(&mut s, 0, false);
        assert_eq!(o.recorded, SessionRecorded::Refreshed);
        assert_eq!(s.snapshot().1.len(), 1);
    }

    #[test]
    fn throttled_band_is_allow_throttled_and_still_recorded() {
        let mut s = DataState::new();
        s.feed_usage(0, 900).unwrap();
        let o = open(&mut s, 0, false);
        assert_eq!(o.record.decision, SessionDecision::AllowThrottled);
        assert_eq!(o.recorded, SessionRecorded::Opened);
    }

    #[test]
    fn deny_records_nothing_and_does_not_close_an_open_session() {
        let mut s = DataState::new();
        open(&mut s, 0, false);
        let o = open(&mut s, 0, true);
        assert_eq!(
            o.record.decision,
            SessionDecision::Deny(DenyReason::RoamingDataNotAllowed)
        );
        assert_eq!(o.recorded, SessionRecorded::NotRecorded);
        // The earlier session is untouched (and its flag not flipped).
        let sessions = s.snapshot().1;
        assert_eq!(sessions.len(), 1);
        assert!(!sessions[0].roaming);
        // Past the cap: denied CapExceeded, session still open.
        s.feed_usage(0, 5000).unwrap();
        let o = open(&mut s, 0, false);
        assert_eq!(
            o.record.decision,
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        assert_eq!(s.snapshot().1.len(), 1);
    }

    #[test]
    fn session_table_is_bounded() {
        let mut s = DataState::new();
        for p in 0..MAX_DATA_SESSIONS {
            let o = s.decide_and_open(
                0,
                0,
                p as u8,
                false,
                AccountStandingForData::Active,
                ProfileLifecycleForData::Enabled,
                ent(),
            );
            assert_eq!(o.recorded, SessionRecorded::Opened);
        }
        let o = s.decide_and_open(
            0,
            1,
            0,
            false,
            AccountStandingForData::Active,
            ProfileLifecycleForData::Enabled,
            ent(),
        );
        // The engine allowed it; only the table could not hold it.
        assert_eq!(o.record.decision, SessionDecision::Allow);
        assert_eq!(o.recorded, SessionRecorded::TableFull);
        assert_eq!(s.snapshot().1.len(), MAX_DATA_SESSIONS);
    }

    #[test]
    fn close_removes_only_the_named_session() {
        let mut s = DataState::new();
        open(&mut s, 0, false);
        assert!(!s.close_session(0, 0, 1));
        assert!(!s.close_session(1, 0, 0));
        assert!(s.close_session(0, 0, 0));
        assert!(!s.close_session(0, 0, 0));
        assert!(s.snapshot().1.is_empty());
    }

    #[test]
    fn mark_observed_sets_last_used_to_the_observed_value_only() {
        let mut s = DataState::new();
        s.feed_usage(0, 100).unwrap();
        let (snap, _) = s.snapshot();
        // Usage moves after the snapshot was taken.
        s.feed_usage(0, 50).unwrap();
        s.mark_observed(&snap);
        let (now, _) = s.snapshot();
        assert_eq!(now[0].last_used, Some(100));
        assert_eq!(now[0].usage.used_bytes, 150);
    }

    #[test]
    fn mark_observed_changes_nothing_but_last_used() {
        let mut s = DataState::new();
        s.feed_usage(0, 100).unwrap();
        open(&mut s, 0, false);
        let (u0, s0) = s.snapshot();
        s.mark_observed(&u0);
        let (u1, s1) = s.snapshot();
        assert_eq!(s0, s1);
        assert_eq!(u1[0].usage, u0[0].usage);
        assert_eq!(u1[0].account, u0[0].account);
    }

    #[test]
    fn reset_zeroes_usage_clears_last_used_and_touches_nothing_else() {
        let mut s = DataState::new();
        s.feed_usage(0, 1600).unwrap();
        s.feed_usage(1, 40).unwrap();
        open(&mut s, 1, false);
        let (snap, _) = s.snapshot();
        s.mark_observed(&snap);
        let sessions_before = s.snapshot().1;
        let (b, a) = s.reset_usage(0);
        assert_eq!((b.used_bytes, a.used_bytes), (1600, 0));
        let (rows, sessions) = s.snapshot();
        let r0 = rows.iter().find(|e| e.account == 0).unwrap();
        assert_eq!(r0.usage.used_bytes, 0);
        assert_eq!(
            r0.last_used, None,
            "reset must be signalled to the reconciler"
        );
        // Another account's row (and its last_used) is untouched.
        let r1 = rows.iter().find(|e| e.account == 1).unwrap();
        assert_eq!((r1.usage.used_bytes, r1.last_used), (40, Some(40)));
        // No session is closed or changed.
        assert_eq!(sessions, sessions_before);
    }

    #[test]
    fn reset_restores_service_for_an_over_cap_account() {
        let mut s = DataState::new();
        s.feed_usage(0, 1600).unwrap();
        assert_eq!(
            open(&mut s, 0, false).record.decision,
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        s.reset_usage(0);
        assert_eq!(
            open(&mut s, 0, false).record.decision,
            SessionDecision::Allow
        );
    }

    #[test]
    fn reset_of_an_unfed_account_creates_no_row() {
        let mut s = DataState::new();
        let (b, a) = s.reset_usage(7);
        assert_eq!((b.used_bytes, a.used_bytes), (0, 0));
        assert!(s.snapshot().0.is_empty());
    }

    #[test]
    fn reset_then_reconcile_snapshot_reports_no_regression() {
        use crate::data_codes::{build_observed, demo_entitlement};
        use runix_mobile::account::AccountStatus;
        use runix_mobile::reconcile::reconcile;
        let mut s = DataState::new();
        s.feed_usage(0, 1600).unwrap();
        let (snap, _) = s.snapshot();
        s.mark_observed(&snap); // the reconciler saw 1600
        let accts = [(0u64, AccountStatus::Active)];
        // Without the clear, a drop to 0 would be reported as a regression...
        let mut tampered = s.snapshot().0;
        tampered[0].usage.used_bytes = 0;
        let o = build_observed(&accts, &[], &tampered, &[], demo_entitlement);
        assert!(!reconcile(&o).is_empty());
        // ...a governed reset is not.
        s.reset_usage(0);
        let (rows, sessions) = s.snapshot();
        let o = build_observed(&accts, &[], &rows, &sessions, demo_entitlement);
        assert!(reconcile(&o).is_empty());
    }

    // ---- billing periods ----

    fn bp(start: u64, len: u64) -> BillingPeriod {
        BillingPeriod::new(start, len).unwrap()
    }

    #[test]
    fn account_without_a_period_gets_no_advice_and_no_period_is_started() {
        let mut s = DataState::new();
        assert_eq!(s.period_of(0), None);
        assert_eq!(s.advise_period(0, 10_000), None);
        assert_eq!(s.start_next_period(0, 10_000), PeriodStarted::NoPeriod);
        assert!(s.period_snapshot().is_empty());
    }

    #[test]
    fn active_period_gives_no_request_and_no_marker() {
        let mut s = DataState::new();
        s.set_period(0, bp(0, 500)).unwrap();
        let a = s.advise_period(0, 499).unwrap();
        assert_eq!(a.request, None);
        assert!(!a.first_request);
        assert_eq!(s.period_snapshot()[0].reset_requested_since, None);
    }

    #[test]
    fn elapsed_period_requests_and_records_only_the_first_request_tick() {
        let mut s = DataState::new();
        s.set_period(0, bp(0, 500)).unwrap();
        let a = s.advise_period(0, 500).unwrap();
        assert_eq!(a.request, Some(PeriodRequest::ResetUsage));
        assert!(a.first_request);
        assert_eq!(s.period_snapshot()[0].reset_requested_since, Some(500));
        // A later poll repeats the request but does not move the marker.
        let b = s.advise_period(0, 9_000).unwrap();
        assert_eq!(b.request, Some(PeriodRequest::ResetUsage));
        assert!(!b.first_request);
        assert_eq!(s.period_snapshot()[0].reset_requested_since, Some(500));
    }

    #[test]
    fn advice_never_resets_or_restricts_anything() {
        let mut s = DataState::new();
        s.set_period(0, bp(0, 10)).unwrap();
        s.feed_usage(0, 1600).unwrap();
        open(&mut s, 1, false);
        let tables_before = s.snapshot();
        let period_before = s.period_of(0);
        s.advise_period(0, 1_000_000).unwrap();
        s.advise_period(0, 2_000_000).unwrap();
        assert_eq!(s.snapshot(), tables_before);
        assert_eq!(s.period_of(0), period_before);
    }

    #[test]
    fn rewound_clock_is_not_a_request_and_sets_no_marker() {
        let mut s = DataState::new();
        s.set_period(0, bp(1_000, 500)).unwrap();
        let a = s.advise_period(0, 10).unwrap();
        assert!(matches!(
            a.assessment,
            PeriodAssessment::ClockBeforeStart { .. }
        ));
        assert_eq!(a.request, None);
        assert_eq!(s.period_snapshot()[0].reset_requested_since, None);
    }

    #[test]
    fn governed_reset_starts_the_next_period_and_clears_the_marker() {
        let mut s = DataState::new();
        s.set_period(0, bp(0, 500)).unwrap();
        s.feed_usage(0, 1600).unwrap();
        s.advise_period(0, 800).unwrap();
        let (b, a, started) = s.reset_usage_and_period(0, 900);
        assert_eq!((b.used_bytes, a.used_bytes), (1600, 0));
        assert_eq!(started, PeriodStarted::Started(bp(900, 500)));
        assert_eq!(s.period_of(0), Some(bp(900, 500)));
        assert_eq!(s.period_snapshot()[0].reset_requested_since, None);
        // The new period is Active: no request.
        assert_eq!(s.advise_period(0, 901).unwrap().request, None);
        // It elapses one length later and requests afresh (a NEW first
        // request, so it would be audited again).
        let adv = s.advise_period(0, 1_400).unwrap();
        assert_eq!(adv.request, Some(PeriodRequest::ResetUsage));
        assert!(adv.first_request);
    }

    #[test]
    fn a_reset_for_an_account_without_a_period_behaves_as_before() {
        let mut s = DataState::new();
        s.feed_usage(0, 1600).unwrap();
        let (b, a, started) = s.reset_usage_and_period(0, 900);
        assert_eq!((b.used_bytes, a.used_bytes), (1600, 0));
        assert_eq!(started, PeriodStarted::NoPeriod);
        assert!(s.period_snapshot().is_empty());
    }

    #[test]
    fn a_reset_before_the_period_start_keeps_the_old_period_and_marker() {
        let mut s = DataState::new();
        s.set_period(0, bp(1_000, 500)).unwrap();
        s.advise_period(0, 2_000).unwrap(); // elapsed: marker = 2000
        let (_, _, started) = s.reset_usage_and_period(0, 5);
        assert!(matches!(
            started,
            PeriodStarted::Rejected(PeriodError::ResetBeforeStart { .. })
        ));
        assert_eq!(s.period_of(0), Some(bp(1_000, 500)));
        assert_eq!(s.period_snapshot()[0].reset_requested_since, Some(2_000));
    }

    #[test]
    fn only_the_governed_reset_touches_the_period_and_marker() {
        // `svc.rs` calls reset_usage_and_period only after the capability and
        // MARSHAL gates; a denial returns before it. The state-level half of
        // that guarantee: no other method (feed, sessions, the reconciler's
        // bookkeeping, even the usage half of the reset alone) moves a period
        // or its marker, so a denied reset leaves the request outstanding.
        let mut s = DataState::new();
        s.set_period(0, bp(0, 500)).unwrap();
        s.advise_period(0, 700).unwrap();
        let before = s.period_snapshot();
        s.feed_usage(0, 5).unwrap();
        open(&mut s, 0, false);
        let (rows, _) = s.snapshot();
        s.mark_observed(&rows);
        s.close_session(0, 0, 0);
        s.reset_usage(0);
        assert_eq!(s.period_snapshot(), before);
    }

    #[test]
    fn period_table_is_bounded_and_replacing_clears_the_marker() {
        let mut s = DataState::new();
        for a in 0..MAX_DATA_ACCOUNTS as u64 {
            s.set_period(a, bp(0, 10)).unwrap();
        }
        assert_eq!(
            s.set_period(MAX_DATA_ACCOUNTS as u64, bp(0, 10)),
            Err(TableFull)
        );
        s.advise_period(3, 100).unwrap();
        assert_eq!(s.period_snapshot()[3].reset_requested_since, Some(100));
        s.set_period(3, bp(100, 10)).unwrap();
        assert_eq!(s.period_snapshot()[3].reset_requested_since, None);
        assert_eq!(s.period_snapshot().len(), MAX_DATA_ACCOUNTS);
    }

    #[test]
    fn snapshot_feeds_check_periods_with_the_marker() {
        use runix_mobile::period::{check_periods, PeriodIncidentKind};
        let mut s = DataState::new();
        s.set_period(0, bp(0, 500)).unwrap();
        // Overdue, never requested: grace runs from the period end (500).
        assert!(check_periods(&s.period_snapshot(), 510, 10).is_empty());
        assert_eq!(check_periods(&s.period_snapshot(), 511, 10).len(), 1);
        // Requested late (tick 5000): the grace restarts from the request.
        s.advise_period(0, 5_000).unwrap();
        assert!(check_periods(&s.period_snapshot(), 5_010, 10).is_empty());
        let r = check_periods(&s.period_snapshot(), 5_011, 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, PeriodIncidentKind::PeriodElapsedNoReset);
    }

    #[test]
    fn assess_matches_the_engine_bands() {
        let mut s = DataState::new();
        assert_eq!(s.assess(0, &ent()).band, UsageBand::Normal);
        s.feed_usage(0, 900).unwrap();
        assert_eq!(
            s.assess(0, &ent()).escalation,
            Some(ActionRequest::Throttle)
        );
        s.feed_usage(0, 700).unwrap();
        assert_eq!(
            s.assess(0, &ent()).escalation,
            Some(ActionRequest::SuspendAccount)
        );
    }
}
