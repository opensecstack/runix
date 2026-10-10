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
//!   tripwire, not an expected event. There is no billing-period reset path in
//!   this slice; when one is added it must clear `last_used` in the same
//!   critical section, or the reconciler will report the legitimate reset as
//!   tampering (see `reconcile::ObservedAccount::last_used_bytes`).
//! - The open-session table the reconciler snapshots. A session is recorded
//!   only when the policy engine allowed it.
//! - NOT here: entitlements (`data_codes::demo_entitlement`), account
//!   standing and profile lifecycle (owned by `mvno.rs` / `sim.rs`; copied in
//!   by the caller), capabilities, WORM audit.
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

use runix_mobile::policy::{
    apply_usage, evaluate_usage, AccountStandingForData, DataEntitlement, DataUsage, NetworkClass,
    PolicyDecisionRecord, ProfileLifecycleForData, SessionDecision, SessionRequest,
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
}

impl DataState {
    pub const fn new() -> Self {
        Self {
            usage: Vec::new(),
            sessions: Vec::new(),
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
