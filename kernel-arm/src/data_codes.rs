//! Pure, host-tested glue for the data policy syscalls (Beta item 4.3): the
//! syscall return-code encodings, the argument packing, the enum adapters
//! between `kernel-arm`'s live state and `runix_mobile`'s decoupled mirrors,
//! the DEMO entitlement table, the WORM/serial description strings, and the
//! reconciler snapshot builder.
//!
//! Lives in the lib target (no hardware dependency) for the same reason
//! `marshal_action.rs` does: the encodings are an ABI contract with `el0.rs`
//! and the strings are grepped by CI, so `cargo test --lib` pins them.
//!
//! # The design these helpers serve
//!
//! The policy engine (`runix_mobile::policy`) and the reconciler
//! (`runix_mobile::reconcile`) are pure and have no authority: the engine only
//! REQUESTS, the reconciler only OBSERVES. The kernel glue (`svc.rs`) is the
//! enforcement point, and a request is carried out by the CALLER, through the
//! existing governed syscall under the caller's own capability -- the data
//! syscalls never suspend, disable, close or mutate account/profile state in
//! response to an [`ActionRequest`]. That is why the usage syscall's return
//! value is the request itself ([`action_request_code`]): EL0 reads it and,
//! if it wants the suspension, issues `SYS_MVNO_SUSPEND` (capability + MARSHAL
//! + WORM), exactly as for any other suspension.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use runix_mobile::account::AccountStatus;
use runix_mobile::period::{BillingPeriod, PeriodAssessment};
use runix_mobile::policy::{
    AccountStandingForData, ActionRequest, DataEntitlement, DataUsage, DenyReason,
    PolicyDecisionRecord, ProfileLifecycleForData, SessionDecision, UsageAssessment,
};
use runix_mobile::reconcile::{
    Observed, ObservedAccount, ObservedProfile, ObservedSession, ProfileState as ReconcileProfile,
    Standing,
};

use crate::data_state::{DataSession, PeriodStarted, UsageEntry};
use crate::marshal_action::{enforce, Blocked, GateOutcome, UnreachablePolicy};
use crate::sim::ProfileState;

// --- SYS_DATA_ACCOUNT return codes ----------------------------------------
// `0..=3` ARE the engine's request (see [`action_request_code`]); `4..` are
// refusals, so a caller can tell "the engine asked for X" from "the call did
// not happen" with one comparison (`code >= USAGE_DENIED`).

/// No request: usage is in the Normal band.
pub const USAGE_NONE: u64 = 0;
/// `ActionRequest::NotifyOnly` (cap reached, below the anomaly threshold).
pub const USAGE_NOTIFY: u64 = 1;
/// `ActionRequest::Throttle`.
pub const USAGE_THROTTLE: u64 = 2;
/// `ActionRequest::SuspendAccount` -- a REQUEST. Nothing was suspended.
pub const USAGE_SUSPEND_REQUESTED: u64 = 3;
/// The caller lacks `data:usage:{account}`.
pub const USAGE_DENIED: u64 = 4;
/// No entitlement is configured for the account (fail closed).
pub const USAGE_NO_ENTITLEMENT: u64 = 5;
/// No such account in the registry.
pub const USAGE_NO_SUCH_ACCOUNT: u64 = 6;
/// The usage table is full; the bytes were not counted.
pub const USAGE_TABLE_FULL: u64 = 7;

/// Encode the engine's optional request as the `SYS_DATA_ACCOUNT` return
/// value: `None` -> 0, `NotifyOnly` -> 1, `Throttle` -> 2, `SuspendAccount`
/// -> 3. Exhaustive: a new `ActionRequest` variant fails to compile here.
pub const fn action_request_code(request: Option<ActionRequest>) -> u64 {
    match request {
        None => USAGE_NONE,
        Some(ActionRequest::NotifyOnly) => USAGE_NOTIFY,
        Some(ActionRequest::Throttle) => USAGE_THROTTLE,
        Some(ActionRequest::SuspendAccount) => USAGE_SUSPEND_REQUESTED,
    }
}

/// Inverse of [`action_request_code`] for `0..=3`; `None` for a refusal code
/// or anything else.
pub const fn action_request_from_code(code: u64) -> Option<Option<ActionRequest>> {
    match code {
        USAGE_NONE => Some(None),
        USAGE_NOTIFY => Some(Some(ActionRequest::NotifyOnly)),
        USAGE_THROTTLE => Some(Some(ActionRequest::Throttle)),
        USAGE_SUSPEND_REQUESTED => Some(Some(ActionRequest::SuspendAccount)),
        _ => None,
    }
}

// --- SYS_DATA_SESSION_OPEN return codes -----------------------------------
// `0`/`1` are the two allow outcomes (session recorded); everything else is
// a refusal, each cause its own code. `2..=6` mirror the engine's
// `DenyReason`; `7..` are refusals made by the kernel glue BEFORE (or around)
// the engine, which therefore have no `DenyReason`.

pub const SESSION_ALLOW: u64 = 0;
pub const SESSION_ALLOW_THROTTLED: u64 = 1;
pub const SESSION_DENY_ACCOUNT_SUSPENDED: u64 = 2;
pub const SESSION_DENY_ACCOUNT_CLOSED: u64 = 3;
pub const SESSION_DENY_PROFILE_NOT_ENABLED: u64 = 4;
pub const SESSION_DENY_ROAMING_NOT_ALLOWED: u64 = 5;
pub const SESSION_DENY_CAP_EXCEEDED: u64 = 6;
/// The caller lacks `data:session:{account}`.
pub const SESSION_REFUSED_CAPABILITY: u64 = 7;
/// No entitlement configured for the account (fail closed).
pub const SESSION_REFUSED_NO_ENTITLEMENT: u64 = 8;
/// No such account in the registry.
pub const SESSION_REFUSED_NO_SUCH_ACCOUNT: u64 = 9;
/// The profile is bound to no account, or to a different one.
pub const SESSION_REFUSED_PROFILE_NOT_BOUND: u64 = 10;
/// `sim.rs` has no such slot/profile.
pub const SESSION_REFUSED_UNKNOWN_PROFILE: u64 = 11;
/// The packed third argument had bits set outside `profile | roaming<<8`.
pub const SESSION_REFUSED_BAD_ARGUMENT: u64 = 12;
/// The engine allowed it but the session table is full: NOT recorded.
pub const SESSION_FAILED_TABLE_FULL: u64 = 13;

/// Encode an engine decision. Exhaustive over `DenyReason`.
pub const fn session_decision_code(decision: SessionDecision) -> u64 {
    match decision {
        SessionDecision::Allow => SESSION_ALLOW,
        SessionDecision::AllowThrottled => SESSION_ALLOW_THROTTLED,
        SessionDecision::Deny(DenyReason::AccountSuspended) => SESSION_DENY_ACCOUNT_SUSPENDED,
        SessionDecision::Deny(DenyReason::AccountClosed) => SESSION_DENY_ACCOUNT_CLOSED,
        SessionDecision::Deny(DenyReason::ProfileNotEnabled(_)) => SESSION_DENY_PROFILE_NOT_ENABLED,
        SessionDecision::Deny(DenyReason::RoamingDataNotAllowed) => {
            SESSION_DENY_ROAMING_NOT_ALLOWED
        }
        SessionDecision::Deny(DenyReason::CapExceeded) => SESSION_DENY_CAP_EXCEEDED,
    }
}

// --- SYS_DATA_SESSION_CLOSE return codes ----------------------------------

pub const CLOSE_OK: u64 = 0;
/// The caller lacks `data:session:{account}`.
pub const CLOSE_DENIED: u64 = 1;
/// No such open session.
pub const CLOSE_NOT_OPEN: u64 = 2;
pub const CLOSE_BAD_ARGUMENT: u64 = 3;

/// `SYS_DATA_RECONCILE` returns the incident count on success and this on a
/// capability denial. `u64::MAX` can never be a count (the snapshot is
/// bounded far below it), so the two cannot be confused.
pub const RECONCILE_DENIED: u64 = u64::MAX;

// --- SYS_DATA_RESET return codes --------------------------------------------
// The governed usage-period reset: capability, then MARSHAL, then the mutation.
// `0` is the only success; each refusal is its own code, in the order the
// checks run.

/// The counter was reset to zero (a new usage period began).
pub const RESET_OK: u64 = 0;
/// The caller lacks `data:reset:{account}`.
pub const RESET_DENIED_CAPABILITY: u64 = 1;
/// A reachable MARSHAL answered `Refuse` or `HardStop`. Nothing changed.
pub const RESET_DENIED_MARSHAL: u64 = 2;
/// The kernel failed to run the MARSHAL evaluation at all (fail closed).
/// Nothing changed.
pub const RESET_DENIED_LOCAL_FAILURE: u64 = 3;
/// No entitlement is configured for the account (fail closed).
pub const RESET_NO_ENTITLEMENT: u64 = 4;
/// No such account in the registry.
pub const RESET_NO_SUCH_ACCOUNT: u64 = 5;
/// MARSHAL was unreachable and the reset's policy is fail-closed. The kernel's
/// own decision, not a remote verdict. Nothing changed.
pub const RESET_DENIED_UNREACHABLE: u64 = 6;

/// The `SYS_DATA_RESET` return code for a MARSHAL block: a remote
/// `Refuse`/`HardStop`, a local evaluation failure and an unreachable-MARSHAL
/// fail-closed are distinguishable to the caller (the same split the DENIED
/// line makes). Exhaustive.
pub const fn reset_blocked_code(blocked: &Blocked) -> u64 {
    match blocked {
        Blocked::Remote(_) => RESET_DENIED_MARSHAL,
        Blocked::Local(_) => RESET_DENIED_LOCAL_FAILURE,
        Blocked::Unreachable => RESET_DENIED_UNREACHABLE,
    }
}

/// The whole MARSHAL half of the reset's decision, pure: `RESET_OK` means the
/// gate lets the mutation proceed (`Execute`, or `Unreachable` only under a
/// fail-open `policy`); anything else is the code the syscall returns with
/// state untouched. `svc.rs` passes the action's own policy
/// (`MarshalAction::DataResetUsage`'s `unreachable_policy()`), runs the real
/// evaluation and the WORM audit of local-failure/unreachable denials; this is
/// the decision they feed, pinned by `cargo test --lib`.
pub fn reset_gate_code(policy: UnreachablePolicy, outcome: GateOutcome) -> u64 {
    match enforce(policy, outcome) {
        Ok(()) => RESET_OK,
        Err(b) => reset_blocked_code(&b),
    }
}

// --- SYS_DATA_PERIOD return codes ---------------------------------------------
// READ-ONLY ADVICE about an account's billing period. `0..=2` are the model's
// assessment (see [`period_assessment_code`]); `3..` are "no advice was
// produced", so a caller tells "the period is over" from "the call did not
// happen" the same way `SYS_DATA_ACCOUNT` callers do (`code >= PERIOD_NO_PERIOD`).
// NOTHING here is an action: code 1 is a REQUEST that the caller issue the
// governed `SYS_DATA_RESET` under its own capability.

/// The period is in progress (`start <= now < end`). No request.
pub const PERIOD_ACTIVE: u64 = 0;
/// The period has elapsed (`now >= end`): a reset is REQUESTED. Nothing was
/// reset; the caller must carry it out through `SYS_DATA_RESET`.
pub const PERIOD_RESET_REQUESTED: u64 = 1;
/// `now < start`: the clock went backwards (or the period is from the future).
/// Never read as "active" and never a reset request; surfaced as an anomaly.
pub const PERIOD_CLOCK_BEFORE_START: u64 = 2;
/// The account has no billing period (fail closed: no advice is invented).
pub const PERIOD_NO_PERIOD: u64 = 3;
/// The caller lacks `data:session:{account}`.
pub const PERIOD_DENIED: u64 = 4;

/// Encode the model's assessment as the `SYS_DATA_PERIOD` return value.
/// Exhaustive: a new `PeriodAssessment` variant fails to compile here.
pub const fn period_assessment_code(a: &PeriodAssessment) -> u64 {
    match a {
        PeriodAssessment::Active { .. } => PERIOD_ACTIVE,
        PeriodAssessment::Elapsed { .. } => PERIOD_RESET_REQUESTED,
        PeriodAssessment::ClockBeforeStart { .. } => PERIOD_CLOCK_BEFORE_START,
    }
}

// --- Argument packing -------------------------------------------------------

/// Bit of the packed `profile | roaming` argument carrying the roaming flag.
pub const ROAMING_FLAG: u64 = 1 << 8;

/// Pack `(profile, roaming)` into the one register the SVC ABI has left.
///
/// WHY packed: the ABI carries `x1..x3` (`el1_vectors.rs`), and a session open
/// needs account, slot, profile AND a network-class flag -- four values. The
/// profile id is a `u8` (`sim::EsimProfile::id`), so its register has 56 spare
/// bits; carrying the flag there avoids widening the ABI a second time (the
/// first widening, for `SYS_SIM_INSTALL`'s identity, is documented in
/// `el1_vectors.rs`) for a single bit. Layout: bits 0..=7 profile, bit 8
/// roaming, bits 9..=63 MUST be zero.
pub const fn pack_profile_roaming(profile: u8, roaming: bool) -> u64 {
    (profile as u64) | if roaming { ROAMING_FLAG } else { 0 }
}

/// Unpack; `None` if any bit above the roaming flag is set. Reserved bits
/// are rejected rather than ignored so a caller that meant something else by
/// them (a wider profile id, a future flag) is refused, not silently
/// mis-served -- fail closed.
pub const fn unpack_profile_roaming(arg: u64) -> Option<(u8, bool)> {
    if arg >> 9 != 0 {
        return None;
    }
    Some(((arg & 0xff) as u8, arg & ROAMING_FLAG != 0))
}

// --- Enum adapters ----------------------------------------------------------
// Exhaustive on purpose: a new variant on either side must fail to compile
// here rather than be silently mis-mapped (same rule as `mvno::adapt`).

pub const fn standing_for_data(status: AccountStatus) -> AccountStandingForData {
    match status {
        AccountStatus::Active => AccountStandingForData::Active,
        AccountStatus::Suspended => AccountStandingForData::Suspended,
        AccountStatus::Closed => AccountStandingForData::Closed,
    }
}

pub const fn standing_for_reconcile(status: AccountStatus) -> Standing {
    match status {
        AccountStatus::Active => Standing::Active,
        AccountStatus::Suspended => Standing::Suspended,
        AccountStatus::Closed => Standing::Closed,
    }
}

pub const fn lifecycle_for_data(state: ProfileState) -> ProfileLifecycleForData {
    match state {
        ProfileState::Created => ProfileLifecycleForData::Created,
        ProfileState::Disabled => ProfileLifecycleForData::Disabled,
        ProfileState::Enabled => ProfileLifecycleForData::Enabled,
        ProfileState::Deleted => ProfileLifecycleForData::Deleted,
    }
}

pub const fn lifecycle_for_reconcile(state: ProfileState) -> ReconcileProfile {
    match state {
        ProfileState::Created => ReconcileProfile::Created,
        ProfileState::Disabled => ReconcileProfile::Disabled,
        ProfileState::Enabled => ReconcileProfile::Enabled,
        ProfileState::Deleted => ReconcileProfile::Deleted,
    }
}

// --- DEMO entitlement table -------------------------------------------------

/// DEMO DATA ONLY (same spirit as `mvno::open_demo_account` and the demo
/// signing key): the compiled-in account -> plan table. There is no
/// provisioning path and no real plan source. Deliberately SMALL numbers so a
/// boot proof is cheap -- not the 5 GiB policy demo constants:
///
/// - account 0: cap 1000 bytes, throttle at 80% (800), roaming NOT allowed,
///   suspension requested at 150% (1500).
///
/// Every other account has NO entitlement and gets `None`: the syscalls refuse
/// it (fail closed) rather than substituting a default plan. Built through
/// the validating constructor; a (never expected) validation failure also
/// yields `None`, i.e. also fails closed.
pub fn demo_entitlement(account: u64) -> Option<DataEntitlement> {
    match account {
        0 => DataEntitlement::new(Some(1000), 80, false, 150).ok(),
        _ => None,
    }
}

// --- DEMO billing periods -----------------------------------------------------

/// DEMO DATA ONLY: length of account 0's billing period, in milliseconds of the
/// generic timer. Converted to ticks from the counter's ACTUAL frequency
/// ([`millis_to_ticks`]) -- never a hardcoded tick count (a fixed count tried
/// once for the capability expiry turned out to be under a millisecond; see
/// `svc::frequency_hz`).
///
/// 500 ms is chosen from two measured facts about the boot (see the el0.rs
/// walk): the counter is already several seconds old when the walk's first
/// `SYS_DATA_PERIOD` runs (24 reclamation evaluations, the TCP proof and two
/// MARSHAL evaluations precede it), so the period (which starts at tick 0) is
/// long over with a wide margin; and the gap between the governed reset and the
/// `SYS_DATA_PERIOD` after it is a few syscalls (milliseconds), a tiny fraction
/// of 500 ms.
pub const DEMO_PERIOD_MILLIS: u64 = 500;

/// DEMO DATA ONLY: the reconciler's grace before an elapsed, unactioned period
/// is reported (`period::check_periods`'s `grace_ticks`). Deliberately LONG
/// next to [`DEMO_PERIOD_MILLIS`]: the demo period is over almost as soon as
/// the walk starts, and the walk (several ~1 s MARSHAL evaluations) runs for
/// seconds after the first `SYS_DATA_PERIOD` request, in boots where the reset
/// is denied (no MARSHAL proxy: fail-closed) and the period therefore stays
/// elapsed. A grace shorter than the walk would make the live reconciler report
/// `PeriodElapsedNoReset` mid-walk and change the incident counts the CI
/// asserts. The grace starts at the request (`reset_requested_since`) or the
/// period end, whichever is later, so it is measured from the walk, not from
/// boot. The path that DOES fire is exercised by `period_proof.rs` on
/// synthetic ticks.
pub const DEMO_GRACE_MILLIS: u64 = 20_000;

/// `millis` of a counter running at `freq_hz`, in ticks: `freq_hz * millis /
/// 1000`, saturating (never wraps, never panics). A zero result for a nonzero
/// `millis` (a counter slower than 1 kHz, or `freq_hz == 0` from an unset
/// `CNTFRQ_EL0`) is raised to 1 tick so a period built from it is valid.
pub const fn millis_to_ticks(freq_hz: u64, millis: u64) -> u64 {
    let t = freq_hz.saturating_mul(millis) / 1000;
    if t == 0 && millis != 0 {
        1
    } else {
        t
    }
}

/// DEMO DATA ONLY (same spirit as [`demo_entitlement`]): the compiled-in
/// account -> billing-period table. Account 0 gets a period that starts at tick
/// 0 and lasts [`DEMO_PERIOD_MILLIS`] at `freq_hz`; every other account has NO
/// period (`None`: `SYS_DATA_PERIOD` answers [`PERIOD_NO_PERIOD`], fail closed).
/// There is no provisioning path and no real billing cycle.
pub fn demo_period(account: u64, freq_hz: u64) -> Option<BillingPeriod> {
    match account {
        0 => BillingPeriod::new(0, millis_to_ticks(freq_hz, DEMO_PERIOD_MILLIS)).ok(),
        _ => None,
    }
}

// --- Description strings (serial + WORM) -------------------------------------

/// One-line, replayable description of a period assessment (ticks of the
/// generic timer), e.g. `elapsed: overdue 31250000 ticks, 1 period(s) missed;
/// reset REQUESTED (advisory: nothing was reset)`.
pub fn describe_period_assessment(a: &PeriodAssessment) -> String {
    match a {
        PeriodAssessment::Active { elapsed, remaining } => format!(
            "active: {elapsed} ticks in, {remaining} remaining; no reset requested"
        ),
        PeriodAssessment::Elapsed {
            overdue_ticks,
            periods_missed,
        } => format!(
            "elapsed: overdue {overdue_ticks} ticks, {periods_missed} period(s) missed; reset REQUESTED (advisory: nothing was reset)"
        ),
        PeriodAssessment::ClockBeforeStart {
            start_tick,
            now_tick,
        } => format!(
            "clock before start: now {now_tick} < period start {start_tick}; anomaly, no reset requested"
        ),
    }
}

/// What the governed reset did about the billing period, for the serial log and
/// the WORM reason.
pub fn describe_period_started(s: &PeriodStarted) -> String {
    match s {
        PeriodStarted::NoPeriod => String::from("no billing period for this account; none started"),
        PeriodStarted::Started(p) => format!(
            "next billing period started at tick {} (length {} ticks); reset request cleared",
            p.start_tick(),
            p.length_ticks()
        ),
        PeriodStarted::Rejected(e) => {
            format!("next billing period NOT started ({e}); old period and request kept")
        }
    }
}

fn cap_text(e: &DataEntitlement) -> String {
    match e.cap_bytes() {
        Some(c) => format!("{c}"),
        None => String::from("unlimited"),
    }
}

/// One-line, replayable description of a session decision: every input the
/// engine saw and the outputs, e.g.
/// `standing=Active lifecycle=Enabled network=Home used=0 cap=1000 throttle=80% escalate=150% roaming_ok=false band=Normal decision=Allow`.
pub fn describe_session_record(r: &PolicyDecisionRecord) -> String {
    format!(
        "standing={:?} lifecycle={:?} network={:?} used={} cap={} throttle={}% escalate={}% roaming_ok={} band={:?} decision={:?}",
        r.request.standing,
        r.request.lifecycle,
        r.request.network,
        r.request.usage.used_bytes,
        cap_text(&r.request.entitlement),
        r.request.entitlement.throttle_at_percent(),
        r.request.entitlement.escalate_at_percent(),
        r.request.entitlement.roaming_data_allowed(),
        r.assessment.band,
        r.decision,
    )
}

/// One-line, replayable description of a usage assessment (the usage feed's
/// decision: `evaluate_usage(entitlement, usage)`).
pub fn describe_usage_assessment(
    e: &DataEntitlement,
    usage: &DataUsage,
    a: &UsageAssessment,
) -> String {
    format!(
        "used={} cap={} throttle={}% escalate={}% band={:?} request={:?}",
        usage.used_bytes,
        cap_text(e),
        e.throttle_at_percent(),
        e.escalate_at_percent(),
        a.band,
        a.escalation,
    )
}

// --- Reconciler snapshot builder ----------------------------------------------

/// One SIM profile as read from `sim.rs`, with its owner from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRow {
    pub slot: usize,
    pub profile: u8,
    pub state: ProfileState,
    pub owner: Option<u64>,
}

/// Build the reconciler's immutable snapshot from COPIES of live state.
///
/// - Policy-intended values (`data_cap_bytes`, `escalate_at_percent`) come
///   from `entitlement_of`. An account with no entitlement is reported with
///   `None` for both (nothing to compare it against, so the usage checks skip
///   it); this is safe because the syscalls refuse to meter it or open a
///   session for it in the first place.
/// - `roaming_allowed` per session comes from the same table, and is `false`
///   when there is no entitlement: a roaming session with no plan behind it is
///   reported, not excused.
/// - An account's `used_bytes` is 0 and `last_used_bytes` `None` until it has
///   been fed (no row in `usage`).
pub fn build_observed(
    accounts: &[(u64, AccountStatus)],
    profiles: &[ProfileRow],
    usage: &[UsageEntry],
    sessions: &[DataSession],
    entitlement_of: impl Fn(u64) -> Option<DataEntitlement>,
) -> Observed {
    let accounts = accounts
        .iter()
        .map(|&(id, status)| {
            let ent = entitlement_of(id);
            let row = usage.iter().find(|u| u.account == id);
            ObservedAccount {
                id,
                standing: standing_for_reconcile(status),
                data_cap_bytes: ent.and_then(|e| e.cap_bytes()),
                escalate_at_percent: ent.map(|e| e.escalate_at_percent()),
                used_bytes: row.map(|u| u.usage.used_bytes).unwrap_or(0),
                last_used_bytes: row.and_then(|u| u.last_used),
            }
        })
        .collect::<Vec<_>>();
    let profiles = profiles
        .iter()
        .map(|p| ObservedProfile {
            slot: p.slot,
            profile: p.profile,
            lifecycle: lifecycle_for_reconcile(p.state),
            owner: p.owner,
        })
        .collect::<Vec<_>>();
    let sessions = sessions
        .iter()
        .map(|s| ObservedSession {
            account: s.account,
            slot: s.slot,
            profile: s.profile,
            roaming: s.roaming,
            roaming_allowed: entitlement_of(s.account)
                .map(|e| e.roaming_data_allowed())
                .unwrap_or(false),
        })
        .collect::<Vec<_>>();
    Observed {
        accounts,
        profiles,
        sessions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runix_mobile::policy::{evaluate_usage, NetworkClass, SessionRequest};
    use runix_mobile::reconcile::{reconcile, IncidentKind};

    #[test]
    fn action_request_encoding_is_pinned() {
        assert_eq!(action_request_code(None), 0);
        assert_eq!(action_request_code(Some(ActionRequest::NotifyOnly)), 1);
        assert_eq!(action_request_code(Some(ActionRequest::Throttle)), 2);
        assert_eq!(action_request_code(Some(ActionRequest::SuspendAccount)), 3);
    }

    #[test]
    fn action_request_codes_round_trip_and_refusals_do_not_decode() {
        for r in [
            None,
            Some(ActionRequest::NotifyOnly),
            Some(ActionRequest::Throttle),
            Some(ActionRequest::SuspendAccount),
        ] {
            assert_eq!(action_request_from_code(action_request_code(r)), Some(r));
        }
        for refusal in [
            USAGE_DENIED,
            USAGE_NO_ENTITLEMENT,
            USAGE_NO_SUCH_ACCOUNT,
            USAGE_TABLE_FULL,
            99,
            u64::MAX,
        ] {
            assert_eq!(action_request_from_code(refusal), None);
            assert!(refusal >= USAGE_DENIED);
        }
    }

    #[test]
    fn session_codes_are_pinned_and_all_distinct() {
        let all = [
            SESSION_ALLOW,
            SESSION_ALLOW_THROTTLED,
            SESSION_DENY_ACCOUNT_SUSPENDED,
            SESSION_DENY_ACCOUNT_CLOSED,
            SESSION_DENY_PROFILE_NOT_ENABLED,
            SESSION_DENY_ROAMING_NOT_ALLOWED,
            SESSION_DENY_CAP_EXCEEDED,
            SESSION_REFUSED_CAPABILITY,
            SESSION_REFUSED_NO_ENTITLEMENT,
            SESSION_REFUSED_NO_SUCH_ACCOUNT,
            SESSION_REFUSED_PROFILE_NOT_BOUND,
            SESSION_REFUSED_UNKNOWN_PROFILE,
            SESSION_REFUSED_BAD_ARGUMENT,
            SESSION_FAILED_TABLE_FULL,
        ];
        for (i, c) in all.iter().enumerate() {
            assert_eq!(*c, i as u64, "codes are the dense list 0..=13");
        }
    }

    #[test]
    fn every_engine_decision_maps_to_its_own_code() {
        let cases = [
            (SessionDecision::Allow, 0),
            (SessionDecision::AllowThrottled, 1),
            (SessionDecision::Deny(DenyReason::AccountSuspended), 2),
            (SessionDecision::Deny(DenyReason::AccountClosed), 3),
            (
                SessionDecision::Deny(DenyReason::ProfileNotEnabled(
                    ProfileLifecycleForData::Disabled,
                )),
                4,
            ),
            (SessionDecision::Deny(DenyReason::RoamingDataNotAllowed), 5),
            (SessionDecision::Deny(DenyReason::CapExceeded), 6),
        ];
        for (d, code) in cases {
            assert_eq!(session_decision_code(d), code);
        }
        // The lifecycle carried by ProfileNotEnabled does not change the code.
        for lc in [
            ProfileLifecycleForData::Created,
            ProfileLifecycleForData::Disabled,
            ProfileLifecycleForData::Deleted,
        ] {
            assert_eq!(
                session_decision_code(SessionDecision::Deny(DenyReason::ProfileNotEnabled(lc))),
                SESSION_DENY_PROFILE_NOT_ENABLED
            );
        }
    }

    #[test]
    fn reset_codes_are_pinned_distinct_and_only_zero_is_success() {
        let all = [
            RESET_OK,
            RESET_DENIED_CAPABILITY,
            RESET_DENIED_MARSHAL,
            RESET_DENIED_LOCAL_FAILURE,
            RESET_NO_ENTITLEMENT,
            RESET_NO_SUCH_ACCOUNT,
            RESET_DENIED_UNREACHABLE,
        ];
        for (i, c) in all.iter().enumerate() {
            assert_eq!(*c, i as u64, "codes are the dense list 0..=6");
        }
    }

    #[test]
    fn period_codes_are_pinned_distinct_and_advice_codes_precede_refusals() {
        let all = [
            PERIOD_ACTIVE,
            PERIOD_RESET_REQUESTED,
            PERIOD_CLOCK_BEFORE_START,
            PERIOD_NO_PERIOD,
            PERIOD_DENIED,
        ];
        for (i, c) in all.iter().enumerate() {
            assert_eq!(*c, i as u64, "codes are the dense list 0..=4");
        }
        assert_eq!(
            period_assessment_code(&PeriodAssessment::Active {
                elapsed: 1,
                remaining: 1
            }),
            0
        );
        assert_eq!(
            period_assessment_code(&PeriodAssessment::Elapsed {
                overdue_ticks: 0,
                periods_missed: 1
            }),
            1
        );
        assert_eq!(
            period_assessment_code(&PeriodAssessment::ClockBeforeStart {
                start_tick: 5,
                now_tick: 1
            }),
            2
        );
    }

    #[test]
    fn millis_to_ticks_scales_from_the_frequency_and_never_wraps_or_hits_zero() {
        // QEMU's virt generic timer runs at 62.5 MHz.
        assert_eq!(millis_to_ticks(62_500_000, 500), 31_250_000);
        assert_eq!(millis_to_ticks(1_000, 1), 1);
        assert_eq!(millis_to_ticks(62_500_000, 0), 0);
        // Unset / too-slow counter: still a valid (>= 1) tick count.
        assert_eq!(millis_to_ticks(0, 500), 1);
        assert_eq!(millis_to_ticks(1, 500), 1);
        // Saturates instead of wrapping.
        assert_eq!(millis_to_ticks(u64::MAX, u64::MAX), u64::MAX / 1000);
        // Strictly increasing in millis at a realistic frequency.
        assert!(millis_to_ticks(62_500_000, 20_000) > millis_to_ticks(62_500_000, 500));
    }

    #[test]
    fn demo_period_table_has_exactly_account_zero_from_tick_zero() {
        let p = demo_period(0, 62_500_000).expect("account 0 has a demo period");
        assert_eq!(p.start_tick(), 0);
        assert_eq!(p.length_ticks(), 31_250_000);
        // Valid even for a degenerate frequency (never a ZeroLength None).
        assert_eq!(demo_period(0, 0).unwrap().length_ticks(), 1);
        for a in [1u64, 2, 15, 99, u64::MAX] {
            assert_eq!(demo_period(a, 62_500_000), None, "account {a}: no period");
        }
        // The grace is much longer than the period (see DEMO_GRACE_MILLIS).
        const _: () = assert!(DEMO_GRACE_MILLIS > 10 * DEMO_PERIOD_MILLIS);
    }

    #[test]
    fn period_descriptions_are_pinned() {
        assert_eq!(
            describe_period_assessment(&PeriodAssessment::Active {
                elapsed: 10,
                remaining: 90
            }),
            "active: 10 ticks in, 90 remaining; no reset requested"
        );
        assert_eq!(
            describe_period_assessment(&PeriodAssessment::Elapsed {
                overdue_ticks: 7,
                periods_missed: 1
            }),
            "elapsed: overdue 7 ticks, 1 period(s) missed; reset REQUESTED (advisory: nothing was reset)"
        );
        assert_eq!(
            describe_period_assessment(&PeriodAssessment::ClockBeforeStart {
                start_tick: 500,
                now_tick: 400
            }),
            "clock before start: now 400 < period start 500; anomaly, no reset requested"
        );
        let p = BillingPeriod::new(900, 500).unwrap();
        assert_eq!(
            describe_period_started(&PeriodStarted::Started(p)),
            "next billing period started at tick 900 (length 500 ticks); reset request cleared"
        );
        assert!(describe_period_started(&PeriodStarted::NoPeriod).contains("none started"));
        let e = runix_mobile::period::PeriodError::ResetBeforeStart {
            start_tick: 9,
            reset_at_tick: 1,
        };
        assert!(describe_period_started(&PeriodStarted::Rejected(e)).contains("NOT started"));
    }

    #[test]
    fn reset_gate_decision_blocks_exactly_what_marshal_blocks() {
        use crate::marshal_action::{LocalFailure, MarshalAction};
        use runix_citadel_integration::ShadowMarshalOutcome::*;
        // The reset's REAL policy is fail-closed: only Execute lets it proceed.
        let policy = MarshalAction::DataResetUsage { account: 0 }.unreachable_policy();
        assert_eq!(policy, UnreachablePolicy::FailClosed);
        assert_eq!(
            reset_gate_code(policy, GateOutcome::Remote(Execute)),
            RESET_OK
        );
        // Unreachable is DENIED with its own code, not waved through.
        assert_eq!(
            reset_gate_code(policy, GateOutcome::Remote(Unreachable)),
            RESET_DENIED_UNREACHABLE
        );
        // A hypothetical fail-open policy would let it proceed (the matrix
        // cell the policy decides).
        assert_eq!(
            reset_gate_code(
                UnreachablePolicy::FailOpen,
                GateOutcome::Remote(Unreachable)
            ),
            RESET_OK
        );
        // Refuse and HardStop block it, state untouched, under both policies.
        for p in [UnreachablePolicy::FailOpen, UnreachablePolicy::FailClosed] {
            assert_eq!(
                reset_gate_code(p, GateOutcome::Remote(Refuse)),
                RESET_DENIED_MARSHAL
            );
            assert_eq!(
                reset_gate_code(p, GateOutcome::Remote(HardStop)),
                RESET_DENIED_MARSHAL
            );
            // Every local failure fails CLOSED, with its own code.
            for l in [
                LocalFailure::SetupFailed,
                LocalFailure::SpawnFailed,
                LocalFailure::ExcursionFaulted,
            ] {
                assert_eq!(
                    reset_gate_code(p, GateOutcome::LocalFailure(l)),
                    RESET_DENIED_LOCAL_FAILURE
                );
            }
        }
    }

    #[test]
    fn packing_round_trips_and_rejects_reserved_bits() {
        for profile in [0u8, 1, 2, 127, 255] {
            for roaming in [false, true] {
                let packed = pack_profile_roaming(profile, roaming);
                assert_eq!(unpack_profile_roaming(packed), Some((profile, roaming)));
            }
        }
        assert_eq!(pack_profile_roaming(1, false), 1);
        assert_eq!(pack_profile_roaming(0, true), 0x100);
        // A plain profile id (the SESSION_CLOSE convention) is "not roaming".
        assert_eq!(unpack_profile_roaming(2), Some((2, false)));
        // Anything above bit 8 is refused, not truncated.
        assert_eq!(unpack_profile_roaming(0x200), None);
        assert_eq!(unpack_profile_roaming(1 << 63), None);
        assert_eq!(unpack_profile_roaming(u64::MAX), None);
        // The classic truncation bug: slot-sized garbage in the high bits.
        assert_eq!(unpack_profile_roaming(0x1_0000_0001), None);
    }

    #[test]
    fn adapters_are_variant_for_variant() {
        assert_eq!(
            standing_for_data(AccountStatus::Active),
            AccountStandingForData::Active
        );
        assert_eq!(
            standing_for_data(AccountStatus::Suspended),
            AccountStandingForData::Suspended
        );
        assert_eq!(
            standing_for_data(AccountStatus::Closed),
            AccountStandingForData::Closed
        );
        assert_eq!(
            standing_for_reconcile(AccountStatus::Active),
            Standing::Active
        );
        assert_eq!(
            standing_for_reconcile(AccountStatus::Suspended),
            Standing::Suspended
        );
        assert_eq!(
            standing_for_reconcile(AccountStatus::Closed),
            Standing::Closed
        );
        for (s, d, r) in [
            (
                ProfileState::Created,
                ProfileLifecycleForData::Created,
                ReconcileProfile::Created,
            ),
            (
                ProfileState::Disabled,
                ProfileLifecycleForData::Disabled,
                ReconcileProfile::Disabled,
            ),
            (
                ProfileState::Enabled,
                ProfileLifecycleForData::Enabled,
                ReconcileProfile::Enabled,
            ),
            (
                ProfileState::Deleted,
                ProfileLifecycleForData::Deleted,
                ReconcileProfile::Deleted,
            ),
        ] {
            assert_eq!(lifecycle_for_data(s), d);
            assert_eq!(lifecycle_for_reconcile(s), r);
        }
    }

    #[test]
    fn demo_table_has_exactly_account_zero_and_it_is_small() {
        let e = demo_entitlement(0).expect("account 0 has a demo plan");
        assert_eq!(e.cap_bytes(), Some(1000));
        assert_eq!(e.throttle_at_percent(), 80);
        assert!(!e.roaming_data_allowed());
        assert_eq!(e.escalate_at_percent(), 150);
        for a in [1u64, 2, 15, 99, u64::MAX] {
            assert_eq!(demo_entitlement(a), None, "account {a} must fail closed");
        }
    }

    #[test]
    fn demo_walk_bands_match_the_el0_walk() {
        // el0.rs feeds 900 then 700 against the account-0 plan.
        let e = demo_entitlement(0).unwrap();
        let a = |used| evaluate_usage(&e, &DataUsage { used_bytes: used }).escalation;
        assert_eq!(a(0), None);
        assert_eq!(a(900), Some(ActionRequest::Throttle));
        assert_eq!(a(1600), Some(ActionRequest::SuspendAccount));
    }

    #[test]
    fn session_record_description_is_pinned() {
        let e = demo_entitlement(0).unwrap();
        let r = PolicyDecisionRecord::decide(SessionRequest {
            standing: AccountStandingForData::Active,
            lifecycle: ProfileLifecycleForData::Enabled,
            entitlement: e,
            usage: DataUsage { used_bytes: 0 },
            network: NetworkClass::Home,
        });
        assert_eq!(
            describe_session_record(&r),
            "standing=Active lifecycle=Enabled network=Home used=0 cap=1000 throttle=80% escalate=150% roaming_ok=false band=Normal decision=Allow"
        );
        let r = PolicyDecisionRecord::decide(SessionRequest {
            network: NetworkClass::Roaming,
            ..r.request
        });
        let s = describe_session_record(&r);
        assert!(s.contains("network=Roaming"));
        assert!(s.ends_with("decision=Deny(RoamingDataNotAllowed)"));
    }

    #[test]
    fn usage_description_is_pinned() {
        let e = demo_entitlement(0).unwrap();
        let u = DataUsage { used_bytes: 1600 };
        let a = evaluate_usage(&e, &u);
        assert_eq!(
            describe_usage_assessment(&e, &u, &a),
            "used=1600 cap=1000 throttle=80% escalate=150% band=Anomalous request=Some(SuspendAccount)"
        );
    }

    fn rows() -> Vec<ProfileRow> {
        alloc::vec![ProfileRow {
            slot: 0,
            profile: 0,
            state: ProfileState::Enabled,
            owner: Some(0),
        }]
    }

    fn usage(used: u64, last: Option<u64>) -> Vec<UsageEntry> {
        alloc::vec![UsageEntry {
            account: 0,
            usage: DataUsage { used_bytes: used },
            last_used: last,
        }]
    }

    fn session() -> Vec<DataSession> {
        alloc::vec![DataSession {
            account: 0,
            slot: 0,
            profile: 0,
            roaming: false
        }]
    }

    fn kinds(o: &Observed) -> Vec<IncidentKind> {
        reconcile(o).iter().map(|i| i.kind).collect()
    }

    #[test]
    fn snapshot_of_the_el0_walk_states_matches_the_expected_incidents() {
        let accts = [(0u64, AccountStatus::Active)];
        // After 900 + 700 with the session open and the account Active.
        let o = build_observed(
            &accts,
            &rows(),
            &usage(1600, None),
            &session(),
            demo_entitlement,
        );
        assert_eq!(
            kinds(&o),
            [
                IncidentKind::UsageOverCapNotRestricted,
                IncidentKind::AnomalousUsageNoEscalation
            ]
        );
        // Suspended, profile force-disabled, session still open.
        let accts = [(0u64, AccountStatus::Suspended)];
        let mut p = rows();
        p[0].state = ProfileState::Disabled;
        let o = build_observed(
            &accts,
            &p,
            &usage(1600, Some(1600)),
            &session(),
            demo_entitlement,
        );
        assert_eq!(kinds(&o), [IncidentKind::SessionWithoutEnabledProfile]);
        // Session closed: clean.
        let o = build_observed(&accts, &p, &usage(1600, Some(1600)), &[], demo_entitlement);
        assert!(kinds(&o).is_empty());
    }

    #[test]
    fn snapshot_without_entitlement_skips_usage_checks_and_flags_roaming() {
        let accts = [(0u64, AccountStatus::Active)];
        let o = build_observed(&accts, &rows(), &usage(u64::MAX, None), &[], |_| None);
        assert!(kinds(&o).is_empty());
        let mut s = session();
        s[0].roaming = true;
        let o = build_observed(&accts, &rows(), &usage(0, None), &s, |_| None);
        assert_eq!(kinds(&o), [IncidentKind::RoamingSessionNotPermitted]);
    }

    #[test]
    fn snapshot_reports_usage_regression_via_last_used() {
        let accts = [(0u64, AccountStatus::Active)];
        let o = build_observed(
            &accts,
            &rows(),
            &usage(100, Some(500)),
            &[],
            demo_entitlement,
        );
        assert_eq!(kinds(&o), [IncidentKind::UsageRegression]);
    }

    #[test]
    fn unfed_account_is_zero_usage_no_last() {
        let accts = [(0u64, AccountStatus::Active)];
        let o = build_observed(&accts, &rows(), &[], &[], demo_entitlement);
        assert_eq!(o.accounts[0].used_bytes, 0);
        assert_eq!(o.accounts[0].last_used_bytes, None);
        assert_eq!(o.accounts[0].data_cap_bytes, Some(1000));
        assert_eq!(o.accounts[0].escalate_at_percent, Some(150));
    }
}
