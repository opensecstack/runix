//! Kernel-side owner of the data policy state (Beta item 4.3): the one place
//! `runix_kernel_arm::data_state::DataState` (usage counters + open-session
//! table) lives at runtime, plus the live-state snapshot the reconciler reads.
//!
//! Like `mvno.rs`, this module holds state and nothing else: it checks no
//! capability, writes no WORM entry and talks to no MARSHAL. Governance lives
//! at the syscall boundary (`svc.rs`), where the requesting context is known.
//! The pure logic (tables, codes, adapters, the demo entitlement table, the
//! snapshot builder) is in the lib target (`data_state.rs`, `data_codes.rs`)
//! where `cargo test --lib` covers it.
//!
//! # Why five of the six data syscalls are not MARSHAL-gated (Beta item 4.3)
//!
//! (The sixth, `SYS_DATA_RESET`, IS gated -- see the paragraph beginning "The
//! usage-period RESET" below. `docs/adrs/0001-data-syscalls-not-marshal-gated.md`
//! records the decision and names the reset as its revisit trigger.)
//!
//! The policy engine (`runix_mobile::policy`) is pure and stateless and only
//! REQUESTS; the reconciler (`runix_mobile::reconcile`) only OBSERVES. The
//! kernel glue is the enforcement point, and a request is carried out by the
//! CALLER through an existing governed syscall under the caller's OWN
//! capability. The four data syscalls therefore never suspend, disable,
//! close or mutate account/profile state in response to an `ActionRequest`:
//!
//! - `SYS_DATA_ACCOUNT` adds to a usage counter and returns the engine's
//!   request as a small code. It is a metering write, not a governance
//!   decision.
//! - `SYS_DATA_SESSION_OPEN` reads policy and records a row in the session
//!   table iff the engine allowed it.
//! - `SYS_DATA_SESSION_CLOSE` removes a row (the caller applying a
//!   restriction; it only ever narrows what is allowed).
//! - `SYS_DATA_RECONCILE` reads, reports and WORM-records evidence; its only
//!   write to this state is the `last_used` bookkeeping.
//!
//! - `SYS_DATA_PERIOD` is read-only ADVICE about the account's billing period:
//!   it reads the generic timer at the moment it is asked, assesses the period
//!   (`runix_mobile::period`) and says "elapsed: a reset is requested". Its one
//!   write is `reset_requested_since`, the tick the request was first issued
//!   (evidence for the reconciler, never moved afterwards). It resets nothing
//!   and restricts nothing, and nothing in the kernel resets on a timer: a
//!   period is DATA, and only a governed `SYS_DATA_RESET` (below) starts the
//!   next one. It reuses the `data:session:{account}` scope rather than
//!   inventing a new one -- see `svc.rs`'s `data_period` for why.
//!
//! None of them is a governance-consequential state change, so none gets a new
//! MARSHAL action type or gate; the consequential action a request can lead to
//! -- suspending the account -- is the existing MARSHAL-gated
//! `SYS_MVNO_SUSPEND`.
//!
//! The usage-period RESET is the exception, and exactly the one the decision
//! record said would be: `SYS_DATA_RESET(account)` zeroes the counter, which
//! LIFTS a cap and restores service the plan had withheld, so whoever holds it
//! can undo enforcement. That makes it consequential and governable, so it has
//! its own capability scope (`data:reset:{account}`) AND a MARSHAL action
//! (`data.reset_usage`), checked in that order before [`reset_usage`] is
//! reached. It clears the reconciler's `last_used` memory in the same critical
//! section so the reset reads as a new period, not as tampering. It still
//! closes no session and changes no standing or profile.
//!
//! The usage FEED is nonetheless privileged. Counting bytes into an account
//! can push it over its cap -- that denies it service -- and over the
//! escalation threshold, which makes the engine ask for its suspension. So
//! `SYS_DATA_ACCOUNT` is capability-scoped on its own resource
//! (`data:usage:{account}`), separate from session access
//! (`data:session:{account}`): holding the right to open or close sessions
//! does not imply the right to meter the account (and neither implies the
//! reset's `data:reset:{account}`). On its success path the reset ALSO starts
//! the account's next billing period (start = the tick the reset took effect,
//! same length) and clears the request marker, in the same critical section;
//! a denied or failed reset changes neither.
//!
//! Every policy decision, every engine request and every reconciler incident
//! is still WORM-audited (on the same chain as the eSIM/MVNO transitions, via
//! `svc.rs`'s `audit_event`): "not gated" is not "not recorded". The audit is
//! NOT total, though: capability denials print to the serial log only (the
//! same as every other syscall here), as do a malformed `SESSION_CLOSE`
//! argument and a close of a session that is not open, and a reconcile pass
//! that finds nothing writes no entry.
//!
//! # Lock order
//!
//! `DATA` is a LEAF. It is held only inside the short functions below, each of
//! which calls nothing outside this module and `data_state`'s pure methods. It
//! is never held while calling `mvno`, `sim` or `svc.rs`'s audit, and none of
//! those call into it. Combined with `mvno.rs`'s registry -> sim rule the full
//! order is registry -> sim -> data, with no reverse edge. Handlers copy what
//! they need out before auditing.
//!
//! # DEMO DATA ONLY
//!
//! Entitlements come from `data_codes::demo_entitlement` and billing periods
//! from `data_codes::demo_period` (account 0 only, installed at boot by
//! `nonsecure.rs`); there is no provisioning path.

use alloc::vec::Vec;
use spin::Mutex;

use runix_kernel_arm::data_codes::{build_observed, ProfileRow};
use runix_kernel_arm::data_state::{
    DataSession, DataState, OpenOutcome, PeriodAdvice, PeriodStarted, TableFull, UsageEntry,
};
use runix_mobile::period::{BillingPeriod, ObservedPeriod};
use runix_mobile::policy::{
    AccountStandingForData, DataEntitlement, DataUsage, ProfileLifecycleForData,
};
use runix_mobile::reconcile::Observed;

use crate::sim::{self, SimError};

static DATA: Mutex<DataState> = Mutex::new(DataState::new());

/// Upper bound on slots probed when snapshotting profiles; `sim.rs` reports
/// `NoSuchSlot` past its real count, which ends the scan first. The bound only
/// keeps the loop finite should that ever change.
const MAX_SLOT_SCAN: usize = 16;

/// Add `bytes` to `account`'s counter; `(before, after)`.
pub fn feed_usage(account: u64, bytes: u64) -> Result<(DataUsage, DataUsage), TableFull> {
    DATA.lock().feed_usage(account, bytes)
}

/// Start a new usage period for `account` (the governed `SYS_DATA_RESET`, called
/// only AFTER its capability check and MARSHAL gate passed): usage back to
/// `reset_usage()`, reconciler `last_used` cleared, and -- if the account has a
/// billing period -- the NEXT period installed with start = `now` and the
/// reset-request marker cleared, all in one critical section. `now` is the
/// generic-timer tick the caller read after the gate passed. Returns `(before,
/// after, period outcome)`. Sessions, standing and profiles are not touched.
pub fn reset_usage(account: u64, now: u64) -> (DataUsage, DataUsage, PeriodStarted) {
    DATA.lock().reset_usage_and_period(account, now)
}

/// Install `period` as `account`'s billing period (boot-time DEMO DATA only;
/// see `data_codes::demo_period`). No syscall reaches this: a period is only
/// ever set here at boot or advanced by [`reset_usage`].
pub fn set_period(account: u64, period: BillingPeriod) -> Result<(), TableFull> {
    DATA.lock().set_period(account, period)
}

/// Assess `account`'s period at `now` (read by the caller from the generic timer
/// at the moment it asked) and record the first reset request. `None`: no
/// period. Advice only -- nothing is reset or restricted.
pub fn advise_period(account: u64, now: u64) -> Option<PeriodAdvice> {
    DATA.lock().advise_period(account, now)
}

/// Copies of every billing period (with its request marker) for the reconciler.
pub fn period_snapshot() -> Vec<ObservedPeriod> {
    DATA.lock().period_snapshot()
}

/// Decide a session and, iff allowed, record it -- one critical section. The
/// caller has already read standing/lifecycle/entitlement (registry and sim
/// locks released) and passes them in by value.
pub fn decide_and_open(
    account: u64,
    slot: usize,
    profile: u8,
    roaming: bool,
    standing: AccountStandingForData,
    lifecycle: ProfileLifecycleForData,
    entitlement: DataEntitlement,
) -> OpenOutcome {
    DATA.lock().decide_and_open(
        account,
        slot,
        profile,
        roaming,
        standing,
        lifecycle,
        entitlement,
    )
}

/// Remove a session; `true` if it was open.
pub fn close_session(account: u64, slot: usize, profile: u8) -> bool {
    DATA.lock().close_session(account, slot, profile)
}

/// Everything the reconciler compares, as one immutable snapshot built from
/// COPIES of live state, plus the usage rows it was built from (so
/// [`mark_observed`] can record exactly what was observed).
///
/// Locks are taken one after another, each released before the next (registry
/// for accounts, registry again per profile owner, sim per slot, data last):
/// never nested, so the registry -> sim -> data order holds trivially. The
/// copies are therefore not a single atomic cut across the three subsystems;
/// that is acceptable here because there is exactly one EL0 context and the
/// SVC handler runs with IRQs masked, so nothing can change state between the
/// reads. A multi-context kernel would need a consistent cut (or tolerate and
/// report the skew) -- noted rather than faked.
pub fn snapshot_for_reconcile() -> (Observed, Vec<UsageEntry>) {
    let accounts = crate::mvno::accounts();

    let mut rows: Vec<ProfileRow> = Vec::new();
    for slot in 0..MAX_SLOT_SCAN {
        match sim::profiles(slot) {
            Ok(profiles) => {
                for p in profiles {
                    rows.push(ProfileRow {
                        slot,
                        profile: p.id,
                        state: p.state,
                        owner: crate::mvno::owner_of(slot, p.id),
                    });
                }
            }
            Err(SimError::NoSuchSlot) => break,
            // Any other error cannot be produced by `profiles` today; skip the
            // slot rather than abort the kernel on a path the SVC can reach.
            Err(_) => continue,
        }
    }

    let (usage, sessions): (Vec<UsageEntry>, Vec<DataSession>) = DATA.lock().snapshot();
    let observed = build_observed(
        &accounts,
        &rows,
        &usage,
        &sessions,
        runix_kernel_arm::data_codes::demo_entitlement,
    );
    (observed, usage)
}

/// Record that the reconciler observed `usage` -- sets `last_used` for the
/// next regression check. The only data-state write the reconcile syscall
/// makes. Called AFTER the snapshot was built.
pub fn mark_observed(usage: &[UsageEntry]) {
    DATA.lock().mark_observed(usage);
}
