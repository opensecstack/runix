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
//! # Why none of this is MARSHAL-gated (Beta item 4.3 design)
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
//! None of them is a governance-consequential state change, so none gets a new
//! MARSHAL action type or gate; the consequential action a request can lead to
//! -- suspending the account -- is the existing MARSHAL-gated
//! `SYS_MVNO_SUSPEND`. That also means a data syscall that needed a MARSHAL
//! round trip would be a design error: the reclamation work (`reclaim.rs`)
//! and the walk's evaluation budget are built around the gated set staying
//! exactly as it is.
//!
//! The usage FEED is nonetheless privileged. Counting bytes into an account
//! can push it over its cap -- that denies it service -- and over the
//! escalation threshold, which makes the engine ask for its suspension. So
//! `SYS_DATA_ACCOUNT` is capability-scoped on its own resource
//! (`data:usage:{account}`), separate from session access
//! (`data:session:{account}`): holding the right to open or close sessions
//! does not imply the right to meter the account.
//!
//! Every refusal and every decision is still WORM-audited (on the same chain
//! as the eSIM/MVNO transitions, via `svc.rs`'s `audit_event`): "not gated" is
//! not "not recorded".
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
//! Entitlements come from `data_codes::demo_entitlement` (account 0 only);
//! there is no provisioning path.

use alloc::vec::Vec;
use spin::Mutex;

use runix_kernel_arm::data_codes::{build_observed, ProfileRow};
use runix_kernel_arm::data_state::{DataSession, DataState, OpenOutcome, TableFull, UsageEntry};
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
