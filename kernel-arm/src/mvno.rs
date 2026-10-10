//! Kernel-side owner of the MVNO account registry (Beta item 3.3): the one
//! place `runix_mobile::account::AccountRegistry` lives at runtime, plus the
//! adapters that couple it to `sim.rs`'s eSIM lifecycle.
//!
//! `runix-mobile` is pure bookkeeping (`core` + `alloc`, no I/O) and, by its
//! own doc comment, deliberately enforces nothing about *who may ask*. This
//! module holds the state; `svc.rs` is the enforcement point (capability
//! check, audit) exactly as it is for `sim.rs`. Nothing in here checks a
//! capability or writes the WORM log -- governance lives at the syscall
//! boundary where the requesting context is known, the same split
//! `esim_marshal.rs` and `sim.rs`'s doc comments describe.
//!
//! # The account <-> lifecycle coupling
//!
//! The registry never owns lifecycle state; `sim.rs` does. Every operation
//! that needs a profile's state is handed [`lifecycle_view`], a read through
//! `sim::profile_state` mapped 1:1 by [`adapt`] onto the registry's local
//! `ProfileLifecycle` mirror. A `sim::SimError` (no such slot/profile) maps
//! to `None`, which the registry treats as `UnknownProfile` -- it fails
//! closed rather than guessing "not Enabled".
//!
//! Two couplings are enforced at the syscall boundary (`svc.rs`), never
//! inside `sim.rs`'s data model:
//!
//! - **Enable gate**: `SYS_SIM_ENABLE` calls [`gate_enable`] after the
//!   capability check and before MARSHAL. A profile bound to no account is
//!   refused (fail closed), as is one whose owner is not `Active`.
//! - **Suspend handshake**: `AccountRegistry::suspend` flips the account and
//!   *returns* the profiles that must be forced `Enabled -> Disabled`; it
//!   cannot apply them. `svc.rs` applies them via `sim::disable`, then calls
//!   [`audit`] to re-verify the invariant against live state. Between the
//!   flip and the disables an Enabled profile under a Suspended account
//!   exists; that window is single-context (one EL0, IRQs masked in the SVC
//!   handler) and the audit is the backstop, never skipped.
//!
//! # Lock order
//!
//! `REGISTRY` may take the `sim.rs` `SLOTS` lock (inside [`lifecycle_view`],
//! which runs under the registry lock for `bind`/`unbind`/`suspend`). The
//! **reverse is forbidden**: nothing may call into this module while holding
//! the `SLOTS` lock (`sim.rs` never does -- it knows nothing of accounts).
//! `svc.rs` keeps the order by releasing the registry lock *before* it calls
//! `sim::disable` for the forced-disable list.
//!
//! # Known, tracked gap: the MVNO syscalls are not MARSHAL-gated yet
//!
//! (`BIND` requires both the account's and the profile's own capability --
//! see `svc.rs`.) `SYS_MVNO_BIND`/`SUSPEND`/`REACTIVATE` are
//! capability-gated and WORM-audited, but **not** routed through `esim_marshal::evaluate` -- that
//! function hardcodes `esim.{action}` slot/profile envelopes, so generalizing
//! it (plus the upstream rbacMap and `citadel_proxy` policy entries) is
//! Beta item 3.4. CLAUDE.md requires privileged actions to flow through
//! MARSHAL; this is a documented, scheduled omission, not an oversight.
//! (`SYS_SIM_ENABLE`'s existing MARSHAL gate is unchanged.)
//!
//! # Demo data
//!
//! [`open_demo_account`] opens one compiled-in account at boot -- **DEMO DATA
//! ONLY**, in the same spirit as `capabilities.rs`'s demo signing key. There
//! is no provisioning path; EL0 cannot open accounts.

use alloc::vec::Vec;
use spin::Mutex;

use runix_mobile::account::{
    AccountError, AccountId, AccountRegistry, AccountStatus, PlanId, ProfileKey, ProfileLifecycle,
    SubscriberId,
};
use runix_mobile::selection::AccountStanding;

use crate::sim::{self, ProfileState};

/// The one registry. `AccountRegistry::new()` is `const`, so no lazy init.
/// See the module doc comment for the lock order (registry -> sim, never
/// the reverse).
static REGISTRY: Mutex<AccountRegistry> = Mutex::new(AccountRegistry::new());

/// 1:1 variant mapping from `sim.rs`'s `ProfileState` to the registry's
/// mirror. Exhaustive on purpose: a new `ProfileState` variant must fail to
/// compile here rather than be silently mis-mapped.
pub fn adapt(state: ProfileState) -> ProfileLifecycle {
    match state {
        ProfileState::Created => ProfileLifecycle::Created,
        ProfileState::Disabled => ProfileLifecycle::Disabled,
        ProfileState::Enabled => ProfileLifecycle::Enabled,
        ProfileState::Deleted => ProfileLifecycle::Deleted,
    }
}

/// The registry's window onto live eSIM state. `None` on any `SimError`, so
/// the registry fails closed (`UnknownProfile`).
fn lifecycle_view(key: ProfileKey) -> Option<ProfileLifecycle> {
    sim::profile_state(key.slot, key.profile).ok().map(adapt)
}

fn key(slot: usize, profile: u8) -> ProfileKey {
    ProfileKey { slot, profile }
}

/// Opens the compiled-in demo account (**DEMO DATA ONLY**) and returns its
/// id. The registry assigns ids sequentially, so on a fresh boot this is
/// account 0, which is what `nonsecure.rs`'s capabilities and `el0.rs`'s
/// walk name.
pub fn open_demo_account() -> Result<AccountId, AccountError> {
    REGISTRY
        .lock()
        .open_account(SubscriberId(0xD0_0001), PlanId(1))
}

/// Binds `(slot, profile)` to `account`, subject to the registry's own rules
/// (not already bound, not Deleted, account not Closed, ...).
pub fn bind(account: u64, slot: usize, profile: u8) -> Result<(), AccountError> {
    REGISTRY
        .lock()
        .bind(AccountId(account), key(slot, profile), &lifecycle_view)
}

/// Releases `(slot, profile)`'s binding. `Ok(None)` means it was never bound
/// (nothing to release -- not an error for the delete path); `Ok(Some(a))`
/// names the previous owner.
pub fn unbind(slot: usize, profile: u8) -> Result<Option<AccountId>, AccountError> {
    let k = key(slot, profile);
    let mut reg = REGISTRY.lock();
    match reg.owner_of(k) {
        None => Ok(None),
        Some(owner) => reg.unbind(k, &lifecycle_view).map(|()| Some(owner)),
    }
}

/// The enable gate: `Ok` only if `(slot, profile)` is bound to an `Active`
/// account. An unbound profile is `Err(NotBound)` (fail closed -- a profile
/// with no owner must not be enableable), as is a non-Active owner.
pub fn gate_enable(slot: usize, profile: u8) -> Result<(), AccountError> {
    let k = key(slot, profile);
    let reg = REGISTRY.lock();
    let owner = reg.owner_of(k).ok_or(AccountError::NotBound)?;
    reg.check_enable(owner, k)
}

/// `Active -> Suspended`. Returns the profiles the caller **must** now force
/// `Enabled -> Disabled` (the registry cannot). The registry lock is released
/// on return, so the caller may take the `sim.rs` lock without inverting the
/// lock order.
pub fn suspend(account: u64) -> Result<Vec<ProfileKey>, AccountError> {
    REGISTRY.lock().suspend(AccountId(account), &lifecycle_view)
}

/// `Suspended -> Active`. Profiles stay Disabled until explicitly re-enabled.
pub fn reactivate(account: u64) -> Result<(), AccountError> {
    REGISTRY.lock().reactivate(AccountId(account))
}

/// Profiles that are Enabled under a non-Active account, per live `sim.rs`
/// state. Empty means the invariant holds.
pub fn audit() -> Vec<ProfileKey> {
    REGISTRY.lock().audit(&lifecycle_view)
}

/// Standing of `account` in `reg`, mapped for `selection::select_network`
/// (which deliberately does not import `account` types). `None` if there is
/// no such account. Takes the registry explicitly: the selection proof uses
/// its own local one, never the global [`REGISTRY`], and nothing reads the
/// global one's standing yet (no attach path until the modem work).
pub fn standing_in(reg: &AccountRegistry, account: u64) -> Option<AccountStanding> {
    reg.account(AccountId(account)).map(|a| match a.status {
        AccountStatus::Active => AccountStanding::Active,
        AccountStatus::Suspended => AccountStanding::Suspended,
        AccountStatus::Closed => AccountStanding::Closed,
    })
}
