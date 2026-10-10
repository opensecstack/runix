//! Subscriber / account / plan model for the MVNO stack core (Beta item 3,
//! step 1): who owns which eSIM profile, and what an account's status allows
//! a profile to do.
//!
//! Pure bookkeeping -- `core` + `alloc` only, no I/O, no clock, no hardware --
//! so it can be unit-tested on the host and later linked into `kernel-arm`.
//! Enforcement of *who may ask* (capability check, MARSHAL gate, WORM audit)
//! deliberately lives at `kernel-arm`'s syscall boundary, not here: this
//! module only answers "is this change consistent?" and refuses if not.
//!
//! # Ownership model
//!
//! One account may own **many** profiles (a subscriber with a phone and a
//! tablet eSIM, say); a profile is bound to **at most one** account. A
//! profile is named by [`ProfileKey`] `{ slot, profile }`, which is exactly
//! the `(slot, profile_id)` pair `kernel-arm/src/sim.rs` uses -- profile IDs
//! are only unique within a slot, so the slot is part of the identity.
//!
//! # The account <-> lifecycle coupling
//!
//! This registry never owns eSIM lifecycle state; `sim.rs` does. Every
//! operation that needs to know a profile's state takes it from the caller
//! through [`ProfileLifecycles`] (a trait, blanket-implemented for closures)
//! using [`ProfileLifecycle`], a local mirror of `sim.rs`'s `ProfileState`.
//! A mirror rather than a dependency because `kernel-arm` is a standalone
//! freestanding package this crate must not depend on; the variants are kept
//! identical so the adapter is a trivial 1:1 `match`.
//!
//! If the caller cannot say what a profile's state is (`None`), the registry
//! fails closed with `UnknownProfile` rather than guessing -- a guess of
//! "not Enabled" is exactly the wrong default for a security check.
//!
//! ```text
//! account status | enable a bound profile | bind new profile      | open -> status change
//! ---------------+------------------------+-----------------------+----------------------
//! Active         | allowed                | allowed               | -> Suspended, Closed
//! Suspended      | REFUSED (check_enable) | allowed, but only a   | -> Active, Closed
//!                |                        | non-Enabled profile   |
//! Closed         | REFUSED (check_enable) | REFUSED               | none: terminal
//!
//! status change  | profile lifecycle requirement / effect
//! ---------------+------------------------------------------------------
//! Active->Suspended | succeeds; returns every bound profile that is
//!                   | currently Enabled -- the caller MUST drive those
//!                   | Enabled->Disabled in sim.rs (the registry cannot)
//! Suspended->Active | no requirement; profiles stay Disabled until
//!                   | someone explicitly enables them again
//! *->Closed         | REFUSED while any bound profile is Enabled; every
//!                   | bound profile must be Created, Disabled or Deleted
//! Closed->*         | REFUSED (terminal)
//!
//! bind / unbind     | bind: profile not already bound, not Deleted; if it
//!                   | is Enabled the account must be Active.
//!                   | unbind: profile must not be Enabled (an Enabled
//!                   | profile with no owner would escape every check).
//! ```
//!
//! Suspension is a two-step handshake by necessity: the registry flips the
//! account to `Suspended` and hands back the forced-disable list; the caller
//! applies the disables. Between those steps an Enabled profile under a
//! Suspended account exists, so [`AccountRegistry::audit`] lets a caller (or a
//! test) re-verify the invariant against live lifecycle state afterwards.
//!
//! # Where the invariants are enforced
//!
//! Every mutation goes through [`AccountRegistry::apply`] -- the analogue of
//! `SimSlot::transition` in `sim.rs`. The public `open_account` / `bind` /
//! `unbind` / `suspend` / `reactivate` / `close` methods are one-line
//! wrappers, so there is exactly one enforcement point, and it validates
//! fully *before* mutating: on `Err` the registry is untouched.
//! [`AccountRegistry::check_enable`] is the one read-only query; it is the
//! gate `kernel-arm` must consult before an `Disabled -> Enabled` transition.
//!
//! # What this deliberately is not
//!
//! - `SubscriberId` is an opaque `u64`, never a name, number or e-mail: the
//!   registry holds no PII, so there is nothing to leak from it. Mapping an
//!   id to a human lives (if anywhere) outside the trusted core.
//! - No persistence across reboots, no billing, no plan semantics: `PlanId`
//!   is an opaque tag here; what a plan *entitles* is later work.
//! - Closed accounts and their `AccountId`s are never reclaimed, mirroring
//!   `sim.rs`'s never-reclaimed `Deleted` profiles: IDs stay unambiguous for
//!   the lifetime of the boot, at the cost of `MAX_ACCOUNTS` being a
//!   lifetime budget rather than a concurrent one.

use alloc::vec::Vec;

/// Bounded on purpose, like `sim.rs`'s `MAX_PROFILES_PER_SLOT`: this is
/// `no_std` code destined for a kernel, so "the registry grows until the heap
/// says no" is not an acceptable failure mode. The number is arbitrary (a
/// demo-scale budget); what matters is that `open_account` has a defined
/// answer when it is reached.
pub const MAX_ACCOUNTS: usize = 16;

/// Per-account profile cap. Also bounds total bindings at
/// `MAX_ACCOUNTS * MAX_PROFILES_PER_ACCOUNT`, so the binding table is bounded
/// without a separate limit.
pub const MAX_PROFILES_PER_ACCOUNT: usize = 4;

/// Opaque subscriber handle. Deliberately not a name/MSISDN/IMSI: no PII.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubscriberId(pub u64);

/// Registry-assigned account handle; sequential and never reused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AccountId(pub u64);

/// Opaque plan tag; entitlements are not modeled here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PlanId(pub u32);

/// One eSIM profile, named the way `kernel-arm/src/sim.rs` names it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProfileKey {
    pub slot: usize,
    pub profile: u8,
}

/// Account standing. `Closed` is terminal; see the module doc table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccountStatus {
    Active,
    Suspended,
    Closed,
}

/// Local mirror of `kernel-arm`'s `ProfileState` (see module doc for why a
/// mirror). Keep variant-for-variant identical to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProfileLifecycle {
    Created,
    Disabled,
    Enabled,
    Deleted,
}

/// Caller-supplied view of eSIM lifecycle state. `None` means "no such
/// profile / unknown", which the registry treats as an error, never as
/// "not Enabled".
pub trait ProfileLifecycles {
    fn lifecycle(&self, key: ProfileKey) -> Option<ProfileLifecycle>;
}

/// Closures are the common case (a lookup into `sim.rs`'s slot table).
impl<F> ProfileLifecycles for F
where
    F: Fn(ProfileKey) -> Option<ProfileLifecycle>,
{
    fn lifecycle(&self, key: ProfileKey) -> Option<ProfileLifecycle> {
        self(key)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Account {
    pub id: AccountId,
    pub subscriber: SubscriberId,
    pub plan: PlanId,
    pub status: AccountStatus,
}

/// Why a registry operation was refused. Every variant means "nothing was
/// changed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccountError {
    /// `MAX_ACCOUNTS` accounts have been opened over this boot.
    RegistryFull,
    /// The account already owns `MAX_PROFILES_PER_ACCOUNT` profiles.
    AccountFull,
    NoSuchAccount,
    /// The account is `Closed`; nothing can be done to it.
    AccountClosed,
    /// The account's status does not permit this (e.g. enabling under a
    /// `Suspended` account). Carries the status that blocked it.
    AccountNotActive(AccountStatus),
    /// Status change not in the table (same-status, or from `Closed`).
    InvalidTransition {
        from: AccountStatus,
        to: AccountStatus,
    },
    /// Profile is already bound; carries the current owner. Unbind first.
    AlreadyBound(AccountId),
    /// Profile is not bound to the account in question (or to anyone).
    NotBound,
    /// Caller's lifecycle view has no such profile; fail closed.
    UnknownProfile(ProfileKey),
    /// A `Deleted` profile is terminal and cannot be bound.
    ProfileDeleted(ProfileKey),
    /// Operation requires this profile not be `Enabled`.
    ProfileEnabled(ProfileKey),
}

/// The set of mutations, so that [`AccountRegistry::apply`] is the single
/// place they are validated.
#[derive(Clone, Copy, Debug)]
pub enum Change {
    Open {
        subscriber: SubscriberId,
        plan: PlanId,
    },
    Bind {
        account: AccountId,
        profile: ProfileKey,
    },
    Unbind {
        profile: ProfileKey,
    },
    SetStatus {
        account: AccountId,
        to: AccountStatus,
    },
}

/// Result of an applied change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Applied {
    /// The account created / affected (for `Unbind`, the previous owner).
    pub account: AccountId,
    /// Profiles the caller MUST now drive `Enabled -> Disabled`. Non-empty
    /// only for `Active -> Suspended`.
    pub force_disable: Vec<ProfileKey>,
}

#[derive(Debug, Default)]
pub struct AccountRegistry {
    accounts: Vec<Account>,
    bindings: Vec<(ProfileKey, AccountId)>,
}

impl AccountRegistry {
    pub const fn new() -> Self {
        Self {
            accounts: Vec::new(),
            bindings: Vec::new(),
        }
    }

    pub fn account(&self, id: AccountId) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Owner of `profile`, if bound.
    pub fn owner_of(&self, profile: ProfileKey) -> Option<AccountId> {
        self.bindings
            .iter()
            .find(|(k, _)| *k == profile)
            .map(|(_, a)| *a)
    }

    /// Profiles bound to `account`, in bind order.
    pub fn profiles_of(&self, account: AccountId) -> Vec<ProfileKey> {
        self.bindings
            .iter()
            .filter(|(_, a)| *a == account)
            .map(|(k, _)| *k)
            .collect()
    }

    /// The gate for `Disabled -> Enabled`: `profile` must be bound to
    /// `account` and `account` must be `Active`. Read-only; a caller that
    /// enables without asking this has bypassed invariant (c).
    pub fn check_enable(
        &self,
        account: AccountId,
        profile: ProfileKey,
    ) -> Result<(), AccountError> {
        let acct = self.account(account).ok_or(AccountError::NoSuchAccount)?;
        if self.owner_of(profile) != Some(account) {
            return Err(AccountError::NotBound);
        }
        match acct.status {
            AccountStatus::Active => Ok(()),
            AccountStatus::Closed => Err(AccountError::AccountClosed),
            s => Err(AccountError::AccountNotActive(s)),
        }
    }

    /// Profiles that are `Enabled` under a non-`Active` account, per the
    /// caller's live lifecycle view. Empty means invariant (c) holds.
    /// Profiles the view does not know are skipped (they cannot be reported
    /// as Enabled); `apply` is where unknowns are refused.
    pub fn audit(&self, lc: &impl ProfileLifecycles) -> Vec<ProfileKey> {
        self.bindings
            .iter()
            .filter(|(k, a)| {
                lc.lifecycle(*k) == Some(ProfileLifecycle::Enabled)
                    && self
                        .account(*a)
                        .map_or(true, |acct| acct.status != AccountStatus::Active)
            })
            .map(|(k, _)| *k)
            .collect()
    }

    /// The **only** place the registry ever changes. Validates fully, then
    /// mutates; on `Err` nothing was touched.
    pub fn apply(
        &mut self,
        change: Change,
        lc: &impl ProfileLifecycles,
    ) -> Result<Applied, AccountError> {
        match change {
            Change::Open { subscriber, plan } => {
                if self.accounts.len() >= MAX_ACCOUNTS {
                    return Err(AccountError::RegistryFull);
                }
                // Accounts are never removed, so the length is a unique,
                // sequential id.
                let id = AccountId(self.accounts.len() as u64);
                self.accounts.push(Account {
                    id,
                    subscriber,
                    plan,
                    status: AccountStatus::Active,
                });
                Ok(Applied {
                    account: id,
                    force_disable: Vec::new(),
                })
            }

            Change::Bind { account, profile } => {
                let status = self
                    .account(account)
                    .ok_or(AccountError::NoSuchAccount)?
                    .status;
                if status == AccountStatus::Closed {
                    return Err(AccountError::AccountClosed);
                }
                // (a)+(b): bound at most once, and only an explicit unbind
                // frees it -- even re-binding to the same owner is refused
                // so there is one way to change ownership, not two.
                if let Some(owner) = self.owner_of(profile) {
                    return Err(AccountError::AlreadyBound(owner));
                }
                let state = lc
                    .lifecycle(profile)
                    .ok_or(AccountError::UnknownProfile(profile))?;
                if state == ProfileLifecycle::Deleted {
                    return Err(AccountError::ProfileDeleted(profile));
                }
                // (c): never create an Enabled profile under a non-Active
                // account via the back door of binding.
                if state == ProfileLifecycle::Enabled && status != AccountStatus::Active {
                    return Err(AccountError::AccountNotActive(status));
                }
                if self.profiles_of(account).len() >= MAX_PROFILES_PER_ACCOUNT {
                    return Err(AccountError::AccountFull);
                }
                self.bindings.push((profile, account));
                Ok(Applied {
                    account,
                    force_disable: Vec::new(),
                })
            }

            Change::Unbind { profile } => {
                let pos = self
                    .bindings
                    .iter()
                    .position(|(k, _)| *k == profile)
                    .ok_or(AccountError::NotBound)?;
                let state = lc
                    .lifecycle(profile)
                    .ok_or(AccountError::UnknownProfile(profile))?;
                if state == ProfileLifecycle::Enabled {
                    return Err(AccountError::ProfileEnabled(profile));
                }
                let (_, owner) = self.bindings.remove(pos);
                Ok(Applied {
                    account: owner,
                    force_disable: Vec::new(),
                })
            }

            Change::SetStatus { account, to } => {
                let idx = self
                    .accounts
                    .iter()
                    .position(|a| a.id == account)
                    .ok_or(AccountError::NoSuchAccount)?;
                let from = self.accounts[idx].status;

                // The status table as one match. `Closed` has no arm as a
                // source, which is what makes it terminal.
                let legal = match (from, to) {
                    (AccountStatus::Closed, _) => return Err(AccountError::AccountClosed),
                    (AccountStatus::Active, AccountStatus::Suspended)
                    | (AccountStatus::Suspended, AccountStatus::Active)
                    | (AccountStatus::Active, AccountStatus::Closed)
                    | (AccountStatus::Suspended, AccountStatus::Closed) => true,
                    _ => false,
                };
                if !legal {
                    return Err(AccountError::InvalidTransition { from, to });
                }

                // Gather lifecycle facts for every bound profile up front so
                // an unknown profile aborts before anything is written.
                let mut force_disable = Vec::new();
                if to != AccountStatus::Active {
                    for key in self.profiles_of(account) {
                        let state = lc.lifecycle(key).ok_or(AccountError::UnknownProfile(key))?;
                        if state == ProfileLifecycle::Enabled {
                            if to == AccountStatus::Closed {
                                // (d): closing never silently disables.
                                return Err(AccountError::ProfileEnabled(key));
                            }
                            force_disable.push(key);
                        }
                    }
                }

                self.accounts[idx].status = to;
                Ok(Applied {
                    account,
                    force_disable,
                })
            }
        }
    }

    pub fn open_account(
        &mut self,
        subscriber: SubscriberId,
        plan: PlanId,
    ) -> Result<AccountId, AccountError> {
        self.apply(Change::Open { subscriber, plan }, &no_lifecycle)
            .map(|a| a.account)
    }

    pub fn bind(
        &mut self,
        account: AccountId,
        profile: ProfileKey,
        lc: &impl ProfileLifecycles,
    ) -> Result<(), AccountError> {
        self.apply(Change::Bind { account, profile }, lc)
            .map(|_| ())
    }

    pub fn unbind(
        &mut self,
        profile: ProfileKey,
        lc: &impl ProfileLifecycles,
    ) -> Result<(), AccountError> {
        self.apply(Change::Unbind { profile }, lc).map(|_| ())
    }

    /// Returns the profiles the caller must force `Enabled -> Disabled`.
    pub fn suspend(
        &mut self,
        account: AccountId,
        lc: &impl ProfileLifecycles,
    ) -> Result<Vec<ProfileKey>, AccountError> {
        self.apply(
            Change::SetStatus {
                account,
                to: AccountStatus::Suspended,
            },
            lc,
        )
        .map(|a| a.force_disable)
    }

    pub fn reactivate(&mut self, account: AccountId) -> Result<(), AccountError> {
        self.apply(
            Change::SetStatus {
                account,
                to: AccountStatus::Active,
            },
            &no_lifecycle,
        )
        .map(|_| ())
    }

    pub fn close(
        &mut self,
        account: AccountId,
        lc: &impl ProfileLifecycles,
    ) -> Result<(), AccountError> {
        self.apply(
            Change::SetStatus {
                account,
                to: AccountStatus::Closed,
            },
            lc,
        )
        .map(|_| ())
    }

    /// **DEMO DATA ONLY** -- compiled-in accounts so the rest of the stack
    /// has something to bind against before real provisioning exists, in the
    /// same spirit as the demo signing key. Not a real subscriber base.
    /// Account 0 owns slot 0 profiles 0 and 1; account 1 owns slot 1
    /// profile 0. Assumes those profiles exist and are not Deleted per `lc`.
    pub fn demo(lc: &impl ProfileLifecycles) -> Result<Self, AccountError> {
        let mut r = Self::new();
        let a = r.open_account(SubscriberId(0xD0_0001), PlanId(1))?;
        let b = r.open_account(SubscriberId(0xD0_0002), PlanId(2))?;
        r.bind(
            a,
            ProfileKey {
                slot: 0,
                profile: 0,
            },
            lc,
        )?;
        r.bind(
            a,
            ProfileKey {
                slot: 0,
                profile: 1,
            },
            lc,
        )?;
        r.bind(
            b,
            ProfileKey {
                slot: 1,
                profile: 0,
            },
            lc,
        )?;
        Ok(r)
    }
}

/// `Open` and `Active`-bound status changes never consult lifecycle state;
/// this satisfies the signature without inventing data.
fn no_lifecycle(_: ProfileKey) -> Option<ProfileLifecycle> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProfileLifecycle::*;

    fn pk(slot: usize, profile: u8) -> ProfileKey {
        ProfileKey { slot, profile }
    }

    /// Lifecycle view: every profile is in `s`.
    fn all(s: ProfileLifecycle) -> impl Fn(ProfileKey) -> Option<ProfileLifecycle> {
        move |_| Some(s)
    }

    /// Lifecycle view from a fixed table; unlisted profiles are unknown.
    fn table(
        t: &'static [(ProfileKey, ProfileLifecycle)],
    ) -> impl Fn(ProfileKey) -> Option<ProfileLifecycle> {
        move |k| t.iter().find(|(p, _)| *p == k).map(|(_, s)| *s)
    }

    fn reg_with_account() -> (AccountRegistry, AccountId) {
        let mut r = AccountRegistry::new();
        let a = r.open_account(SubscriberId(1), PlanId(1)).unwrap();
        (r, a)
    }

    #[test]
    fn open_assigns_sequential_active_accounts() {
        let mut r = AccountRegistry::new();
        let a = r.open_account(SubscriberId(10), PlanId(3)).unwrap();
        let b = r.open_account(SubscriberId(11), PlanId(4)).unwrap();
        assert_eq!(a, AccountId(0));
        assert_eq!(b, AccountId(1));
        let acct = r.account(a).unwrap();
        assert_eq!(acct.subscriber, SubscriberId(10));
        assert_eq!(acct.plan, PlanId(3));
        assert_eq!(acct.status, AccountStatus::Active);
        assert_eq!(r.accounts().len(), 2);
    }

    #[test]
    fn registry_is_bounded() {
        let mut r = AccountRegistry::new();
        for i in 0..MAX_ACCOUNTS {
            r.open_account(SubscriberId(i as u64), PlanId(0)).unwrap();
        }
        assert_eq!(
            r.open_account(SubscriberId(99), PlanId(0)),
            Err(AccountError::RegistryFull)
        );
        assert_eq!(r.accounts().len(), MAX_ACCOUNTS);
    }

    #[test]
    fn closed_accounts_still_consume_registry_budget() {
        let mut r = AccountRegistry::new();
        for i in 0..MAX_ACCOUNTS {
            let a = r.open_account(SubscriberId(i as u64), PlanId(0)).unwrap();
            r.close(a, &all(Disabled)).unwrap();
        }
        assert_eq!(
            r.open_account(SubscriberId(99), PlanId(0)),
            Err(AccountError::RegistryFull)
        );
    }

    #[test]
    fn one_account_many_profiles() {
        let (mut r, a) = reg_with_account();
        let lc = all(Disabled);
        r.bind(a, pk(0, 0), &lc).unwrap();
        r.bind(a, pk(0, 1), &lc).unwrap();
        r.bind(a, pk(1, 0), &lc).unwrap();
        assert_eq!(r.profiles_of(a), [pk(0, 0), pk(0, 1), pk(1, 0)]);
        assert_eq!(r.owner_of(pk(1, 0)), Some(a));
    }

    #[test]
    fn profile_key_includes_slot() {
        let (mut r, a) = reg_with_account();
        let lc = all(Disabled);
        r.bind(a, pk(0, 1), &lc).unwrap();
        // Same profile id, different slot: a different profile.
        assert_eq!(r.owner_of(pk(1, 1)), None);
        r.bind(a, pk(1, 1), &lc).unwrap();
    }

    #[test]
    fn per_account_profile_limit() {
        let (mut r, a) = reg_with_account();
        let lc = all(Disabled);
        for i in 0..MAX_PROFILES_PER_ACCOUNT {
            r.bind(a, pk(0, i as u8), &lc).unwrap();
        }
        assert_eq!(r.bind(a, pk(1, 0), &lc), Err(AccountError::AccountFull));
        // Another account is unaffected by a full sibling.
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        r.bind(b, pk(1, 0), &lc).unwrap();
    }

    #[test]
    fn profile_bound_to_at_most_one_account() {
        let (mut r, a) = reg_with_account();
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        let lc = all(Disabled);
        r.bind(a, pk(0, 0), &lc).unwrap();
        assert_eq!(r.bind(b, pk(0, 0), &lc), Err(AccountError::AlreadyBound(a)));
        // Even the same owner cannot bind twice.
        assert_eq!(r.bind(a, pk(0, 0), &lc), Err(AccountError::AlreadyBound(a)));
        assert_eq!(r.profiles_of(a), [pk(0, 0)]);
        assert!(r.profiles_of(b).is_empty());
    }

    #[test]
    fn rebind_requires_unbind_first() {
        let (mut r, a) = reg_with_account();
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        let lc = all(Disabled);
        r.bind(a, pk(0, 0), &lc).unwrap();
        assert!(r.bind(b, pk(0, 0), &lc).is_err());
        r.unbind(pk(0, 0), &lc).unwrap();
        assert_eq!(r.owner_of(pk(0, 0)), None);
        r.bind(b, pk(0, 0), &lc).unwrap();
        assert_eq!(r.owner_of(pk(0, 0)), Some(b));
    }

    #[test]
    fn deleted_profile_can_be_unbound_but_never_bound() {
        let (mut r, a) = reg_with_account();
        assert_eq!(
            r.bind(a, pk(0, 0), &all(Deleted)),
            Err(AccountError::ProfileDeleted(pk(0, 0)))
        );
        r.bind(a, pk(0, 0), &all(Disabled)).unwrap();
        // Later deleted in sim.rs: the stale binding can be released.
        r.unbind(pk(0, 0), &all(Deleted)).unwrap();
        assert_eq!(r.owner_of(pk(0, 0)), None);
    }

    #[test]
    fn unbind_refuses_enabled_and_unbound_and_unknown() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Disabled)).unwrap();
        assert_eq!(
            r.unbind(pk(0, 0), &all(Enabled)),
            Err(AccountError::ProfileEnabled(pk(0, 0)))
        );
        assert_eq!(
            r.unbind(pk(0, 0), &|_| None),
            Err(AccountError::UnknownProfile(pk(0, 0)))
        );
        assert_eq!(
            r.unbind(pk(3, 3), &all(Disabled)),
            Err(AccountError::NotBound)
        );
        assert_eq!(r.owner_of(pk(0, 0)), Some(a));
    }

    #[test]
    fn bind_unknown_profile_fails_closed() {
        let (mut r, a) = reg_with_account();
        assert_eq!(
            r.bind(a, pk(0, 0), &|_| None),
            Err(AccountError::UnknownProfile(pk(0, 0)))
        );
        assert!(r.profiles_of(a).is_empty());
    }

    #[test]
    fn bind_to_missing_account() {
        let mut r = AccountRegistry::new();
        assert_eq!(
            r.bind(AccountId(7), pk(0, 0), &all(Disabled)),
            Err(AccountError::NoSuchAccount)
        );
    }

    #[test]
    fn check_enable_only_when_active_and_owner() {
        let (mut r, a) = reg_with_account();
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        r.bind(a, pk(0, 0), &all(Disabled)).unwrap();
        assert_eq!(r.check_enable(a, pk(0, 0)), Ok(()));
        // Wrong account / unbound profile.
        assert_eq!(r.check_enable(b, pk(0, 0)), Err(AccountError::NotBound));
        assert_eq!(r.check_enable(a, pk(2, 2)), Err(AccountError::NotBound));
        assert_eq!(
            r.check_enable(AccountId(9), pk(0, 0)),
            Err(AccountError::NoSuchAccount)
        );
        r.suspend(a, &all(Disabled)).unwrap();
        assert_eq!(
            r.check_enable(a, pk(0, 0)),
            Err(AccountError::AccountNotActive(AccountStatus::Suspended))
        );
        r.reactivate(a).unwrap();
        assert_eq!(r.check_enable(a, pk(0, 0)), Ok(()));
        r.close(a, &all(Disabled)).unwrap();
        assert_eq!(
            r.check_enable(a, pk(0, 0)),
            Err(AccountError::AccountClosed)
        );
    }

    #[test]
    fn suspend_returns_exactly_the_enabled_bound_profiles() {
        let (mut r, a) = reg_with_account();
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        static T: [(ProfileKey, ProfileLifecycle); 4] = [
            (
                ProfileKey {
                    slot: 0,
                    profile: 0,
                },
                Enabled,
            ),
            (
                ProfileKey {
                    slot: 0,
                    profile: 1,
                },
                Disabled,
            ),
            (
                ProfileKey {
                    slot: 1,
                    profile: 0,
                },
                Enabled,
            ),
            (
                ProfileKey {
                    slot: 2,
                    profile: 0,
                },
                Enabled,
            ),
        ];
        let lc = table(&T);
        r.bind(a, pk(0, 0), &lc).unwrap();
        r.bind(a, pk(0, 1), &lc).unwrap();
        r.bind(a, pk(1, 0), &lc).unwrap();
        r.bind(b, pk(2, 0), &lc).unwrap(); // other account's Enabled profile
        let forced = r.suspend(a, &lc).unwrap();
        assert_eq!(forced, [pk(0, 0), pk(1, 0)]);
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Suspended);
        assert_eq!(r.account(b).unwrap().status, AccountStatus::Active);
        // Until the caller disables them the audit flags exactly those.
        assert_eq!(r.audit(&lc), [pk(0, 0), pk(1, 0)]);
        assert!(r.audit(&all(Disabled)).is_empty());
    }

    #[test]
    fn suspend_with_nothing_enabled_returns_empty() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Disabled)).unwrap();
        assert!(r.suspend(a, &all(Disabled)).unwrap().is_empty());
    }

    #[test]
    fn suspend_unknown_lifecycle_is_refused_without_mutation() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Disabled)).unwrap();
        assert_eq!(
            r.suspend(a, &|_| None),
            Err(AccountError::UnknownProfile(pk(0, 0)))
        );
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Active);
    }

    #[test]
    fn suspended_to_active_allowed_and_cycle_repeats() {
        let (mut r, a) = reg_with_account();
        for _ in 0..3 {
            r.suspend(a, &all(Disabled)).unwrap();
            assert_eq!(r.account(a).unwrap().status, AccountStatus::Suspended);
            r.reactivate(a).unwrap();
            assert_eq!(r.account(a).unwrap().status, AccountStatus::Active);
        }
    }

    #[test]
    fn same_status_transitions_are_rejected() {
        let (mut r, a) = reg_with_account();
        assert_eq!(
            r.reactivate(a),
            Err(AccountError::InvalidTransition {
                from: AccountStatus::Active,
                to: AccountStatus::Active
            })
        );
        r.suspend(a, &all(Disabled)).unwrap();
        assert_eq!(
            r.suspend(a, &all(Disabled)),
            Err(AccountError::InvalidTransition {
                from: AccountStatus::Suspended,
                to: AccountStatus::Suspended
            })
        );
    }

    #[test]
    fn bind_enabled_profile_requires_active_account() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Enabled)).unwrap(); // Active: fine
        r.suspend(a, &all(Disabled)).unwrap();
        assert_eq!(
            r.bind(a, pk(0, 1), &all(Enabled)),
            Err(AccountError::AccountNotActive(AccountStatus::Suspended))
        );
        // A non-Enabled profile may still be bound to a Suspended account.
        r.bind(a, pk(0, 1), &all(Disabled)).unwrap();
        r.bind(a, pk(0, 2), &all(Created)).unwrap();
    }

    #[test]
    fn close_refused_while_any_profile_enabled() {
        let (mut r, a) = reg_with_account();
        static T: [(ProfileKey, ProfileLifecycle); 2] = [
            (
                ProfileKey {
                    slot: 0,
                    profile: 0,
                },
                Disabled,
            ),
            (
                ProfileKey {
                    slot: 0,
                    profile: 1,
                },
                Enabled,
            ),
        ];
        let lc = table(&T);
        r.bind(a, pk(0, 0), &lc).unwrap();
        r.bind(a, pk(0, 1), &lc).unwrap();
        assert_eq!(r.close(a, &lc), Err(AccountError::ProfileEnabled(pk(0, 1))));
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Active);
        // Same from Suspended.
        r.suspend(a, &lc).unwrap();
        assert_eq!(r.close(a, &lc), Err(AccountError::ProfileEnabled(pk(0, 1))));
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Suspended);
    }

    #[test]
    fn close_allows_created_disabled_deleted_profiles() {
        let (mut r, a) = reg_with_account();
        static T: [(ProfileKey, ProfileLifecycle); 3] = [
            (
                ProfileKey {
                    slot: 0,
                    profile: 0,
                },
                Created,
            ),
            (
                ProfileKey {
                    slot: 0,
                    profile: 1,
                },
                Disabled,
            ),
            (
                ProfileKey {
                    slot: 0,
                    profile: 2,
                },
                Deleted,
            ),
        ];
        let lc = table(&T);
        r.bind(a, pk(0, 0), &lc).unwrap();
        r.bind(a, pk(0, 1), &lc).unwrap();
        r.bind(a, pk(0, 2), &all(Disabled)).unwrap();
        r.close(a, &lc).unwrap();
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Closed);
    }

    #[test]
    fn close_from_suspended_allowed() {
        let (mut r, a) = reg_with_account();
        r.suspend(a, &all(Disabled)).unwrap();
        r.close(a, &all(Disabled)).unwrap();
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Closed);
    }

    #[test]
    fn closed_is_terminal() {
        let (mut r, a) = reg_with_account();
        r.close(a, &all(Disabled)).unwrap();
        let lc = all(Disabled);
        assert_eq!(r.reactivate(a), Err(AccountError::AccountClosed));
        assert_eq!(r.suspend(a, &lc), Err(AccountError::AccountClosed));
        assert_eq!(r.close(a, &lc), Err(AccountError::AccountClosed));
        assert_eq!(r.bind(a, pk(0, 0), &lc), Err(AccountError::AccountClosed));
        assert_eq!(r.account(a).unwrap().status, AccountStatus::Closed);
    }

    #[test]
    fn closed_account_profiles_can_be_released_and_rebound_elsewhere() {
        let (mut r, a) = reg_with_account();
        let b = r.open_account(SubscriberId(2), PlanId(1)).unwrap();
        let lc = all(Disabled);
        r.bind(a, pk(0, 0), &lc).unwrap();
        r.close(a, &lc).unwrap();
        // Still bound until explicitly released.
        assert_eq!(r.bind(b, pk(0, 0), &lc), Err(AccountError::AlreadyBound(a)));
        r.unbind(pk(0, 0), &lc).unwrap();
        r.bind(b, pk(0, 0), &lc).unwrap();
    }

    #[test]
    fn rejected_changes_leave_registry_untouched() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Enabled)).unwrap();
        let before_accts = r.accounts().to_vec();
        let before_binds = r.profiles_of(a);
        assert!(r.close(a, &all(Enabled)).is_err());
        assert!(r.bind(a, pk(0, 0), &all(Disabled)).is_err());
        assert!(r.unbind(pk(0, 0), &all(Enabled)).is_err());
        assert!(r.reactivate(a).is_err());
        assert_eq!(r.accounts(), &before_accts[..]);
        assert_eq!(r.profiles_of(a), before_binds);
    }

    #[test]
    fn operations_on_missing_account_do_not_panic() {
        let mut r = AccountRegistry::new();
        let lc = all(Disabled);
        assert_eq!(
            r.suspend(AccountId(u64::MAX), &lc),
            Err(AccountError::NoSuchAccount)
        );
        assert_eq!(r.reactivate(AccountId(0)), Err(AccountError::NoSuchAccount));
        assert_eq!(r.close(AccountId(0), &lc), Err(AccountError::NoSuchAccount));
        assert_eq!(
            r.unbind(pk(usize::MAX, 255), &lc),
            Err(AccountError::NotBound)
        );
    }

    #[test]
    fn audit_clean_for_active_accounts() {
        let (mut r, a) = reg_with_account();
        r.bind(a, pk(0, 0), &all(Enabled)).unwrap();
        assert!(r.audit(&all(Enabled)).is_empty());
    }

    #[test]
    fn demo_registry_is_consistent() {
        let r = AccountRegistry::demo(&all(Disabled)).unwrap();
        assert_eq!(r.accounts().len(), 2);
        assert_eq!(r.profiles_of(AccountId(0)), [pk(0, 0), pk(0, 1)]);
        assert_eq!(r.owner_of(pk(1, 0)), Some(AccountId(1)));
        assert_eq!(r.check_enable(AccountId(0), pk(0, 0)), Ok(()));
        assert_eq!(
            r.check_enable(AccountId(1), pk(0, 0)),
            Err(AccountError::NotBound)
        );
    }
}
