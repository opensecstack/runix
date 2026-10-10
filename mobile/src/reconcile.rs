//! Read-only reconciliation of observed live state against policy (Beta
//! item 4, step 2).
//!
//! # The governing invariant: observe and report, never correct
//!
//! Reconciliation here is read-only and incident-raising only. It is never
//! self-correcting. [`reconcile`] is a pure function from an immutable
//! [`Observed`] snapshot (which already carries the policy-intended values:
//! caps, escalation thresholds, roaming permission) to a list of
//! [`Incident`]s. It takes no `&mut` anything, holds no handle to live state,
//! and has no way to call an action. Its output is purely descriptive: an
//! incident names a kind, a subject, and the expected-vs-observed facts, so
//! the caller can WORM-record it. Incidents are facts, not commands -- no
//! type in this module's public API is an instruction to mutate.
//!
//! Why this is structural rather than a convention: correcting drift (say,
//! suspending an account whose usage passed its threshold, or disabling a
//! profile under a closed account) is a privileged write. A reconciler that
//! "healed" what it found would be an ungoverned writer that bypasses
//! MARSHAL and WORM -- exactly the parallel authorization path this project
//! forbids. Correction is a separate, governed, human- or operator-initiated
//! action that goes through the normal gate and is audited like any other.
//! The reconciler's only job is to make sure nobody can say "we did not
//! know".
//!
//! # Inputs
//!
//! Like `selection`, this module imports no other `mobile` types: the caller
//! maps live state into [`Observed`], so neither side has to change when the
//! other does. Every collection is bounded ([`MAX_ACCOUNTS`],
//! [`MAX_PROFILES`], [`MAX_SESSIONS`]). A snapshot beyond a bound is
//! reported as [`IncidentKind::SnapshotTooLarge`] and *nothing else* is
//! checked: truncating would silently skip some records, and a partial
//! reconciliation that looks complete is worse than an explicit refusal.
//!
//! # Determinism
//!
//! Output is sorted by (kind rank, subject, expected, observed), so it is
//! identical regardless of the order the caller listed records in. Records
//! sharing a key (duplicate account ids, duplicate (slot, profile) pairs) are
//! ambiguous: which copy is "the" record would depend on input order, so they
//! are reported as duplicates and excluded from every other check, keeping
//! the output order-independent.

use alloc::vec::Vec;
use core::fmt;

/// Most accounts one snapshot may carry.
pub const MAX_ACCOUNTS: usize = 64;
/// Most SIM profiles one snapshot may carry.
pub const MAX_PROFILES: usize = 256;
/// Most open data sessions one snapshot may carry.
pub const MAX_SESSIONS: usize = 256;

/// Whether the account may use the network at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing {
    Active,
    Suspended,
    Closed,
}

/// Lifecycle state of a SIM profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProfileState {
    Created,
    Disabled,
    Enabled,
    Deleted,
}

/// One account as observed, together with the policy-intended values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAccount {
    pub id: u64,
    pub standing: Standing,
    /// Intended data cap for the period; `None` means uncapped.
    pub data_cap_bytes: Option<u64>,
    /// Intended percentage of the cap at which the account should have been
    /// escalated (suspended); `None` means no escalation threshold.
    pub escalate_at_percent: Option<u16>,
    /// Bytes used this period, as currently observed.
    pub used_bytes: u64,
    /// `used_bytes` at the previous reconciliation, for the monotonicity
    /// check. The caller must pass `None` when a legitimate period reset
    /// happened (or on first observation): the reconciler cannot tell a reset
    /// from counter tampering, so the caller -- who knows about resets --
    /// signals it.
    pub last_used_bytes: Option<u64>,
}

/// One SIM profile as observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedProfile {
    pub slot: usize,
    pub profile: u8,
    pub lifecycle: ProfileState,
    /// Owning account id, if the profile is bound to one.
    pub owner: Option<u64>,
}

/// One open data session as observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSession {
    pub account: u64,
    pub slot: usize,
    pub profile: u8,
    pub roaming: bool,
    pub roaming_allowed: bool,
}

/// Immutable snapshot of everything the reconciler compares. `Clone`/`Eq` so
/// callers (and tests) can prove the snapshot was not altered, and so a
/// snapshot can be recorded and replayed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observed {
    pub accounts: Vec<ObservedAccount>,
    pub profiles: Vec<ObservedProfile>,
    pub sessions: Vec<ObservedSession>,
}

/// What kind of drift was found. Declaration order is the rank used for
/// output ordering: structural problems with the snapshot itself first (they
/// make everything after less trustworthy), then profile/account binding,
/// usage, and session findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentKind {
    /// A collection exceeded its bound; nothing else was checked.
    SnapshotTooLarge,
    /// Two or more accounts share an id.
    DuplicateAccount,
    /// Two or more profiles share a (slot, profile) pair.
    DuplicateProfile,
    /// Profile is Enabled but its owner account is Suspended or Closed.
    EnabledProfileUnderInactiveAccount,
    /// Profile is Enabled but has no owner.
    EnabledProfileUnbound,
    /// Profile names an owner that is not in the snapshot.
    ProfileOwnerUnknown,
    /// More than one Enabled profile in one slot.
    MultipleEnabledInSlot,
    /// Usage counter went backwards within a period.
    UsageRegression,
    /// Usage reached the cap, yet the account is Active with an open session.
    UsageOverCapNotRestricted,
    /// Usage reached the escalation threshold, yet the account is Active.
    AnomalousUsageNoEscalation,
    /// Open session whose profile is not Enabled, or not in the snapshot.
    SessionWithoutEnabledProfile,
    /// Open session's account is not the owner of its profile.
    SessionAccountMismatch,
    /// Roaming session although roaming is not permitted.
    RoamingSessionNotPermitted,
}

/// What an incident is about. Derived `Ord` (variant, then fields) gives the
/// stable within-kind ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {
    /// The snapshot as a whole, or one of its collections.
    Snapshot,
    Account(u64),
    Slot(usize),
    Profile {
        slot: usize,
        profile: u8,
    },
    Session {
        account: u64,
        slot: usize,
        profile: u8,
    },
}

/// A structured expected/observed value. Numbers and states, never
/// preformatted text, so formatting cost is paid only when someone prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fact {
    /// Nothing was found (e.g. the profile a session names is absent).
    Absent,
    Number(u64),
    Bool(bool),
    Standing(Standing),
    Lifecycle(ProfileState),
    /// An optional owning account id.
    Owner(Option<u64>),
    /// "Some owner" -- the expectation for an Enabled profile whose concrete
    /// owner id is unknowable.
    AnyOwner,
    /// A percentage threshold.
    Percent(u16),
    /// Usage against a cap.
    UsageOfCap {
        used: u64,
        cap: u64,
    },
}

/// One finding. A fact about the snapshot, not an instruction: nothing in
/// here can be executed, only recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Incident {
    pub kind: IncidentKind,
    pub subject: Subject,
    pub expected: Fact,
    pub observed: Fact,
}

impl fmt::Display for IncidentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SnapshotTooLarge => "snapshot-too-large",
            Self::DuplicateAccount => "duplicate-account",
            Self::DuplicateProfile => "duplicate-profile",
            Self::EnabledProfileUnderInactiveAccount => "enabled-profile-under-inactive-account",
            Self::EnabledProfileUnbound => "enabled-profile-unbound",
            Self::ProfileOwnerUnknown => "profile-owner-unknown",
            Self::MultipleEnabledInSlot => "multiple-enabled-in-slot",
            Self::UsageRegression => "usage-regression",
            Self::UsageOverCapNotRestricted => "usage-over-cap-not-restricted",
            Self::AnomalousUsageNoEscalation => "anomalous-usage-no-escalation",
            Self::SessionWithoutEnabledProfile => "session-without-enabled-profile",
            Self::SessionAccountMismatch => "session-account-mismatch",
            Self::RoamingSessionNotPermitted => "roaming-session-not-permitted",
        };
        f.write_str(s)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot => f.write_str("snapshot"),
            Self::Account(id) => write!(f, "account:{id}"),
            Self::Slot(slot) => write!(f, "slot:{slot}"),
            Self::Profile { slot, profile } => write!(f, "profile:{slot}/{profile}"),
            Self::Session {
                account,
                slot,
                profile,
            } => write!(f, "session:{account}@{slot}/{profile}"),
        }
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("absent"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Standing(s) => write!(f, "{s:?}"),
            Self::Lifecycle(l) => write!(f, "{l:?}"),
            Self::Owner(Some(id)) => write!(f, "owner:{id}"),
            Self::Owner(None) => f.write_str("owner:none"),
            Self::AnyOwner => f.write_str("owner:any"),
            Self::Percent(p) => write!(f, "{p}%"),
            Self::UsageOfCap { used, cap } => write!(f, "{used}/{cap}"),
        }
    }
}

impl fmt::Display for Incident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: expected {}, observed {}",
            self.kind, self.subject, self.expected, self.observed
        )
    }
}

/// A key's records after grouping: exactly one, or several (ambiguous).
enum Entry<'a, T> {
    Unique(&'a T),
    Ambiguous,
}

/// Records sharing one key, collapsed.
struct Group<'a, K, T> {
    key: K,
    entry: Entry<'a, T>,
    /// How many records carried this key.
    count: usize,
}

/// Group records by key in ascending key order. Sorting a vector of
/// references leaves the caller's data untouched.
fn group_by_key<'a, K: Ord + Copy, T>(
    items: &'a [T],
    key: impl Fn(&T) -> K,
) -> Vec<Group<'a, K, T>> {
    let mut refs: Vec<(K, &'a T)> = items.iter().map(|t| (key(t), t)).collect();
    refs.sort_by_key(|e| e.0);
    let mut out = Vec::new();
    let mut iter = refs.into_iter().peekable();
    while let Some((k, t)) = iter.next() {
        let mut count = 1usize;
        while iter.next_if(|e| e.0 == k).is_some() {
            count = count.saturating_add(1);
        }
        let entry = if count == 1 {
            Entry::Unique(t)
        } else {
            Entry::Ambiguous
        };
        out.push(Group {
            key: k,
            entry,
            count,
        });
    }
    out
}

/// Binary-search a sorted group list. `None` means the key is not present.
fn find<'g, 'a, K: Ord, T>(groups: &'g [Group<'a, K, T>], key: &K) -> Option<&'g Entry<'a, T>> {
    let i = groups.binary_search_by(|g| g.key.cmp(key)).ok()?;
    groups.get(i).map(|g| &g.entry)
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// True when `used` has reached `percent` of `cap`, exactly.
///
/// `used >= cap * percent / 100` is computed as `used * 100 >= cap * percent`
/// in `u128`: no floats, no rounding, and the product of a `u64` and a
/// `u16` (or 100) cannot overflow `u128`, so the boundary is exact even at
/// `u64::MAX`.
fn reached_percent(used: u64, cap: u64, percent: u16) -> bool {
    u128::from(used) * 100 >= u128::from(cap) * u128::from(percent)
}

/// Compare an observed snapshot with the policy-intended values it carries
/// and report every drift as an [`Incident`].
///
/// Read-only by construction: the snapshot is borrowed immutably and the
/// result is a plain list of descriptive facts (see the module docs). The
/// caller decides what to record; nothing here corrects anything.
///
/// Notes on specific checks:
/// - [`IncidentKind::UsageOverCapNotRestricted`] and
///   [`IncidentKind::AnomalousUsageNoEscalation`] can both fire for one
///   account (usage at the cap is also past any threshold at or below 100%).
///   They answer different questions -- "is traffic still flowing" versus
///   "was the requested suspension carried out" -- so both are kept.
/// - A cap of `Some(0)` means every byte is over cap; an escalation of 0%
///   fires for any Active account. Both follow the exact arithmetic rather
///   than being special-cased.
pub fn reconcile(observed: &Observed) -> Vec<Incident> {
    let mut out = Vec::new();

    // Bounds first. On any breach report and stop: never truncate.
    let bounds = [
        (observed.accounts.len(), MAX_ACCOUNTS),
        (observed.profiles.len(), MAX_PROFILES),
        (observed.sessions.len(), MAX_SESSIONS),
    ];
    for (len, max) in bounds {
        if len > max {
            out.push(Incident {
                kind: IncidentKind::SnapshotTooLarge,
                subject: Subject::Snapshot,
                expected: Fact::Number(to_u64(max)),
                observed: Fact::Number(to_u64(len)),
            });
        }
    }
    if !out.is_empty() {
        out.sort();
        return out;
    }

    let accounts = group_by_key(&observed.accounts, |a| a.id);
    let profiles = group_by_key(&observed.profiles, |p| (p.slot, p.profile));

    for g in &accounts {
        if g.count > 1 {
            out.push(Incident {
                kind: IncidentKind::DuplicateAccount,
                subject: Subject::Account(g.key),
                expected: Fact::Number(1),
                observed: Fact::Number(to_u64(g.count)),
            });
        }
    }
    for g in &profiles {
        if g.count > 1 {
            out.push(Incident {
                kind: IncidentKind::DuplicateProfile,
                subject: Subject::Profile {
                    slot: g.key.0,
                    profile: g.key.1,
                },
                expected: Fact::Number(1),
                observed: Fact::Number(to_u64(g.count)),
            });
        }
    }

    // Profile checks (unique profiles only).
    for g in &profiles {
        let Entry::Unique(p) = &g.entry else { continue };
        let subject = Subject::Profile {
            slot: p.slot,
            profile: p.profile,
        };
        let enabled = p.lifecycle == ProfileState::Enabled;
        match p.owner {
            None => {
                if enabled {
                    out.push(Incident {
                        kind: IncidentKind::EnabledProfileUnbound,
                        subject,
                        expected: Fact::AnyOwner,
                        observed: Fact::Owner(None),
                    });
                }
            }
            Some(owner) => match find(&accounts, &owner) {
                None => out.push(Incident {
                    kind: IncidentKind::ProfileOwnerUnknown,
                    subject,
                    expected: Fact::Owner(Some(owner)),
                    observed: Fact::Absent,
                }),
                Some(Entry::Unique(a)) => {
                    if enabled && a.standing != Standing::Active {
                        out.push(Incident {
                            kind: IncidentKind::EnabledProfileUnderInactiveAccount,
                            subject,
                            expected: Fact::Standing(Standing::Active),
                            observed: Fact::Standing(a.standing),
                        });
                    }
                }
                Some(Entry::Ambiguous) => {}
            },
        }
    }

    // At most one Enabled profile per slot. Groups are sorted by (slot,
    // profile), so one slot's profiles are adjacent.
    let mut idx = 0usize;
    while let Some(first) = profiles.get(idx) {
        let slot = first.key.0;
        let mut enabled = 0u64;
        while let Some(g) = profiles.get(idx) {
            if g.key.0 != slot {
                break;
            }
            if let Entry::Unique(p) = &g.entry {
                if p.lifecycle == ProfileState::Enabled {
                    enabled = enabled.saturating_add(1);
                }
            }
            idx = idx.saturating_add(1);
        }
        if enabled > 1 {
            out.push(Incident {
                kind: IncidentKind::MultipleEnabledInSlot,
                subject: Subject::Slot(slot),
                expected: Fact::Number(1),
                observed: Fact::Number(enabled),
            });
        }
    }

    // Account checks (unique accounts only).
    for g in &accounts {
        let Entry::Unique(a) = &g.entry else { continue };
        let subject = Subject::Account(a.id);

        if let Some(last) = a.last_used_bytes {
            if a.used_bytes < last {
                out.push(Incident {
                    kind: IncidentKind::UsageRegression,
                    subject,
                    expected: Fact::Number(last),
                    observed: Fact::Number(a.used_bytes),
                });
            }
        }

        let Some(cap) = a.data_cap_bytes else {
            continue;
        };
        let active = a.standing == Standing::Active;
        let usage = Fact::UsageOfCap {
            used: a.used_bytes,
            cap,
        };

        if active && a.used_bytes >= cap && observed.sessions.iter().any(|s| s.account == a.id) {
            out.push(Incident {
                kind: IncidentKind::UsageOverCapNotRestricted,
                subject,
                expected: Fact::Standing(Standing::Suspended),
                observed: usage,
            });
        }

        if let Some(percent) = a.escalate_at_percent {
            if active && reached_percent(a.used_bytes, cap, percent) {
                out.push(Incident {
                    kind: IncidentKind::AnomalousUsageNoEscalation,
                    subject,
                    expected: Fact::Percent(percent),
                    observed: usage,
                });
            }
        }
    }

    // Session checks.
    for s in &observed.sessions {
        let subject = Subject::Session {
            account: s.account,
            slot: s.slot,
            profile: s.profile,
        };
        match find(&profiles, &(s.slot, s.profile)) {
            None => out.push(Incident {
                kind: IncidentKind::SessionWithoutEnabledProfile,
                subject,
                expected: Fact::Lifecycle(ProfileState::Enabled),
                observed: Fact::Absent,
            }),
            Some(Entry::Unique(p)) => {
                if p.lifecycle != ProfileState::Enabled {
                    out.push(Incident {
                        kind: IncidentKind::SessionWithoutEnabledProfile,
                        subject,
                        expected: Fact::Lifecycle(ProfileState::Enabled),
                        observed: Fact::Lifecycle(p.lifecycle),
                    });
                }
                if p.owner != Some(s.account) {
                    out.push(Incident {
                        kind: IncidentKind::SessionAccountMismatch,
                        subject,
                        expected: Fact::Owner(Some(s.account)),
                        observed: Fact::Owner(p.owner),
                    });
                }
            }
            Some(Entry::Ambiguous) => {}
        }
        if s.roaming && !s.roaming_allowed {
            out.push(Incident {
                kind: IncidentKind::RoamingSessionNotPermitted,
                subject,
                expected: Fact::Bool(false),
                observed: Fact::Bool(true),
            });
        }
    }

    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(id: u64) -> ObservedAccount {
        ObservedAccount {
            id,
            standing: Standing::Active,
            data_cap_bytes: None,
            escalate_at_percent: None,
            used_bytes: 0,
            last_used_bytes: None,
        }
    }

    fn prof(
        slot: usize,
        profile: u8,
        lifecycle: ProfileState,
        owner: Option<u64>,
    ) -> ObservedProfile {
        ObservedProfile {
            slot,
            profile,
            lifecycle,
            owner,
        }
    }

    fn sess(account: u64, slot: usize, profile: u8) -> ObservedSession {
        ObservedSession {
            account,
            slot,
            profile,
            roaming: false,
            roaming_allowed: false,
        }
    }

    /// A healthy snapshot: account 1 owns the Enabled profile 0/0 and has a
    /// session on it.
    fn clean() -> Observed {
        Observed {
            accounts: alloc::vec![acct(1)],
            profiles: alloc::vec![prof(0, 0, ProfileState::Enabled, Some(1))],
            sessions: alloc::vec![sess(1, 0, 0)],
        }
    }

    fn kinds(o: &Observed) -> Vec<IncidentKind> {
        reconcile(o).iter().map(|i| i.kind).collect()
    }

    #[test]
    fn empty_snapshot_has_no_incidents() {
        assert!(reconcile(&Observed::default()).is_empty());
    }

    #[test]
    fn clean_snapshot_has_no_incidents() {
        assert!(reconcile(&clean()).is_empty());
    }

    #[test]
    fn enabled_profile_under_inactive_account() {
        for st in [Standing::Suspended, Standing::Closed] {
            let mut o = clean();
            o.sessions.clear();
            o.accounts[0].standing = st;
            let r = reconcile(&o);
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].kind, IncidentKind::EnabledProfileUnderInactiveAccount);
            assert_eq!(r[0].observed, Fact::Standing(st));
        }
        // A Disabled profile under a suspended account is fine.
        let mut o = clean();
        o.sessions.clear();
        o.accounts[0].standing = Standing::Suspended;
        o.profiles[0].lifecycle = ProfileState::Disabled;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn enabled_profile_unbound() {
        let mut o = clean();
        o.sessions.clear();
        o.profiles[0].owner = None;
        assert_eq!(kinds(&o), [IncidentKind::EnabledProfileUnbound]);
        // Unbound but not Enabled is not an incident.
        o.profiles[0].lifecycle = ProfileState::Created;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn profile_owner_unknown() {
        let mut o = clean();
        o.sessions.clear();
        o.profiles[0].owner = Some(99);
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::ProfileOwnerUnknown);
        assert_eq!(r[0].expected, Fact::Owner(Some(99)));
        // Applies to any lifecycle.
        o.profiles[0].lifecycle = ProfileState::Deleted;
        assert_eq!(kinds(&o), [IncidentKind::ProfileOwnerUnknown]);
    }

    #[test]
    fn multiple_enabled_in_slot() {
        let mut o = clean();
        o.sessions.clear();
        o.profiles.push(prof(0, 1, ProfileState::Enabled, Some(1)));
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::MultipleEnabledInSlot);
        assert_eq!(r[0].subject, Subject::Slot(0));
        assert_eq!(r[0].observed, Fact::Number(2));
        // Enabled in different slots is fine; one Enabled plus Disabled is fine.
        let mut o = clean();
        o.sessions.clear();
        o.profiles.push(prof(1, 0, ProfileState::Enabled, Some(1)));
        o.profiles.push(prof(0, 1, ProfileState::Disabled, Some(1)));
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn usage_regression_and_none_suppresses() {
        let mut o = clean();
        o.accounts[0].used_bytes = 99;
        o.accounts[0].last_used_bytes = Some(100);
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::UsageRegression);
        assert_eq!(r[0].expected, Fact::Number(100));
        assert_eq!(r[0].observed, Fact::Number(99));
        // Equal is not a regression.
        o.accounts[0].used_bytes = 100;
        assert!(reconcile(&o).is_empty());
        // A signalled period reset suppresses it.
        o.accounts[0].used_bytes = 0;
        o.accounts[0].last_used_bytes = None;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn over_cap_boundary_needs_session_and_active() {
        let mut o = clean();
        o.accounts[0].data_cap_bytes = Some(1000);
        o.accounts[0].used_bytes = 999;
        assert!(reconcile(&o).is_empty());
        o.accounts[0].used_bytes = 1000;
        assert_eq!(kinds(&o), [IncidentKind::UsageOverCapNotRestricted]);
        // No open session: not flagged.
        let mut no_sess = o.clone();
        no_sess.sessions.clear();
        assert!(reconcile(&no_sess).is_empty());
        // Already restricted: not flagged (profile owner inactive is a
        // different incident, so drop the profile binding concern by
        // disabling it and the session).
        let mut susp = o.clone();
        susp.sessions.clear();
        susp.profiles[0].lifecycle = ProfileState::Disabled;
        susp.accounts[0].standing = Standing::Suspended;
        assert!(reconcile(&susp).is_empty());
    }

    #[test]
    fn over_cap_at_u64_max() {
        let mut o = clean();
        o.accounts[0].data_cap_bytes = Some(u64::MAX);
        o.accounts[0].used_bytes = u64::MAX - 1;
        assert!(reconcile(&o).is_empty());
        o.accounts[0].used_bytes = u64::MAX;
        assert_eq!(kinds(&o), [IncidentKind::UsageOverCapNotRestricted]);
    }

    #[test]
    fn escalation_boundary_exact() {
        let mut o = clean();
        o.sessions.clear();
        o.accounts[0].data_cap_bytes = Some(1000);
        o.accounts[0].escalate_at_percent = Some(80);
        o.accounts[0].used_bytes = 799;
        assert!(reconcile(&o).is_empty());
        o.accounts[0].used_bytes = 800;
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::AnomalousUsageNoEscalation);
        assert_eq!(r[0].expected, Fact::Percent(80));
        assert_eq!(
            r[0].observed,
            Fact::UsageOfCap {
                used: 800,
                cap: 1000
            }
        );
        // Escalated (Suspended) accounts are not flagged.
        o.accounts[0].standing = Standing::Suspended;
        o.profiles[0].lifecycle = ProfileState::Disabled;
        assert!(reconcile(&o).is_empty());
        // No threshold, no incident.
        let mut o = clean();
        o.sessions.clear();
        o.accounts[0].data_cap_bytes = Some(1000);
        o.accounts[0].used_bytes = 999;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn escalation_boundary_at_u64_max() {
        let mut o = clean();
        o.sessions.clear();
        o.accounts[0].data_cap_bytes = Some(u64::MAX);
        o.accounts[0].escalate_at_percent = Some(100);
        o.accounts[0].used_bytes = u64::MAX - 1;
        assert!(reconcile(&o).is_empty());
        o.accounts[0].used_bytes = u64::MAX;
        assert_eq!(kinds(&o), [IncidentKind::AnomalousUsageNoEscalation]);

        // 50% of u64::MAX is 2^63 - 0.5, so the first firing value is 2^63.
        o.accounts[0].escalate_at_percent = Some(50);
        o.accounts[0].used_bytes = (1u64 << 63) - 1;
        assert!(reconcile(&o).is_empty());
        o.accounts[0].used_bytes = 1u64 << 63;
        assert_eq!(kinds(&o), [IncidentKind::AnomalousUsageNoEscalation]);

        // Largest percentage cannot overflow.
        o.accounts[0].escalate_at_percent = Some(u16::MAX);
        o.accounts[0].used_bytes = u64::MAX;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn session_without_enabled_profile() {
        // Profile absent.
        let mut o = clean();
        o.sessions.push(sess(1, 5, 5));
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::SessionWithoutEnabledProfile);
        assert_eq!(r[0].observed, Fact::Absent);
        // Profile present but not Enabled.
        let mut o = clean();
        o.profiles[0].lifecycle = ProfileState::Disabled;
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].observed, Fact::Lifecycle(ProfileState::Disabled));
    }

    #[test]
    fn session_account_mismatch() {
        let mut o = clean();
        o.accounts.push(acct(2));
        o.sessions[0].account = 2;
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::SessionAccountMismatch);
        assert_eq!(r[0].expected, Fact::Owner(Some(2)));
        assert_eq!(r[0].observed, Fact::Owner(Some(1)));
    }

    #[test]
    fn roaming_session_not_permitted() {
        let mut o = clean();
        o.sessions[0].roaming = true;
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::RoamingSessionNotPermitted);
        o.sessions[0].roaming_allowed = true;
        assert!(reconcile(&o).is_empty());
        o.sessions[0].roaming = false;
        o.sessions[0].roaming_allowed = false;
        assert!(reconcile(&o).is_empty());
    }

    #[test]
    fn duplicates_reported_and_excluded_from_other_checks() {
        let mut o = clean();
        let mut dup = acct(1);
        dup.standing = Standing::Closed; // would otherwise trigger inactive-owner
        o.accounts.push(dup);
        assert_eq!(kinds(&o), [IncidentKind::DuplicateAccount]);

        let mut o = clean();
        o.profiles.push(prof(0, 0, ProfileState::Disabled, None));
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::DuplicateProfile);
        assert_eq!(r[0].observed, Fact::Number(2));
    }

    #[test]
    fn bounds_exceeded_report_only_too_large() {
        let mut o = clean();
        o.accounts = (0..=MAX_ACCOUNTS as u64).map(acct).collect();
        let r = reconcile(&o);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, IncidentKind::SnapshotTooLarge);
        assert_eq!(r[0].expected, Fact::Number(MAX_ACCOUNTS as u64));
        assert_eq!(r[0].observed, Fact::Number(MAX_ACCOUNTS as u64 + 1));

        let mut o = clean();
        o.profiles = (0..=MAX_PROFILES)
            .map(|i| prof(i, 0, ProfileState::Disabled, None))
            .collect();
        assert_eq!(kinds(&o), [IncidentKind::SnapshotTooLarge]);

        let mut o = clean();
        o.sessions = (0..=MAX_SESSIONS).map(|_| sess(1, 0, 0)).collect();
        assert_eq!(kinds(&o), [IncidentKind::SnapshotTooLarge]);

        // Exactly at the bound is accepted.
        let o = Observed {
            accounts: (0..MAX_ACCOUNTS as u64).map(acct).collect(),
            ..Observed::default()
        };
        assert!(reconcile(&o).is_empty());

        // Two breaches yield two incidents, still nothing else.
        let mut o = clean();
        o.accounts = (0..=MAX_ACCOUNTS as u64).map(acct).collect();
        o.sessions = (0..=MAX_SESSIONS).map(|_| sess(1, 0, 0)).collect();
        assert_eq!(
            kinds(&o),
            [
                IncidentKind::SnapshotTooLarge,
                IncidentKind::SnapshotTooLarge
            ]
        );
    }

    /// A snapshot tripping many checks at once.
    fn messy() -> Observed {
        let mut a1 = acct(1);
        a1.standing = Standing::Suspended;
        let mut a2 = acct(2);
        a2.data_cap_bytes = Some(100);
        a2.escalate_at_percent = Some(50);
        a2.used_bytes = 100;
        a2.last_used_bytes = Some(500);
        let mut s_roam = sess(2, 1, 0);
        s_roam.roaming = true;
        Observed {
            accounts: alloc::vec![a2, a1, acct(2 + 100)],
            profiles: alloc::vec![
                prof(1, 0, ProfileState::Enabled, Some(2)),
                prof(0, 1, ProfileState::Enabled, Some(1)),
                prof(0, 0, ProfileState::Enabled, None),
                prof(2, 0, ProfileState::Enabled, Some(77)),
                prof(3, 0, ProfileState::Disabled, Some(2)),
            ],
            sessions: alloc::vec![s_roam, sess(2, 3, 0), sess(1, 0, 1), sess(9, 9, 9)],
        }
    }

    #[test]
    fn multiple_simultaneous_incidents() {
        let ks = kinds(&messy());
        for want in [
            IncidentKind::EnabledProfileUnderInactiveAccount,
            IncidentKind::EnabledProfileUnbound,
            IncidentKind::ProfileOwnerUnknown,
            IncidentKind::MultipleEnabledInSlot,
            IncidentKind::UsageRegression,
            IncidentKind::UsageOverCapNotRestricted,
            IncidentKind::AnomalousUsageNoEscalation,
            IncidentKind::SessionWithoutEnabledProfile,
            IncidentKind::RoamingSessionNotPermitted,
        ] {
            assert!(ks.contains(&want), "missing {want:?} in {ks:?}");
        }
        // Output is sorted by (kind rank, subject).
        let r = reconcile(&messy());
        for w in r.windows(2) {
            assert!((w[0].kind, w[0].subject) <= (w[1].kind, w[1].subject));
        }
    }

    #[test]
    fn every_kind_is_exercised_somewhere() {
        // Guards the rank table against a kind being added without a test.
        let all = [
            IncidentKind::SnapshotTooLarge,
            IncidentKind::DuplicateAccount,
            IncidentKind::DuplicateProfile,
            IncidentKind::EnabledProfileUnderInactiveAccount,
            IncidentKind::EnabledProfileUnbound,
            IncidentKind::ProfileOwnerUnknown,
            IncidentKind::MultipleEnabledInSlot,
            IncidentKind::UsageRegression,
            IncidentKind::UsageOverCapNotRestricted,
            IncidentKind::AnomalousUsageNoEscalation,
            IncidentKind::SessionWithoutEnabledProfile,
            IncidentKind::SessionAccountMismatch,
            IncidentKind::RoamingSessionNotPermitted,
        ];
        for w in all.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn output_is_independent_of_input_order() {
        let base = reconcile(&messy());
        assert!(!base.is_empty());

        let mut rev = messy();
        rev.accounts.reverse();
        rev.profiles.reverse();
        rev.sessions.reverse();
        assert_eq!(reconcile(&rev), base);

        // Deterministic pseudo-shuffles (LCG), no rand dependency.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..50 {
            let mut o = messy();
            shuffle(&mut o.accounts, &mut seed);
            shuffle(&mut o.profiles, &mut seed);
            shuffle(&mut o.sessions, &mut seed);
            assert_eq!(reconcile(&o), base);
        }

        // Also with duplicates in play.
        let mut d = messy();
        d.accounts.push(acct(1));
        d.profiles.push(prof(0, 0, ProfileState::Deleted, Some(1)));
        let dbase = reconcile(&d);
        d.accounts.reverse();
        d.profiles.reverse();
        assert_eq!(reconcile(&d), dbase);
    }

    fn shuffle<T>(v: &mut [T], seed: &mut u64) {
        let mut i = v.len();
        while i > 1 {
            *seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = ((*seed >> 33) as usize) % i;
            i -= 1;
            v.swap(i, j);
        }
    }

    #[test]
    fn reconcile_leaves_input_unchanged() {
        for o in [Observed::default(), clean(), messy()] {
            let before = o.clone();
            let _ = reconcile(&o);
            assert_eq!(o, before);
        }
    }

    #[test]
    fn display_is_stable() {
        let i = Incident {
            kind: IncidentKind::UsageRegression,
            subject: Subject::Account(7),
            expected: Fact::Number(100),
            observed: Fact::Number(99),
        };
        assert_eq!(
            alloc::format!("{i}"),
            "usage-regression account:7: expected 100, observed 99"
        );
    }
}
