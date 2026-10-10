//! Pure network-selection decision (Beta item 3, step 2).
//!
//! Given the subscriber's standing, what the plan permits, and which
//! networks the radio can currently see, decide which network to attach to
//! -- or refuse, saying exactly why. No I/O and no state: the caller
//! (eventually `kernel-arm`'s syscall boundary) gathers the inputs, calls
//! [`select_network`], and enforces the answer. Keeping this a function of
//! its arguments is what makes every refusal path unit-testable on the host
//! and what lets the Item 4 data policy engine re-run the same decision
//! from a recorded [`SelectionInput`] when auditing.
//!
//! This module deliberately does not import `account` types: the caller
//! maps account state into [`SelectionInput`], so neither module has to
//! change when the other does.
//!
//! Every refusal is its own [`RefusalReason`] variant. A generic "denied"
//! would force an operator reading the WORM log to guess whether the plan,
//! the account, or the radio environment was at fault.

use alloc::vec::Vec;
use core::cmp::Reverse;

/// Most candidate networks one decision will consider.
///
/// A modem scan reports a handful of networks; a list far beyond that is a
/// buggy or hostile radio stack. Refusing (rather than truncating) keeps the
/// decision from silently ignoring a network that might have been the right
/// answer, and bounds the work done on a privileged path.
pub const MAX_CANDIDATES: usize = 32;

/// Most networks a plan's allowed set may list; same reasoning as
/// [`MAX_CANDIDATES`], applied to the plan side of the comparison.
pub const MAX_ALLOWED_NETWORKS: usize = 64;

/// A mobile network, identified by its MCC/MNC pair.
///
/// Field order gives the derived `Ord` (MCC, then MNC), which is the
/// deterministic final tie-break between otherwise equal candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId {
    /// Mobile country code.
    pub mcc: u16,
    /// Mobile network code.
    pub mnc: u16,
}

impl NetworkId {
    pub const fn new(mcc: u16, mnc: u16) -> Self {
        Self { mcc, mnc }
    }
}

/// Whether the subscriber's account may use the network at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStanding {
    Active,
    Suspended,
    Closed,
}

/// One network the radio currently sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub network: NetworkId,
    /// Signal quality; larger is better. The unit is the caller's choice
    /// (dBm, RSRP, ...) as long as it is consistent within one input.
    pub signal: i32,
    /// Whether this is the subscriber's home network. Anything else is
    /// roaming, which the plan must explicitly permit.
    pub is_home: bool,
}

/// Everything the decision depends on. Derives `Clone`/`Eq`/`Debug` so a
/// policy engine can record and replay it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionInput {
    pub standing: AccountStanding,
    /// Networks the plan permits. Empty means the plan permits none.
    pub allowed: Vec<NetworkId>,
    /// Network the plan prefers when it is visible and eligible.
    pub preferred: Option<NetworkId>,
    pub roaming_allowed: bool,
    pub candidates: Vec<Candidate>,
}

/// Why a network was chosen, strongest rule first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// The plan's preferred network was visible and eligible.
    PlanPreferred,
    /// No preferred match; the home network was eligible.
    HomeNetwork,
    /// Neither of the above; strongest eligible signal won.
    StrongestSignal,
}

/// Why no network may be used. Each variant names one distinct cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Account is suspended.
    AccountSuspended,
    /// Account is closed.
    AccountClosed,
    /// More than [`MAX_CANDIDATES`] candidates were supplied.
    TooManyCandidates,
    /// More than [`MAX_ALLOWED_NETWORKS`] allowed networks were supplied.
    TooManyAllowedNetworks,
    /// The radio sees no networks.
    NoCandidates,
    /// The plan's allowed set is empty.
    NoAllowedNetworksInPlan,
    /// Networks are visible, but none is in the plan's allowed set.
    NoAllowedCandidate,
    /// Allowed networks are visible, but all require roaming and the plan
    /// does not permit it.
    RoamingNotPermitted,
}

/// Outcome of [`select_network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    Allowed {
        network: NetworkId,
        reason: SelectionReason,
    },
    Refused(RefusalReason),
}

/// Choose a network, or refuse with a specific reason.
///
/// Checks run cheapest-and-most-fundamental first so the reported reason is
/// the root cause: account standing, then input bounds, then empty inputs,
/// then plan allow-list, then roaming. Among eligible candidates the order
/// is plan-preferred, then home, then higher signal, then lower
/// [`NetworkId`] -- the last rule exists purely so the result never depends
/// on the order the modem happened to list networks in.
///
/// The preferred network gets no exemption from the allow-list or roaming
/// rules: preference only ranks eligible networks, it never makes an
/// ineligible one eligible.
pub fn select_network(input: &SelectionInput) -> Selection {
    match input.standing {
        AccountStanding::Active => {}
        AccountStanding::Suspended => return Selection::Refused(RefusalReason::AccountSuspended),
        AccountStanding::Closed => return Selection::Refused(RefusalReason::AccountClosed),
    }
    if input.candidates.len() > MAX_CANDIDATES {
        return Selection::Refused(RefusalReason::TooManyCandidates);
    }
    if input.allowed.len() > MAX_ALLOWED_NETWORKS {
        return Selection::Refused(RefusalReason::TooManyAllowedNetworks);
    }
    if input.candidates.is_empty() {
        return Selection::Refused(RefusalReason::NoCandidates);
    }
    if input.allowed.is_empty() {
        return Selection::Refused(RefusalReason::NoAllowedNetworksInPlan);
    }

    let mut any_allowed = false;
    let mut best: Option<(Candidate, bool)> = None;
    for c in input
        .candidates
        .iter()
        .filter(|c| input.allowed.contains(&c.network))
    {
        any_allowed = true;
        if !c.is_home && !input.roaming_allowed {
            continue;
        }
        let is_pref = input.preferred == Some(c.network);
        let better = match &best {
            None => true,
            Some((b, b_pref)) => rank(c, is_pref) > rank(b, *b_pref),
        };
        if better {
            best = Some((*c, is_pref));
        }
    }

    match best {
        Some((c, is_pref)) => {
            let reason = if is_pref {
                SelectionReason::PlanPreferred
            } else if c.is_home {
                SelectionReason::HomeNetwork
            } else {
                SelectionReason::StrongestSignal
            };
            Selection::Allowed {
                network: c.network,
                reason,
            }
        }
        None if any_allowed => Selection::Refused(RefusalReason::RoamingNotPermitted),
        None => Selection::Refused(RefusalReason::NoAllowedCandidate),
    }
}

/// Total order over eligible candidates; larger wins. `Reverse` on the id so
/// the numerically lowest network wins a full tie.
fn rank(c: &Candidate, is_pref: bool) -> (bool, bool, i32, Reverse<NetworkId>) {
    (is_pref, c.is_home, c.signal, Reverse(c.network))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: NetworkId = NetworkId::new(310, 260);
    const PARTNER: NetworkId = NetworkId::new(310, 410);
    const ABROAD: NetworkId = NetworkId::new(262, 1);
    const OTHER: NetworkId = NetworkId::new(999, 99);

    fn cand(network: NetworkId, signal: i32, is_home: bool) -> Candidate {
        Candidate {
            network,
            signal,
            is_home,
        }
    }

    fn input(candidates: Vec<Candidate>) -> SelectionInput {
        SelectionInput {
            standing: AccountStanding::Active,
            allowed: vec![HOME, PARTNER, ABROAD],
            preferred: None,
            roaming_allowed: true,
            candidates,
        }
    }

    fn allowed(network: NetworkId, reason: SelectionReason) -> Selection {
        Selection::Allowed { network, reason }
    }

    #[test]
    fn suspended_account_refused() {
        let mut i = input(vec![cand(HOME, -70, true)]);
        i.standing = AccountStanding::Suspended;
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::AccountSuspended)
        );
    }

    #[test]
    fn closed_account_refused() {
        let mut i = input(vec![cand(HOME, -70, true)]);
        i.standing = AccountStanding::Closed;
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::AccountClosed)
        );
    }

    #[test]
    fn standing_checked_before_everything_else() {
        let mut i = input(vec![]);
        i.standing = AccountStanding::Closed;
        i.allowed.clear();
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::AccountClosed)
        );
    }

    #[test]
    fn no_candidates_refused() {
        assert_eq!(
            select_network(&input(vec![])),
            Selection::Refused(RefusalReason::NoCandidates)
        );
    }

    #[test]
    fn empty_plan_allow_list_refused() {
        let mut i = input(vec![cand(HOME, -70, true)]);
        i.allowed.clear();
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::NoAllowedNetworksInPlan)
        );
    }

    #[test]
    fn everything_empty_reports_no_candidates() {
        let mut i = input(vec![]);
        i.allowed.clear();
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::NoCandidates)
        );
    }

    #[test]
    fn no_visible_network_in_allow_list_refused() {
        let i = input(vec![cand(OTHER, -50, false), cand(OTHER, -60, true)]);
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::NoAllowedCandidate)
        );
    }

    #[test]
    fn roaming_not_permitted_when_only_roaming_candidates_allowed() {
        let mut i = input(vec![cand(ABROAD, -60, false), cand(OTHER, -50, true)]);
        i.roaming_allowed = false;
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::RoamingNotPermitted)
        );
    }

    #[test]
    fn roaming_blocked_even_for_preferred_network() {
        let mut i = input(vec![cand(ABROAD, -40, false)]);
        i.preferred = Some(ABROAD);
        i.roaming_allowed = false;
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::RoamingNotPermitted)
        );
    }

    #[test]
    fn roaming_disallowed_still_picks_home() {
        let mut i = input(vec![cand(ABROAD, -40, false), cand(HOME, -100, true)]);
        i.roaming_allowed = false;
        assert_eq!(
            select_network(&i),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn roaming_allowed_permits_non_home() {
        let i = input(vec![cand(ABROAD, -60, false)]);
        assert_eq!(
            select_network(&i),
            allowed(ABROAD, SelectionReason::StrongestSignal)
        );
    }

    #[test]
    fn preferred_beats_home_and_signal() {
        let mut i = input(vec![
            cand(HOME, -50, true),
            cand(PARTNER, -110, false),
            cand(ABROAD, -40, false),
        ]);
        i.preferred = Some(PARTNER);
        assert_eq!(
            select_network(&i),
            allowed(PARTNER, SelectionReason::PlanPreferred)
        );
    }

    #[test]
    fn preferred_not_visible_falls_back_to_home() {
        let mut i = input(vec![cand(ABROAD, -40, false), cand(HOME, -100, true)]);
        i.preferred = Some(PARTNER);
        assert_eq!(
            select_network(&i),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn preferred_not_in_allow_list_gets_no_exemption() {
        let mut i = input(vec![cand(OTHER, -30, true), cand(HOME, -90, true)]);
        i.preferred = Some(OTHER);
        assert_eq!(
            select_network(&i),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn home_beats_stronger_roaming_signal() {
        let i = input(vec![cand(ABROAD, -40, false), cand(HOME, -100, true)]);
        assert_eq!(
            select_network(&i),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn strongest_signal_wins_among_equals() {
        let i = input(vec![cand(PARTNER, -80, false), cand(ABROAD, -60, false)]);
        assert_eq!(
            select_network(&i),
            allowed(ABROAD, SelectionReason::StrongestSignal)
        );
    }

    #[test]
    fn stronger_home_signal_wins_among_home_candidates() {
        let i = input(vec![cand(HOME, -90, true), cand(PARTNER, -60, true)]);
        assert_eq!(
            select_network(&i),
            allowed(PARTNER, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn disallowed_candidate_never_chosen_despite_signal() {
        let i = input(vec![cand(OTHER, -10, true), cand(ABROAD, -120, false)]);
        assert_eq!(
            select_network(&i),
            allowed(ABROAD, SelectionReason::StrongestSignal)
        );
    }

    #[test]
    fn tie_break_is_lowest_network_id_regardless_of_order() {
        let a = cand(PARTNER, -70, false);
        let b = cand(ABROAD, -70, false);
        let fwd = select_network(&input(vec![a, b]));
        let rev = select_network(&input(vec![b, a]));
        assert_eq!(fwd, rev);
        // ABROAD is MCC 262, lower than PARTNER's 310.
        assert_eq!(fwd, allowed(ABROAD, SelectionReason::StrongestSignal));
    }

    #[test]
    fn tie_break_within_mcc_uses_mnc() {
        let lo = cand(NetworkId::new(310, 100), -70, true);
        let hi = cand(NetworkId::new(310, 200), -70, true);
        let mut i = input(vec![hi, lo]);
        i.allowed = vec![lo.network, hi.network];
        assert_eq!(
            select_network(&i),
            allowed(lo.network, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn duplicate_candidate_uses_stronger_signal_and_is_deterministic() {
        let i1 = input(vec![cand(HOME, -90, true), cand(HOME, -60, true)]);
        let i2 = input(vec![cand(HOME, -60, true), cand(HOME, -90, true)]);
        assert_eq!(select_network(&i1), select_network(&i2));
        assert_eq!(
            select_network(&i1),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn negative_and_extreme_signals_compare_correctly() {
        let i = input(vec![
            cand(HOME, i32::MIN, false),
            cand(PARTNER, i32::MAX, false),
            cand(ABROAD, -1, false),
        ]);
        assert_eq!(
            select_network(&i),
            allowed(PARTNER, SelectionReason::StrongestSignal)
        );
    }

    #[test]
    fn max_candidates_accepted() {
        let cs: Vec<Candidate> = (0..MAX_CANDIDATES)
            .map(|n| cand(NetworkId::new(1, n as u16), -80, false))
            .collect();
        let mut i = input(cs);
        i.allowed = vec![NetworkId::new(1, 0)];
        assert_eq!(
            select_network(&i),
            allowed(NetworkId::new(1, 0), SelectionReason::StrongestSignal)
        );
    }

    #[test]
    fn too_many_candidates_refused_not_truncated() {
        // The only allowed network sits past the bound; truncation would
        // have turned this into NoAllowedCandidate or a wrong pick.
        let mut cs: Vec<Candidate> = (0..MAX_CANDIDATES)
            .map(|n| cand(NetworkId::new(1, n as u16), -80, false))
            .collect();
        cs.push(cand(HOME, -50, true));
        assert_eq!(
            select_network(&input(cs)),
            Selection::Refused(RefusalReason::TooManyCandidates)
        );
    }

    #[test]
    fn too_many_allowed_networks_refused() {
        let mut i = input(vec![cand(HOME, -70, true)]);
        i.allowed = (0..=MAX_ALLOWED_NETWORKS)
            .map(|n| NetworkId::new(2, n as u16))
            .collect();
        assert_eq!(
            select_network(&i),
            Selection::Refused(RefusalReason::TooManyAllowedNetworks)
        );
    }

    #[test]
    fn max_allowed_networks_accepted() {
        let mut i = input(vec![cand(HOME, -70, true)]);
        i.allowed = (0..MAX_ALLOWED_NETWORKS)
            .map(|n| NetworkId::new(2, n as u16))
            .collect();
        i.allowed[0] = HOME;
        assert_eq!(
            select_network(&i),
            allowed(HOME, SelectionReason::HomeNetwork)
        );
    }

    #[test]
    fn input_is_clone_eq_debug_for_policy_engine() {
        let i = input(vec![cand(HOME, -70, true)]);
        let j = i.clone();
        assert_eq!(i, j);
        assert_eq!(select_network(&i), select_network(&j));
        assert!(!alloc::format!("{i:?}").is_empty());
    }

    #[test]
    fn refusal_variants_are_pairwise_distinct() {
        let all = [
            RefusalReason::AccountSuspended,
            RefusalReason::AccountClosed,
            RefusalReason::TooManyCandidates,
            RefusalReason::TooManyAllowedNetworks,
            RefusalReason::NoCandidates,
            RefusalReason::NoAllowedNetworksInPlan,
            RefusalReason::NoAllowedCandidate,
            RefusalReason::RoamingNotPermitted,
        ];
        for (a, x) in all.iter().enumerate() {
            for (b, y) in all.iter().enumerate() {
                assert_eq!(a == b, x == y);
            }
        }
    }
}
