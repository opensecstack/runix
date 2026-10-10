//! Data policy engine: account entitlements (Beta item 4, step 1).
//!
//! A set of PURE, STATELESS functions of (entitlement, usage, standing,
//! lifecycle, network class). No I/O, no clock, no stored state: every
//! decision is a function of its inputs, so it can be recorded (see
//! [`PolicyDecisionRecord`]) and replayed bit-for-bit during audit or in a
//! host test. Billing-period rollover is therefore the caller's explicit act
//! ([`reset_usage`]); the engine has no idea what time it is.
//!
//! # THIS MODULE HAS NO AUTHORITY
//!
//! The policy engine *decides* and *requests*; it never *acts*. An
//! [`ActionRequest`] such as [`ActionRequest::SuspendAccount`] is advice to the
//! caller, nothing more. The caller (eventually `kernel-arm`'s syscall
//! boundary) must carry any request out through the existing governed path --
//! capability check, MARSHAL gate, WORM audit -- under its OWN capability. This
//! module holds no capability, performs no suspension, and must never grow a
//! side channel that does: a usage counter that could suspend accounts by
//! itself would be an ambient-authority bypass of the very gate that guards
//! `AccountRegistry::suspend`.
//!
//! # Decoupling
//!
//! Like `selection.rs`, this module imports no `account`/`sim` types. The
//! caller maps its state into the local mirrors below:
//!
//! ```text
//! account::AccountStatus  -> AccountStandingForData   (variant for variant)
//! account::ProfileLifecycle (== sim.rs ProfileState)
//!                         -> ProfileLifecycleForData  (variant for variant)
//! attached network        -> NetworkClass  (Home iff the attached network is
//!                            the subscriber's home network, else Roaming)
//! ```
//!
//! # Check order for a session (root cause first)
//!
//! 1. account standing (`Suspended`, then `Closed`)
//! 2. profile lifecycle (anything but `Enabled` has no data session)
//! 3. network class (roaming without entitlement)
//! 4. usage vs. cap (band `CapReached` or `Anomalous` => cap exceeded;
//!    `Throttled` => allowed, throttled)
//!
//! Reporting the first failing check means an operator reading the WORM log
//! sees the cause that must be fixed first (a suspended account's data is
//! not "over cap" in any useful sense, even if it also is).
//!
//! # Usage bands (see [`evaluate_usage`])
//!
//! With cap `C`, usage `U`, throttle percent `T`, escalate percent `E`, all
//! comparisons are exact integer tests `U * 100 >= C * P` done in `u128`
//! (so `u64::MAX` values cannot overflow, and there are no floats and no
//! rounding). "At the threshold" always counts as reaching it (`>=`).
//! Bands are evaluated strongest first:
//!
//! ```text
//! Anomalous  : U*100 >= C*E           -> escalation: SuspendAccount (request)
//! CapReached : U >= C                 -> escalation: NotifyOnly
//! Throttled  : U*100 >= C*T           -> escalation: Throttle
//! Normal     : otherwise              -> no escalation
//! ```
//!
//! Because `E >= 100`, `Anomalous` implies the cap is also reached, so a
//! session in that band is denied as `CapExceeded` as well; the suspension
//! request is *additional*, and `CapReached` alone never requests one. With
//! `E == 100` the `CapReached` band is unreachable (anomaly wins at the cap).
//! `T == 0` means "throttled from the first byte"; `T == 100` means the
//! throttle point coincides with the cap, so `Throttled` is unreachable.
//!
//! # Special caps
//!
//! - `cap_bytes == None`: unlimited. Always `Normal`, never throttled, never
//!   escalates, regardless of usage or the percentages.
//! - `cap_bytes == Some(0)`: a plan with no data allowance. It is a VALID
//!   entitlement whose meaning is "every session is denied `CapExceeded`":
//!   usage is always `>= 0`, so the band is `CapReached` even at zero usage.
//!   No share-of-cap exists for a zero cap, so it never reports `Anomalous`
//!   and never requests suspension (a zero-cap account is not misbehaving by
//!   being unable to use data).

/// Largest accepted `escalate_at_percent`. A threshold of 100x the cap is far
/// beyond any sensible anomaly rule; refusing larger values catches unit
/// mistakes (a raw byte count typed into a percent field) at construction.
pub const MAX_ESCALATE_PERCENT: u16 = 10_000;

/// Why an entitlement was rejected. Each variant names one distinct defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementError {
    /// `throttle_at_percent` was above 100.
    ThrottlePercentAbove100,
    /// `escalate_at_percent` was below 100: escalation would fire before the
    /// cap is even reached, which contradicts "anomalous overage".
    EscalatePercentBelow100,
    /// `escalate_at_percent` was above [`MAX_ESCALATE_PERCENT`].
    EscalatePercentTooLarge,
}

/// What an account's plan allows. Fields are private so the only way to
/// obtain one is [`DataEntitlement::new`] (or the compiled-in demo values,
/// which a test proves valid): an incoherent entitlement can never be
/// evaluated. Escalate >= throttle is implied by `throttle <= 100 <=
/// escalate`, so it needs no separate error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataEntitlement {
    cap_bytes: Option<u64>,
    throttle_at_percent: u8,
    roaming_data_allowed: bool,
    escalate_at_percent: u16,
}

impl DataEntitlement {
    /// Validate and build an entitlement. `cap_bytes == None` is unlimited;
    /// `Some(0)` is a valid "no allowance" plan (see module doc).
    pub const fn new(
        cap_bytes: Option<u64>,
        throttle_at_percent: u8,
        roaming_data_allowed: bool,
        escalate_at_percent: u16,
    ) -> Result<Self, EntitlementError> {
        if throttle_at_percent > 100 {
            return Err(EntitlementError::ThrottlePercentAbove100);
        }
        if escalate_at_percent < 100 {
            return Err(EntitlementError::EscalatePercentBelow100);
        }
        if escalate_at_percent > MAX_ESCALATE_PERCENT {
            return Err(EntitlementError::EscalatePercentTooLarge);
        }
        Ok(Self {
            cap_bytes,
            throttle_at_percent,
            roaming_data_allowed,
            escalate_at_percent,
        })
    }

    /// Billing-period allowance in bytes; `None` is unlimited.
    pub const fn cap_bytes(&self) -> Option<u64> {
        self.cap_bytes
    }
    pub const fn throttle_at_percent(&self) -> u8 {
        self.throttle_at_percent
    }
    pub const fn roaming_data_allowed(&self) -> bool {
        self.roaming_data_allowed
    }
    pub const fn escalate_at_percent(&self) -> u16 {
        self.escalate_at_percent
    }
}

/// One billing-period usage counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataUsage {
    pub used_bytes: u64,
}

/// Add `bytes` to the counter. Saturates at `u64::MAX`: a wrapped counter
/// would read as "almost nothing used" and silently re-open a capped account,
/// whereas a saturated one stays at the safe (over-cap) end.
pub const fn apply_usage(usage: DataUsage, bytes: u64) -> DataUsage {
    DataUsage {
        used_bytes: usage.used_bytes.saturating_add(bytes),
    }
}

/// Start a new billing period. The caller decides *when*; there is no clock
/// here.
pub const fn reset_usage() -> DataUsage {
    DataUsage { used_bytes: 0 }
}

/// Local mirror of `account::AccountStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStandingForData {
    Active,
    Suspended,
    Closed,
}

/// Local mirror of `account::ProfileLifecycle` / `sim.rs` `ProfileState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileLifecycleForData {
    Created,
    Disabled,
    Enabled,
    Deleted,
}

/// Whether the attached network is the subscriber's home network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkClass {
    Home,
    Roaming,
}

/// Everything a session decision depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRequest {
    pub standing: AccountStandingForData,
    pub lifecycle: ProfileLifecycleForData,
    pub entitlement: DataEntitlement,
    pub usage: DataUsage,
    pub network: NetworkClass,
}

/// Why a data session is refused. Each variant names one distinct cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    AccountSuspended,
    AccountClosed,
    /// The profile is not `Enabled` (carries which state it was in).
    ProfileNotEnabled(ProfileLifecycleForData),
    /// Attached to a roaming network the entitlement does not cover.
    RoamingDataNotAllowed,
    /// Usage has reached the cap (including anomalous overage and the
    /// zero-allowance plan).
    CapExceeded,
}

/// Outcome of [`evaluate_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDecision {
    Allow,
    /// Session permitted but the caller should apply its throttled rate.
    AllowThrottled,
    Deny(DenyReason),
}

/// Usage band; see the module doc for exact boundary semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageBand {
    Normal,
    Throttled,
    CapReached,
    Anomalous,
}

/// A REQUEST to the caller. The policy engine has no authority and performs
/// none of these; see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionRequest {
    /// Tell the subscriber/operator; no state change requested.
    NotifyOnly,
    /// Ask the data path to apply the throttled rate.
    Throttle,
    /// Ask for the account to be suspended. Must go through the governed
    /// path (capability + MARSHAL + WORM) under the caller's capability.
    SuspendAccount,
}

/// Result of [`evaluate_usage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageAssessment {
    pub band: UsageBand,
    pub escalation: Option<ActionRequest>,
}

/// `used * 100 >= cap * percent`, exactly, with no overflow possible: the
/// largest left side is `u64::MAX * 100` (< 2^71) and right side
/// `u64::MAX * 65535`, both far inside `u128`. Saturating anyway so a future
/// widening of the inputs cannot introduce a wrap.
fn share_reached(used: u64, cap: u64, percent: u16) -> bool {
    let lhs = u128::from(used).saturating_mul(100);
    let rhs = u128::from(cap).saturating_mul(u128::from(percent));
    lhs >= rhs
}

/// Classify usage against an entitlement. Pure; see module doc for the band
/// table, the unlimited cap and the zero cap.
pub fn evaluate_usage(entitlement: &DataEntitlement, usage: &DataUsage) -> UsageAssessment {
    let cap = match entitlement.cap_bytes {
        None => {
            return UsageAssessment {
                band: UsageBand::Normal,
                escalation: None,
            }
        }
        Some(cap) => cap,
    };
    let used = usage.used_bytes;
    if cap == 0 {
        // No share-of-cap exists; denied, but never an anomaly.
        return UsageAssessment {
            band: UsageBand::CapReached,
            escalation: Some(ActionRequest::NotifyOnly),
        };
    }
    if share_reached(used, cap, entitlement.escalate_at_percent) {
        UsageAssessment {
            band: UsageBand::Anomalous,
            escalation: Some(ActionRequest::SuspendAccount),
        }
    } else if used >= cap {
        UsageAssessment {
            band: UsageBand::CapReached,
            escalation: Some(ActionRequest::NotifyOnly),
        }
    } else if share_reached(used, cap, u16::from(entitlement.throttle_at_percent)) {
        UsageAssessment {
            band: UsageBand::Throttled,
            escalation: Some(ActionRequest::Throttle),
        }
    } else {
        UsageAssessment {
            band: UsageBand::Normal,
            escalation: None,
        }
    }
}

/// Decide whether a data session may run. Check order (root cause first):
/// standing, lifecycle, network class, cap. See the module doc.
pub fn evaluate_session(request: &SessionRequest) -> SessionDecision {
    match request.standing {
        AccountStandingForData::Active => {}
        AccountStandingForData::Suspended => {
            return SessionDecision::Deny(DenyReason::AccountSuspended)
        }
        AccountStandingForData::Closed => return SessionDecision::Deny(DenyReason::AccountClosed),
    }
    if request.lifecycle != ProfileLifecycleForData::Enabled {
        return SessionDecision::Deny(DenyReason::ProfileNotEnabled(request.lifecycle));
    }
    if request.network == NetworkClass::Roaming && !request.entitlement.roaming_data_allowed {
        return SessionDecision::Deny(DenyReason::RoamingDataNotAllowed);
    }
    match evaluate_usage(&request.entitlement, &request.usage).band {
        UsageBand::Normal => SessionDecision::Allow,
        UsageBand::Throttled => SessionDecision::AllowThrottled,
        UsageBand::CapReached | UsageBand::Anomalous => {
            SessionDecision::Deny(DenyReason::CapExceeded)
        }
    }
}

/// Inputs plus outputs of one decision, so kernel glue can WORM-record it and
/// an auditor can replay it. The record is self-verifying: [`Self::replays`]
/// recomputes from `request` and compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecisionRecord {
    pub request: SessionRequest,
    pub decision: SessionDecision,
    pub assessment: UsageAssessment,
}

impl PolicyDecisionRecord {
    /// Evaluate `request` and capture everything.
    pub fn decide(request: SessionRequest) -> Self {
        Self {
            request,
            decision: evaluate_session(&request),
            assessment: evaluate_usage(&request.entitlement, &request.usage),
        }
    }

    /// True iff re-evaluating the recorded inputs reproduces the recorded
    /// outputs exactly (false means the record was altered or the policy
    /// changed since it was written).
    pub fn replays(&self) -> bool {
        *self == Self::decide(self.request)
    }
}

// --- DEMO DATA ONLY -------------------------------------------------------
// Compiled-in sample plans for the kernel proof, like account.rs's demo data.
// NOT real plans and not a source of truth for any subscriber.

/// DEMO DATA ONLY: 5 GiB cap, throttle at 80%, no roaming, suspension
/// requested at 150% of cap.
pub const DEMO_CAPPED_ENTITLEMENT: DataEntitlement = DataEntitlement {
    cap_bytes: Some(5 * 1024 * 1024 * 1024),
    throttle_at_percent: 80,
    roaming_data_allowed: false,
    escalate_at_percent: 150,
};

/// DEMO DATA ONLY: unlimited data with roaming allowed.
pub const DEMO_UNLIMITED_ENTITLEMENT: DataEntitlement = DataEntitlement {
    cap_bytes: None,
    throttle_at_percent: 100,
    roaming_data_allowed: true,
    escalate_at_percent: 100,
};

/// DEMO DATA ONLY: the demo plans, capped first.
pub const fn demo_entitlements() -> [DataEntitlement; 2] {
    [DEMO_CAPPED_ENTITLEMENT, DEMO_UNLIMITED_ENTITLEMENT]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(cap: Option<u64>, t: u8, roam: bool, e: u16) -> DataEntitlement {
        DataEntitlement::new(cap, t, roam, e).unwrap()
    }

    fn req(entitlement: DataEntitlement, used: u64) -> SessionRequest {
        SessionRequest {
            standing: AccountStandingForData::Active,
            lifecycle: ProfileLifecycleForData::Enabled,
            entitlement,
            usage: DataUsage { used_bytes: used },
            network: NetworkClass::Home,
        }
    }

    fn band(e: &DataEntitlement, used: u64) -> UsageBand {
        evaluate_usage(e, &DataUsage { used_bytes: used }).band
    }

    #[test]
    fn invalid_entitlements_rejected_each_variant() {
        assert_eq!(
            DataEntitlement::new(Some(10), 101, false, 150),
            Err(EntitlementError::ThrottlePercentAbove100)
        );
        assert_eq!(
            DataEntitlement::new(Some(10), 50, false, 99),
            Err(EntitlementError::EscalatePercentBelow100)
        );
        assert_eq!(
            DataEntitlement::new(Some(10), 50, false, 0),
            Err(EntitlementError::EscalatePercentBelow100)
        );
        assert_eq!(
            DataEntitlement::new(None, 50, false, MAX_ESCALATE_PERCENT + 1),
            Err(EntitlementError::EscalatePercentTooLarge)
        );
        assert!(DataEntitlement::new(Some(10), 100, false, 100).is_ok());
        assert!(DataEntitlement::new(Some(10), 0, false, MAX_ESCALATE_PERCENT).is_ok());
    }

    #[test]
    fn demo_entitlements_are_valid() {
        let [capped, unlimited] = demo_entitlements();
        assert_eq!(
            DataEntitlement::new(
                capped.cap_bytes(),
                capped.throttle_at_percent(),
                capped.roaming_data_allowed(),
                capped.escalate_at_percent()
            ),
            Ok(capped)
        );
        assert_eq!(
            DataEntitlement::new(
                unlimited.cap_bytes(),
                unlimited.throttle_at_percent(),
                unlimited.roaming_data_allowed(),
                unlimited.escalate_at_percent()
            ),
            Ok(unlimited)
        );
        assert!(capped.cap_bytes().is_some());
        assert!(unlimited.cap_bytes().is_none());
    }

    #[test]
    fn every_deny_reason_is_reachable() {
        let e = ent(Some(100), 80, false, 150);
        let mut r = req(e, 0);
        r.standing = AccountStandingForData::Suspended;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::AccountSuspended)
        );
        r.standing = AccountStandingForData::Closed;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::AccountClosed)
        );
        for lc in [
            ProfileLifecycleForData::Created,
            ProfileLifecycleForData::Disabled,
            ProfileLifecycleForData::Deleted,
        ] {
            let mut r = req(e, 0);
            r.lifecycle = lc;
            assert_eq!(
                evaluate_session(&r),
                SessionDecision::Deny(DenyReason::ProfileNotEnabled(lc))
            );
        }
        let mut r = req(e, 0);
        r.network = NetworkClass::Roaming;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::RoamingDataNotAllowed)
        );
        assert_eq!(
            evaluate_session(&req(e, 100)),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        assert_eq!(evaluate_session(&req(e, 0)), SessionDecision::Allow);
    }

    #[test]
    fn precedence_standing_lifecycle_network_cap() {
        let e = ent(Some(100), 80, false, 150);
        // Everything wrong at once: standing wins.
        let mut r = req(e, 1000);
        r.standing = AccountStandingForData::Closed;
        r.lifecycle = ProfileLifecycleForData::Deleted;
        r.network = NetworkClass::Roaming;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::AccountClosed)
        );
        r.standing = AccountStandingForData::Suspended;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::AccountSuspended)
        );
        // Standing fine: lifecycle next.
        r.standing = AccountStandingForData::Active;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::ProfileNotEnabled(
                ProfileLifecycleForData::Deleted
            ))
        );
        // Lifecycle fine: network before cap.
        r.lifecycle = ProfileLifecycleForData::Enabled;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::RoamingDataNotAllowed)
        );
        // Network fine: cap.
        r.network = NetworkClass::Home;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
    }

    #[test]
    fn closed_and_suspended_deny_even_with_zero_usage_and_unlimited() {
        for e in demo_entitlements() {
            for (s, reason) in [
                (
                    AccountStandingForData::Suspended,
                    DenyReason::AccountSuspended,
                ),
                (AccountStandingForData::Closed, DenyReason::AccountClosed),
            ] {
                let mut r = req(e, 0);
                r.standing = s;
                assert_eq!(evaluate_session(&r), SessionDecision::Deny(reason));
            }
        }
    }

    #[test]
    fn roaming_rules() {
        let no = ent(Some(100), 80, false, 150);
        let yes = ent(Some(100), 80, true, 150);
        let mut r = req(no, 0);
        r.network = NetworkClass::Roaming;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::RoamingDataNotAllowed)
        );
        r.entitlement = yes;
        assert_eq!(evaluate_session(&r), SessionDecision::Allow);
        // Roaming allowed still honours the cap and throttle.
        r.usage.used_bytes = 80;
        assert_eq!(evaluate_session(&r), SessionDecision::AllowThrottled);
        r.usage.used_bytes = 100;
        assert_eq!(
            evaluate_session(&r),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        // Home is unaffected by the roaming flag.
        assert_eq!(evaluate_session(&req(no, 0)), SessionDecision::Allow);
    }

    #[test]
    fn band_boundaries_exact() {
        // cap 1000, throttle 80% => 800, escalate 150% => 1500.
        let e = ent(Some(1000), 80, false, 150);
        assert_eq!(band(&e, 0), UsageBand::Normal);
        assert_eq!(band(&e, 799), UsageBand::Normal);
        assert_eq!(band(&e, 800), UsageBand::Throttled);
        assert_eq!(band(&e, 999), UsageBand::Throttled);
        assert_eq!(band(&e, 1000), UsageBand::CapReached);
        assert_eq!(band(&e, 1499), UsageBand::CapReached);
        assert_eq!(band(&e, 1500), UsageBand::Anomalous);
        assert_eq!(band(&e, u64::MAX), UsageBand::Anomalous);
    }

    #[test]
    fn band_boundaries_non_divisible_use_exact_math() {
        // cap 7, throttle 50% => threshold 3.5, so 3 is Normal, 4 Throttled.
        let e = ent(Some(7), 50, false, 150);
        assert_eq!(band(&e, 3), UsageBand::Normal);
        assert_eq!(band(&e, 4), UsageBand::Throttled);
        // escalate 10.5: 10 CapReached, 11 Anomalous.
        assert_eq!(band(&e, 10), UsageBand::CapReached);
        assert_eq!(band(&e, 11), UsageBand::Anomalous);
    }

    #[test]
    fn session_decisions_at_band_boundaries() {
        let e = ent(Some(1000), 80, false, 150);
        assert_eq!(evaluate_session(&req(e, 799)), SessionDecision::Allow);
        assert_eq!(
            evaluate_session(&req(e, 800)),
            SessionDecision::AllowThrottled
        );
        assert_eq!(
            evaluate_session(&req(e, 999)),
            SessionDecision::AllowThrottled
        );
        assert_eq!(
            evaluate_session(&req(e, 1000)),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        assert_eq!(
            evaluate_session(&req(e, 1500)),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
    }

    #[test]
    fn throttle_percent_extremes() {
        // 0: throttled from the first byte.
        let e0 = ent(Some(100), 0, false, 150);
        assert_eq!(band(&e0, 0), UsageBand::Throttled);
        // 100: throttle coincides with cap, Throttled unreachable.
        let e100 = ent(Some(100), 100, false, 150);
        assert_eq!(band(&e100, 99), UsageBand::Normal);
        assert_eq!(band(&e100, 100), UsageBand::CapReached);
        // escalate 100: anomaly wins at the cap, CapReached unreachable.
        let ee = ent(Some(100), 80, false, 100);
        assert_eq!(band(&ee, 99), UsageBand::Throttled);
        assert_eq!(band(&ee, 100), UsageBand::Anomalous);
    }

    #[test]
    fn u64_max_edges_do_not_overflow() {
        let e = ent(Some(u64::MAX), 80, false, MAX_ESCALATE_PERCENT);
        assert_eq!(band(&e, 0), UsageBand::Normal);
        assert_eq!(band(&e, u64::MAX - 1), UsageBand::Throttled);
        // used == cap: cap reached, but 100% < 10000% so not anomalous.
        assert_eq!(band(&e, u64::MAX), UsageBand::CapReached);
        let e = ent(Some(u64::MAX), 100, false, 100);
        assert_eq!(band(&e, u64::MAX - 1), UsageBand::Normal);
        assert_eq!(band(&e, u64::MAX), UsageBand::Anomalous);
        // Throttle threshold on a huge cap: 80% of u64::MAX.
        let e = ent(Some(u64::MAX), 80, false, 150);
        let t = (u128::from(u64::MAX) * 80).div_ceil(100) as u64;
        assert_eq!(band(&e, t - 1), UsageBand::Normal);
        assert_eq!(band(&e, t), UsageBand::Throttled);
        // Small cap with maximal usage.
        let e = ent(Some(1), 80, false, MAX_ESCALATE_PERCENT);
        assert_eq!(band(&e, u64::MAX), UsageBand::Anomalous);
    }

    #[test]
    fn saturating_usage_and_reset() {
        let u = DataUsage { used_bytes: 10 };
        assert_eq!(apply_usage(u, 5).used_bytes, 15);
        assert_eq!(apply_usage(u, 0), u);
        let near = DataUsage {
            used_bytes: u64::MAX - 1,
        };
        assert_eq!(apply_usage(near, 1).used_bytes, u64::MAX);
        assert_eq!(apply_usage(near, 2).used_bytes, u64::MAX);
        assert_eq!(apply_usage(near, u64::MAX).used_bytes, u64::MAX);
        // A saturated counter stays over cap rather than wrapping open.
        let e = ent(Some(100), 80, false, 150);
        let sat = apply_usage(near, u64::MAX);
        assert_eq!(
            evaluate_session(&SessionRequest {
                usage: sat,
                ..req(e, 0)
            }),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        assert_eq!(reset_usage().used_bytes, 0);
        assert_eq!(apply_usage(sat, 0).used_bytes, u64::MAX);
        assert_eq!(
            evaluate_session(&req(e, reset_usage().used_bytes)),
            SessionDecision::Allow
        );
    }

    #[test]
    fn unlimited_never_throttles_or_escalates() {
        let e = ent(None, 0, true, 100);
        for used in [0, 1, 1 << 40, u64::MAX] {
            let a = evaluate_usage(&e, &DataUsage { used_bytes: used });
            assert_eq!(a.band, UsageBand::Normal);
            assert_eq!(a.escalation, None);
            assert_eq!(evaluate_session(&req(e, used)), SessionDecision::Allow);
        }
    }

    #[test]
    fn zero_cap_means_every_session_cap_exceeded_never_anomalous() {
        let e = ent(Some(0), 80, true, 150);
        for used in [0, 1, u64::MAX] {
            let a = evaluate_usage(&e, &DataUsage { used_bytes: used });
            assert_eq!(a.band, UsageBand::CapReached);
            assert_ne!(a.escalation, Some(ActionRequest::SuspendAccount));
            assert_eq!(
                evaluate_session(&req(e, used)),
                SessionDecision::Deny(DenyReason::CapExceeded)
            );
        }
    }

    #[test]
    fn escalation_suspend_only_at_anomalous() {
        let e = ent(Some(1000), 80, false, 150);
        let esc = |used| evaluate_usage(&e, &DataUsage { used_bytes: used }).escalation;
        assert_eq!(esc(0), None);
        assert_eq!(esc(799), None);
        assert_eq!(esc(800), Some(ActionRequest::Throttle));
        assert_eq!(esc(1000), Some(ActionRequest::NotifyOnly));
        assert_eq!(esc(1499), Some(ActionRequest::NotifyOnly));
        assert_eq!(esc(1500), Some(ActionRequest::SuspendAccount));
        // Sweep: SuspendAccount appears iff band is Anomalous.
        for used in (0..3000).step_by(7) {
            let a = evaluate_usage(&e, &DataUsage { used_bytes: used });
            assert_eq!(
                a.escalation == Some(ActionRequest::SuspendAccount),
                a.band == UsageBand::Anomalous
            );
        }
    }

    #[test]
    fn cap_reached_denies_without_suspension_request() {
        let e = ent(Some(1000), 80, false, 150);
        let r = req(e, 1200);
        let rec = PolicyDecisionRecord::decide(r);
        assert_eq!(rec.decision, SessionDecision::Deny(DenyReason::CapExceeded));
        assert_eq!(rec.assessment.band, UsageBand::CapReached);
        assert_ne!(
            rec.assessment.escalation,
            Some(ActionRequest::SuspendAccount)
        );
    }

    #[test]
    fn anomalous_denies_and_requests_suspension() {
        let e = ent(Some(1000), 80, false, 150);
        let rec = PolicyDecisionRecord::decide(req(e, 1500));
        assert_eq!(rec.decision, SessionDecision::Deny(DenyReason::CapExceeded));
        assert_eq!(
            rec.assessment.escalation,
            Some(ActionRequest::SuspendAccount)
        );
    }

    #[test]
    fn records_are_deterministic_and_replay() {
        for e in demo_entitlements() {
            for used in [0, 1, 4 << 30, 5 << 30, 8 << 30, u64::MAX] {
                for network in [NetworkClass::Home, NetworkClass::Roaming] {
                    let mut r = req(e, used);
                    r.network = network;
                    let a = PolicyDecisionRecord::decide(r);
                    let b = PolicyDecisionRecord::decide(r);
                    assert_eq!(a, b);
                    assert!(a.replays());
                    assert_eq!(a.decision, evaluate_session(&r));
                }
            }
        }
        // A tampered record fails to replay.
        let mut rec = PolicyDecisionRecord::decide(req(DEMO_CAPPED_ENTITLEMENT, 0));
        rec.decision = SessionDecision::Deny(DenyReason::CapExceeded);
        assert!(!rec.replays());
    }

    #[test]
    fn demo_capped_plan_behaviour() {
        let e = DEMO_CAPPED_ENTITLEMENT;
        let gib = 1u64 << 30;
        assert_eq!(evaluate_session(&req(e, gib)), SessionDecision::Allow);
        assert_eq!(
            evaluate_session(&req(e, 4 * gib)),
            SessionDecision::AllowThrottled
        );
        assert_eq!(
            evaluate_session(&req(e, 5 * gib)),
            SessionDecision::Deny(DenyReason::CapExceeded)
        );
        assert_eq!(band(&e, 7 * gib + gib / 2), UsageBand::Anomalous);
        let mut r = req(DEMO_UNLIMITED_ENTITLEMENT, u64::MAX);
        r.network = NetworkClass::Roaming;
        assert_eq!(evaluate_session(&r), SessionDecision::Allow);
    }
}
