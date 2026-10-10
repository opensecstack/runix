//! Pure billing-period model (Beta item 4 follow-up: usage-period reset).
//!
//! # No clock, no authority
//!
//! This module has neither a clock nor any authority. A [`BillingPeriod`] is
//! plain data (a start tick and a length in ticks); [`assess_period`] answers
//! "has the period elapsed?" purely as a function of an explicit `now_tick`
//! the *caller* passes in. Nothing here reads a timer: the kernel will later
//! hand in the ARM generic timer's counter value, and a host test hands in a
//! literal. Keeping the clock outside keeps this code deterministic,
//! host-testable, and free of any hardware dependency.
//!
//! The module only ever *requests*. [`PeriodRequest::ResetUsage`] is a fact
//! ("this period is over, usage should be reset"), not an action. Resetting
//! usage is a privileged write: it is MARSHAL-gated and WORM-audited, and is
//! carried out by a caller under its own capability via the governed reset
//! syscall (`SYS_DATA_RESET`), which then starts the next period (see
//! [`next_period`]). A period model that reset usage itself would be an
//! ungoverned writer on a schedule -- the parallel authorization path this
//! project forbids. Nothing resets on a schedule today; that remains a
//! documented gap, and this module is the pure half of closing it.
//!
//! # Boundary semantics
//!
//! With `end = start + length` (computed without wrapping, see below):
//!
//! * `now < start`            -> [`PeriodAssessment::ClockBeforeStart`]
//! * `start <= now < end`     -> [`PeriodAssessment::Active`]
//! * `now == end` (exactly)   -> [`PeriodAssessment::Elapsed`], overdue 0,
//!   one period missed
//! * `now > end`              -> [`PeriodAssessment::Elapsed`]
//!
//! `now < start` is its own anomaly (the clock went backwards, or the period
//! came from the future) and is never treated as "active": an attacker or a
//! fault that rewinds the counter must not be able to extend a period.
//!
//! All arithmetic is on `u64` ticks with `now >= start` established first, so
//! `now - start` cannot underflow; `start + length` is never formed in `u64`
//! (it could wrap near `u64::MAX`), only compared via the difference.
//!
//! # Read-only checking
//!
//! [`check_periods`] is the reconciler-style checker: `&[ObservedPeriod]` in,
//! descriptive [`PeriodIncident`]s out. It never corrects anything, is
//! bounded ([`MAX_PERIODS`]; over the bound yields only
//! [`PeriodIncidentKind::TooManyPeriods`], never a truncated check), and its
//! output order is independent of input order. It is self-contained: it
//! imports no other `mobile` types.

use alloc::vec::Vec;
use core::fmt;

/// Most periods one [`check_periods`] call may carry.
pub const MAX_PERIODS: usize = 64;

/// Length of the DEMO period, in ticks. DEMO DATA ONLY.
pub const DEMO_PERIOD_TICKS: u64 = 1_000;

/// Why a period could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodError {
    /// A zero-length period would be "elapsed" the instant it starts, and
    /// would make `periods_missed` a division by zero.
    ZeroLength,
    /// The next period was asked to start before the period it replaces began.
    /// A reset cannot happen before the thing it resets existed.
    ResetBeforeStart { start_tick: u64, reset_at_tick: u64 },
}

impl fmt::Display for PeriodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeriodError::ZeroLength => write!(f, "billing period length must be non-zero"),
            PeriodError::ResetBeforeStart {
                start_tick,
                reset_at_tick,
            } => write!(
                f,
                "reset at tick {reset_at_tick} is before the period start {start_tick}"
            ),
        }
    }
}

/// A billing period: `length_ticks` ticks beginning at `start_tick`.
///
/// Fields are private so a zero-length period cannot be constructed; use
/// [`BillingPeriod::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingPeriod {
    start_tick: u64,
    length_ticks: u64,
}

impl BillingPeriod {
    /// Builds a period; rejects `length_ticks == 0`.
    pub fn new(start_tick: u64, length_ticks: u64) -> Result<Self, PeriodError> {
        if length_ticks == 0 {
            return Err(PeriodError::ZeroLength);
        }
        Ok(Self {
            start_tick,
            length_ticks,
        })
    }

    /// Tick at which the period begins.
    pub fn start_tick(&self) -> u64 {
        self.start_tick
    }

    /// Length of the period in ticks (always non-zero).
    pub fn length_ticks(&self) -> u64 {
        self.length_ticks
    }
}

/// DEMO DATA ONLY: a short period (`DEMO_PERIOD_TICKS`) starting at
/// `start_tick`, for the kernel proof. Not a real plan's billing cycle.
pub fn demo_period(start_tick: u64) -> BillingPeriod {
    BillingPeriod {
        start_tick,
        length_ticks: DEMO_PERIOD_TICKS,
    }
}

/// What a period looks like at a given tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodAssessment {
    /// `start <= now < start + length`.
    Active {
        /// `now - start`.
        elapsed: u64,
        /// Ticks left until the period ends (at least 1).
        remaining: u64,
    },
    /// `now >= start + length`.
    Elapsed {
        /// `now - (start + length)`; 0 exactly at the boundary.
        overdue_ticks: u64,
        /// `floor((now - start) / length)`: whole periods that have passed
        /// (at least 1). More than 1 means resets were skipped entirely.
        periods_missed: u64,
    },
    /// `now < start`: the clock went backwards, or the period is from the
    /// future. Distinct from `Active` on purpose.
    ClockBeforeStart { start_tick: u64, now_tick: u64 },
}

/// Assesses `period` at the caller-supplied `now_tick`. Pure; reads no clock.
pub fn assess_period(period: &BillingPeriod, now_tick: u64) -> PeriodAssessment {
    let Some(elapsed) = now_tick.checked_sub(period.start_tick) else {
        return PeriodAssessment::ClockBeforeStart {
            start_tick: period.start_tick,
            now_tick,
        };
    };
    match period.length_ticks.checked_sub(elapsed) {
        // elapsed < length (remaining >= 1): still inside the period.
        Some(remaining) if remaining > 0 => PeriodAssessment::Active { elapsed, remaining },
        _ => PeriodAssessment::Elapsed {
            overdue_ticks: elapsed.saturating_sub(period.length_ticks),
            // length is non-zero by construction; checked_div keeps the
            // function panic-free even so.
            periods_missed: elapsed.checked_div(period.length_ticks).unwrap_or(u64::MAX),
        },
    }
}

/// A request for the caller to act. It has no authority and performs nothing.
///
/// LOUD: a value of this type is only a statement that something is due. The
/// caller must carry it out through the governed reset syscall
/// (`SYS_DATA_RESET`) under its *own* capability, which is MARSHAL-gated and
/// WORM-audited. Nothing in this module resets usage, and nothing may treat
/// receiving this request as authorization to do so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodRequest {
    /// The period has elapsed; usage should be reset by a governed caller.
    ResetUsage,
}

/// `Some(ResetUsage)` only when the period is `Elapsed`. `Active` and
/// `ClockBeforeStart` yield `None`: a rewound clock must never trigger (or
/// suppress) a reset on its own; it is surfaced as an incident instead.
pub fn period_request(period: &BillingPeriod, now_tick: u64) -> Option<PeriodRequest> {
    match assess_period(period, now_tick) {
        PeriodAssessment::Elapsed { .. } => Some(PeriodRequest::ResetUsage),
        PeriodAssessment::Active { .. } | PeriodAssessment::ClockBeforeStart { .. } => None,
    }
}

/// The period a reset *starts*: same length, beginning at `reset_at_tick`.
///
/// Pure arithmetic on data -- it does not perform the reset. The caller calls
/// it after the governed reset succeeds, with the tick the reset took effect.
/// A `reset_at_tick` earlier than the old start is rejected with
/// [`PeriodError::ResetBeforeStart`]. A reset at a tick inside the old period
/// (early) or long after its end (late) is allowed: policy about *when* is the
/// governed caller's, and lateness is what [`check_periods`] reports.
pub fn next_period(old: &BillingPeriod, reset_at_tick: u64) -> Result<BillingPeriod, PeriodError> {
    if reset_at_tick < old.start_tick {
        return Err(PeriodError::ResetBeforeStart {
            start_tick: old.start_tick,
            reset_at_tick,
        });
    }
    BillingPeriod::new(reset_at_tick, old.length_ticks)
}

/// One account's period as observed, for [`check_periods`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPeriod {
    pub account: u64,
    pub period: BillingPeriod,
    /// Tick at which a reset request was first outstanding, if any.
    pub reset_requested_since: Option<u64>,
}

/// Kind of finding. Declaration order is the output rank: problems with the
/// input itself first, then clock anomalies, then overdue resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeriodIncidentKind {
    /// More than [`MAX_PERIODS`] entries; nothing else was checked.
    TooManyPeriods,
    /// Two or more entries share an account; they are excluded from other
    /// checks because which copy is "the" record would depend on input order.
    DuplicateAccount,
    /// `now < start` for this account's period.
    ClockBeforeStart,
    /// Period elapsed and no reset happened within the grace.
    PeriodElapsedNoReset,
}

/// A descriptive fact. Not a command. Field order is the sort key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeriodIncident {
    pub kind: PeriodIncidentKind,
    /// Subject account (0 for `TooManyPeriods`, which has no subject).
    pub account: u64,
    /// What was expected: `TooManyPeriods` -> the bound; `DuplicateAccount` ->
    /// 1; `ClockBeforeStart` -> the start tick; `PeriodElapsedNoReset` -> the
    /// tick by which the reset should have happened (inclusive).
    pub expected: u64,
    /// What was seen: entry count / copies / `now_tick` respectively.
    pub observed: u64,
}

impl fmt::Display for PeriodIncident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PeriodIncidentKind::TooManyPeriods => write!(
                f,
                "too many periods: {} given, at most {} accepted; nothing checked",
                self.observed, self.expected
            ),
            PeriodIncidentKind::DuplicateAccount => write!(
                f,
                "account {}: {} period records share this id",
                self.account, self.observed
            ),
            PeriodIncidentKind::ClockBeforeStart => write!(
                f,
                "account {}: clock at tick {} is before period start {}",
                self.account, self.observed, self.expected
            ),
            PeriodIncidentKind::PeriodElapsedNoReset => write!(
                f,
                "account {}: period elapsed, no reset by tick {} (now {})",
                self.account, self.expected, self.observed
            ),
        }
    }
}

/// Saturating `usize` -> `u64` for counts in incident facts.
fn count_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Read-only check of observed periods. Takes `&[..]`, returns facts, mutates
/// and corrects nothing.
///
/// `PeriodElapsedNoReset` fires when a period is `Elapsed` and
/// `now > deadline`, where `deadline = max(end, reset_requested_since) +
/// grace_ticks` (saturating). The grace therefore starts when the reset was
/// due (`end`), or when it was first requested if that was later, so a
/// late-noticed request still gets a fair grace. `now == deadline` is still
/// within grace. A `ClockBeforeStart` period raises only that incident.
pub fn check_periods(
    periods: &[ObservedPeriod],
    now_tick: u64,
    grace_ticks: u64,
) -> Vec<PeriodIncident> {
    let mut out: Vec<PeriodIncident> = Vec::new();

    if periods.len() > MAX_PERIODS {
        out.push(PeriodIncident {
            kind: PeriodIncidentKind::TooManyPeriods,
            account: 0,
            expected: count_u64(MAX_PERIODS),
            observed: count_u64(periods.len()),
        });
        return out;
    }

    // Find duplicated account ids via a sorted copy of the ids.
    let mut ids: Vec<u64> = periods.iter().map(|p| p.account).collect();
    ids.sort_unstable();
    let mut dup_ids: Vec<u64> = Vec::new();
    let mut run: Option<(u64, usize)> = None;
    for id in ids {
        run = match run {
            Some((cur, n)) if cur == id => Some((cur, n.saturating_add(1))),
            other => {
                if let Some((cur, n)) = other {
                    if n > 1 {
                        dup_ids.push(cur);
                        out.push(dup_incident(cur, n));
                    }
                }
                Some((id, 1))
            }
        };
    }
    if let Some((cur, n)) = run {
        if n > 1 {
            dup_ids.push(cur);
            out.push(dup_incident(cur, n));
        }
    }

    for p in periods {
        if dup_ids.binary_search(&p.account).is_ok() {
            continue;
        }
        match assess_period(&p.period, now_tick) {
            PeriodAssessment::Active { .. } => {}
            PeriodAssessment::ClockBeforeStart { start_tick, .. } => {
                out.push(PeriodIncident {
                    kind: PeriodIncidentKind::ClockBeforeStart,
                    account: p.account,
                    expected: start_tick,
                    observed: now_tick,
                });
            }
            PeriodAssessment::Elapsed { overdue_ticks, .. } => {
                // Elapsed implies now >= start + length, so end <= now fits.
                let end = now_tick.saturating_sub(overdue_ticks);
                let since = p.reset_requested_since.unwrap_or(0).max(end);
                let deadline = since.saturating_add(grace_ticks);
                if now_tick > deadline {
                    out.push(PeriodIncident {
                        kind: PeriodIncidentKind::PeriodElapsedNoReset,
                        account: p.account,
                        expected: deadline,
                        observed: now_tick,
                    });
                }
            }
        }
    }

    out.sort();
    out
}

fn dup_incident(account: u64, copies: usize) -> PeriodIncident {
    PeriodIncident {
        kind: PeriodIncidentKind::DuplicateAccount,
        account,
        expected: 1,
        observed: count_u64(copies),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    fn p(start: u64, len: u64) -> BillingPeriod {
        BillingPeriod::new(start, len).unwrap()
    }

    fn obs(account: u64, start: u64, len: u64, since: Option<u64>) -> ObservedPeriod {
        ObservedPeriod {
            account,
            period: p(start, len),
            reset_requested_since: since,
        }
    }

    // ---- constructor ----

    #[test]
    fn zero_length_rejected() {
        assert_eq!(BillingPeriod::new(5, 0), Err(PeriodError::ZeroLength));
        assert_eq!(BillingPeriod::new(0, 0), Err(PeriodError::ZeroLength));
        assert_eq!(
            BillingPeriod::new(u64::MAX, 0),
            Err(PeriodError::ZeroLength)
        );
    }

    #[test]
    fn valid_constructor_and_getters() {
        let b = p(10, 20);
        assert_eq!(b.start_tick(), 10);
        assert_eq!(b.length_ticks(), 20);
        assert!(BillingPeriod::new(0, 1).is_ok());
        assert!(BillingPeriod::new(u64::MAX, u64::MAX).is_ok());
    }

    // ---- assess_period ----

    #[test]
    fn boundaries() {
        let b = p(100, 50); // end = 150
        assert_eq!(
            assess_period(&b, 99),
            PeriodAssessment::ClockBeforeStart {
                start_tick: 100,
                now_tick: 99
            }
        );
        assert_eq!(
            assess_period(&b, 100),
            PeriodAssessment::Active {
                elapsed: 0,
                remaining: 50
            }
        );
        assert_eq!(
            assess_period(&b, 149),
            PeriodAssessment::Active {
                elapsed: 49,
                remaining: 1
            }
        );
        assert_eq!(
            assess_period(&b, 150),
            PeriodAssessment::Elapsed {
                overdue_ticks: 0,
                periods_missed: 1
            }
        );
        assert_eq!(
            assess_period(&b, 151),
            PeriodAssessment::Elapsed {
                overdue_ticks: 1,
                periods_missed: 1
            }
        );
    }

    #[test]
    fn periods_missed_math() {
        let b = p(0, 10);
        let missed = |now| match assess_period(&b, now) {
            PeriodAssessment::Elapsed { periods_missed, .. } => periods_missed,
            other => panic!("expected Elapsed, got {other:?}"),
        };
        assert_eq!(missed(10), 1);
        assert_eq!(missed(19), 1);
        assert_eq!(missed(20), 2);
        assert_eq!(missed(35), 3);
        assert_eq!(missed(u64::MAX), u64::MAX / 10);
        let one = p(0, 1);
        assert_eq!(
            assess_period(&one, u64::MAX),
            PeriodAssessment::Elapsed {
                overdue_ticks: u64::MAX - 1,
                periods_missed: u64::MAX
            }
        );
    }

    #[test]
    fn u64_max_edges_do_not_overflow() {
        // start near MAX: start + length would wrap in u64.
        let b = p(u64::MAX - 5, 100);
        assert_eq!(
            assess_period(&b, u64::MAX),
            PeriodAssessment::Active {
                elapsed: 5,
                remaining: 95
            }
        );
        assert_eq!(
            assess_period(&b, 0),
            PeriodAssessment::ClockBeforeStart {
                start_tick: u64::MAX - 5,
                now_tick: 0
            }
        );
        // length MAX from 0: never elapses before now == MAX.
        let m = p(0, u64::MAX);
        assert_eq!(
            assess_period(&m, u64::MAX - 1),
            PeriodAssessment::Active {
                elapsed: u64::MAX - 1,
                remaining: 1
            }
        );
        assert_eq!(
            assess_period(&m, u64::MAX),
            PeriodAssessment::Elapsed {
                overdue_ticks: 0,
                periods_missed: 1
            }
        );
        // start MAX, length MAX, now MAX: just started.
        let s = p(u64::MAX, u64::MAX);
        assert_eq!(
            assess_period(&s, u64::MAX),
            PeriodAssessment::Active {
                elapsed: 0,
                remaining: u64::MAX
            }
        );
    }

    // ---- period_request ----

    #[test]
    fn request_only_when_elapsed() {
        let b = p(100, 50);
        assert_eq!(period_request(&b, 50), None);
        assert_eq!(period_request(&b, 100), None);
        assert_eq!(period_request(&b, 149), None);
        assert_eq!(period_request(&b, 150), Some(PeriodRequest::ResetUsage));
        assert_eq!(period_request(&b, 10_000), Some(PeriodRequest::ResetUsage));
    }

    // ---- next_period ----

    #[test]
    fn next_period_rules() {
        let b = p(100, 50);
        let n = next_period(&b, 160).unwrap();
        assert_eq!(n.start_tick(), 160);
        assert_eq!(n.length_ticks(), 50);
        // Early reset and reset exactly at old start are allowed.
        assert_eq!(next_period(&b, 100).unwrap().start_tick(), 100);
        assert_eq!(next_period(&b, 120).unwrap().start_tick(), 120);
        assert_eq!(
            next_period(&b, 99),
            Err(PeriodError::ResetBeforeStart {
                start_tick: 100,
                reset_at_tick: 99
            })
        );
        // The new period is Active at its own start.
        assert!(matches!(
            assess_period(&n, 160),
            PeriodAssessment::Active { .. }
        ));
        // Old period is untouched (Copy value semantics).
        assert_eq!(b.start_tick(), 100);
    }

    #[test]
    fn demo_period_is_valid() {
        let d = demo_period(42);
        assert_eq!(d.start_tick(), 42);
        assert_eq!(d.length_ticks(), DEMO_PERIOD_TICKS);
        const _: () = assert!(DEMO_PERIOD_TICKS > 0);
    }

    // ---- check_periods ----

    #[test]
    fn empty_and_clean_inputs() {
        assert!(check_periods(&[], 1_000, 0).is_empty());
        let clean = [obs(1, 0, 100, None), obs(2, 50, 100, None)];
        assert!(check_periods(&clean, 99, 0).is_empty());
    }

    #[test]
    fn elapsed_no_reset_and_grace_boundary() {
        let v = [obs(7, 0, 100, None)]; // end = 100
                                        // grace 10: deadline 110. now 110 still within grace.
        assert!(check_periods(&v, 100, 10).is_empty());
        assert!(check_periods(&v, 110, 10).is_empty());
        let r = check_periods(&v, 111, 10);
        assert_eq!(
            r,
            vec![PeriodIncident {
                kind: PeriodIncidentKind::PeriodElapsedNoReset,
                account: 7,
                expected: 110,
                observed: 111
            }]
        );
        // grace 0: fires one tick after end.
        assert!(check_periods(&v, 100, 0).is_empty());
        assert_eq!(check_periods(&v, 101, 0).len(), 1);
    }

    #[test]
    fn outstanding_request_starts_grace_later() {
        let v = [obs(7, 0, 100, Some(150))];
        assert!(check_periods(&v, 160, 10).is_empty());
        assert_eq!(check_periods(&v, 161, 10).len(), 1);
        // A request "since" before the end cannot pull the deadline earlier.
        let early = [obs(7, 0, 100, Some(5))];
        assert!(check_periods(&early, 110, 10).is_empty());
        assert_eq!(check_periods(&early, 111, 10).len(), 1);
    }

    #[test]
    fn grace_saturates_without_overflow() {
        let v = [obs(1, 0, 10, None)];
        assert!(check_periods(&v, u64::MAX, u64::MAX).is_empty());
        let w = [obs(1, 0, 10, Some(u64::MAX))];
        assert!(check_periods(&w, u64::MAX, 5).is_empty());
    }

    #[test]
    fn clock_before_start_incident() {
        let v = [obs(3, 500, 100, None)];
        let r = check_periods(&v, 400, 0);
        assert_eq!(
            r,
            vec![PeriodIncident {
                kind: PeriodIncidentKind::ClockBeforeStart,
                account: 3,
                expected: 500,
                observed: 400
            }]
        );
        assert!(check_periods(&v, 500, 0).is_empty());
    }

    #[test]
    fn duplicates_reported_and_excluded() {
        let v = [
            obs(5, 0, 10, None), // would be elapsed, but duplicated
            obs(5, 0, 10, None),
            obs(5, 900, 10, None),
            obs(6, 0, 10, None), // elapsed, not duplicated
        ];
        let r = check_periods(&v, 100, 0);
        assert_eq!(
            r,
            vec![
                PeriodIncident {
                    kind: PeriodIncidentKind::DuplicateAccount,
                    account: 5,
                    expected: 1,
                    observed: 3
                },
                PeriodIncident {
                    kind: PeriodIncidentKind::PeriodElapsedNoReset,
                    account: 6,
                    expected: 10,
                    observed: 100
                },
            ]
        );
    }

    #[test]
    fn bound_exceeded_yields_only_that_incident() {
        let mut v = Vec::new();
        for i in 0..=MAX_PERIODS as u64 {
            v.push(obs(i, 0, 1, None)); // all elapsed, would be incidents
        }
        let r = check_periods(&v, 1_000, 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, PeriodIncidentKind::TooManyPeriods);
        assert_eq!(r[0].expected, MAX_PERIODS as u64);
        assert_eq!(r[0].observed, MAX_PERIODS as u64 + 1);
        // Exactly at the bound is checked normally.
        v.pop();
        assert_eq!(v.len(), MAX_PERIODS);
        let ok = check_periods(&v, 1_000, 0);
        assert_eq!(ok.len(), MAX_PERIODS);
        assert!(ok
            .iter()
            .all(|i| i.kind == PeriodIncidentKind::PeriodElapsedNoReset));
    }

    #[test]
    fn output_independent_of_input_order() {
        let v = vec![
            obs(9, 0, 10, None),
            obs(2, 5_000, 10, None),
            obs(4, 0, 10, Some(50)),
            obs(8, 0, 10, None),
            obs(8, 1, 10, None),
            obs(1, 100, 10, None),
        ];
        let base = check_periods(&v, 200, 5);
        assert!(!base.is_empty());
        let mut rev = v.clone();
        rev.reverse();
        assert_eq!(check_periods(&rev, 200, 5), base);
        let mut rot = v.clone();
        rot.rotate_left(3);
        assert_eq!(check_periods(&rot, 200, 5), base);
        let mut swp = v.clone();
        swp.swap(0, 4);
        swp.swap(1, 3);
        assert_eq!(check_periods(&swp, 200, 5), base);
    }

    #[test]
    fn input_is_unchanged() {
        let v = vec![
            obs(1, 0, 10, None),
            obs(2, 500, 10, Some(3)),
            obs(1, 0, 10, None),
        ];
        let before = v.clone();
        let _ = check_periods(&v, 100, 0);
        assert_eq!(v, before);
    }

    #[test]
    fn display_is_descriptive() {
        let v = [obs(7, 0, 100, None), obs(3, 500, 10, None)];
        let r = check_periods(&v, 200, 0);
        assert_eq!(r.len(), 2);
        let text: Vec<_> = r.iter().map(|i| format!("{i}")).collect();
        assert!(text[0].contains("account 3") && text[0].contains("before"));
        assert!(text[1].contains("account 7") && text[1].contains("no reset"));
        assert!(format!("{}", PeriodError::ZeroLength).contains("non-zero"));
        assert!(format!(
            "{}",
            PeriodError::ResetBeforeStart {
                start_tick: 2,
                reset_at_tick: 1
            }
        )
        .contains("before"));
    }
}
