//! Boot-time proof of `runix_mobile::period`'s pure billing-period model
//! (`assess_period`, `period_request`, `next_period`, `check_periods`), in the
//! style of `mvno_proof.rs`: EL1-only, no syscall, serial-grep PASS/FAIL.
//!
//! # Why this exists next to the live `SYS_DATA_PERIOD` walk
//!
//! The EL0 walk exercises the model against LIVE state, but only along the
//! paths a ~6 s boot can reach: a period that elapsed, a reset that started the
//! next one (or was denied and started none). It cannot reach
//! `PeriodElapsedNoReset` (the reconciler's grace is deliberately long, see
//! `data_codes::DEMO_GRACE_MILLIS`: a short one would fire mid-walk and change
//! the reconciler incident counts CI pins) nor `ClockBeforeStart` (the demo
//! period starts at tick 0, so the counter is never before it). This proof
//! drives both, and the boundary and `next_period` rules, on SYNTHETIC ticks, so
//! those paths run on the real target (aarch64, `panic = "abort"`, the actual
//! `no_std` build) and not only in `cargo test --lib` on the host.
//!
//! # What it deliberately does NOT touch
//!
//! No live state: it builds its own `BillingPeriod`/`ObservedPeriod` values from
//! literals, reads no clock (the ticks are literals -- the model takes an
//! explicit `now`), takes no lock, makes no WORM entry and no capability check.
//! The global data state, the audit chain's entry count and the registry are
//! exactly as they were before it ran. Like the model itself it only OBSERVES
//! and REQUESTS; nothing here resets anything.

use alloc::vec;
use alloc::vec::Vec;

use runix_mobile::period::{
    assess_period, check_periods, next_period, period_request, BillingPeriod, ObservedPeriod,
    PeriodAssessment, PeriodError, PeriodIncident, PeriodIncidentKind, PeriodRequest,
};

use crate::serial_println;

fn period(start: u64, len: u64) -> Option<BillingPeriod> {
    BillingPeriod::new(start, len).ok()
}

/// Prints one labelled result and folds `ok` into `pass`.
fn step(pass: &mut bool, label: &str, shown: impl core::fmt::Debug, ok: bool) {
    serial_println!(
        "Runix ARM kernel: period proof {} -> {:?}{}",
        label,
        shown,
        if ok { "" } else { " (UNEXPECTED)" }
    );
    *pass &= ok;
}

pub fn prove_periods() {
    let mut pass = true;
    let Some(p) = period(1_000, 500) else {
        serial_println!("Runix ARM kernel: period proof FAILED (could not build the test period)");
        return;
    };

    // --- assessment and request, one tick either side of each boundary ---
    let a = assess_period(&p, 1_200);
    step(
        &mut pass,
        "assess start=1000 len=500 now=1200",
        a,
        a == PeriodAssessment::Active {
            elapsed: 200,
            remaining: 300,
        },
    );
    let r = period_request(&p, 1_499);
    step(
        &mut pass,
        "request now=1499 (last active tick)",
        r,
        r.is_none(),
    );

    let a = assess_period(&p, 1_500);
    step(
        &mut pass,
        "assess now=1500 (exactly the end)",
        a,
        a == PeriodAssessment::Elapsed {
            overdue_ticks: 0,
            periods_missed: 1,
        },
    );
    let r = period_request(&p, 1_500);
    step(
        &mut pass,
        "request now=1500",
        r,
        r == Some(PeriodRequest::ResetUsage),
    );

    let a = assess_period(&p, 3_100);
    step(
        &mut pass,
        "assess now=3100 (resets skipped)",
        a,
        a == PeriodAssessment::Elapsed {
            overdue_ticks: 1_600,
            periods_missed: 4,
        },
    );

    let a = assess_period(&p, 400);
    step(
        &mut pass,
        "assess now=400 (clock before start)",
        a,
        a == PeriodAssessment::ClockBeforeStart {
            start_tick: 1_000,
            now_tick: 400,
        },
    );
    let r = period_request(&p, 400);
    step(&mut pass, "request now=400 (rewound clock)", r, r.is_none());

    // --- the next period ---
    match next_period(&p, 3_100) {
        Ok(n) => {
            let ok = n.start_tick() == 3_100
                && n.length_ticks() == 500
                && matches!(assess_period(&n, 3_100), PeriodAssessment::Active { .. })
                && period_request(&n, 3_599).is_none()
                && period_request(&n, 3_600) == Some(PeriodRequest::ResetUsage);
            step(
                &mut pass,
                "next_period(reset at 3100)",
                (n.start_tick(), n.length_ticks()),
                ok,
            );
        }
        Err(e) => step(&mut pass, "next_period(reset at 3100)", e, false),
    }
    let e = next_period(&p, 999);
    step(
        &mut pass,
        "next_period(reset at 999, before start)",
        e,
        e == Err(PeriodError::ResetBeforeStart {
            start_tick: 1_000,
            reset_at_tick: 999,
        }),
    );

    // --- the reconciler-style check, incl. the two incidents the live walk
    // cannot reach ---
    let (Some(p_elapsed), Some(p_future), Some(p_active), Some(p_edge)) = (
        period(0, 100),
        period(5_000, 100),
        period(900, 500),
        period(0, 100),
    ) else {
        serial_println!("Runix ARM kernel: period proof FAILED (could not build observed periods)");
        return;
    };
    let observed: Vec<ObservedPeriod> = vec![
        // Elapsed at 100, never reset, never requested: grace 50 -> deadline 150.
        ObservedPeriod {
            account: 1,
            period: p_elapsed,
            reset_requested_since: None,
        },
        // Starts at 5000 but the clock reads 1000: ClockBeforeStart.
        ObservedPeriod {
            account: 2,
            period: p_future,
            reset_requested_since: None,
        },
        // Healthy: 900..1400 contains 1000.
        ObservedPeriod {
            account: 3,
            period: p_active,
            reset_requested_since: None,
        },
        // Elapsed, but requested at 980: the grace runs from the request
        // (deadline 1030), so it is still within grace at 1000.
        ObservedPeriod {
            account: 4,
            period: p_edge,
            reset_requested_since: Some(980),
        },
    ];
    let incidents = check_periods(&observed, 1_000, 50);
    for i in &incidents {
        serial_println!("Runix ARM kernel: period proof incident {}", i);
    }
    let expected = [
        PeriodIncident {
            kind: PeriodIncidentKind::ClockBeforeStart,
            account: 2,
            expected: 5_000,
            observed: 1_000,
        },
        PeriodIncident {
            kind: PeriodIncidentKind::PeriodElapsedNoReset,
            account: 1,
            expected: 150,
            observed: 1_000,
        },
    ];
    step(
        &mut pass,
        "check_periods(now=1000, grace=50) incident count",
        incidents.len(),
        incidents.len() == 2,
    );
    step(
        &mut pass,
        "check_periods incidents (ClockBeforeStart first, then PeriodElapsedNoReset)",
        incidents.iter().map(|i| i.kind).collect::<Vec<_>>(),
        incidents.as_slice() == expected.as_slice(),
    );
    // The same set, later than every grace has run: account 4 now fires too, and
    // the future-period account is still a clock anomaly.
    let later = check_periods(&observed, 1_031, 50);
    step(
        &mut pass,
        "check_periods(now=1031) incident count (request grace over)",
        later.len(),
        later.len() == 3,
    );

    if pass {
        serial_println!("Runix ARM kernel: period proof PASS");
    } else {
        serial_println!("Runix ARM kernel: period proof FAILED");
    }
}
