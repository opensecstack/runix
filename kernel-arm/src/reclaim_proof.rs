//! Boot-time proof that a MARSHAL evaluation gives back everything it took
//! (`process::AddressSpace::destroy`, `scheduler::exit_current`/
//! `reap_exited`, `net_process`'s block adoption and device reset), in the
//! style of `load_proof.rs`/`mvno_proof.rs`: serial-grep PASS/FAIL, since this
//! crate has no QEMU-native `cargo test` harness.
//!
//! # What runs
//!
//! [`prove_reclamation`] drives [`RUNS`] real evaluations through
//! `marshal_transport::evaluate_configured` -- the exact production path
//! (probe the device, build the address space, map the virtqueues and
//! buffers, load the `net-driver-host-arm` ELF, spawn a scheduler thread,
//! `eret` into EL0, bring up the virtio device and smoltcp, report back) --
//! with one difference: the remote port is `0`, which smoltcp rejects as
//! unaddressable, so the driver reports "connect failed" immediately instead
//! of spending ~1 s per run waiting out its 2,000,000-iteration timeout. No
//! packet is ever sent, so it needs no network and cannot touch a
//! `guestfwd` listener; it does not touch the MVNO/eSIM registries or the
//! WORM entry count either (it only builds a request and runs a process).
//!
//! # What is asserted
//!
//! The heap's free-byte watermark after the last run must be within
//! [`DRIFT_BUDGET`] of the watermark after the *first* run (the first run
//! absorbs one-time growth: the zombie list's capacity and similar). Before
//! reclamation each run leaked ~0.4 MiB, so [`RUNS`] runs would have needed
//! several times the whole 4 MiB heap -- the old kernel died at run 7-8.
//! Also asserted: exactly [`RUNS`] threads were reaped (so every run really
//! got as far as spawning and finishing a thread).

use crate::{heap, marshal_transport, scheduler, serial_println, svc};
use runix_kernel_arm::marshal_action::MarshalAction;

/// Far beyond what the old leak could survive (heap / ~0.4 MiB per run = ~10).
const RUNS: usize = 24;

/// Allowed free-heap loss between the first and last run, in bytes. The true
/// steady-state drift is expected to be 0; this absorbs allocator-metadata
/// fragmentation only, and is orders of magnitude below one leaked run.
const DRIFT_BUDGET: usize = 16 * 1024;

pub fn prove_reclamation() {
    if crate::virtio_mmio::probe().net.is_none() {
        serial_println!(
            "Runix ARM kernel: evaluation reclamation SKIPPED (no virtio-net device to drive)"
        );
        return;
    }

    let action = MarshalAction::Esim {
        op: "enable",
        slot: 0,
        profile: 0,
    };
    let (reaped_before, _) = scheduler::reap_totals();
    let free_before = heap::free_bytes();
    let started = svc::now_ticks();
    let mut after_first = 0usize;

    for run in 0..RUNS {
        // Port 0: connect fails immediately, see the module doc comment.
        let _ =
            marshal_transport::evaluate_configured(&action, "reclaim-proof", [10, 0, 2, 100], 0);
        let reaped_now = scheduler::reap_exited();
        if reaped_now != 1 {
            serial_println!(
                "Runix ARM kernel: evaluation reclamation FAIL (run {} reaped {} threads, \
                 expected 1; heap free={})",
                run,
                reaped_now,
                heap::free_bytes()
            );
            return;
        }
        if run == 0 {
            after_first = heap::free_bytes();
        }
    }

    let after_last = heap::free_bytes();
    let (reaped_after, reclaimed_bytes) = scheduler::reap_totals();
    let reaped = reaped_after - reaped_before;
    let elapsed_ms = (svc::now_ticks() - started) * 1000 / svc::frequency_hz().max(1);
    let drift = after_first.saturating_sub(after_last);

    let ok = reaped == RUNS && drift <= DRIFT_BUDGET;
    serial_println!(
        "Runix ARM kernel: evaluation reclamation {} ({} runs, heap free before={} \
         after-first={} after-last={}, drift={} (budget {}), heap used={}, reaped={}, reclaimed total={} B, {} ms)",
        if ok { "PASS" } else { "FAIL" },
        RUNS,
        free_before,
        after_first,
        after_last,
        drift,
        DRIFT_BUDGET,
        heap::used_bytes(),
        reaped,
        reclaimed_bytes,
        elapsed_ms
    );
}
