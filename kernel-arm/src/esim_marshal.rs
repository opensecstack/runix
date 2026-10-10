//! MARSHAL-shaped gate in front of `kernel-arm`'s destructive eSIM
//! lifecycle operations (enable, delete — the two operations with real,
//! hard-to-undo consequences for a live SIM profile), mirroring
//! `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate` /
//! `enforce_marshal_decision` pair on the x86_64 kernel.
//!
//! # Shared by the MVNO syscalls (Beta item 3.4)
//!
//! Despite the name, [`enforce`] / [`MarshalEnforcementError`] are *the* single
//! enforcement point for every MARSHAL-gated syscall in this crate: the three
//! MVNO account syscalls (`SYS_MVNO_BIND`/`SUSPEND`/`REACTIVATE`) call
//! `marshal_transport::evaluate` with a [`MarshalAction`] value and then this
//! module's [`enforce`], rather than growing a parallel gate. The name is kept
//! (no rename churn); [`evaluate`] below remains the eSIM-specific wrapper.
//!
//! # Real transport, via `marshal_transport.rs`
//!
//! [`evaluate`] now delegates to [`crate::marshal_transport::evaluate`] --
//! `kernel-arm`'s real MARSHAL transport (Beta mobile item 2.6), loading a
//! real `net-driver-host-arm` process per call and sending a real Kerkese-
//! shaped request over a real TCP connection when a proxy address is
//! configured (`marshal_transport::set_marshal_proxy`), or short-circuiting
//! to `Remote(Unreachable)` with no process spawned at all when none is --
//! the same fail-open default this module always returned back when there
//! was no transport of any kind to attempt. See `marshal_transport.rs`'s own
//! doc comment for the full mechanism.
//!
//! # Fail-open vs. fail-closed (precise split)
//!
//! - **Remote could not be reached / did not answer** (no proxy configured,
//!   no virtio-net device, connect failure or timeout, the process not
//!   reporting back within its bounded budget, an undecodable reply):
//!   `Remote(Unreachable)` -> **fail-open** (Option B,
//!   `docs/MARSHAL-ENFORCEMENT-POLICY.md`).
//! - **The kernel failed to run the evaluation** (process setup failing,
//!   including out of memory; thread spawn failing; the EL0 excursion
//!   faulting): `LocalFailure(..)` -> **fail-closed**. A buggy or hostile
//!   EL0 caller can drive these by looping on governed syscalls, so they
//!   must not be an ungoverned bypass.
//! - A reachable MARSHAL's `Refuse`/`HardStop` always blocks.
//!
//! This module **is** wired into `svc.rs`'s dispatch: `SYS_SIM_ENABLE` and
//! `SYS_SIM_DELETE` both call [`evaluate`] then [`enforce`] between their
//! capability check and the real `sim::*` call. It is deliberately *not*
//! wired into `sim.rs`'s `transition` function — governance decisions
//! belong at the syscall boundary where the requesting context is known,
//! not inside the data model, which `sim.rs`'s own doc comment already says
//! is "only the data model and the transition logic."
//!
//! # Real `ShadowMarshalOutcome`, not a local duplicate
//!
//! This module used to define its own local four-variant
//! `ShadowMarshalOutcome` copy -- see this crate's git history for why that
//! was the right call while `kernel-arm` had no real transport to shape a
//! request/response conversion layer around. Now that [`evaluate`] has one
//! (`marshal_transport.rs`, which itself needs
//! `runix_ipc::marshal::{MarshalRequest, MarshalResponse}`), importing
//! `citadel-integration`'s own [`ShadowMarshalOutcome`] directly is the
//! same "no parallel type for the same four-outcome shape" discipline
//! `kernel/src/grid_sandbox.rs` already applies on the x86_64 side.

use runix_kernel_arm::marshal_action::{Blocked, GateOutcome, MarshalAction};

/// Evaluates whether a destructive eSIM lifecycle operation (`"enable"` or
/// `"delete"` — see this module's doc comment) should be allowed to
/// proceed, for the given `slot`/`profile`, as requested by `principal`.
///
/// Delegates to [`crate::marshal_transport::evaluate`] — see that
/// function's own doc comment for the exact classification of what
/// becomes `Remote(Unreachable)` (fail-open) versus `LocalFailure(..)`
/// (fail-closed).
pub fn evaluate(operation: &str, slot: usize, profile: u8, principal: &str) -> GateOutcome {
    crate::marshal_transport::evaluate(
        &MarshalAction::Esim {
            op: operation,
            slot,
            profile,
        },
        principal,
    )
}

/// What [`enforce`] hands back when an operation is blocked: either a
/// reachable MARSHAL refused/hard-stopped it (`Remote`), or the kernel failed
/// to run the evaluation at all (`Local`, fail closed). Kept as its own type,
/// distinct from any boot-time module-authorization error type this crate may
/// grow, for the same reason `kernel/src/grid_sandbox.rs`'s
/// `MarshalEnforcementError` is kept separate from `CitadelError` there.
pub type MarshalEnforcementError = Blocked;

/// The enforcement gate itself — Option B from
/// `docs/MARSHAL-ENFORCEMENT-POLICY.md` for the remote verdict (fail-open when
/// the remote is unreachable, fail-closed when it said no), plus fail-closed
/// for every local evaluation failure. The decision is the pure
/// [`runix_kernel_arm::marshal_action::enforce`] (host-tested); this is its
/// stable name for callers.
pub fn enforce(outcome: GateOutcome) -> Result<(), MarshalEnforcementError> {
    runix_kernel_arm::marshal_action::enforce(outcome)
}
