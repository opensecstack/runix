//! MARSHAL-shaped gate in front of `kernel-arm`'s destructive eSIM
//! lifecycle operations (enable, delete — the two operations with real,
//! hard-to-undo consequences for a live SIM profile), mirroring
//! `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate` /
//! `enforce_marshal_decision` pair on the x86_64 kernel.
//!
//! # Real transport, via `marshal_transport.rs`
//!
//! [`evaluate`] now delegates to [`crate::marshal_transport::evaluate`] --
//! `kernel-arm`'s real MARSHAL transport (Beta mobile item 2.6), loading a
//! real `net-driver-host-arm` process per call and sending a real Kerkese-
//! shaped request over a real TCP connection when a proxy address is
//! configured (`marshal_transport::set_marshal_proxy`), or short-circuiting
//! to [`ShadowMarshalOutcome::Unreachable`] with no process spawned at all
//! when none is -- the same fail-open default this module always returned
//! back when there was no transport of any kind to attempt. See
//! `marshal_transport.rs`'s own doc comment for the full mechanism.
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

pub use runix_citadel_integration::ShadowMarshalOutcome;

/// Evaluates whether a destructive eSIM lifecycle operation (`"enable"` or
/// `"delete"` — see this module's doc comment) should be allowed to
/// proceed, for the given `slot`/`profile`, as requested by `principal`.
///
/// Delegates to [`crate::marshal_transport::evaluate`] — see that
/// function's own doc comment for exactly what it does with these
/// arguments (building a Kerkese-shaped request, which only happens at all
/// once a MARSHAL proxy is configured) and for why
/// [`ShadowMarshalOutcome::Unreachable`] is still the correct answer with
/// none configured, exactly as it always was when this module had no
/// transport of any kind.
pub fn evaluate(
    operation: &str,
    slot: usize,
    profile: u8,
    principal: &str,
) -> ShadowMarshalOutcome {
    crate::marshal_transport::evaluate(operation, slot, profile, principal)
}

/// What [`enforce`] hands back when a reachable MARSHAL deployment refused
/// (or hard-stopped) the operation. Kept as its own enum, distinct from any
/// boot-time module-authorization error type this crate may grow, for the
/// same reason `kernel/src/grid_sandbox.rs`'s `MarshalEnforcementError` is
/// kept separate from `CitadelError` there: boot-time authorization ("is
/// this allowed to exist at all") and runtime governance ("CITADEL says
/// don't run this right now") are different failure categories that callers
/// legitimately want to handle differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarshalEnforcementError {
    /// A reachable MARSHAL deployment returned `Refuse` or `HardStop` for
    /// this operation. Carries the exact outcome so a caller/log message
    /// can tell the two apart without re-deriving it.
    Blocked(ShadowMarshalOutcome),
}

/// The enforcement gate itself — Option B from
/// `docs/MARSHAL-ENFORCEMENT-POLICY.md`: fail-open when there is nothing to
/// honor ([`ShadowMarshalOutcome::Unreachable`]), fail-closed only when a
/// reachable MARSHAL actually said no. Deliberately separated from
/// [`evaluate`] so this policy — the entire fail-open/fail-closed decision —
/// stays in one small, trivially auditable match, exactly as
/// `kernel/src/grid_sandbox.rs`'s `enforce_marshal_decision` is kept
/// separate from `shadow_marshal_evaluate`.
pub fn enforce(outcome: ShadowMarshalOutcome) -> Result<(), MarshalEnforcementError> {
    match outcome {
        ShadowMarshalOutcome::Unreachable => Ok(()),
        ShadowMarshalOutcome::Execute => Ok(()),
        ShadowMarshalOutcome::Refuse | ShadowMarshalOutcome::HardStop => {
            Err(MarshalEnforcementError::Blocked(outcome))
        }
    }
}
