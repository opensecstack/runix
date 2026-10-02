//! Structural placeholder for a MARSHAL-shaped gate in front of
//! `kernel-arm`'s destructive eSIM lifecycle operations (enable, delete —
//! the two operations with real, hard-to-undo consequences for a live SIM
//! profile), mirroring the shape (not yet the substance) of
//! `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate` /
//! `enforce_marshal_decision` pair on the x86_64 kernel.
//!
//! # Why this exists now, with no transport behind it
//!
//! `kernel-arm` has no network stack and no MARSHAL transport of any kind
//! today — there is nothing real to call yet, unlike the x86_64 kernel's
//! `grid_sandbox` module, which has a working `marshal_client` and a
//! configurable proxy address. This module exists anyway so that:
//!
//! - every destructive eSIM operation can already be routed through one
//!   gate today, with that gate proven to fail open correctly (see
//!   [`evaluate`]/[`enforce`]'s own tests, once wired up by a caller), and
//! - swapping in a real transport later is a drop-in replacement of
//!   [`evaluate`]'s body only — everything that calls [`evaluate`] and
//!   [`enforce`] today keeps working unchanged once that body starts
//!   actually talking to a MARSHAL proxy, the same way
//!   `shadow_marshal_evaluate` does on the x86_64 side.
//!
//! This module **is** wired into `svc.rs`'s dispatch, as of the eSIM
//! lifecycle integration: `SYS_SIM_ENABLE` and `SYS_SIM_DELETE` both call
//! [`evaluate`] then [`enforce`] between their capability check and the
//! real `sim::*` call. It is deliberately *not* wired into `sim.rs`'s
//! `transition` function — governance decisions belong at the syscall
//! boundary where the requesting context is known, not inside the data
//! model, which `sim.rs`'s own doc comment already says is "only the data
//! model and the transition logic."
//!
//! # Local `ShadowMarshalOutcome`, not `citadel-integration`'s
//!
//! `citadel-integration` defines its own `pub` `ShadowMarshalOutcome` (see
//! `kernel/src/grid_sandbox.rs`'s `use runix_citadel_integration::{..,
//! ShadowMarshalOutcome, ..}`), but this module defines a local copy
//! anyway. The original reason — that depending on `citadel-integration`
//! at all would drag `citadel-kerkese-core`, `serde`, `hex`, and `sha2`
//! into a crate that had none of them — no longer holds: `kernel-arm` now
//! *does* depend on `citadel-integration`, for `WormLog` (see `svc.rs`'s
//! `ESIM_WORM_LOG`), and it builds for `aarch64-unknown-none` fine. What
//! remains is a weaker but still real reason to keep the copy for now:
//! `citadel-integration`'s enum is shaped around that crate's own
//! request/response types, and switching to it is only worth doing as part
//! of the same change that gives this module a real transport (which will
//! want those types anyway). Until then the copy costs one four-variant
//! enum and avoids a conversion layer in between.
//!
//! # What changes when `kernel-arm` gets real networking
//!
//! [`evaluate`] unconditionally returns [`ShadowMarshalOutcome::Unreachable`]
//! — the documented fail-open default per
//! `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s Option B ("fail-open when there's
//! nothing to honor"), which is simply *always* true today since there is no
//! transport to attempt contact with. Once `kernel-arm` has real networking,
//! mirror `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate`: look up a
//! configured MARSHAL proxy address, attempt a real call if one is
//! configured, and map a reachable response's outcome onto this module's
//! [`ShadowMarshalOutcome`] — collapsing "not configured" and "configured
//! but unreachable" into [`ShadowMarshalOutcome::Unreachable`] exactly as
//! `shadow_marshal_evaluate` does. [`enforce`] itself should not need to
//! change at all.

/// Mirrors `citadel-integration`'s own `ShadowMarshalOutcome` (see this
/// module's doc comment for why this is a local copy rather than a
/// dependency on that crate).
///
/// `allow(dead_code)`: [`evaluate`] can only construct `Unreachable`
/// today, so the other three variants have no constructor anywhere in the
/// crate. They are written out now rather than added later because
/// [`enforce`]'s policy match — the whole fail-open/fail-closed decision —
/// is only auditable if it covers every outcome a real transport will
/// eventually return. Narrowly scoped to this enum, and expected to be
/// removable (not just inherited) the moment [`evaluate`] gains a real
/// transport body.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowMarshalOutcome {
    /// No MARSHAL transport configured, or a configured one that couldn't
    /// be reached. Today this is the *only* outcome [`evaluate`] can ever
    /// produce, since `kernel-arm` has no transport at all yet.
    Unreachable,
    /// A reachable MARSHAL deployment approved the operation.
    Execute,
    /// A reachable MARSHAL deployment refused the operation.
    Refuse,
    /// A reachable MARSHAL deployment issued a hard stop.
    HardStop,
}

/// Evaluates whether a destructive eSIM lifecycle operation (`"enable"` or
/// `"delete"` — see this module's doc comment) should be allowed to
/// proceed, for the given `slot`/`profile`.
///
/// `operation`, `slot`, and `profile` are accepted now (rather than added
/// later) so a real transport's body can use them to shape a real request
/// without changing this function's signature or any caller.
///
/// **Always returns [`ShadowMarshalOutcome::Unreachable`] today.** There is
/// no MARSHAL transport of any kind in `kernel-arm` yet — no network stack,
/// no configured proxy, nothing to attempt contact with — so this is
/// unconditionally the fail-open case per
/// `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s Option B, not a placeholder that
/// happens to always take one branch of a real check. See this module's own
/// doc comment for exactly what to change here (mirroring
/// `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate`) once
/// `kernel-arm` has real networking.
pub fn evaluate(_operation: &str, _slot: usize, _profile: u8) -> ShadowMarshalOutcome {
    ShadowMarshalOutcome::Unreachable
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
///
/// Since [`evaluate`] can only ever return [`ShadowMarshalOutcome::Unreachable`]
/// today, this always returns `Ok(())` for now — but the full match is
/// written out now so nothing here needs to change once [`evaluate`] starts
/// returning real outcomes.
pub fn enforce(outcome: ShadowMarshalOutcome) -> Result<(), MarshalEnforcementError> {
    match outcome {
        ShadowMarshalOutcome::Unreachable => Ok(()),
        ShadowMarshalOutcome::Execute => Ok(()),
        ShadowMarshalOutcome::Refuse | ShadowMarshalOutcome::HardStop => {
            Err(MarshalEnforcementError::Blocked(outcome))
        }
    }
}
