//! Demo capability trust root -- the ARM-side analogue of
//! `kernel/src/capabilities.rs`, reusing the *same* `capability-manager`
//! crate rather than a separate implementation. Not a real trust anchor:
//! same caveat as the x86_64 side's `demo_signing_key` -- this exists to
//! prove the capability-token model actually gates something on this
//! architecture too, not to be production key material.
//!
//! Originally named `ril_capability` and scoped to RIL channels only; now
//! generalized to hold *any* number of independently-scoped resources
//! (RIL channels, SIM slots, ...) for the one EL0 context this crate
//! supports -- see `sim.rs`'s doc comment for why SIM provisioning needed
//! this generalization rather than its own separate capability store.
//!
//! # Simplified from the x86_64 pattern, honestly
//!
//! `kernel/src/capabilities.rs::check` looks up "the current thread's
//! capability" via `scheduler::current_capability()` -- there is no
//! scheduler here yet (see `main.rs`'s doc comment: this crate has no
//! multi-threading, no process concept beyond the single hand-written EL0
//! context `el0.rs` drops into). `CURRENT_CAPABILITIES` is a single global
//! set standing in for that -- correct for "exactly one EL0 context
//! exists, holding a small fixed set of resources," not yet a real
//! per-caller model. Wiring this into an actual scheduler is real
//! follow-up work, not something to fake here.

use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::{SigningKey, VerifyingKey};
use runix_capability_manager::{CapabilityError, CapabilityToken};
use spin::Mutex;

// Arbitrary fixed bytes, distinct from every other demo seed in this repo
// (kernel/src/capabilities.rs's x86_64 one, kernel/src/citadel.rs's) --
// same reasoning as those: not a real secret, picked only so the demo
// keypair is reproducible across boots instead of needing an entropy
// source this crate doesn't have.
const DEMO_SEED: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

fn demo_signing_key() -> SigningKey {
    SigningKey::from_bytes(&DEMO_SEED)
}

fn demo_verifying_key() -> VerifyingKey {
    demo_signing_key().verifying_key()
}

/// The resource string a capability must match to authorize
/// `SYS_RIL_ACCESS`/`SYS_RIL_SEND`/`SYS_RIL_RECV` on `channel` -- the
/// convention `svc::dispatch`'s checks and whoever issues tokens both have
/// to agree on, same shape as `kernel/src/capabilities.rs::port_resource`.
pub fn ril_resource(channel: usize) -> String {
    alloc::format!("ril:{channel}")
}

/// The resource string a capability must match to authorize
/// `SYS_SIM_PROVISION`/`SYS_SIM_ACTIVATE`/`SYS_SIM_STATUS` on `slot`.
pub fn sim_resource(slot: usize) -> String {
    alloc::format!("sim:{slot}")
}

/// Small, fixed-scope set rather than `Option<CapabilityToken>` (the
/// original single-resource shape) -- the one EL0 context now holds
/// capabilities for more than one *kind* of resource at once (a RIL
/// channel and a SIM slot), not just more than one RIL channel. No
/// eviction, no capacity limit beyond what a demo boot actually issues --
/// a real per-thread capability set (once a scheduler exists) would need
/// both; this doesn't need to model them to prove the check works.
static CURRENT_CAPABILITIES: Mutex<Vec<CapabilityToken>> = Mutex::new(Vec::new());

/// Issues a demo token authorizing `resource` and adds it to the current
/// EL0 context's held set -- called from EL1, before dropping into
/// `el0.rs`'s entry, once per resource the demo should actually be
/// authorized for. Stands in for a real issuer (CITADEL MARSHAL, in the
/// target architecture) the same way `main.rs`'s x86_64-side demo token
/// issuance does.
pub fn issue_and_hold(resource: String, now: u64) {
    // 60 real seconds' worth of ticks at the platform's actual generic-timer
    // frequency -- plenty for `el0_demo`'s handful of SVCs, comfortably
    // outliving heap init and a few UART prints. See `svc::frequency_hz`'s
    // doc comment for why this isn't a fixed tick count.
    let expires_at = now + 60 * crate::svc::frequency_hz();
    let token = CapabilityToken::issue(
        "el0:arm-demo",
        resource,
        now,
        expires_at,
        "demo-key",
        &demo_signing_key(),
    );
    CURRENT_CAPABILITIES.lock().push(token);
}

/// Checks whether the current EL0 context holds *any* token authorizing
/// `resource` at time `now` -- called from `svc::dispatch`'s
/// capability-gated handlers, the same way `kernel/src/capabilities.rs::check`
/// is called from `syscall::dispatch`'s `SYS_IPC_SEND` handler. Scans the
/// whole held set rather than a single slot, since more than one resource
/// can be held at once now; returns the *last* error seen if nothing
/// matches (arbitrary among non-matches -- there's no meaningfully "more
/// correct" error to prefer when every held token is for some other
/// resource).
pub fn check(resource: &str, now: u64) -> Result<(), CapabilityError> {
    let guard = CURRENT_CAPABILITIES.lock();
    if guard.is_empty() {
        return Err(CapabilityError::InvalidSignature);
    }
    let mut last_err = CapabilityError::InvalidSignature;
    for token in guard.iter() {
        match token.verify(&demo_verifying_key(), resource, now) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}
