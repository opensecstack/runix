//! Demo capability trust root: a single hardcoded Ed25519 keypair the
//! kernel both issues and verifies tokens against. Real key provisioning
//! (loaded from firmware/the future WORM boot chain, never baked into the
//! kernel binary) is a later item — this exists only to prove the
//! `capability-manager` <-> syscall-gate wiring works end to end, so
//! anything this module signs should be treated as a demo fixture, not a
//! real trust anchor.
//!
//! Gated behind the `insecure-demo-keys` feature (on by default — see
//! `Cargo.toml`) so the hardcoded seed can never end up in a build that
//! didn't explicitly ask for it: a release recipe that disables default
//! features gets the [`compile_error!`] below instead of a silently
//! shipped demo key.

#[cfg(not(feature = "insecure-demo-keys"))]
compile_error!(
    "capabilities.rs's hardcoded Ed25519 demo trust root requires the \
     `insecure-demo-keys` feature. There is no real key provisioning yet \
     (see this module's doc comment) — if you're building something meant \
     to ship, that has to exist first. If this is still an alpha/dev \
     build, re-enable default features."
);

use alloc::format;
use alloc::string::String;
use ed25519_dalek::{SigningKey, VerifyingKey};
use lazy_static::lazy_static;
use runix_capability_manager::{CapabilityError, CapabilityToken, RevocationList};
use spin::Mutex;

// Arbitrary fixed bytes — not a real secret, not derived from anything.
// Any 32 bytes are a valid Ed25519 seed; these are picked purely so the
// demo keypair is reproducible across boots instead of needing an entropy
// source the kernel doesn't have yet.
const DEMO_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

pub fn demo_signing_key() -> SigningKey {
    SigningKey::from_bytes(&DEMO_SEED)
}

pub fn demo_verifying_key() -> VerifyingKey {
    demo_signing_key().verifying_key()
}

/// The resource string a capability must match to authorize `SYS_IPC_SEND`
/// on `port` — the convention `syscall::dispatch`'s check and whoever
/// issues tokens both have to agree on.
pub fn port_resource(port: usize) -> String {
    format!("port:{port}")
}

/// Checks `token` against the demo trust root for `resource` at time `now`.
/// `now` is `interrupts::ticks()` (PIT ticks since boot), not wall-clock
/// time — there's no RTC driver yet, so token lifetimes are expressed in
/// ticks for now, not seconds. Good enough to prove expiry enforcement
/// works; not a real deadline until a real clock exists.
pub fn check(token: &CapabilityToken, resource: &str, now: u64) -> Result<(), CapabilityError> {
    token.verify(&demo_verifying_key(), resource, now)
}

lazy_static! {
    static ref REVOCATIONS: Mutex<RevocationList> = Mutex::new(RevocationList::new());
}

/// Revokes `token` — after this, [`is_revoked`] reports it even though
/// [`check`]/[`CapabilityToken::verify`] still consider its signature,
/// expiry, and resource scope valid entirely on their own (revocation is
/// deliberately not part of what `verify` checks — see
/// `RevocationList`'s doc comment in `capability-manager`). Meant for
/// trusted kernel code (an admin path, once one exists), not exposed as a
/// syscall: "let the token holder revoke their own token" isn't a
/// meaningful operation — they'd just stop using it.
pub fn revoke(token: &CapabilityToken) {
    REVOCATIONS.lock().revoke(token);
}

pub fn is_revoked(token: &CapabilityToken) -> bool {
    REVOCATIONS.lock().is_revoked(token)
}
