//! Demo CITADEL boot-time trust root: proves the `citadel-integration`
//! <-> kernel wiring works end to end, the same way `capabilities.rs`
//! proves the `capability-manager` <-> syscall-gate wiring works — this is
//! not a real trust anchor, and nothing here gates a real module load yet.
//!
//! `citadel-integration`'s `BootAllowlist::authorize_module_load` exists,
//! is tested, and until this module was added, `kernel/Cargo.toml` didn't
//! even depend on the crate — the logic was "correct in isolation and
//! inert in practice" (see `docs/THREAT_MODEL.md`). This module closes
//! that specific gap: `main.rs`'s boot sequence now actually calls
//! `authorize_module_load` and observes a real accept/reject outcome.
//!
//! What this does *not* yet do: gate an actual module the kernel goes on to
//! load. `main.rs` doesn't ELF-load anything in its own boot path today
//! (only `kernel/tests/*.rs` do, e.g. `grid_sandbox_wasm.rs` loading
//! `grid-sandbox-host`) — moving that load into `main.rs` and gating it
//! through this allowlist is the next slice, not this one.

use ed25519_dalek::{SigningKey, VerifyingKey};
use runix_citadel_integration::{BootAllowlist, CitadelError, ModuleManifestEntry};
use sha2::Digest;

// Arbitrary fixed bytes, distinct from `capabilities.rs`'s demo seed —
// CITADEL's boot-authorization trust root and the capability-manager's
// token trust root are conceptually separate roots in a real deployment
// (different signers, different purposes), so the demo fixtures stay
// separate too rather than implying they're the same key. Not a real
// secret, not derived from anything.
const DEMO_SEED: [u8; 32] = [
    0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
    0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
];

fn demo_signing_key() -> SigningKey {
    SigningKey::from_bytes(&DEMO_SEED)
}

fn demo_verifying_key() -> VerifyingKey {
    demo_signing_key().verifying_key()
}

/// Builds a one-entry allowlist authorizing `module_id`/`module_bytes` under
/// the demo trust root, signing the entry with the same demo key the check
/// verifies against — standing in for CITADEL's real, offline release-time
/// signing step (see `ModuleManifestEntry::issue`'s doc comment).
fn demo_allowlist(module_id: &str, module_bytes: &[u8]) -> BootAllowlist {
    let signing_key = demo_signing_key();
    let sha256_hex = hex::encode(sha2::Sha256::digest(module_bytes));
    let entry = ModuleManifestEntry::issue(module_id, sha256_hex, "demo-key", &signing_key);
    let mut allowlist = BootAllowlist::new();
    allowlist.insert(entry);
    allowlist
}

/// Runs the demo boot-time authorization gate against `module_id`/
/// `module_bytes`, under an allowlist that authorizes exactly that module —
/// proving the crate's own `authorize_module_load` accepts what it should.
pub fn demo_authorize(module_id: &str, module_bytes: &[u8]) -> Result<(), CitadelError> {
    let allowlist = demo_allowlist(module_id, module_bytes);
    allowlist.authorize_module_load(&demo_verifying_key(), module_id, module_bytes)
}

/// Same gate, but against tampered bytes the allowlist entry wasn't issued
/// for — proving the *rejection* path works too, not just the happy path
/// (an allowlist that only ever says "yes" would be worthless).
pub fn demo_reject_tampered(module_id: &str, module_bytes: &[u8]) -> Result<(), CitadelError> {
    let allowlist = demo_allowlist(module_id, module_bytes);
    let mut tampered = module_bytes.to_vec();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0xff;
    } else {
        tampered.push(0xff);
    }
    allowlist.authorize_module_load(&demo_verifying_key(), module_id, &tampered)
}
