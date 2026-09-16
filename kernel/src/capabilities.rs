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

/// The resource string a capability must name to be scoped to one spawned
/// `grid-sandbox-host` *instance* specifically — never a module-wide grant
/// reused across instances (see
/// `runix_citadel_integration::InstanceManifestEntry`'s doc comment and
/// `grid_sandbox::spawn_instance`, which issues exactly one token per
/// instance against this resource string, keyed on that instance's own
/// `instance_id`). A token scoped to one instance's resource string never
/// matches another instance's, by construction — `CapabilityToken::verify`
/// checks the resource string exactly, same as `port_resource` above.
pub fn grid_instance_resource(instance_id: &str) -> String {
    format!("grid-instance:{instance_id}")
}

/// The resource-string convention for per-file filesystem-IPC
/// authorization (`blk-driver-host`'s `ipc::fs` surface,
/// `docs/STATUS.md`'s filesystem-driver Phase 8 section) — one capability
/// per file name, checked by `blk-driver-host` itself against a token
/// embedded in each request, not by the kernel's own `SYS_IPC_SEND` gate
/// (that gate only ever sees the fixed request/response port, never the
/// dynamic filename inside the payload). `name` is the display-form ASCII
/// filename (e.g. `"HELLO.TXT"`), matching what `ipc::fs::FsRequest`
/// carries.
pub fn file_resource(name: &str) -> String {
    format!("file:{name}")
}

/// The resource-string convention for port-I/O access: one capability
/// covers a whole inclusive port range, not one token per port — matching
/// the granularity `port_resource` already uses for IPC (one token per
/// whole port, not per byte sent). Chosen over a per-register-purpose
/// scheme so a device driver process needs exactly one token for its
/// device's whole register block, with no new capability-manager mechanism
/// (wildcard/prefix matching) required — see docs/STATUS.md's network-stack
/// section for the reasoning.
pub fn ioport_range_resource(base: u16, len: u16) -> String {
    format!("ioport:{base}-{}", base + len - 1)
}

/// Parses a resource string produced by [`ioport_range_resource`] back into
/// its `(base, end)` bounds (both inclusive). Returns `None` for anything
/// that isn't in exactly that shape — including a token's `resource` field
/// that was never an ioport range at all (e.g. a `port:<n>` IPC token
/// presented to a port-I/O syscall by mistake).
fn parse_ioport_range(resource: &str) -> Option<(u16, u16)> {
    let rest = resource.strip_prefix("ioport:")?;
    let (base, end) = rest.split_once('-')?;
    Some((base.parse().ok()?, end.parse().ok()?))
}

/// Checks whether `token` is valid (signature, expiry — same checks
/// [`check`] runs) *and* was issued for an ioport range that contains
/// `port`. Unlike [`check`], the caller doesn't supply the expected
/// resource string up front — it can't, since it doesn't know what range
/// the token claims until the token itself is parsed. Instead this verifies
/// the signature against the token's *own* `resource` field (confirming the
/// token really was signed for whatever range it claims to cover, not a
/// forged claim), then checks that range contains `port`.
pub fn check_ioport_range(
    token: &CapabilityToken,
    port: u16,
    now: u64,
) -> Result<(), CapabilityError> {
    token.verify(&demo_verifying_key(), &token.resource, now)?;
    match parse_ioport_range(&token.resource) {
        Some((base, end)) if base <= port && port <= end => Ok(()),
        _ => Err(CapabilityError::WrongResource),
    }
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

/// The "look up caller's token, check not revoked, check the resource"
/// sequence every capability-gated syscall needs — `SYS_IPC_SEND` inlines
/// its own copy of this shape (see `syscall.rs::dispatch`); `SYS_PORT_IN`/
/// `SYS_PORT_OUT` are the second and third callers, past the point where
/// duplicating it a third time stopped being worth it.
pub fn authorized_for_ioport(port: u16, now: u64) -> bool {
    crate::scheduler::current_capability()
        .is_some_and(|token| !is_revoked(&token) && check_ioport_range(&token, port, now).is_ok())
}
