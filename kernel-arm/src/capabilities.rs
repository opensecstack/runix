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

/// The resource string a capability must match to authorize slot-level
/// SIM operations -- today just `SYS_SIM_CREATE`, which allocates a new
/// profile container in `slot`. Deliberately still slot-level rather than
/// folded into [`sim_profile_resource`]: `CREATE`'s whole job is to bring a
/// profile into existence, so there is no profile ID to scope its check to
/// at the moment it runs. Every *subsequent* operation on that profile
/// checks the finer-grained per-profile resource instead.
pub fn sim_resource(slot: usize) -> String {
    alloc::format!("sim:{slot}")
}

/// The resource string a capability must match to authorize general
/// per-profile access (status queries, enable/disable) on `profile` within
/// `slot` -- `sim.rs`'s data model holds multiple `EsimProfile`s per slot
/// now, so `sim_resource`'s slot-level granularity is too coarse to grant
/// access to one profile without implicitly granting it to every other
/// profile sharing that slot. The resource is just an opaque string as far
/// as `capability-manager` is concerned -- no special parsing, same as
/// `ril_resource`/`sim_resource` -- so adding a `:{profile}` segment is
/// enough to scope it.
pub fn sim_profile_resource(slot: usize, profile: u8) -> String {
    alloc::format!("sim:{slot}:{profile}")
}

/// The resource string a capability must match to authorize *deleting*
/// `profile` within `slot` specifically -- deliberately a distinct resource
/// string from `sim_profile_resource`'s, not a boolean "can-delete" flag or
/// separate field on the same token, because deletion is the one
/// irreversible eSIM operation: a context holding general profile access
/// (status/enable/disable) should not thereby also hold delete authority.
/// Since the resource is just an opaque string to `capability-manager`
/// (same design point as `sim_profile_resource`'s), keeping it a wholly
/// separate string is sufficient to require a separately issued token
/// before `check` will authorize the delete path.
pub fn sim_delete_resource(slot: usize, profile: u8) -> String {
    alloc::format!("sim:delete:{slot}:{profile}")
}

/// The resource-string convention for physical-MMIO-range access -- the
/// ARM analogue of `kernel/src/capabilities.rs::ioport_range_resource`, for
/// a context that has no port I/O at all. Names an authorized `(base,
/// len)` physical address range, not a fixed device: once this crate has a
/// process/scheduler model (in progress, separately, as of this writing --
/// see `docs/BETA_MOBILE_PROGRESS.md`'s Item 2.4), a real EL0 driver
/// process will hold a token for exactly the MMIO window(s) it's allowed to
/// have mapped into its own `process::AddressSpace`, checked before that
/// mapping is established -- the same role `ioport_range_resource` plays
/// for x86_64 port I/O, just scoped to memory addresses instead of port
/// numbers. No caller exists yet (same as `elf.rs`'s parser had none when
/// first written) -- this is purely the naming + containment-check
/// primitive the future loader/syscall path will need.
///
/// Encodes `base`/`len` in hex (`{:#x}`), not decimal like
/// `ril_resource`/`sim_resource`'s channel/slot numbers -- physical
/// addresses in this codebase are always written and reasoned about in hex
/// (see `virtio_mmio.rs`'s own `VIRTIO_MMIO_BASE`/`SLOT_STRIDE`), so hex
/// here is the format an implementer debugging a mismatched capability
/// would actually want to read. The resource is still just an opaque
/// string as far as `capability-manager` is concerned -- no special
/// parsing there, same design point as every other `{kind}_resource`
/// function in this file.
///
/// `allow(dead_code)`: no caller yet, same reasoning as `sim.rs`'s
/// `profiles`/`delete_profile` and `esim_marshal::evaluate`'s
/// `Unreachable` arm -- this is purely the naming primitive the future
/// EL0-driver loader/syscall path will need.
#[allow(dead_code)]
pub fn mmio_window_resource(base: usize, len: usize) -> String {
    alloc::format!("mmio:{base:#x}:{len:#x}")
}

/// Parses a resource string produced by [`mmio_window_resource`] back into
/// its `(base, len)` pair. Returns `None` for anything not in exactly that
/// shape -- including a token's `resource` field that was never an MMIO
/// window at all. Private, same visibility as
/// `kernel/src/capabilities.rs::parse_ioport_range`: only [`check_mmio_window`]
/// needs the parsed form, everyone else deals in resource strings.
///
/// `allow(dead_code)`: [`check_mmio_window`] is this function's only
/// caller, and it has no caller of its own yet either -- see that
/// function's own `allow(dead_code)`.
#[allow(dead_code)]
fn parse_mmio_window(resource: &str) -> Option<(usize, usize)> {
    let rest = resource.strip_prefix("mmio:")?;
    let (base_str, len_str) = rest.split_once(':')?;
    let base = usize::from_str_radix(base_str.strip_prefix("0x")?, 16).ok()?;
    let len = usize::from_str_radix(len_str.strip_prefix("0x")?, 16).ok()?;
    Some((base, len))
}

/// `VIRTIO_MMIO_BASE`/`SLOT_STRIDE`, duplicated from `virtio_mmio.rs`
/// rather than imported from it. Two reasons, not one: (1) this task is
/// deliberately scoped to not modify `virtio_mmio.rs` at all (a parallel
/// task is mid-flight on the process/loader side of this crate), and its
/// two constants are private `const`s there, not `pub(crate)`; (2) even
/// setting that aside, this file has no real reason to *depend* on
/// `virtio_mmio.rs` -- that module is itself tracked, deliberate
/// throwaway EL1 scaffolding (see `docs/BETA_MOBILE_PROGRESS.md`'s Item
/// 2.4) due to be replaced by a real EL0 driver, while a capability-naming
/// convention should outlive that rewrite. Two `usize` constants are a
/// small, inert duplication; if `virtio_mmio.rs`'s layout ever changes,
/// this will silently name the *wrong* slot until someone notices, which
/// is an acceptable risk for a value with no caller yet -- revisit if/when
/// a real EL0 driver actually starts issuing these tokens.
///
/// `allow(dead_code)`: only [`virtio_mmio_slot_resource`] reads these, and
/// it has no caller yet either.
#[allow(dead_code)]
const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;
#[allow(dead_code)]
const VIRTIO_MMIO_SLOT_STRIDE: usize = 0x200;

/// Convenience constructor over [`mmio_window_resource`] scoped to one
/// `virtio-mmio` device slot, rather than an arbitrary byte range --
/// mirrors how `sim_profile_resource`/`sim_delete_resource` added scoped
/// convenience on top of the more general `sim_resource`. Slot-level
/// scoping, not an arbitrary `(base, len)` pair, is the right granularity
/// for the concrete motivating case: a real EL0 virtio-net driver wants to
/// say "I'm authorized for exactly slot 31," not "I'm authorized for some
/// byte range that happens to currently equal slot 31's address" -- the
/// latter phrasing would still *work* (the bytes are identical) but reads
/// as though the range itself were the authorized thing, when the actual
/// authorization boundary administrators and auditors reason about is "one
/// virtio device slot."
///
/// `allow(dead_code)`: no caller yet, same reasoning as
/// [`mmio_window_resource`]'s.
#[allow(dead_code)]
pub fn virtio_mmio_slot_resource(slot: usize) -> String {
    mmio_window_resource(
        VIRTIO_MMIO_BASE + slot * VIRTIO_MMIO_SLOT_STRIDE,
        VIRTIO_MMIO_SLOT_STRIDE,
    )
}

/// True iff the granted window `[granted_base, granted_base + granted_len)`
/// fully covers the requested window `[requested_base, requested_base +
/// requested_len)`. This, not a plain string-equality resource match, is
/// the real future check: a loader won't ask "does this token's resource
/// string equal the exact range I'm about to map" (callers may legitimately
/// hold a token for a whole device's window while mapping a narrower slice
/// of it), it'll ask "does whatever range this token grants actually cover
/// the range I'm about to map."
///
/// Every addition here is `checked_add`: both `granted_base + granted_len`
/// and `requested_base + requested_len` can in principle overflow `usize`
/// (a maliciously or mistakenly constructed token/request could claim a
/// range right up against the address space's top), and a wrapped sum
/// would silently make an enormous or inverted range compare as "small" --
/// exactly the kind of bounds bug this crate's `panic = "abort"` docs (see
/// this module's own top-level doc comment) call a security bug, not a
/// style nit. Overflow on *either* side means "this can't be verified safe"
/// and returns `false`, not `true` -- never fail open.
///
/// `allow(dead_code)`: no caller yet, same reasoning as
/// [`mmio_window_resource`]'s.
#[allow(dead_code)]
pub fn mmio_window_contains(
    granted_base: usize,
    granted_len: usize,
    requested_base: usize,
    requested_len: usize,
) -> bool {
    let (Some(granted_end), Some(requested_end)) = (
        granted_base.checked_add(granted_len),
        requested_base.checked_add(requested_len),
    ) else {
        return false;
    };
    requested_base >= granted_base && requested_end <= granted_end
}

/// Checks whether `token` is valid (signature, expiry -- same checks
/// [`check`] runs) *and* was issued for an MMIO window that covers
/// `[requested_base, requested_base + requested_len)`. Unlike [`check`],
/// the caller doesn't supply the expected resource string up front -- it
/// can't, since it doesn't know what range the token claims until the
/// token itself is parsed. Mirrors
/// `kernel/src/capabilities.rs::check_ioport_range`'s shape exactly: verify
/// the signature against the token's *own* `resource` field first
/// (confirming the token really was signed for whatever range it claims,
/// not a forged claim), then check containment.
///
/// `allow(dead_code)`: no caller yet, same reasoning as
/// [`mmio_window_resource`]'s.
#[allow(dead_code)]
pub fn check_mmio_window(
    token: &CapabilityToken,
    requested_base: usize,
    requested_len: usize,
    now: u64,
) -> Result<(), CapabilityError> {
    token.verify(&demo_verifying_key(), &token.resource, now)?;
    match parse_mmio_window(&token.resource) {
        Some((granted_base, granted_len))
            if mmio_window_contains(granted_base, granted_len, requested_base, requested_len) =>
        {
            Ok(())
        }
        _ => Err(CapabilityError::WrongResource),
    }
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
    //
    // `cfg(test)` stands in for `svc::frequency_hz()` here: this file is
    // now also compiled as part of `runix_kernel_arm`'s *library* target,
    // under `#[cfg(test)] pub mod capabilities;` in `lib.rs` (`cfg(test)`
    // there, not unconditional like `elf`, because `svc` -- a
    // hardware-dependent module that per `lib.rs`'s own doc comment never
    // joins the lib tree -- is the one thing in this file the real
    // `aarch64-unknown-none` lib build can't see). So the new, purely
    // numeric MMIO-window helpers below can run as real host tests under
    // `cargo test --lib`, the same reason `elf.rs` got a lib target in the
    // first place, while the real target's lib build never even compiles
    // this module at all. Nothing under test calls `issue_and_hold` itself,
    // so the placeholder frequency's exact value is moot -- this split
    // exists only so the *file* compiles for `cargo test --lib`, not to
    // make this particular function meaningfully testable.
    #[cfg(not(test))]
    let ticks_per_sec = crate::svc::frequency_hz();
    #[cfg(test)]
    let ticks_per_sec: u64 = 1;
    let expires_at = now + 60 * ticks_per_sec;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmio_window_resource_round_trips_through_parse() {
        let s = mmio_window_resource(0x0a00_0000, 0x200);
        assert_eq!(s, "mmio:0xa000000:0x200");
        assert_eq!(parse_mmio_window(&s), Some((0x0a00_0000, 0x200)));
    }

    #[test]
    fn parse_mmio_window_rejects_non_mmio_strings() {
        assert_eq!(parse_mmio_window("ril:3"), None);
        assert_eq!(parse_mmio_window("mmio:0xa000000"), None); // missing len
        assert_eq!(parse_mmio_window("mmio:a000000:200"), None); // missing 0x
        assert_eq!(parse_mmio_window("mmio:0xzz:0x200"), None); // bad hex
    }

    #[test]
    fn virtio_mmio_slot_resource_matches_known_slot_addresses() {
        // Slot 0 sits exactly at VIRTIO_MMIO_BASE; slot 31 is the last of
        // the 32-slot window `virtio_mmio.rs` documents.
        assert_eq!(
            virtio_mmio_slot_resource(0),
            mmio_window_resource(0x0a00_0000, 0x200)
        );
        assert_eq!(
            virtio_mmio_slot_resource(31),
            mmio_window_resource(0x0a00_0000 + 31 * 0x200, 0x200)
        );
    }

    #[test]
    fn mmio_window_contains_exact_match() {
        assert!(mmio_window_contains(0x1000, 0x200, 0x1000, 0x200));
    }

    #[test]
    fn mmio_window_contains_proper_subset() {
        // Requested range is a narrower slice strictly inside the granted
        // one -- the "I hold a token for the whole device, mapping one
        // register" case.
        assert!(mmio_window_contains(0x1000, 0x1000, 0x1010, 0x10));
    }

    #[test]
    fn mmio_window_contains_rejects_requested_larger_than_granted() {
        assert!(!mmio_window_contains(0x1000, 0x200, 0x1000, 0x400));
    }

    #[test]
    fn mmio_window_contains_rejects_requested_starting_before_granted() {
        assert!(!mmio_window_contains(0x1000, 0x200, 0x0f00, 0x200));
    }

    #[test]
    fn mmio_window_contains_rejects_requested_extending_past_granted_end() {
        assert!(!mmio_window_contains(0x1000, 0x200, 0x1100, 0x200));
    }

    #[test]
    fn mmio_window_contains_rejects_granted_range_overflow() {
        // granted_base + granted_len overflows usize -- must not be
        // mistaken for "covers everything".
        assert!(!mmio_window_contains(usize::MAX - 1, 10, usize::MAX - 1, 1));
    }

    #[test]
    fn mmio_window_contains_rejects_requested_range_overflow() {
        assert!(!mmio_window_contains(0x1000, 0x200, usize::MAX - 1, 10));
    }

    #[test]
    fn mmio_window_contains_accepts_zero_length_requested_range_at_boundaries() {
        // A zero-length request is a degenerate edge case (nothing real
        // asks for one), but it should be decided consistently: contained
        // anywhere within the granted range, including exactly at its
        // (exclusive) end, never treated as an error.
        assert!(mmio_window_contains(0x1000, 0x200, 0x1000, 0));
        assert!(mmio_window_contains(0x1000, 0x200, 0x1200, 0));
        assert!(!mmio_window_contains(0x1000, 0x200, 0x1201, 0));
    }

    #[test]
    fn check_mmio_window_accepts_token_covering_requested_range() {
        let now = 0u64;
        let token = CapabilityToken::issue(
            "el0:arm-demo",
            virtio_mmio_slot_resource(5),
            now,
            now + 100,
            "demo-key",
            &demo_signing_key(),
        );
        assert!(check_mmio_window(
            &token,
            VIRTIO_MMIO_BASE + 5 * VIRTIO_MMIO_SLOT_STRIDE,
            VIRTIO_MMIO_SLOT_STRIDE,
            now
        )
        .is_ok());
    }

    #[test]
    fn check_mmio_window_rejects_token_for_a_different_slot() {
        let now = 0u64;
        let token = CapabilityToken::issue(
            "el0:arm-demo",
            virtio_mmio_slot_resource(5),
            now,
            now + 100,
            "demo-key",
            &demo_signing_key(),
        );
        assert!(check_mmio_window(
            &token,
            VIRTIO_MMIO_BASE + 6 * VIRTIO_MMIO_SLOT_STRIDE,
            VIRTIO_MMIO_SLOT_STRIDE,
            now
        )
        .is_err());
    }

    #[test]
    fn check_mmio_window_rejects_non_mmio_token() {
        let now = 0u64;
        let token = CapabilityToken::issue(
            "el0:arm-demo",
            ril_resource(3),
            now,
            now + 100,
            "demo-key",
            &demo_signing_key(),
        );
        assert!(check_mmio_window(&token, 0x1000, 0x200, now).is_err());
    }
}
