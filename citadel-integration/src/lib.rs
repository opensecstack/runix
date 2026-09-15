//! CITADEL boundary (L5 desktop / L4 mobile).
//!
//! Alpha shipped this crate as `CitadelRuntimeStub`, an empty placeholder,
//! because a live MARSHAL runtime call didn't fit boot-time gating at all —
//! see the "Why not a Kerkese/MARSHAL round-trip" section below. What's
//! implemented now is the boundary that decision led to: **boot-time module
//! authorization via a build-time-signed allowlist**, not a live governance
//! call. Real MARSHAL/WORM/VIGIL integration for *runtime* privileged
//! actions (once Runix has running user-space processes to gate) is still
//! Beta/RC work — see the module-level docs on [`ModuleManifestEntry`] and
//! [`BootAllowlist`] for what this crate covers today.
//!
//! # Why not a Kerkese/MARSHAL round-trip
//!
//! The obvious design — kernel submits a `Kerkese` to MARSHAL at boot,
//! blocks on `EXECUTE`/`REFUSE`/`HARD_STOP` — doesn't fit two ways:
//!
//! 1. **Kerkese requires Separation of Duties between two human
//!    principals** (`Actor`/`Verifier`, distinct `sig_operator`/
//!    `sig_verifier`, distinct sinauth identities — see
//!    `citadel/internal/marshal/types.go` and Gate 3/NDS). A kernel boot
//!    has no second human to verify a module load. Filling both roles with
//!    the same identity (e.g. `"kernel"`) would satisfy the schema while
//!    violating the exact invariant Gate 3 exists to enforce — root
//!    CLAUDE.md is explicit that this is a defect, not a shortcut: *"Do not
//!    add code paths that let one identity satisfy both roles."*
//! 2. **There's no network stack in `kernel/` yet** (Beta roadmap item,
//!    still in early PCI-enumeration bring-up — see the top-level README).
//!    A live HTTP round-trip to MARSHAL isn't reachable from boot-time
//!    kernel code today regardless of the SoD question above.
//!
//! Boot-time module authorization doesn't need a *live decision* the way a
//! human-approved config change does — it needs *proof this exact binary
//! was authorized in advance*. That's a signature-verification problem, not
//! a governance round-trip, so it's solved the same way
//! `capability-manager` solves capability tokens: Ed25519 over a
//! canonical, pipe-joined string, verified entirely offline. See
//! `opensecstack/opensecstack#34` for the still-open question of what a
//! *runtime* (non-boot) MARSHAL client looks like for Beta's user-space
//! processes, once there's a network stack and something ring-3 to gate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical-form version prefix — same convention as
/// `capability-manager::CapabilityToken`. Bump if the signed field set or
/// order ever changes.
const CANONICAL_VERSION: &str = "v2";

/// Grid sandbox isolation tier assigned to a module by its signed manifest
/// entry — see CLAUDE.md's "Sandbox tiers" architecture rule (T1 Critical →
/// MARSHAL real-time <300ms, T2 Trusted → MARSHAL standard, T3 Untrusted →
/// MARSHAL evidence-gated). Because this is part of [`ModuleManifestEntry`]'s
/// signed canonical string, a validly-signed entry authenticates its tier
/// the same way it authenticates `module_id`/`sha256_hex` — no separate
/// tier check is needed anywhere signature verification already happens.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxTier {
    T1Critical,
    T2Trusted,
    T3Untrusted,
}

impl SandboxTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxTier::T1Critical => "t1",
            SandboxTier::T2Trusted => "t2",
            SandboxTier::T3Untrusted => "t3",
        }
    }
}

/// A single boot-time authorization: "this exact module, identified by
/// `module_id` and content hash `sha256_hex`, was signed off in advance,
/// with sandbox isolation tier `tier`."
///
/// Produced offline (at build/release time, by whatever holds the trust
/// root's `SigningKey` — CITADEL's release process, not the kernel), then
/// embedded alongside the module it authorizes. The kernel only ever
/// *verifies* these; it never signs one itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifestEntry {
    pub module_id: String,
    /// Lowercase hex-encoded SHA-256 of the module's exact bytes.
    pub sha256_hex: String,
    /// The sandbox isolation tier this module is authorized to run at.
    pub tier: SandboxTier,
    /// Which signing key produced [`Self::signature`], so a verifier knows
    /// which [`VerifyingKey`] to check against — deliberately not looked up
    /// by this crate itself, same split `capability-manager` uses for
    /// `CapabilityToken::key_id`.
    pub key_id: String,
    /// Hex-encoded 64-byte Ed25519 signature over [`Self::canonical_string`].
    pub signature: String,
}

impl ModuleManifestEntry {
    /// The exact bytes that get signed: `v2|module_id|sha256_hex|tier`.
    fn canonical_string(&self) -> String {
        format!(
            "{CANONICAL_VERSION}|{}|{}|{}",
            self.module_id,
            self.sha256_hex,
            self.tier.as_str()
        )
    }

    /// Builds and signs a manifest entry for `module_id`/`sha256_hex`/`tier`
    /// with `signing_key`. Not meant to run inside the kernel — this is the
    /// release-time signing step, exposed here mainly so tests (and a
    /// future release-tooling binary) don't have to reimplement the
    /// canonical-string format by hand.
    pub fn issue(
        module_id: impl Into<String>,
        sha256_hex: impl Into<String>,
        tier: SandboxTier,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let mut entry = ModuleManifestEntry {
            module_id: module_id.into(),
            sha256_hex: sha256_hex.into(),
            tier,
            key_id: key_id.into(),
            signature: String::new(),
        };
        let signature: Signature = signing_key.sign(entry.canonical_string().as_bytes());
        entry.signature = hex::encode(signature.to_bytes());
        entry
    }

    /// Verifies this entry authorizes exactly `expected_module_id` with
    /// content hash `expected_sha256_hex`, and that the signature is valid
    /// under `verifying_key`. A validly-signed entry for a *different*
    /// module or hash must not authorize this one — same reasoning as
    /// `CapabilityToken::verify`'s resource check.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_module_id: &str,
        expected_sha256_hex: &str,
    ) -> Result<(), CitadelError> {
        if self.module_id != expected_module_id {
            return Err(CitadelError::WrongModule);
        }
        if self.sha256_hex != expected_sha256_hex {
            return Err(CitadelError::HashMismatch);
        }
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CitadelError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(self.canonical_string().as_bytes(), &signature)
            .map_err(|_| CitadelError::InvalidSignature)
    }
}

/// The set of modules a boot image is allowed to load — one signed entry
/// per module, checked against the module's actual bytes before the kernel
/// maps it into any address space.
///
/// Deliberately a flat `Vec`, not a hash map: Alpha/Beta's module count is
/// small (a handful of drivers/services, not an app store), and a linear
/// scan keeps this usable from `no_std` code without pulling in a hashing
/// dependency beyond what's already here for the entries' own content
/// hashes. Revisit if the module count ever makes that matter.
#[derive(Debug, Default)]
pub struct BootAllowlist {
    entries: Vec<ModuleManifestEntry>,
    /// `RefCell`, not a plain field, deliberately: `authorize_module_load`
    /// keeps its existing `&self` signature (kernel/'s own boot sequence
    /// already calls it that way, in `kernel/src/citadel.rs`, and this
    /// crate has no way to update that call site as part of this change)
    /// while still recording evidence as a side effect of every decision.
    /// Single-threaded by construction (boot-time module authorization,
    /// same as everything else in this crate) — no atomics needed.
    evidence: RefCell<WormLog>,
}

impl BootAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: ModuleManifestEntry) {
        self.entries.push(entry);
    }

    fn find(&self, module_id: &str) -> Option<&ModuleManifestEntry> {
        self.entries.iter().find(|e| e.module_id == module_id)
    }

    /// This allowlist's local evidence log — every call to
    /// `authorize_module_load` appends exactly one entry here, allow or
    /// deny, before returning. See [`WormLog`]/[`WormEntry`] for what
    /// "local evidence" does and doesn't claim.
    pub fn evidence_log(&self) -> Ref<'_, WormLog> {
        self.evidence.borrow()
    }

    /// The boot-time gate: computes SHA-256 of `module_bytes`, looks up
    /// `module_id` in the allowlist, and verifies the resulting hash and
    /// signature both check out under `verifying_key`.
    ///
    /// Returns [`CitadelError::NotAllowlisted`] if no entry exists for
    /// `module_id` at all — distinct from [`CitadelError::HashMismatch`]
    /// (an entry exists but the bytes don't match it) so a caller can tell
    /// "unknown module" apart from "known module, tampered bytes" if that
    /// distinction ever matters for diagnostics. Both are refused either
    /// way — this crate does not have a `FailMode`/fail-open setting akin
    /// to `sdk/go/citadel`'s: a boot-time authorization check has no safe
    /// "open" mode (see the top-level README's boundary design decisions).
    ///
    /// Every call — allow or deny — also appends one entry to this
    /// allowlist's [`WormLog`] (`evidence_log`), recording the module,
    /// outcome, and (on success) the tier granted. This is local evidence
    /// collection, not a live MARSHAL Gate decision — see the module doc
    /// comment and `WormEntry`'s own doc comment for exactly what that
    /// does and doesn't mean.
    pub fn authorize_module_load(
        &self,
        verifying_key: &VerifyingKey,
        module_id: &str,
        module_bytes: &[u8],
    ) -> Result<SandboxTier, CitadelError> {
        let result = self.evaluate_module_load(verifying_key, module_id, module_bytes);
        match &result {
            Ok(tier) => {
                self.evidence
                    .borrow_mut()
                    .record(module_id, None, Some(*tier), true, None);
            }
            Err(err) => {
                self.evidence.borrow_mut().record(
                    module_id,
                    None,
                    None,
                    false,
                    Some(format!("{err}")),
                );
            }
        }
        result
    }

    fn evaluate_module_load(
        &self,
        verifying_key: &VerifyingKey,
        module_id: &str,
        module_bytes: &[u8],
    ) -> Result<SandboxTier, CitadelError> {
        let entry = self.find(module_id).ok_or(CitadelError::NotAllowlisted)?;
        let computed = hex::encode(Sha256::digest(module_bytes));
        entry.verify(verifying_key, module_id, &computed)?;
        Ok(entry.tier)
    }
}

#[derive(Debug)]
pub enum CitadelError {
    /// No manifest entry exists for the requested module at all.
    NotAllowlisted,
    /// A manifest entry exists but names a different module than the one
    /// being checked.
    WrongModule,
    /// An [`InstanceManifestEntry`] exists for this module, but names a
    /// different instance than the one being checked — the per-instance
    /// analogue of [`Self::WrongModule`], see [`InstanceAllowlist`].
    WrongInstance,
    /// A manifest entry exists for this module, but its declared hash
    /// doesn't match the actual bytes being loaded.
    HashMismatch,
    /// The entry's signature doesn't verify under the given key.
    InvalidSignature,
}

impl fmt::Display for CitadelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CitadelError::NotAllowlisted => write!(f, "module is not in the boot allowlist"),
            CitadelError::WrongModule => {
                write!(f, "manifest entry does not authorize this module")
            }
            CitadelError::WrongInstance => {
                write!(f, "manifest entry does not authorize this instance")
            }
            CitadelError::HashMismatch => {
                write!(f, "module bytes do not match the allowlisted hash")
            }
            CitadelError::InvalidSignature => write!(f, "manifest entry signature invalid"),
        }
    }
}

/// A single entry in a [`WormLog`] — "what happened, when (relative to this
/// boot), under which tier." Deliberately narrower than a real WORM (Write-
/// Once-Read-Many) audit chain: there is no live MARSHAL Gate to send this
/// to (still blocked on `opensecstack/sdk/rust`, see the module doc comment
/// — not attempted here), no signing key backs it, and there is no RTC to
/// stamp a real timestamp with (same gap `capability-manager`'s token
/// expiry already lives with) — `seq` is a monotonic, per-log sequence
/// number, not wall-clock time, honest about what's actually available
/// this early in boot. What this *does* give: a local, append-only,
/// hash-chained record of every authorization decision this crate makes,
/// so an eventual live Gate integration has real evidence to submit
/// instead of nothing, and a local operator/test has something to inspect
/// today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WormEntry {
    /// Monotonic position in the log — the first recorded entry is `0`.
    pub seq: u64,
    pub module_id: String,
    /// `Some` for an [`InstanceAllowlist`] decision, `None` for a
    /// module-wide [`BootAllowlist`] decision — the two allowlists keep
    /// separate logs (see each type's `evidence_log`), so this is never
    /// ambiguous within one log.
    pub instance_id: Option<String>,
    /// The tier a successful authorization granted. `None` for a denial —
    /// there is nothing to grant.
    pub tier: Option<SandboxTier>,
    pub authorized: bool,
    /// `Display` of the [`CitadelError`] that caused a denial. `None` when
    /// `authorized` is `true`.
    pub reason: Option<String>,
    /// The previous entry's `entry_hash` (all-zero for the first entry) —
    /// this is what makes the log a *chain*: recomputing `entry_hash` for
    /// every entry and checking it against both its own recorded value and
    /// the next entry's `prev_hash` (see [`WormLog::verify_chain`]) detects
    /// any entry that was edited, reordered, or deleted after the fact.
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl WormEntry {
    fn compute_hash(
        prev_hash: &[u8; 32],
        seq: u64,
        module_id: &str,
        instance_id: Option<&str>,
        tier: Option<SandboxTier>,
        authorized: bool,
        reason: Option<&str>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(seq.to_le_bytes());
        hasher.update(module_id.as_bytes());
        hasher.update([instance_id.is_some() as u8]);
        if let Some(id) = instance_id {
            hasher.update(id.as_bytes());
        }
        hasher.update([tier.is_some() as u8]);
        if let Some(t) = tier {
            hasher.update(t.as_str().as_bytes());
        }
        hasher.update([authorized as u8]);
        if let Some(r) = reason {
            hasher.update(r.as_bytes());
        }
        hasher.finalize().into()
    }
}

/// Local evidence log — see [`WormEntry`] for exactly what "local" means
/// here and what it deliberately doesn't claim. Owned internally by
/// [`BootAllowlist`] and [`InstanceAllowlist`] (one log per allowlist, via
/// `evidence_log`) rather than a type either crate consumer constructs
/// directly — recording only ever happens as a side effect of an actual
/// authorization decision, never as a separate call a caller could forget
/// or fake independently of the real gate.
#[derive(Debug, Default)]
pub struct WormLog {
    entries: Vec<WormEntry>,
}

impl WormLog {
    fn record(
        &mut self,
        module_id: &str,
        instance_id: Option<&str>,
        tier: Option<SandboxTier>,
        authorized: bool,
        reason: Option<String>,
    ) {
        let seq = self.entries.len() as u64;
        let prev_hash = self.entries.last().map(|e| e.entry_hash).unwrap_or([0u8; 32]);
        let entry_hash = WormEntry::compute_hash(
            &prev_hash,
            seq,
            module_id,
            instance_id,
            tier,
            authorized,
            reason.as_deref(),
        );
        self.entries.push(WormEntry {
            seq,
            module_id: module_id.into(),
            instance_id: instance_id.map(String::from),
            tier,
            authorized,
            reason,
            prev_hash,
            entry_hash,
        });
    }

    /// Every entry recorded so far, oldest first.
    pub fn entries(&self) -> &[WormEntry] {
        &self.entries
    }

    /// Recomputes every entry's hash from its own recorded fields and
    /// confirms it matches both the entry's own stored `entry_hash` and the
    /// next entry's `prev_hash` — the tamper-evidence property this log
    /// exists for. Returns `false` the moment any entry was edited,
    /// reordered, or spliced out after being recorded; `true` (including
    /// for an empty log) otherwise. Not itself a defense against a caller
    /// who can run arbitrary code in this process and just discard the log
    /// entirely — that needs a real signing/WORM-boot-chain root, same
    /// "tamper-evident, not tamper-proof, until that lands" honesty as this
    /// module's own doc comment.
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = [0u8; 32];
        for entry in &self.entries {
            if entry.prev_hash != prev_hash {
                return false;
            }
            let recomputed = WormEntry::compute_hash(
                &entry.prev_hash,
                entry.seq,
                &entry.module_id,
                entry.instance_id.as_deref(),
                entry.tier,
                entry.authorized,
                entry.reason.as_deref(),
            );
            if recomputed != entry.entry_hash {
                return false;
            }
            prev_hash = entry.entry_hash;
        }
        true
    }
}

/// Canonical-form version prefix for [`InstanceManifestEntry`] — kept
/// distinct from [`CANONICAL_VERSION`] (`ModuleManifestEntry`'s own) even
/// though some field values could coincide, so a validly-signed entry of
/// one kind can never be replayed as the other.
const INSTANCE_CANONICAL_VERSION: &str = "vi1";

/// A single boot-time authorization scoped to one *instance* of a module,
/// not just the module itself — the primitive multi-tenant Grid Sandbox
/// spawning needs.
///
/// [`BootAllowlist`]/[`ModuleManifestEntry`] authorize a module *binary*:
/// one signed entry per `module_id`, so at most one concurrently-running
/// authorization exists for a given binary. That was correct while exactly
/// one `grid-sandbox-host` instance ever ran (see `docs/STATUS.md`'s
/// "Grid sandbox isolation tiers" section) but stops being enough the
/// moment more than one instance of the *same* binary needs to run at
/// once — e.g. one `grid-sandbox-host` process per app. Reusing one
/// module-wide grant across every instance would be ambient authority
/// (CLAUDE.md: "never reach for a resource with ambient authority"): any
/// instance could claim any tier the module was ever authorized for,
/// instead of the specific tier *that instance* was actually issued.
///
/// `InstanceManifestEntry` closes that gap the same way `ModuleManifestEntry`
/// closes it for a module: `instance_id` is part of the signed canonical
/// string, so a validly-signed entry authenticates exactly one instance of
/// exactly one module at exactly one tier — a caller (in practice, the
/// kernel-side spawn loop that assigns each spawned process its own
/// `instance_id`) verifies each instance independently before spawning it,
/// never trusting one grant to cover more than the one instance it names.
/// Actually driving `scheduler::spawn_ring3_process` in a loop, once per
/// instance, is kernel-side wiring and deliberately not part of this
/// crate — this type is the capability-scoped authorization primitive that
/// wiring would call into, not the wiring itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceManifestEntry {
    pub module_id: String,
    /// Identifies one running instance of `module_id` — e.g. an app ID or a
    /// per-spawn UUID assigned by whatever issues capability tokens for
    /// this instance. Opaque to this crate; it only needs to be unique
    /// enough that two concurrently-running instances of the same module
    /// never collide.
    pub instance_id: String,
    /// Lowercase hex-encoded SHA-256 of the module's exact bytes — every
    /// instance of the same binary shares this, since it's still the same
    /// compiled code; what's per-instance is authorization and tier, not
    /// content.
    pub sha256_hex: String,
    pub tier: SandboxTier,
    pub key_id: String,
    pub signature: String,
}

impl InstanceManifestEntry {
    /// The exact bytes that get signed:
    /// `vi1|module_id|instance_id|sha256_hex|tier`.
    fn canonical_string(&self) -> String {
        format!(
            "{INSTANCE_CANONICAL_VERSION}|{}|{}|{}|{}",
            self.module_id,
            self.instance_id,
            self.sha256_hex,
            self.tier.as_str()
        )
    }

    /// Builds and signs an instance-scoped manifest entry. Same "release-time
    /// signing step, not meant to run inside the kernel" role
    /// `ModuleManifestEntry::issue` plays for module-wide entries.
    pub fn issue(
        module_id: impl Into<String>,
        instance_id: impl Into<String>,
        sha256_hex: impl Into<String>,
        tier: SandboxTier,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let mut entry = InstanceManifestEntry {
            module_id: module_id.into(),
            instance_id: instance_id.into(),
            sha256_hex: sha256_hex.into(),
            tier,
            key_id: key_id.into(),
            signature: String::new(),
        };
        let signature: Signature = signing_key.sign(entry.canonical_string().as_bytes());
        entry.signature = hex::encode(signature.to_bytes());
        entry
    }

    /// Verifies this entry authorizes exactly `expected_module_id` +
    /// `expected_instance_id` with content hash `expected_sha256_hex`,
    /// under `verifying_key`. A validly-signed entry for a different
    /// module, a different instance of the *same* module, or mismatched
    /// content must not authorize this one — same reasoning as
    /// `ModuleManifestEntry::verify` and `CapabilityToken::verify`.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_module_id: &str,
        expected_instance_id: &str,
        expected_sha256_hex: &str,
    ) -> Result<(), CitadelError> {
        if self.module_id != expected_module_id {
            return Err(CitadelError::WrongModule);
        }
        if self.instance_id != expected_instance_id {
            return Err(CitadelError::WrongInstance);
        }
        if self.sha256_hex != expected_sha256_hex {
            return Err(CitadelError::HashMismatch);
        }
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CitadelError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(self.canonical_string().as_bytes(), &signature)
            .map_err(|_| CitadelError::InvalidSignature)
    }
}

/// The multi-tenant counterpart to [`BootAllowlist`]: one signed entry per
/// `(module_id, instance_id)` pair, so more than one concurrently-running
/// instance of the same module binary can each hold its own,
/// independently-verified tier grant — never one shared, ambient grant
/// reused across instances. See [`InstanceManifestEntry`]'s doc comment for
/// the full rationale.
///
/// Deliberately a separate type from `BootAllowlist`, not a generalization
/// of it: `BootAllowlist` still exists, unchanged, exactly as `kernel/`'s
/// existing boot-time module-load gate already depends on it (Phase B6/B7,
/// see `docs/STATUS.md`) — this type is additive, for the multi-tenant case
/// that gate doesn't yet need to handle.
#[derive(Debug, Default)]
pub struct InstanceAllowlist {
    entries: Vec<InstanceManifestEntry>,
    /// Same `RefCell` reasoning as `BootAllowlist::evidence` — recording
    /// evidence as a side effect of `authorize_instance_load` needs
    /// mutation through a `&self` call.
    evidence: RefCell<WormLog>,
}

impl InstanceAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: InstanceManifestEntry) {
        self.entries.push(entry);
    }

    fn find(&self, module_id: &str, instance_id: &str) -> Option<&InstanceManifestEntry> {
        self.entries
            .iter()
            .find(|e| e.module_id == module_id && e.instance_id == instance_id)
    }

    /// This allowlist's local evidence log — see `BootAllowlist::evidence_log`.
    pub fn evidence_log(&self) -> Ref<'_, WormLog> {
        self.evidence.borrow()
    }

    /// The multi-tenant authorization gate: computes SHA-256 of
    /// `module_bytes`, looks up the `(module_id, instance_id)` pair, and
    /// verifies the resulting hash and signature both check out under
    /// `verifying_key` — the same fail-closed contract
    /// `BootAllowlist::authorize_module_load` has, scoped to one instance.
    /// A caller spawning N instances calls this once per instance, with
    /// that instance's own `instance_id`, and gets back *that instance's*
    /// authorized tier — never a module-wide grant applied to every
    /// instance regardless of what it was actually issued.
    ///
    /// Every call — allow or deny — appends one entry to this allowlist's
    /// [`WormLog`] (`evidence_log`), same as `authorize_module_load`.
    pub fn authorize_instance_load(
        &self,
        verifying_key: &VerifyingKey,
        module_id: &str,
        instance_id: &str,
        module_bytes: &[u8],
    ) -> Result<SandboxTier, CitadelError> {
        let result =
            self.evaluate_instance_load(verifying_key, module_id, instance_id, module_bytes);
        match &result {
            Ok(tier) => {
                self.evidence.borrow_mut().record(
                    module_id,
                    Some(instance_id),
                    Some(*tier),
                    true,
                    None,
                );
            }
            Err(err) => {
                self.evidence.borrow_mut().record(
                    module_id,
                    Some(instance_id),
                    None,
                    false,
                    Some(format!("{err}")),
                );
            }
        }
        result
    }

    fn evaluate_instance_load(
        &self,
        verifying_key: &VerifyingKey,
        module_id: &str,
        instance_id: &str,
        module_bytes: &[u8],
    ) -> Result<SandboxTier, CitadelError> {
        let entry = self
            .find(module_id, instance_id)
            .ok_or(CitadelError::NotAllowlisted)?;
        let computed = hex::encode(Sha256::digest(module_bytes));
        entry.verify(verifying_key, module_id, instance_id, &computed)?;
        Ok(entry.tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn authorizes_matching_module() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"fake kernel module bytes";
        let hash = hex::encode(Sha256::digest(bytes));

        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        assert_eq!(
            allowlist
                .authorize_module_load(&verifying_key, "net-driver", bytes)
                .unwrap(),
            SandboxTier::T2Trusted
        );
    }

    #[test]
    fn rejects_unlisted_module() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let allowlist = BootAllowlist::new();

        let err = allowlist
            .authorize_module_load(&verifying_key, "net-driver", b"anything")
            .unwrap_err();
        assert!(matches!(err, CitadelError::NotAllowlisted));
    }

    #[test]
    fn rejects_tampered_bytes() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let real_bytes = b"real module bytes";
        let hash = hex::encode(Sha256::digest(real_bytes));

        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        let tampered = b"tampered module bytes!!";
        let err = allowlist
            .authorize_module_load(&verifying_key, "net-driver", tampered)
            .unwrap_err();
        assert!(matches!(err, CitadelError::HashMismatch));
    }

    #[test]
    fn rejects_wrong_signing_key() {
        let real_key = test_key();
        let attacker_key = test_key();
        let bytes = b"module bytes";
        let hash = hex::encode(Sha256::digest(bytes));

        // Entry signed by an attacker's key, not the trusted release key.
        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &attacker_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        let trusted_verifying_key = real_key.verifying_key();
        let err = allowlist
            .authorize_module_load(&trusted_verifying_key, "net-driver", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::InvalidSignature));
    }

    #[test]
    fn rejects_entry_reused_for_different_module() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"shared bytes, wrong module claim";
        let hash = hex::encode(Sha256::digest(bytes));

        // Validly signed for "net-driver"...
        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        // ...must not authorize loading the same bytes under a different id.
        let err = allowlist
            .authorize_module_load(&verifying_key, "disk-driver", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::NotAllowlisted));
    }

    #[test]
    fn rejects_tampered_tier() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"module bytes for tier tamper test";
        let hash = hex::encode(Sha256::digest(bytes));

        let mut entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        // Mutate the tier post-signing, without re-signing — the signature
        // was computed over the original (signed) tier, so this must be
        // caught the same way `rejects_tampered_bytes` catches tampered
        // module content.
        entry.tier = SandboxTier::T1Critical;
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        let err = allowlist
            .authorize_module_load(&verifying_key, "net-driver", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::InvalidSignature));
    }

    #[test]
    fn evidence_log_records_authorized_and_denied_decisions() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"module bytes for evidence test";
        let hash = hex::encode(Sha256::digest(bytes));

        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        // One authorized decision...
        allowlist
            .authorize_module_load(&verifying_key, "net-driver", bytes)
            .unwrap();
        // ...and one denied decision (unlisted module), both on the same
        // allowlist, both expected to land in the same log.
        allowlist
            .authorize_module_load(&verifying_key, "disk-driver", b"anything")
            .unwrap_err();

        let log = allowlist.evidence_log();
        let entries = log.entries();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].module_id, "net-driver");
        assert!(entries[0].authorized);
        assert_eq!(entries[0].tier, Some(SandboxTier::T2Trusted));
        assert!(entries[0].reason.is_none());

        assert_eq!(entries[1].module_id, "disk-driver");
        assert!(!entries[1].authorized);
        assert!(entries[1].tier.is_none());
        assert!(entries[1].reason.is_some());

        // Tamper-evidence: the chain verifies as recorded...
        assert!(log.verify_chain());
    }

    #[test]
    fn evidence_log_detects_tampering() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"module bytes for tamper-detection test";
        let hash = hex::encode(Sha256::digest(bytes));

        let entry = ModuleManifestEntry::issue(
            "net-driver",
            hash,
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);
        allowlist
            .authorize_module_load(&verifying_key, "net-driver", bytes)
            .unwrap();
        allowlist
            .authorize_module_load(&verifying_key, "net-driver", bytes)
            .unwrap();
        assert!(allowlist.evidence_log().verify_chain());

        // Directly mutate a recorded entry's outcome after the fact,
        // without recomputing its hash — the same "tampered field, not
        // tampered bytes" property `rejects_tampered_tier` proves for a
        // manifest entry, now proved for a recorded evidence entry.
        {
            let mut log = allowlist.evidence.borrow_mut();
            log.entries[0].authorized = false;
        }
        assert!(!allowlist.evidence_log().verify_chain());
    }

    #[test]
    fn instance_allowlist_authorizes_only_the_named_instance() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"grid-sandbox-host bytes";
        let hash = hex::encode(Sha256::digest(bytes));

        let entry = InstanceManifestEntry::issue(
            "grid-sandbox-host",
            "app-1",
            hash.clone(),
            SandboxTier::T2Trusted,
            "release-2027-q1",
            &signing_key,
        );
        let mut allowlist = InstanceAllowlist::new();
        allowlist.insert(entry);

        // The named instance is authorized...
        assert_eq!(
            allowlist
                .authorize_instance_load(&verifying_key, "grid-sandbox-host", "app-1", bytes)
                .unwrap(),
            SandboxTier::T2Trusted
        );

        // ...but a second, differently-named instance of the *same*
        // binary, with no entry of its own, is not — proving one instance's
        // grant never covers another, even though both would load the
        // identical bytes.
        let err = allowlist
            .authorize_instance_load(&verifying_key, "grid-sandbox-host", "app-2", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::NotAllowlisted));

        let log = allowlist.evidence_log();
        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.entries()[0].instance_id.as_deref(), Some("app-1"));
        assert_eq!(log.entries()[1].instance_id.as_deref(), Some("app-2"));
        assert!(log.verify_chain());
    }

    #[test]
    fn instance_allowlist_rejects_tampered_instance_id() {
        let signing_key = test_key();
        let verifying_key = signing_key.verifying_key();
        let bytes = b"grid-sandbox-host bytes for tamper test";
        let hash = hex::encode(Sha256::digest(bytes));

        let mut entry = InstanceManifestEntry::issue(
            "grid-sandbox-host",
            "app-1",
            hash,
            SandboxTier::T1Critical,
            "release-2027-q1",
            &signing_key,
        );
        // Mutate the instance_id post-signing, without re-signing — must be
        // caught the same way `rejects_tampered_tier` catches a tampered
        // tier field.
        entry.instance_id = String::from("app-2");
        let mut allowlist = InstanceAllowlist::new();
        allowlist.insert(entry);

        let err = allowlist
            .authorize_instance_load(&verifying_key, "grid-sandbox-host", "app-2", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::InvalidSignature));
    }
}
