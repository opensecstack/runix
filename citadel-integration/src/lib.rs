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
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical-form version prefix — same convention as
/// `capability-manager::CapabilityToken`. Bump if the signed field set or
/// order ever changes.
const CANONICAL_VERSION: &str = "v1";

/// A single boot-time authorization: "this exact module, identified by
/// `module_id` and content hash `sha256_hex`, was signed off in advance."
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
    /// Which signing key produced [`Self::signature`], so a verifier knows
    /// which [`VerifyingKey`] to check against — deliberately not looked up
    /// by this crate itself, same split `capability-manager` uses for
    /// `CapabilityToken::key_id`.
    pub key_id: String,
    /// Hex-encoded 64-byte Ed25519 signature over [`Self::canonical_string`].
    pub signature: String,
}

impl ModuleManifestEntry {
    /// The exact bytes that get signed: `v1|module_id|sha256_hex`.
    fn canonical_string(&self) -> String {
        format!(
            "{CANONICAL_VERSION}|{}|{}",
            self.module_id, self.sha256_hex
        )
    }

    /// Builds and signs a manifest entry for `module_id`/`sha256_hex` with
    /// `signing_key`. Not meant to run inside the kernel — this is the
    /// release-time signing step, exposed here mainly so tests (and a
    /// future release-tooling binary) don't have to reimplement the
    /// canonical-string format by hand.
    pub fn issue(
        module_id: impl Into<String>,
        sha256_hex: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let mut entry = ModuleManifestEntry {
            module_id: module_id.into(),
            sha256_hex: sha256_hex.into(),
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
    pub fn authorize_module_load(
        &self,
        verifying_key: &VerifyingKey,
        module_id: &str,
        module_bytes: &[u8],
    ) -> Result<(), CitadelError> {
        let entry = self
            .find(module_id)
            .ok_or(CitadelError::NotAllowlisted)?;
        let computed = hex::encode(Sha256::digest(module_bytes));
        entry.verify(verifying_key, module_id, &computed)
    }
}

#[derive(Debug)]
pub enum CitadelError {
    /// No manifest entry exists for the requested module at all.
    NotAllowlisted,
    /// A manifest entry exists but names a different module than the one
    /// being checked.
    WrongModule,
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
            CitadelError::HashMismatch => {
                write!(f, "module bytes do not match the allowlisted hash")
            }
            CitadelError::InvalidSignature => write!(f, "manifest entry signature invalid"),
        }
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

        let entry = ModuleManifestEntry::issue("net-driver", hash, "release-2027-q1", &signing_key);
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        assert!(allowlist
            .authorize_module_load(&verifying_key, "net-driver", bytes)
            .is_ok());
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

        let entry = ModuleManifestEntry::issue("net-driver", hash, "release-2027-q1", &signing_key);
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
        let entry = ModuleManifestEntry::issue("net-driver", hash, "release-2027-q1", &attacker_key);
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
        let entry = ModuleManifestEntry::issue("net-driver", hash, "release-2027-q1", &signing_key);
        let mut allowlist = BootAllowlist::new();
        allowlist.insert(entry);

        // ...must not authorize loading the same bytes under a different id.
        let err = allowlist
            .authorize_module_load(&verifying_key, "disk-driver", bytes)
            .unwrap_err();
        assert!(matches!(err, CitadelError::NotAllowlisted));
    }
}
