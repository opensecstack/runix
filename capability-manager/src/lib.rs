//! Capability manager (L2). Every resource access requires a signed,
//! time-bounded capability token issued by this layer.
//!
//! `no_std` + `alloc`, not full `std` — this crate is meant to eventually
//! be verified from `kernel/` itself (see the "B4" integration note in the
//! top-level README), which has no `std` at all. `#[cfg(test)]` opts back
//! into `std` (same pattern the `x86_64` crate this repo already depends on
//! uses) since the test harness needs it regardless of what the library
//! itself requires.
//!
//! Signing follows CITADEL's own convention (see
//! `citadel/internal/marshal/sig.go` and `sdk/go/citadel/sign.go` in
//! opensecstack/opensecstack) rather than inventing a new one: **Ed25519**
//! over a version-tagged, pipe-joined canonical string, not a signature over
//! serialized JSON. CITADEL made that call deliberately — canonical-JSON
//! signing is a well-known cross-implementation footgun (key ordering,
//! whitespace, escaping all have to match bit-for-bit between signer and
//! verifier), and plain string concatenation has none of that ambiguity.
//! Keys and signatures are hex-encoded throughout, matching CITADEL's
//! `signing_keys` table and `Kerkese` payload — no base64/PEM/multibase.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Canonical-form version prefix. Bump this if the signed field set or
/// order ever changes, so a verifier can never be tricked into checking an
/// old-format signature against new-format field semantics (or vice versa).
const CANONICAL_VERSION: &str = "v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub subject: String,
    pub resource: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Which signing key issued this token, so a verifier knows which
    /// public key to check the signature against (mirrors CITADEL's
    /// `signing_keys` registry). Not itself part of the signed payload —
    /// key lookup and signature verification are deliberately separate
    /// steps, same split CITADEL uses.
    pub key_id: String,
    /// Hex-encoded 64-byte Ed25519 signature over [`Self::canonical_string`].
    pub signature: String,
}

impl CapabilityToken {
    /// The exact bytes that get signed: `v1|subject|resource|issued_at|expires_at`.
    fn canonical_string(&self) -> String {
        format!(
            "{CANONICAL_VERSION}|{}|{}|{}|{}",
            self.subject, self.resource, self.issued_at, self.expires_at
        )
    }

    /// Builds and signs a new token with `signing_key`, stamping `key_id`
    /// alongside so a verifier knows which public key to check it against.
    pub fn issue(
        subject: impl Into<String>,
        resource: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let mut token = CapabilityToken {
            subject: subject.into(),
            resource: resource.into(),
            issued_at,
            expires_at,
            key_id: key_id.into(),
            signature: String::new(),
        };
        let signature: Signature = signing_key.sign(token.canonical_string().as_bytes());
        token.signature = hex::encode(signature.to_bytes());
        token
    }

    /// Verifies the signature against `verifying_key`, that `now` hasn't
    /// passed `expires_at`, and that `resource` matches exactly what's on
    /// the token — a valid-and-unexpired token for a *different* resource
    /// must not authorize this one. Does *not* look up `key_id` in a
    /// registry — resolving `key_id` to the right `VerifyingKey` is the
    /// caller's job, same split as verification/lookup being separate in
    /// CITADEL.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        resource: &str,
        now: u64,
    ) -> Result<(), CapabilityError> {
        if now > self.expires_at {
            return Err(CapabilityError::Expired);
        }
        if self.resource != resource {
            return Err(CapabilityError::WrongResource);
        }
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CapabilityError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(self.canonical_string().as_bytes(), &signature)
            .map_err(|_| CapabilityError::InvalidSignature)
    }
}

/// Tracks revoked tokens by signature — each token's signature is already
/// a unique identifier for its exact signed content (subject, resource,
/// timestamps, key), so there's no need for a separate token-ID field just
/// for this. Deliberately *not* consulted by [`CapabilityToken::verify`]:
/// revocation is administrative state (who's tracking it, for how long,
/// synced from where), not cryptography, and forcing every verifier to
/// carry a list — even one that's always empty — would be the wrong
/// default for the common case. Callers that care check both:
/// `token.verify(...).is_ok() && !revocations.is_revoked(&token)`.
#[derive(Debug, Default)]
pub struct RevocationList {
    revoked_signatures: BTreeSet<String>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, token: &CapabilityToken) {
        self.revoked_signatures.insert(token.signature.clone());
    }

    pub fn is_revoked(&self, token: &CapabilityToken) -> bool {
        self.revoked_signatures.contains(&token.signature)
    }
}

#[derive(Debug)]
pub enum CapabilityError {
    Expired,
    WrongResource,
    InvalidSignature,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::Expired => write!(f, "capability token expired"),
            CapabilityError::WrongResource => {
                write!(f, "capability token is not authorized for this resource")
            }
            CapabilityError::InvalidSignature => write!(f, "capability token signature invalid"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for CapabilityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn round_trips_a_valid_token() {
        let (signing_key, verifying_key) = keypair();
        let token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        assert!(token.verify(&verifying_key, "res:disk0", 1500).is_ok());
    }

    #[test]
    fn rejects_expired_token() {
        let (signing_key, verifying_key) = keypair();
        let token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        assert!(matches!(
            token.verify(&verifying_key, "res:disk0", 2001),
            Err(CapabilityError::Expired)
        ));
    }

    #[test]
    fn rejects_tampered_field() {
        let (signing_key, verifying_key) = keypair();
        let mut token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        token.resource = "res:disk1".to_string();
        assert!(matches!(
            token.verify(&verifying_key, "res:disk1", 1500),
            Err(CapabilityError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let (signing_key, _) = keypair();
        let (_, other_verifying_key) = keypair();
        let token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        assert!(matches!(
            token.verify(&other_verifying_key, "res:disk0", 1500),
            Err(CapabilityError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_valid_token_for_wrong_resource() {
        // A token legitimately issued (and correctly signed) for one
        // resource must not authorize a *different* resource, even though
        // the signature itself checks out — this is what actually makes
        // capabilities resource-scoped rather than just "proof of identity".
        let (signing_key, verifying_key) = keypair();
        let token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        assert!(matches!(
            token.verify(&verifying_key, "res:disk1", 1500),
            Err(CapabilityError::WrongResource)
        ));
    }

    #[test]
    fn revoked_token_is_flagged_without_changing_verify() {
        let (signing_key, verifying_key) = keypair();
        let token =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);

        let mut revocations = RevocationList::new();
        assert!(!revocations.is_revoked(&token));

        revocations.revoke(&token);
        assert!(revocations.is_revoked(&token));

        // `verify()` itself never knows about revocation — by design, a
        // caller has to check both. Confirms that split actually holds,
        // not just that `is_revoked` flips a bool.
        assert!(token.verify(&verifying_key, "res:disk0", 1500).is_ok());
    }

    #[test]
    fn revoking_one_token_does_not_affect_a_different_one() {
        let (signing_key, _) = keypair();
        let token_a =
            CapabilityToken::issue("user:alice", "res:disk0", 1000, 2000, "key:1", &signing_key);
        let token_b =
            CapabilityToken::issue("user:alice", "res:disk1", 1000, 2000, "key:1", &signing_key);

        let mut revocations = RevocationList::new();
        revocations.revoke(&token_a);

        assert!(revocations.is_revoked(&token_a));
        assert!(!revocations.is_revoked(&token_b));
    }
}
