//! `citadel_proxy`'s own Verifier identity — the second, code-distinct
//! principal Option A of `docs/RFC-VERIFIER-IDENTITY.md` calls for.
//!
//! # Why this exists
//!
//! `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate` used to build a
//! Kerkese-shaped envelope asserting `"actor":"kernel","verifier":"kernel"`
//! — the same identity playing both Kerkese SoD roles, which trips CITADEL
//! Gate 3's unconditional `NDS_SAME_IDENTITY` hard-stop
//! (`citadel/internal/marshal/marshal.go`'s `gate3NDS`) regardless of any
//! deployment configuration. Per the RFC's Option A, the kernel now only
//! ever asserts an `actor` — see the one-line change in `grid_sandbox.rs`'s
//! `shadow_marshal_evaluate`, owned by a separate, parallel task — and this
//! module is what fills the Verifier role for real: a genuinely separate
//! process (`citadel_proxy`), holding its own key material, running its own
//! policy check (`super::policy`) before it ever attaches this identity to
//! an envelope.
//!
//! # What's real here, what isn't
//!
//! **Real**: the [`PROXY_SIGNING_KEY`]/[`proxy_verifying_key`] keypair is
//! genuinely distinct from every key `kernel/` holds
//! (`kernel/src/capabilities.rs`'s capability-token trust root,
//! `kernel/src/citadel.rs`'s boot-allowlist trust root) — same demo-fixture
//! honesty those two modules already apply (see their own doc comments):
//! arbitrary fixed bytes, reproducible across runs, never claimed as a real
//! trust anchor. [`canonical_payload`] reproduces
//! `citadel/internal/marshal/sig.go`'s `CanonicalPayload` byte-for-byte (see
//! that function's own doc comment and `sig_test.go`'s shared fixture with
//! `sdk/go/citadel/sign_test.go`), and [`sign_verifier_payload`] produces a
//! real Ed25519 signature over it with this module's own key — not a
//! placeholder string.
//!
//! **Scoped down, flagged rather than faked**: nothing in this codebase
//! registers [`proxy_verifying_key`] with a live CITADEL deployment's
//! `Store::GetSigningKey`, and `EnforceSignatures` defaults to `false` on
//! CITADEL's engine (see `Engine::EnforceSignatures`'s doc comment) — so
//! `sig_verifier` is currently *evidence a real Verifier co-signed this
//! request*, not something any live deployment actually checks yet. Real
//! key provisioning against a live CITADEL instance is exactly the "own ADR
//! on key provisioning, not just envelope shape" the RFC's Option A section
//! names as follow-up work, and needs infrastructure (CITADEL-side key
//! registration, sinauth-backed Verifier bearer tokens for `VerifierToken`)
//! this task cannot reasonably stand up from inside this repo.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Arbitrary fixed bytes, distinct from `kernel/src/capabilities.rs`'s
/// `DEMO_SEED` and `kernel/src/citadel.rs`'s `DEMO_SEED` — three separate
/// demo trust roots for three conceptually separate purposes (capability
/// tokens, boot-time module authorization, and now the proxy's own Kerkese
/// Verifier identity), same "not a real secret, not derived from anything"
/// honesty each of those modules' own doc comments already state. Real key
/// provisioning (generated at first run and persisted, or issued by
/// CITADEL's own release process — see this module's doc comment) is a
/// later item.
const PROXY_DEMO_SEED: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

/// The proxy's own demo signing key — see [`PROXY_DEMO_SEED`]'s doc comment
/// for why this is a demo fixture, not a real trust anchor, and why it's
/// deliberately distinct from every key `kernel/` holds.
pub fn proxy_signing_key() -> SigningKey {
    SigningKey::from_bytes(&PROXY_DEMO_SEED)
}

pub fn proxy_verifying_key() -> VerifyingKey {
    proxy_signing_key().verifying_key()
}

/// The `sinauth`-shaped subject identifier the proxy asserts as Verifier —
/// see `citadel/internal/marshal/types.go`'s `KerkeseVerifier.UserID` doc
/// comment ("the sinauth subject (UUID string)"). Not a real sinauth
/// identity (no sinauth deployment exists here yet) — a stable, obviously
/// non-human identifier that is unconditionally distinct from any
/// `actor.user_id` the kernel could ever assert (see
/// [`super::policy::KERNEL_ACTOR_USER_ID`]).
pub const PROXY_VERIFIER_USER_ID: &str = "citadel_proxy:verifier";

/// The role the proxy asserts for itself. Deliberately **not** `"operator"`
/// (the kernel actor's role, see `super::policy::KERNEL_ACTOR_ROLE`) or any
/// other role CITADEL's `roleGroupMap` places in the `"privileged"` group —
/// `gate3NDS`'s same-*role-group* check (independent of the same-*identity*
/// check this whole RFC is about) hard-stops if operator and verifier land
/// in the same group. `"auditor"` maps to `"oversight"`
/// (`citadel/internal/marshal/types.go`'s `roleGroupMap`), which is neither
/// `"privileged"` nor the `"standard"` group the RFC's open questions
/// section flags as `analyst`/`viewer`-only — a reasonable fit for "a
/// separate process attesting to and auditing a kernel-initiated action"
/// even before CITADEL's role taxonomy grows the
/// `"automation"`/`"service"` role the RFC's open questions section
/// discusses.
pub const PROXY_VERIFIER_ROLE: &str = "auditor";

/// Mirrors `citadel/internal/marshal/types.go`'s `KerkeseActor` — see that
/// type's own doc comment. Field names match exactly (`user_id`, `role`,
/// `email` with Go's `omitempty`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerkeseActor {
    pub user_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Mirrors `citadel/internal/marshal/types.go`'s `KerkeseVerifier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerkeseVerifier {
    pub user_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl KerkeseVerifier {
    /// This proxy's own Verifier identity — see [`PROXY_VERIFIER_USER_ID`]/
    /// [`PROXY_VERIFIER_ROLE`]'s doc comments.
    pub fn this_proxy() -> Self {
        KerkeseVerifier {
            user_id: PROXY_VERIFIER_USER_ID.to_string(),
            role: PROXY_VERIFIER_ROLE.to_string(),
            email: None,
        }
    }
}

/// Mirrors `citadel/internal/marshal/types.go`'s `KerkeseSoD` — what Gate 3's
/// `NDS_SAME_IDENTITY` check actually keys on (`k.SoD.OperatorUserID ==
/// k.SoD.VerifierUserID`), not `actor`/`verifier` directly. Building this
/// with `operator_user_id == verifier_user_id` is exactly the defect this
/// whole RFC exists to fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerkeseSoD {
    pub operator_user_id: String,
    pub verifier_user_id: String,
}

/// Mirrors `citadel/internal/marshal/types.go`'s `KerkeseAction` (only the
/// fields this proxy ever populates — `IncidentID`/`RootCause`/
/// `CorrectiveAct` stay unset/omitted, same as every other Runix call site
/// today).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerkeseAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Mirrors `citadel/internal/marshal/types.go`'s `KerkeseEvidence`, using
/// only `extra` — a free-form bag for the `module_id`/`instance_id` context
/// the kernel's minimal envelope carries but the real `KerkeseAction`/
/// `Kerkese` types have no dedicated field for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KerkeseEvidence {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra: std::collections::BTreeMap<String, String>,
}

/// The full, correctly-shaped envelope this proxy forwards to CITADEL —
/// mirrors `citadel/internal/marshal/types.go`'s `Kerkese` struct (only the
/// fields this proxy populates; `emergency`/`emergency_justification`/
/// `actor_token`/`verifier_token` stay unset, matching Go's `omitempty` by
/// simply never being serialized here since this struct doesn't declare
/// them — see this module's doc comment for why token-backed identity is
/// explicitly out of scope for now).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kerkese {
    pub kerkese_version: String,
    /// RFC3339, UTC, no fractional seconds — matches Go's
    /// `time.Time.UTC().Format(time.RFC3339)`, which is exactly what
    /// [`canonical_payload`] needs to reproduce byte-for-byte (see that
    /// function's doc comment).
    pub ts_utc: String,
    pub project_id: String,
    /// A real UUID string — `citadel/internal/marshal/types.go`'s
    /// `Kerkese.ExecutionID` is a Go `uuid.UUID`, which fails to unmarshal
    /// from a non-UUID string (e.g. the kernel's own `instance_id`, which
    /// can be any opaque identifier — see `super::proxy`'s doc comment for
    /// where the real `instance_id` ends up instead: `evidence.extra`).
    pub execution_id: String,
    pub action: KerkeseAction,
    pub actor: KerkeseActor,
    pub verifier: KerkeseVerifier,
    #[serde(default, skip_serializing_if = "is_default_evidence")]
    pub evidence: KerkeseEvidence,
    pub sod: KerkeseSoD,
    #[serde(default)]
    pub dry_run: bool,
    /// Hex-encoded Ed25519 signature over [`canonical_payload`] produced by
    /// this proxy's own key — see this module's doc comment for exactly
    /// what registering that key with a live CITADEL deployment would still
    /// take.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_verifier: String,
}

fn is_default_evidence(e: &KerkeseEvidence) -> bool {
    e.extra.is_empty()
}

/// Reproduces `citadel/internal/marshal/sig.go`'s `CanonicalPayload`
/// byte-for-byte:
///
/// ```go
/// return "v1|" +
///     k.ExecutionID.String() + "|" +
///     k.Action.Type + "|" +
///     k.Action.ChangeID + "|" +
///     k.Actor.UserID + "|" +
///     k.Actor.Role + "|" +
///     k.Verifier.UserID + "|" +
///     k.Verifier.Role + "|" +
///     k.SoD.OperatorUserID + "|" +
///     k.SoD.VerifierUserID + "|" +
///     k.TsUTC.UTC().Format(time.RFC3339)
/// ```
///
/// `Action.ChangeID` is always empty here (this proxy never populates it —
/// see [`KerkeseAction`]'s doc comment), included as an empty field to keep
/// the pipe-joined shape identical to the Go implementation. A signature
/// computed over any other byte sequence — a JSON re-serialization, a
/// differently-ordered join, a different timestamp format — verifies as
/// garbage against a real CITADEL deployment; see this module's doc comment
/// for why matching this exactly, not approximately, is the whole point.
pub fn canonical_payload(k: &Kerkese) -> String {
    format!(
        "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        k.execution_id,
        k.action.action_type,
        "", // Action.ChangeID — always empty, see this function's doc comment
        k.actor.user_id,
        k.actor.role,
        k.verifier.user_id,
        k.verifier.role,
        k.sod.operator_user_id,
        k.sod.verifier_user_id,
        k.ts_utc,
    )
}

/// Signs `payload` (expected to be [`canonical_payload`]'s output) with the
/// proxy's own key and returns the hex-encoded 64-byte Ed25519 signature —
/// the same encoding `citadel/internal/marshal/sig.go`'s `VerifySignature`
/// expects (`hex.DecodeString(sigHex)`, checked against
/// `ed25519.SignatureSize`).
pub fn sign_verifier_payload(payload: &str, signing_key: &SigningKey) -> String {
    let signature: Signature = signing_key.sign(payload.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Formats a Unix timestamp (seconds since epoch, UTC) as RFC3339 with no
/// fractional seconds and a literal `Z` offset — e.g.
/// `2026-09-22T12:34:56Z` — matching Go's `time.RFC3339`
/// (`"2006-01-02T15:04:05Z07:00"`) for the UTC case, which is all
/// [`canonical_payload`] ever needs to reproduce. Implemented by hand
/// (Howard Hinnant's `civil_from_days` algorithm) rather than pulling in a
/// date/time crate for one call site — `desktop/`'s existing dependency set
/// (`reqwest`, `tokio`, `citadel-kerkese-core`) has no date/time library to
/// reuse, and this is a well-known, easily-verified algorithm rather than
/// something worth a new dependency for.
pub fn format_rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )
}

/// Howard Hinnant's `civil_from_days`: converts a day count relative to the
/// Unix epoch (1970-01-01) into a proleptic-Gregorian `(year, month, day)`
/// triple. See <http://howardhinnant.github.io/date_algorithms.html>
/// ("civil_from_days") — a standard, widely-used, dependency-free algorithm
/// for exactly this conversion, valid across the full `i64` range with no
/// leap-second handling needed (neither Go's `time.RFC3339` formatting nor
/// this call site's use case involves leap seconds).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Current wall-clock time as a Unix timestamp — thin wrapper so
/// [`super::proxy`]'s enrichment logic has one obvious place to call rather
/// than reaching into `std::time` directly, and so a test can shadow it if
/// ever needed.
pub fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_correctly() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_date_formats_correctly() {
        // 2026-04-05T10:00:00Z — same fixture date/time
        // `citadel/internal/marshal/marshal_test.go`'s `baseKerkese` uses
        // (`time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC)`), chosen so this
        // Rust-side formatter's output is directly comparable to that Go
        // fixture's expected `RFC3339` rendering.
        let unix = 1_775_383_200; // 2026-04-05T10:00:00Z
        assert_eq!(format_rfc3339_utc(unix), "2026-04-05T10:00:00Z");
    }

    #[test]
    fn signature_verifies_under_the_proxys_own_key() {
        let key = proxy_signing_key();
        let payload = "v1|exec-1|grid_sandbox.spawn_instance||kernel:grid_sandbox|operator|citadel_proxy:verifier|auditor|kernel:grid_sandbox|citadel_proxy:verifier|2026-04-05T10:00:00Z";
        let sig_hex = sign_verifier_payload(payload, &key);
        let sig_bytes = hex::decode(&sig_hex).expect("valid hex");
        let sig_array: [u8; 64] = sig_bytes.try_into().expect("64 bytes");
        let signature = Signature::from_bytes(&sig_array);
        use ed25519_dalek::Verifier as _;
        assert!(proxy_verifying_key()
            .verify(payload.as_bytes(), &signature)
            .is_ok());
    }

    #[test]
    fn canonical_payload_matches_go_shape() {
        let k = Kerkese {
            kerkese_version: "1.0".into(),
            ts_utc: "2026-04-05T10:00:00Z".into(),
            project_id: "runix".into(),
            execution_id: "00000000-0000-0000-0000-000000000001".into(),
            action: KerkeseAction {
                action_type: "grid_sandbox.spawn_instance".into(),
                description: String::new(),
            },
            actor: KerkeseActor {
                user_id: "kernel:grid_sandbox".into(),
                role: "operator".into(),
                email: None,
            },
            verifier: KerkeseVerifier::this_proxy(),
            evidence: KerkeseEvidence::default(),
            sod: KerkeseSoD {
                operator_user_id: "kernel:grid_sandbox".into(),
                verifier_user_id: PROXY_VERIFIER_USER_ID.into(),
            },
            dry_run: true,
            sig_verifier: String::new(),
        };
        let payload = canonical_payload(&k);
        assert_eq!(
            payload,
            "v1|00000000-0000-0000-0000-000000000001|grid_sandbox.spawn_instance||kernel:grid_sandbox|operator|citadel_proxy:verifier|auditor|kernel:grid_sandbox|citadel_proxy:verifier|2026-04-05T10:00:00Z"
        );
    }
}
