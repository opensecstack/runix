//! `citadel_proxy`'s local policy check — the real, if minimal, second
//! check `docs/RFC-VERIFIER-IDENTITY.md`'s Option A calls for: run *before*
//! the proxy ever attaches its own [`super::identity::KerkeseVerifier`]
//! identity to an envelope and forwards it to CITADEL.
//!
//! # What this checks, and what it deliberately doesn't
//!
//! The RFC's own "What changes" section names the target check as "does
//! this module have a valid `InstanceManifestEntry`? is the requested tier
//! consistent with the module's signed tier?" — a re-verification of
//! `runix_citadel_integration::InstanceAllowlist`'s decision. That data is
//! **not available to this process today**: `InstanceAllowlist` is
//! kernel-owned, in-kernel-memory state (see that type's own doc comment),
//! and `kernel::citadel::demo_authorize_instance` builds a throwaway,
//! self-signed, self-verified allowlist per call (see
//! `kernel/src/citadel.rs`'s own doc comment) — there is no persisted,
//! independently-checkable manifest this process could load, and extending
//! `runix_ipc::marshal::MarshalRequest` to carry that evidence (the RFC's
//! own suggested fix — a new field so the kernel can send it) is an `ipc`
//! wire-contract change explicitly out of this task's scope (see this
//! crate's own `mod.rs` doc comment history / the task that added this
//! module).
//!
//! So this is scoped down from "re-verify `InstanceAllowlist`'s decision"
//! to what's actually checkable given the kernel's minimal envelope: a
//! genuinely independent policy decision the proxy makes on its own,
//! looking only at what's carried by [`KernelMinimalEnvelope`] (parsed from
//! the kernel's `kerkese_json`, see [`super::proxy`]) — not a no-op, and not
//! a relabeled version of the same check the kernel's own
//! `InstanceAllowlist` already ran:
//!
//! 1. **Action-type recognition.** The proxy only vouches for action types
//!    it explicitly recognizes ([`RECOGNIZED_ACTION_TYPES`]) — matching
//!    CITADEL's own `rbacMap` entries for `grid_sandbox.spawn_instance`
//!    (`citadel/internal/marshal/types.go`), so this rejects a request for
//!    an action type CITADEL wouldn't even authorize an "operator" role for
//!    regardless of SoD. An unrecognized action type is refused before any
//!    envelope is built.
//! 2. **Identifier well-formedness.** `module_id`/`instance_id` must be
//!    non-empty and composed only of ASCII alphanumerics, `-`, `_`, `.`,
//!    `:` — bounded length, no control characters, nothing that could
//!    corrupt the enriched envelope's `evidence.extra` values or hint at
//!    injection. Deliberately conservative rather than permissive.
//! 3. **`dry_run` must be present and explicit**, not defaulted — the
//!    RFC's own suggested floor ("even 'the action type is one this proxy
//!    recognizes and the dry_run flag is honestly set' is more real than a
//!    no-op"). [`super::proxy`]'s JSON parse already requires the field to
//!    exist (`serde` with no `#[serde(default)]` on that field) — this
//!    check exists so that requirement has a named policy reason attached
//!    to its failure, not just a generic parse error.
//! 4. **The kernel must not itself assert a `verifier`.** If the incoming
//!    envelope already carries a `verifier` field at all, that's either a
//!    regression back to the exact defect this RFC fixes, or a forged/
//!    confused request — either way, this proxy is the only thing that may
//!    attach a Verifier identity, and it refuses to double-vouch for one
//!    that's already there rather than silently overwriting it.
//!
//! Honest framing: this is real (it can and does refuse real, malformed, or
//! unrecognized requests — see this module's tests), but it is **not** a
//! substitute for re-verifying `InstanceManifestEntry`'s signature. If this
//! policy logic ever grows to duplicate that signature check instead of
//! adding a genuinely independent one, the RFC's own recommendation section
//! says that's the signal to fall back to its Option C, not to keep adding
//! logic here.

use serde::Deserialize;

/// Action types this proxy is willing to vouch for as Verifier — kept in
/// sync with `citadel/internal/marshal/types.go`'s `rbacMap`'s
/// `grid_sandbox.spawn_instance` entries (both the `"admin"` and
/// `"operator"` role lists carry it today). A request for anything else is
/// refused before an envelope is even built, regardless of how well-formed
/// it otherwise is.
pub const RECOGNIZED_ACTION_TYPES: &[&str] = &["grid_sandbox.spawn_instance"];

/// The `sinauth`-shaped subject identifier the kernel asserts as Actor —
/// see `super::identity::PROXY_VERIFIER_USER_ID`'s doc comment for why this
/// and that constant must always differ (the entire point of this RFC).
/// Not itself checked against the incoming envelope's `actor.user_id`
/// (`grid_sandbox.rs`'s own construction is the one source of truth for
/// what the kernel actually asserts, and this proxy has no independent way
/// to authenticate that claim today — see this module's doc comment on
/// scope) — kept here only so the constant lives next to the policy that
/// depends on it never colliding with [`super::identity::PROXY_VERIFIER_USER_ID`].
pub const KERNEL_ACTOR_USER_ID_PREFIX: &str = "kernel:";

/// The role `grid_sandbox.rs`'s minimal envelope asserts for its actor —
/// see [`super::identity::PROXY_VERIFIER_ROLE`]'s doc comment for why the
/// proxy's own role must land in a different `roleGroupMap` group.
pub const KERNEL_ACTOR_ROLE: &str = "operator";

/// The minimal envelope `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate`
/// sends — deliberately narrow (only what that `format!` string actually
/// carries today), not the full `Kerkese` shape. See [`super::identity::Kerkese`]
/// for the real, full envelope this proxy builds *from* one of these after
/// this module's check passes.
#[derive(Debug, Clone, Deserialize)]
pub struct KernelMinimalEnvelope {
    #[serde(default)]
    pub kerkese_version: String,
    pub dry_run: bool,
    pub action: KernelMinimalAction,
    pub actor: KernelMinimalActor,
    #[serde(default)]
    pub execution_id: String,
    /// Present only if the kernel (incorrectly, per this RFC) asserted a
    /// Verifier identity of its own — see this module's point 4. Using
    /// `serde_json::Value` rather than a typed field: this proxy doesn't
    /// need to interpret *what* was asserted, only that asserting anything
    /// here at all is itself the policy violation.
    #[serde(default)]
    pub verifier: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KernelMinimalAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub module_id: String,
    #[serde(default)]
    pub instance_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KernelMinimalActor {
    pub user_id: String,
    pub role: String,
}

/// Why [`check`] refused to vouch for a request — every variant is a real,
/// specific policy reason, never a generic catch-all, so a denial is
/// diagnosable from the response alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnrecognizedActionType(String),
    EmptyIdentifier(&'static str),
    MalformedIdentifier(&'static str, String),
    KernelAssertedVerifier,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnrecognizedActionType(t) => {
                write!(f, "POLICY_REFUSE: action type {t:?} is not one this proxy recognizes")
            }
            PolicyError::EmptyIdentifier(field) => {
                write!(f, "POLICY_REFUSE: {field} is empty")
            }
            PolicyError::MalformedIdentifier(field, value) => {
                write!(f, "POLICY_REFUSE: {field} {value:?} contains characters outside [A-Za-z0-9._:-]")
            }
            PolicyError::KernelAssertedVerifier => write!(
                f,
                "POLICY_REFUSE: request already carries a verifier field — only this proxy may attach one"
            ),
        }
    }
}

fn is_well_formed_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Runs this proxy's local policy check against `envelope`. `Ok(())` means
/// this proxy is willing to attach its own Verifier identity and forward
/// the resulting envelope; `Err` means it refuses, and [`super::proxy`]
/// must never forward the request to CITADEL in that case — see this
/// module's doc comment for exactly what is and isn't checked.
pub fn check(envelope: &KernelMinimalEnvelope) -> Result<(), PolicyError> {
    if envelope.verifier.is_some() {
        return Err(PolicyError::KernelAssertedVerifier);
    }

    if !RECOGNIZED_ACTION_TYPES.contains(&envelope.action.action_type.as_str()) {
        return Err(PolicyError::UnrecognizedActionType(
            envelope.action.action_type.clone(),
        ));
    }

    if envelope.action.module_id.is_empty() {
        return Err(PolicyError::EmptyIdentifier("module_id"));
    }
    if !is_well_formed_identifier(&envelope.action.module_id) {
        return Err(PolicyError::MalformedIdentifier(
            "module_id",
            envelope.action.module_id.clone(),
        ));
    }

    if envelope.action.instance_id.is_empty() {
        return Err(PolicyError::EmptyIdentifier("instance_id"));
    }
    if !is_well_formed_identifier(&envelope.action.instance_id) {
        return Err(PolicyError::MalformedIdentifier(
            "instance_id",
            envelope.action.instance_id.clone(),
        ));
    }

    if envelope.actor.user_id.is_empty() {
        return Err(PolicyError::EmptyIdentifier("actor.user_id"));
    }
    if !is_well_formed_identifier(&envelope.actor.user_id) {
        return Err(PolicyError::MalformedIdentifier(
            "actor.user_id",
            envelope.actor.user_id.clone(),
        ));
    }

    // dry_run itself needs no further check beyond "the field deserialized
    // at all" — `KernelMinimalEnvelope::dry_run` has no `#[serde(default)]`,
    // so a request missing it entirely already failed to parse before
    // `check` is ever called (see `super::proxy::parse_kernel_envelope`).
    // This comment exists so that contract stays documented next to the
    // policy statement that depends on it, per this module's own doc
    // comment (point 3).

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_envelope() -> KernelMinimalEnvelope {
        KernelMinimalEnvelope {
            kerkese_version: "1.0".into(),
            dry_run: true,
            action: KernelMinimalAction {
                action_type: "grid_sandbox.spawn_instance".into(),
                module_id: "grid-sandbox-host".into(),
                instance_id: "app-1".into(),
            },
            actor: KernelMinimalActor {
                user_id: "kernel:grid_sandbox".into(),
                role: KERNEL_ACTOR_ROLE.into(),
            },
            execution_id: "app-1".into(),
            verifier: None,
        }
    }

    #[test]
    fn accepts_well_formed_recognized_request() {
        assert!(check(&valid_envelope()).is_ok());
    }

    #[test]
    fn rejects_unrecognized_action_type() {
        let mut e = valid_envelope();
        e.action.action_type = "wasm_runtime.hot_reload".into();
        assert_eq!(
            check(&e),
            Err(PolicyError::UnrecognizedActionType(
                "wasm_runtime.hot_reload".into()
            ))
        );
    }

    #[test]
    fn rejects_empty_module_id() {
        let mut e = valid_envelope();
        e.action.module_id = String::new();
        assert_eq!(check(&e), Err(PolicyError::EmptyIdentifier("module_id")));
    }

    #[test]
    fn rejects_malformed_instance_id() {
        let mut e = valid_envelope();
        e.action.instance_id = "app-1; DROP TABLE worm".into();
        match check(&e) {
            Err(PolicyError::MalformedIdentifier("instance_id", _)) => {}
            other => panic!("expected MalformedIdentifier, got {other:?}"),
        }
    }

    #[test]
    fn rejects_request_that_already_asserts_a_verifier() {
        let mut e = valid_envelope();
        e.verifier = Some(serde_json::json!({"user_id": "kernel", "role": "operator"}));
        assert_eq!(check(&e), Err(PolicyError::KernelAssertedVerifier));
    }

    #[test]
    fn parses_the_real_minimal_envelope_shape_grid_sandbox_sends() {
        // Mirrors exactly what `kernel/src/grid_sandbox.rs`'s
        // `shadow_marshal_evaluate` now builds (post-RFC: `actor` is an
        // object, no `verifier` key at all) — proves this module's
        // `Deserialize` impl actually accepts that shape, not just a
        // hand-constructed Rust value.
        let json = r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"grid_sandbox.spawn_instance","module_id":"grid-sandbox-host","instance_id":"app-1"},"actor":{"user_id":"kernel:grid_sandbox","role":"operator"},"execution_id":"app-1"}"#;
        let envelope: KernelMinimalEnvelope =
            serde_json::from_str(json).expect("should parse the real grid_sandbox.rs shape");
        assert!(check(&envelope).is_ok());
        assert!(envelope.verifier.is_none());
    }
}
