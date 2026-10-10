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
//!    `esim.enable`/`esim.delete`, and `mvno.bind_profile`/
//!    `mvno.suspend_account`/`mvno.reactivate_account`, and `data.reset_usage`
//!    (`citadel/internal/marshal/types.go`; `data.reset_usage` is identified
//!    by `account` alone and is the ONE data action that is MARSHAL-gated --
//!    the other data syscalls never reach this proxy, see
//!    `docs/adrs/0001-data-syscalls-not-marshal-gated.md`; eSIM actions are identified by
//!    `slot`/`profile`, MVNO actions by `account` (plus `slot`/`profile`
//!    for `mvno.bind_profile` only), instead of `module_id`/`instance_id`,
//!    and [`check`] enforces those per-family splits), so this rejects a request for
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
/// `grid_sandbox.spawn_instance`, `esim.enable`/`esim.delete` and
/// `mvno.bind_profile`/`mvno.suspend_account`/`mvno.reactivate_account` and
/// `data.reset_usage` entries (both the `"admin"` and `"operator"` role lists carry them today). A request for anything else is
/// refused before an envelope is even built, regardless of how well-formed
/// it otherwise is.
pub const RECOGNIZED_ACTION_TYPES: &[&str] = &[
    "grid_sandbox.spawn_instance",
    ESIM_ENABLE_ACTION,
    ESIM_DELETE_ACTION,
    MVNO_BIND_PROFILE_ACTION,
    MVNO_SUSPEND_ACCOUNT_ACTION,
    MVNO_REACTIVATE_ACCOUNT_ACTION,
    DATA_RESET_USAGE_ACTION,
];

/// `kernel-arm/src/marshal_transport.rs` sends these two (`esim.{action}`)
/// for `SYS_SIM_ENABLE`/`SYS_SIM_DELETE`; they are the `esim.*` entries
/// opensecstack added to `rbacMap` (admin + operator lists, `types.go`).
pub const ESIM_ENABLE_ACTION: &str = "esim.enable";
pub const ESIM_DELETE_ACTION: &str = "esim.delete";

/// `kernel-arm` sends these (`mvno.{verb}`) for the MVNO account lifecycle;
/// they are the `mvno.*` entries added to `rbacMap` (admin + operator).
pub const MVNO_BIND_PROFILE_ACTION: &str = "mvno.bind_profile";
pub const MVNO_SUSPEND_ACCOUNT_ACTION: &str = "mvno.suspend_account";
pub const MVNO_REACTIVATE_ACCOUNT_ACTION: &str = "mvno.reactivate_account";

/// `kernel-arm` sends this for the data usage-counter reset -- the one data
/// action that is MARSHAL-gated (see
/// `docs/adrs/0001-data-syscalls-not-marshal-gated.md`, "Revisit when");
/// identified by `account` alone.
pub const DATA_RESET_USAGE_ACTION: &str = "data.reset_usage";

/// Whether `action_type` is the (MARSHAL-gated) data usage reset.
pub fn is_data_action(action_type: &str) -> bool {
    action_type == DATA_RESET_USAGE_ACTION
}

/// Whether `action_type` is one of the MVNO actions, identified by
/// `account` (and, for `mvno.bind_profile` only, `slot`/`profile`).
pub fn is_mvno_action(action_type: &str) -> bool {
    matches!(
        action_type,
        MVNO_BIND_PROFILE_ACTION | MVNO_SUSPEND_ACCOUNT_ACTION | MVNO_REACTIVATE_ACCOUNT_ACTION
    )
}

/// Whether `action_type` is one of the eSIM lifecycle actions, whose
/// identifying fields are `slot`/`profile` rather than `module_id`/
/// `instance_id`.
pub fn is_esim_action(action_type: &str) -> bool {
    matches!(action_type, ESIM_ENABLE_ACTION | ESIM_DELETE_ACTION)
}

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
    /// eSIM actions only (`esim.enable`/`esim.delete`): the SIM slot index.
    #[serde(default)]
    pub slot: Option<u64>,
    /// eSIM actions only: the profile id within `slot`.
    #[serde(default)]
    pub profile: Option<u64>,
    /// MVNO actions (`mvno.*`) and `data.reset_usage`: the account id.
    #[serde(default)]
    pub account: Option<u64>,
}

impl KernelMinimalAction {
    /// The `(module_id, instance_id)` pair this proxy attributes its WORM
    /// verification entry to. For `grid_sandbox.spawn_instance` that is the
    /// envelope's own fields; for eSIM actions, which have no module or
    /// instance, it is the fixed module `"esim"` and an instance of
    /// `slot-{slot}-profile-{profile}`; for MVNO actions it is the fixed
    /// module `"mvno"` and an instance of `account-{account}` (or
    /// `account-{account}-slot-{slot}-profile-{profile}` for
    /// `mvno.bind_profile`) (empty parts if a field is missing --
    /// [`check`] refuses that case, but the refusal itself still gets
    /// recorded, so this must not panic). `data.reset_usage` is the fixed
    /// module `"data"` and an instance of `account-{account}`.
    pub fn audit_ids(&self) -> (String, String) {
        let part = |v: Option<u64>| v.map_or_else(String::new, |n| n.to_string());
        if is_data_action(&self.action_type) {
            (
                "data".to_string(),
                format!("account-{}", part(self.account)),
            )
        } else if is_mvno_action(&self.action_type) {
            let instance = if self.action_type == MVNO_BIND_PROFILE_ACTION {
                format!(
                    "account-{}-slot-{}-profile-{}",
                    part(self.account),
                    part(self.slot),
                    part(self.profile)
                )
            } else {
                format!("account-{}", part(self.account))
            };
            ("mvno".to_string(), instance)
        } else if is_esim_action(&self.action_type) {
            (
                "esim".to_string(),
                format!("slot-{}-profile-{}", part(self.slot), part(self.profile)),
            )
        } else {
            (self.module_id.clone(), self.instance_id.clone())
        }
    }
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
    MissingField(&'static str),
    UnexpectedField(&'static str),
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
            PolicyError::MissingField(field) => {
                write!(f, "POLICY_REFUSE: {field} is required for this action type")
            }
            PolicyError::UnexpectedField(field) => {
                write!(f, "POLICY_REFUSE: {field} is not valid for this action type")
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

    if is_data_action(&envelope.action.action_type) {
        // `data.reset_usage` is identified by `account` alone.
        if envelope.action.account.is_none() {
            return Err(PolicyError::MissingField("account"));
        }
        if envelope.action.slot.is_some() {
            return Err(PolicyError::UnexpectedField("slot"));
        }
        if envelope.action.profile.is_some() {
            return Err(PolicyError::UnexpectedField("profile"));
        }
        if !envelope.action.module_id.is_empty() {
            return Err(PolicyError::UnexpectedField("module_id"));
        }
        if !envelope.action.instance_id.is_empty() {
            return Err(PolicyError::UnexpectedField("instance_id"));
        }
    } else if is_mvno_action(&envelope.action.action_type) {
        // MVNO actions are identified by `account` (plus slot/profile for
        // bind); module/instance ids have no meaning here.
        let is_bind = envelope.action.action_type == MVNO_BIND_PROFILE_ACTION;
        if envelope.action.account.is_none() {
            return Err(PolicyError::MissingField("account"));
        }
        if is_bind {
            if envelope.action.slot.is_none() {
                return Err(PolicyError::MissingField("slot"));
            }
            if envelope.action.profile.is_none() {
                return Err(PolicyError::MissingField("profile"));
            }
        } else {
            if envelope.action.slot.is_some() {
                return Err(PolicyError::UnexpectedField("slot"));
            }
            if envelope.action.profile.is_some() {
                return Err(PolicyError::UnexpectedField("profile"));
            }
        }
        if !envelope.action.module_id.is_empty() {
            return Err(PolicyError::UnexpectedField("module_id"));
        }
        if !envelope.action.instance_id.is_empty() {
            return Err(PolicyError::UnexpectedField("instance_id"));
        }
    } else if is_esim_action(&envelope.action.action_type) {
        if envelope.action.account.is_some() {
            return Err(PolicyError::UnexpectedField("account"));
        }
        // eSIM actions are identified by (slot, profile); module/instance
        // ids have no meaning here, and accepting them would let a caller
        // smuggle free-form strings into the enriched envelope's evidence.
        if envelope.action.slot.is_none() {
            return Err(PolicyError::MissingField("slot"));
        }
        if envelope.action.profile.is_none() {
            return Err(PolicyError::MissingField("profile"));
        }
        if !envelope.action.module_id.is_empty() {
            return Err(PolicyError::UnexpectedField("module_id"));
        }
        if !envelope.action.instance_id.is_empty() {
            return Err(PolicyError::UnexpectedField("instance_id"));
        }
    } else {
        if envelope.action.account.is_some() {
            return Err(PolicyError::UnexpectedField("account"));
        }
        if envelope.action.slot.is_some() {
            return Err(PolicyError::UnexpectedField("slot"));
        }
        if envelope.action.profile.is_some() {
            return Err(PolicyError::UnexpectedField("profile"));
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
                slot: None,
                profile: None,
                account: None,
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

    fn esim_envelope(action_type: &str) -> KernelMinimalEnvelope {
        let mut e = valid_envelope();
        e.action = KernelMinimalAction {
            action_type: action_type.into(),
            module_id: String::new(),
            instance_id: String::new(),
            slot: Some(0),
            profile: Some(1),
            account: None,
        };
        e.actor.user_id = "el0:arm-demo".into();
        e
    }

    #[test]
    fn accepts_well_formed_esim_requests() {
        assert!(check(&esim_envelope(ESIM_ENABLE_ACTION)).is_ok());
        assert!(check(&esim_envelope(ESIM_DELETE_ACTION)).is_ok());
    }

    #[test]
    fn rejects_esim_request_missing_slot_or_profile() {
        let mut e = esim_envelope(ESIM_ENABLE_ACTION);
        e.action.slot = None;
        assert_eq!(check(&e), Err(PolicyError::MissingField("slot")));
        let mut e = esim_envelope(ESIM_DELETE_ACTION);
        e.action.profile = None;
        assert_eq!(check(&e), Err(PolicyError::MissingField("profile")));
    }

    #[test]
    fn rejects_esim_request_carrying_module_or_instance_id() {
        let mut e = esim_envelope(ESIM_ENABLE_ACTION);
        e.action.module_id = "grid-sandbox-host".into();
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("module_id")));
        let mut e = esim_envelope(ESIM_ENABLE_ACTION);
        e.action.instance_id = "x".into();
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("instance_id")));
    }

    #[test]
    fn rejects_grid_sandbox_request_carrying_slot_or_profile() {
        let mut e = valid_envelope();
        e.action.slot = Some(0);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("slot")));
    }

    #[test]
    fn audit_ids_are_derived_per_action_type() {
        let e = esim_envelope(ESIM_ENABLE_ACTION);
        assert_eq!(
            e.action.audit_ids(),
            ("esim".to_string(), "slot-0-profile-1".to_string())
        );
        let g = valid_envelope();
        assert_eq!(
            g.action.audit_ids(),
            ("grid-sandbox-host".to_string(), "app-1".to_string())
        );
    }

    #[test]
    fn parses_the_real_esim_envelope_shape_kernel_arm_sends() {
        // Mirrors `kernel-arm/src/marshal_transport.rs`'s format string.
        let json = r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"esim.enable","slot":0,"profile":0},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"esim-enable-0-0"}"#;
        let envelope: KernelMinimalEnvelope =
            serde_json::from_str(json).expect("should parse the real kernel-arm shape");
        assert!(check(&envelope).is_ok());
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
    fn mvno_envelope(action_type: &str) -> KernelMinimalEnvelope {
        let mut e = valid_envelope();
        let bind = action_type == MVNO_BIND_PROFILE_ACTION;
        e.action = KernelMinimalAction {
            action_type: action_type.into(),
            module_id: String::new(),
            instance_id: String::new(),
            slot: bind.then_some(1),
            profile: bind.then_some(2),
            account: Some(7),
        };
        e.actor.user_id = "el0:arm-demo".into();
        e
    }

    const MVNO_ALL: [&str; 3] = [
        MVNO_BIND_PROFILE_ACTION,
        MVNO_SUSPEND_ACCOUNT_ACTION,
        MVNO_REACTIVATE_ACCOUNT_ACTION,
    ];

    #[test]
    fn accepts_well_formed_mvno_requests() {
        for t in MVNO_ALL {
            assert!(check(&mvno_envelope(t)).is_ok(), "{t}");
            assert!(RECOGNIZED_ACTION_TYPES.contains(&t));
        }
    }

    #[test]
    fn rejects_mvno_request_missing_account() {
        for t in MVNO_ALL {
            let mut e = mvno_envelope(t);
            e.action.account = None;
            assert_eq!(check(&e), Err(PolicyError::MissingField("account")), "{t}");
        }
    }

    #[test]
    fn rejects_mvno_bind_missing_slot_or_profile() {
        let mut e = mvno_envelope(MVNO_BIND_PROFILE_ACTION);
        e.action.slot = None;
        assert_eq!(check(&e), Err(PolicyError::MissingField("slot")));
        let mut e = mvno_envelope(MVNO_BIND_PROFILE_ACTION);
        e.action.profile = None;
        assert_eq!(check(&e), Err(PolicyError::MissingField("profile")));
    }

    #[test]
    fn rejects_mvno_suspend_and_reactivate_carrying_slot_or_profile() {
        for t in [MVNO_SUSPEND_ACCOUNT_ACTION, MVNO_REACTIVATE_ACCOUNT_ACTION] {
            let mut e = mvno_envelope(t);
            e.action.slot = Some(0);
            assert_eq!(check(&e), Err(PolicyError::UnexpectedField("slot")), "{t}");
            let mut e = mvno_envelope(t);
            e.action.profile = Some(0);
            assert_eq!(
                check(&e),
                Err(PolicyError::UnexpectedField("profile")),
                "{t}"
            );
        }
    }

    #[test]
    fn rejects_mvno_request_carrying_module_or_instance_id() {
        for t in MVNO_ALL {
            let mut e = mvno_envelope(t);
            e.action.module_id = "grid-sandbox-host".into();
            assert_eq!(
                check(&e),
                Err(PolicyError::UnexpectedField("module_id")),
                "{t}"
            );
            let mut e = mvno_envelope(t);
            e.action.instance_id = "x".into();
            assert_eq!(
                check(&e),
                Err(PolicyError::UnexpectedField("instance_id")),
                "{t}"
            );
        }
    }

    #[test]
    fn rejects_esim_and_grid_sandbox_requests_carrying_account() {
        for t in [ESIM_ENABLE_ACTION, ESIM_DELETE_ACTION] {
            let mut e = esim_envelope(t);
            e.action.account = Some(1);
            assert_eq!(
                check(&e),
                Err(PolicyError::UnexpectedField("account")),
                "{t}"
            );
        }
        let mut e = valid_envelope();
        e.action.account = Some(1);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("account")));
    }

    #[test]
    fn mvno_audit_ids_are_derived_and_never_panic() {
        assert_eq!(
            mvno_envelope(MVNO_SUSPEND_ACCOUNT_ACTION)
                .action
                .audit_ids(),
            ("mvno".to_string(), "account-7".to_string())
        );
        assert_eq!(
            mvno_envelope(MVNO_REACTIVATE_ACCOUNT_ACTION)
                .action
                .audit_ids(),
            ("mvno".to_string(), "account-7".to_string())
        );
        assert_eq!(
            mvno_envelope(MVNO_BIND_PROFILE_ACTION).action.audit_ids(),
            ("mvno".to_string(), "account-7-slot-1-profile-2".to_string())
        );
        let mut e = mvno_envelope(MVNO_BIND_PROFILE_ACTION);
        e.action.account = None;
        e.action.slot = None;
        e.action.profile = None;
        assert_eq!(
            e.action.audit_ids(),
            ("mvno".to_string(), "account--slot--profile-".to_string())
        );
        e.action.action_type = MVNO_SUSPEND_ACCOUNT_ACTION.into();
        assert_eq!(
            e.action.audit_ids(),
            ("mvno".to_string(), "account-".to_string())
        );
    }

    fn data_envelope() -> KernelMinimalEnvelope {
        let mut e = valid_envelope();
        e.action = KernelMinimalAction {
            action_type: DATA_RESET_USAGE_ACTION.into(),
            module_id: String::new(),
            instance_id: String::new(),
            slot: None,
            profile: None,
            account: Some(4),
        };
        e.actor.user_id = "el0:arm-demo".into();
        e
    }

    #[test]
    fn accepts_well_formed_data_reset_usage_request() {
        assert!(check(&data_envelope()).is_ok());
        assert!(RECOGNIZED_ACTION_TYPES.contains(&DATA_RESET_USAGE_ACTION));
        assert!(is_data_action(DATA_RESET_USAGE_ACTION));
        assert!(!is_data_action(MVNO_SUSPEND_ACCOUNT_ACTION));
        assert!(!is_mvno_action(DATA_RESET_USAGE_ACTION));
        assert!(!is_esim_action(DATA_RESET_USAGE_ACTION));
    }

    #[test]
    fn rejects_data_reset_usage_missing_account() {
        let mut e = data_envelope();
        e.action.account = None;
        assert_eq!(check(&e), Err(PolicyError::MissingField("account")));
    }

    #[test]
    fn rejects_data_reset_usage_with_stray_fields() {
        let mut e = data_envelope();
        e.action.slot = Some(0);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("slot")));
        let mut e = data_envelope();
        e.action.profile = Some(0);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("profile")));
        let mut e = data_envelope();
        e.action.module_id = "grid-sandbox-host".into();
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("module_id")));
        let mut e = data_envelope();
        e.action.instance_id = "x".into();
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("instance_id")));
    }

    #[test]
    fn other_families_unaffected_by_data_reset_usage() {
        let mut e = esim_envelope(ESIM_ENABLE_ACTION);
        e.action.account = Some(1);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("account")));
        let mut e = valid_envelope();
        e.action.account = Some(1);
        assert_eq!(check(&e), Err(PolicyError::UnexpectedField("account")));
        for t in MVNO_ALL {
            assert!(check(&mvno_envelope(t)).is_ok(), "{t}");
        }
        // The same account-only body under an mvno suspend type follows mvno rules.
        let mut e = data_envelope();
        e.action.action_type = MVNO_SUSPEND_ACCOUNT_ACTION.into();
        assert!(check(&e).is_ok());
    }

    #[test]
    fn data_audit_ids_are_derived_and_never_panic() {
        assert_eq!(
            data_envelope().action.audit_ids(),
            ("data".to_string(), "account-4".to_string())
        );
        let mut e = data_envelope();
        e.action.account = None;
        assert_eq!(
            e.action.audit_ids(),
            ("data".to_string(), "account-".to_string())
        );
    }

    #[test]
    fn parses_the_real_data_reset_usage_envelope_kernel_arm_sends() {
        let json = r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"data.reset_usage","account":3},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"data-reset-3"}"#;
        let envelope: KernelMinimalEnvelope =
            serde_json::from_str(json).expect("should parse the real kernel-arm shape");
        assert!(check(&envelope).is_ok());
        let bad = json.replace(r#""account":3"#, r#""account":3,"slot":0"#);
        let envelope: KernelMinimalEnvelope = serde_json::from_str(&bad).expect("parses");
        assert_eq!(check(&envelope), Err(PolicyError::UnexpectedField("slot")));
    }

    #[test]
    fn parses_the_real_mvno_envelope_shapes_kernel_arm_sends() {
        let jsons = [
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.bind_profile","account":3,"slot":0,"profile":1},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-bind-3-0-1"}"#,
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.suspend_account","account":3},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-suspend-3"}"#,
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.reactivate_account","account":3},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-reactivate-3"}"#,
        ];
        for json in jsons {
            let envelope: KernelMinimalEnvelope =
                serde_json::from_str(json).expect("should parse the real kernel-arm shape");
            assert!(check(&envelope).is_ok(), "{json}");
        }
    }
}
