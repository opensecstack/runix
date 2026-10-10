//! The governed actions `kernel-arm` asks MARSHAL about, as one value, and the
//! pure builders that turn one into the Kerkese request, the execution id and
//! the serial-log label (Beta item 3.4: the three MVNO syscalls join the eSIM
//! pair behind the same gate).
//!
//! Lives in the lib target (no hardware dependency) so `cargo test --lib` can
//! pin the exact strings: the Kerkese JSON is a cross-boundary contract with
//! `desktop`'s `citadel_proxy` policy layer (it recognizes exactly these
//! `action.type` values and field names), and the log labels are grepped by CI.
//!
//! The eSIM shapes are byte-identical to what `marshal_transport` hardcoded
//! before this type existed (`esim.{op}` with `slot`/`profile`, execution id
//! `esim-{op}-{slot}-{profile}`, label `{op} slot={slot} profile={profile}`).

use alloc::format;
use alloc::string::String;
use runix_citadel_integration::ShadowMarshalOutcome;
use runix_ipc::marshal::{MarshalError, MarshalOutcome, MarshalResponse};

/// One governed action. `Esim::op` is `"enable"` or `"delete"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarshalAction<'a> {
    Esim {
        op: &'a str,
        slot: usize,
        profile: u8,
    },
    MvnoBind {
        account: u64,
        slot: usize,
        profile: u8,
    },
    MvnoSuspend {
        account: u64,
    },
    MvnoReactivate {
        account: u64,
    },
    /// Beta follow-up: the governed data usage-period reset. Consequential
    /// because it lifts a cap (restores service), so it is the one data
    /// action that is MARSHAL-gated; see `svc.rs`'s `data_reset`.
    DataResetUsage {
        account: u64,
    },
}

impl MarshalAction<'_> {
    /// The Kerkese `action.type` string.
    pub fn action_type(&self) -> String {
        match self {
            MarshalAction::Esim { op, .. } => format!("esim.{op}"),
            MarshalAction::MvnoBind { .. } => String::from("mvno.bind_profile"),
            MarshalAction::MvnoSuspend { .. } => String::from("mvno.suspend_account"),
            MarshalAction::MvnoReactivate { .. } => String::from("mvno.reactivate_account"),
            MarshalAction::DataResetUsage { .. } => String::from("data.reset_usage"),
        }
    }

    /// The Kerkese `action` JSON object (type plus the action's own fields).
    pub fn action_json(&self) -> String {
        let ty = self.action_type();
        match self {
            MarshalAction::Esim { slot, profile, .. } => {
                format!(r#"{{"type":"{ty}","slot":{slot},"profile":{profile}}}"#)
            }
            MarshalAction::MvnoBind {
                account,
                slot,
                profile,
            } => format!(
                r#"{{"type":"{ty}","account":{account},"slot":{slot},"profile":{profile}}}"#
            ),
            MarshalAction::MvnoSuspend { account }
            | MarshalAction::MvnoReactivate { account }
            | MarshalAction::DataResetUsage { account } => {
                format!(r#"{{"type":"{ty}","account":{account}}}"#)
            }
        }
    }

    /// The Kerkese `execution_id`.
    pub fn execution_id(&self) -> String {
        match self {
            MarshalAction::Esim { op, slot, profile } => format!("esim-{op}-{slot}-{profile}"),
            MarshalAction::MvnoBind {
                account,
                slot,
                profile,
            } => format!("mvno-bind-{account}-{slot}-{profile}"),
            MarshalAction::MvnoSuspend { account } => format!("mvno-suspend-{account}"),
            MarshalAction::MvnoReactivate { account } => format!("mvno-reactivate-{account}"),
            MarshalAction::DataResetUsage { account } => format!("data-reset-{account}"),
        }
    }

    /// The human label used in `MARSHAL evaluation for <label>: <Outcome>`.
    pub fn label(&self) -> String {
        match self {
            MarshalAction::Esim { op, slot, profile } => {
                format!("{op} slot={slot} profile={profile}")
            }
            MarshalAction::MvnoBind {
                account,
                slot,
                profile,
            } => format!("mvno.bind_profile account={account} slot={slot} profile={profile}"),
            MarshalAction::MvnoSuspend { account } => {
                format!("mvno.suspend_account account={account}")
            }
            MarshalAction::MvnoReactivate { account } => {
                format!("mvno.reactivate_account account={account}")
            }
            MarshalAction::DataResetUsage { account } => {
                format!("data.reset_usage account={account}")
            }
        }
    }

    /// What the kernel does when MARSHAL could not give a verdict for THIS
    /// action (`Remote(Unreachable)`): allow it ([`UnreachablePolicy::FailOpen`])
    /// or block it ([`UnreachablePolicy::FailClosed`]).
    ///
    /// One exhaustive `match`, no wildcard: a new action variant cannot compile
    /// without choosing, and flipping an action later is a one-line change in
    /// exactly one reviewable place. (Refuse/HardStop and local evaluation
    /// failures block regardless of this policy.)
    pub fn unreachable_policy(&self) -> UnreachablePolicy {
        match self {
            // FailOpen: eSIM enable/delete act on a single local profile and the
            // MVNO gate has already checked the account owns it; an outsider who
            // can only take the network down gains no new service from it
            // (Option B in docs/MARSHAL-ENFORCEMENT-POLICY.md; behaviour kept
            // exactly as before this policy existed).
            MarshalAction::Esim { .. } => UnreachablePolicy::FailOpen,
            // FailOpen: binding a profile to an account is capacity bookkeeping
            // the registry itself bounds; unchanged Option B behaviour.
            MarshalAction::MvnoBind { .. } => UnreachablePolicy::FailOpen,
            // FailOpen: suspension is the restrictive direction; refusing to
            // cut service because MARSHAL is down would help an abuser, so the
            // pre-existing Option B behaviour is kept.
            MarshalAction::MvnoSuspend { .. } => UnreachablePolicy::FailOpen,
            // FailOpen: reactivation restores a suspended account, but the
            // pre-existing behaviour is deliberately kept unchanged here; flip
            // this line if the restoring direction should also fail closed.
            MarshalAction::MvnoReactivate { .. } => UnreachablePolicy::FailOpen,
            // FailClosed: a usage reset RESTORES data service to an account
            // whose policy cut it off. An unreachable MARSHAL (which anyone
            // able to drop the network can cause) must not wave through the
            // lifting of a cap; the reset is denied and WORM-audited instead
            // (docs/adrs/0002: the strongest reset-specific weakness).
            MarshalAction::DataResetUsage { .. } => UnreachablePolicy::FailClosed,
        }
    }

    /// The full minimal-but-well-formed Kerkese envelope (`dry_run: true`).
    pub fn kerkese_json(&self, principal: &str) -> String {
        let action = self.action_json();
        let exec = self.execution_id();
        format!(
            r#"{{"kerkese_version":"1.0","dry_run":true,"action":{action},"actor":{{"user_id":"{principal}","role":"operator"}},"execution_id":"{exec}"}}"#
        )
    }
}

// ---------------------------------------------------------------------------
// The enforcement decision: remote verdict vs. local failure
// ---------------------------------------------------------------------------

/// Why the kernel could not even *run* a MARSHAL evaluation -- a failure of
/// this kernel's own evaluation machinery, as opposed to the remote MARSHAL
/// being unreachable. Every one of these **fails closed**: the consequential
/// operation is denied.
///
/// Why this is a different category from `Unreachable`: an unreachable remote
/// is something an outsider can cause only by taking the network down (the
/// documented Option B fail-open in `docs/MARSHAL-ENFORCEMENT-POLICY.md`).
/// A local resource failure (heap exhaustion from repeated evaluations, a
/// failed thread spawn, a faulting excursion) can be driven by a buggy or
/// hostile EL0 caller just by repeating governed syscalls; treating it as
/// fail-open would let that caller bypass MARSHAL entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalFailure {
    /// `net_process::setup` failed (out of memory for a page/translation
    /// table, ELF load failure, ...) or returned an inconsistent result.
    SetupFailed,
    /// The evaluation thread could not be spawned.
    SpawnFailed,
    /// The EL0 evaluation process faulted instead of finishing.
    ExcursionFaulted,
}

impl LocalFailure {
    /// Stable, greppable name used in the DENIED line and the WORM reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            LocalFailure::SetupFailed => "SetupFailed",
            LocalFailure::SpawnFailed => "SpawnFailed",
            LocalFailure::ExcursionFaulted => "ExcursionFaulted",
        }
    }
}

/// The result of one MARSHAL evaluation attempt, as seen by enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// The evaluation machinery ran; this is the remote verdict (or
    /// `Unreachable` when the remote could not be reached / answered).
    Remote(ShadowMarshalOutcome),
    /// The kernel failed to run the evaluation at all.
    LocalFailure(LocalFailure),
}

/// What to do with an action when MARSHAL gave no usable verdict
/// (`Remote(Unreachable)`). Chosen per action by
/// [`MarshalAction::unreachable_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachablePolicy {
    /// Allow it (Option B, `docs/MARSHAL-ENFORCEMENT-POLICY.md`). The success
    /// is recorded as NOT governed (see [`verdict_text`]).
    FailOpen,
    /// Block it with [`Blocked::Unreachable`] and WORM-audit the denial.
    FailClosed,
}

/// Why [`enforce`] blocked an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// A reachable MARSHAL returned `Refuse` or `HardStop`.
    Remote(ShadowMarshalOutcome),
    /// The kernel failed to run the evaluation (fail closed).
    Local(LocalFailure),
    /// MARSHAL was unreachable and this action's policy is
    /// [`UnreachablePolicy::FailClosed`]. The kernel's own policy decision,
    /// not a remote governance verdict.
    Unreachable,
}

impl core::fmt::Display for Blocked {
    /// `Remote` prints exactly `MARSHAL <Outcome>` (the pre-existing DENIED
    /// text CI greps); `Local` prints `MARSHAL local failure: <reason>`;
    /// `Unreachable` prints `MARSHAL unreachable: fail-closed for this action`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Blocked::Remote(o) => write!(f, "MARSHAL {o:?}"),
            Blocked::Local(l) => write!(f, "MARSHAL local failure: {}", l.as_str()),
            Blocked::Unreachable => write!(f, "MARSHAL unreachable: fail-closed for this action"),
        }
    }
}

/// The whole fail-open / fail-closed decision, pure. Remote: `Execute`
/// allows; `Unreachable` allows under [`UnreachablePolicy::FailOpen`] (Option
/// B: nothing to honor when the remote is down or unconfigured) and blocks
/// under `FailClosed`; `Refuse`/`HardStop` block. Every local failure blocks.
pub fn enforce(policy: UnreachablePolicy, outcome: GateOutcome) -> Result<(), Blocked> {
    match outcome {
        GateOutcome::Remote(ShadowMarshalOutcome::Execute) => Ok(()),
        GateOutcome::Remote(ShadowMarshalOutcome::Unreachable) => match policy {
            UnreachablePolicy::FailOpen => Ok(()),
            UnreachablePolicy::FailClosed => Err(Blocked::Unreachable),
        },
        GateOutcome::Remote(o @ ShadowMarshalOutcome::Refuse)
        | GateOutcome::Remote(o @ ShadowMarshalOutcome::HardStop) => Err(Blocked::Remote(o)),
        GateOutcome::LocalFailure(l) => Err(Blocked::Local(l)),
    }
}

/// The text recorded (WORM reason and serial success line) for the verdict
/// that let an action through, so an auditor can tell a governed action from
/// an ungoverned one. Total over every outcome (the blocked arms exist only so
/// the function cannot panic or lie if a caller misuses it).
pub fn verdict_text(outcome: GateOutcome) -> String {
    match outcome {
        GateOutcome::Remote(ShadowMarshalOutcome::Execute) => {
            String::from("MARSHAL verdict: Execute")
        }
        GateOutcome::Remote(ShadowMarshalOutcome::Unreachable) => {
            String::from("MARSHAL verdict: Unreachable (fail-open: not governed)")
        }
        GateOutcome::Remote(o) => format!("MARSHAL verdict: {o:?} (blocked)"),
        GateOutcome::LocalFailure(l) => {
            format!("MARSHAL verdict: local failure {} (blocked)", l.as_str())
        }
    }
}

/// A WORM reason carrying the verdict: the existing reason (if any), then the
/// verdict text, `; `-separated.
pub fn reason_with_verdict(base: Option<String>, verdict: &str) -> String {
    match base {
        Some(b) => format!("{b}; {verdict}"),
        None => String::from(verdict),
    }
}

/// Pure classification of a decoded proxy reply (`None` = no reply bytes or
/// undecodable) into the remote verdict.
///
/// - `Decision{outcome}` passes through;
/// - `Error(PolicyRefused(_))` is an explicit negative answer from the proxy's
///   own policy layer: `Refuse` (blocked by [`enforce`]);
/// - `Error(Unreachable|Timeout|BadResponse|Other)` and `None` are "no usable
///   Decision": `Unreachable` (fail-open). A refusal must never land here.
pub fn classify_response(resp: Option<&MarshalResponse>) -> ShadowMarshalOutcome {
    match resp {
        Some(MarshalResponse::Decision { outcome, .. }) => match outcome {
            MarshalOutcome::Execute => ShadowMarshalOutcome::Execute,
            MarshalOutcome::Refuse => ShadowMarshalOutcome::Refuse,
            MarshalOutcome::HardStop => ShadowMarshalOutcome::HardStop,
        },
        Some(MarshalResponse::Error(MarshalError::PolicyRefused(_))) => {
            ShadowMarshalOutcome::Refuse
        }
        Some(MarshalResponse::Error(
            MarshalError::Unreachable(_)
            | MarshalError::Timeout
            | MarshalError::BadResponse(_)
            | MarshalError::Other(_),
        ))
        | None => ShadowMarshalOutcome::Unreachable,
    }
}

/// First source port handed to a MARSHAL evaluation. `49152` itself is left
/// to the TCP proof (`tcp_proof.rs` / the driver's `TCP_LOCAL_PORT`).
pub const MARSHAL_LOCAL_PORT_BASE: u16 = 49153;
/// How many distinct ports the MARSHAL range spans before wrapping
/// (49153..=65152, safely inside the ephemeral range, never 0).
pub const MARSHAL_LOCAL_PORT_SPAN: u16 = 16000;

/// Source port for the `n`th MARSHAL evaluation of this boot. Each
/// evaluation is a fresh driver process that abandons its flow, so SLIRP
/// may still hold the previous 4-tuple; a distinct port per evaluation
/// keeps every SYN a new flow. Wraps inside a bounded range.
pub fn marshal_local_port(n: u64) -> u16 {
    MARSHAL_LOCAL_PORT_BASE + (n % MARSHAL_LOCAL_PORT_SPAN as u64) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marshal_local_ports_are_distinct_in_range_and_wrap_safely() {
        let first = marshal_local_port(0);
        assert_eq!(first, MARSHAL_LOCAL_PORT_BASE);
        assert_ne!(first, 49152);
        for n in 0..(MARSHAL_LOCAL_PORT_SPAN as u64) {
            let p = marshal_local_port(n);
            assert!(p >= MARSHAL_LOCAL_PORT_BASE && p != 0);
            assert!(
                u32::from(p)
                    < u32::from(MARSHAL_LOCAL_PORT_BASE) + u32::from(MARSHAL_LOCAL_PORT_SPAN)
            );
            if n > 0 {
                assert_ne!(p, marshal_local_port(n - 1));
            }
        }
        assert_ne!(marshal_local_port(1), marshal_local_port(2));
        assert_eq!(marshal_local_port(MARSHAL_LOCAL_PORT_SPAN as u64), first);
        // No overflow even at the extreme.
        let _ = marshal_local_port(u64::MAX);
    }

    #[test]
    fn enforce_matrix_policy_x_outcome() {
        use ShadowMarshalOutcome::*;
        use UnreachablePolicy::*;
        for policy in [FailOpen, FailClosed] {
            // Execute always allows; Refuse/HardStop always block.
            assert_eq!(enforce(policy, GateOutcome::Remote(Execute)), Ok(()));
            assert_eq!(
                enforce(policy, GateOutcome::Remote(Refuse)),
                Err(Blocked::Remote(Refuse))
            );
            assert_eq!(
                enforce(policy, GateOutcome::Remote(HardStop)),
                Err(Blocked::Remote(HardStop))
            );
            // Every local failure blocks under both policies.
            for l in [
                LocalFailure::SetupFailed,
                LocalFailure::SpawnFailed,
                LocalFailure::ExcursionFaulted,
            ] {
                assert_eq!(
                    enforce(policy, GateOutcome::LocalFailure(l)),
                    Err(Blocked::Local(l))
                );
            }
        }
        // The only cell the policy decides.
        assert_eq!(enforce(FailOpen, GateOutcome::Remote(Unreachable)), Ok(()));
        assert_eq!(
            enforce(FailClosed, GateOutcome::Remote(Unreachable)),
            Err(Blocked::Unreachable)
        );
    }

    #[test]
    fn unreachable_policy_table_is_pinned() {
        use UnreachablePolicy::*;
        let table = [
            (
                MarshalAction::Esim {
                    op: "enable",
                    slot: 0,
                    profile: 0,
                },
                FailOpen,
            ),
            (
                MarshalAction::Esim {
                    op: "delete",
                    slot: 0,
                    profile: 0,
                },
                FailOpen,
            ),
            (
                MarshalAction::MvnoBind {
                    account: 0,
                    slot: 0,
                    profile: 0,
                },
                FailOpen,
            ),
            (MarshalAction::MvnoSuspend { account: 0 }, FailOpen),
            (MarshalAction::MvnoReactivate { account: 0 }, FailOpen),
            (MarshalAction::DataResetUsage { account: 0 }, FailClosed),
        ];
        for (action, expected) in table {
            assert_eq!(action.unreachable_policy(), expected, "{}", action.label());
        }
    }

    #[test]
    fn verdict_text_is_pinned_and_marks_ungoverned_success() {
        use ShadowMarshalOutcome::*;
        assert_eq!(
            verdict_text(GateOutcome::Remote(Execute)),
            "MARSHAL verdict: Execute"
        );
        assert_eq!(
            verdict_text(GateOutcome::Remote(Unreachable)),
            "MARSHAL verdict: Unreachable (fail-open: not governed)"
        );
        assert_eq!(
            verdict_text(GateOutcome::Remote(Refuse)),
            "MARSHAL verdict: Refuse (blocked)"
        );
        assert_eq!(
            verdict_text(GateOutcome::Remote(HardStop)),
            "MARSHAL verdict: HardStop (blocked)"
        );
        assert_eq!(
            verdict_text(GateOutcome::LocalFailure(LocalFailure::SpawnFailed)),
            "MARSHAL verdict: local failure SpawnFailed (blocked)"
        );
        // The two ways to be allowed are never confusable.
        assert_ne!(
            verdict_text(GateOutcome::Remote(Execute)),
            verdict_text(GateOutcome::Remote(Unreachable))
        );
    }

    #[test]
    fn reason_with_verdict_appends_or_stands_alone() {
        assert_eq!(
            reason_with_verdict(None, "MARSHAL verdict: Execute"),
            "MARSHAL verdict: Execute"
        );
        assert_eq!(
            reason_with_verdict(Some(String::from("x")), "MARSHAL verdict: Execute"),
            "x; MARSHAL verdict: Execute"
        );
    }

    #[test]
    fn denial_text_is_stable() {
        assert_eq!(
            format!("{}", Blocked::Remote(ShadowMarshalOutcome::Refuse)),
            "MARSHAL Refuse"
        );
        assert_eq!(
            format!("{}", Blocked::Remote(ShadowMarshalOutcome::HardStop)),
            "MARSHAL HardStop"
        );
        assert_eq!(
            format!("{}", Blocked::Local(LocalFailure::SetupFailed)),
            "MARSHAL local failure: SetupFailed"
        );
        assert_eq!(
            format!("{}", Blocked::Local(LocalFailure::SpawnFailed)),
            "MARSHAL local failure: SpawnFailed"
        );
        assert_eq!(
            format!("{}", Blocked::Local(LocalFailure::ExcursionFaulted)),
            "MARSHAL local failure: ExcursionFaulted"
        );
        assert_eq!(
            format!("{}", Blocked::Unreachable),
            "MARSHAL unreachable: fail-closed for this action"
        );
    }

    #[test]
    fn classify_response_table() {
        use alloc::vec::Vec;
        use ShadowMarshalOutcome::*;
        let dec = |o| MarshalResponse::Decision {
            outcome: o,
            decision_json: Vec::new(),
        };
        let err = |e| MarshalResponse::Error(e);
        let s = || String::from("x");
        assert_eq!(
            classify_response(Some(&dec(MarshalOutcome::Execute))),
            Execute
        );
        assert_eq!(
            classify_response(Some(&dec(MarshalOutcome::Refuse))),
            Refuse
        );
        assert_eq!(
            classify_response(Some(&dec(MarshalOutcome::HardStop))),
            HardStop
        );
        assert_eq!(
            classify_response(Some(&err(MarshalError::PolicyRefused(s())))),
            Refuse
        );
        assert_eq!(
            classify_response(Some(&err(MarshalError::Unreachable(s())))),
            Unreachable
        );
        assert_eq!(
            classify_response(Some(&err(MarshalError::Timeout))),
            Unreachable
        );
        assert_eq!(
            classify_response(Some(&err(MarshalError::BadResponse(s())))),
            Unreachable
        );
        assert_eq!(
            classify_response(Some(&err(MarshalError::Other(s())))),
            Unreachable
        );
        assert_eq!(classify_response(None), Unreachable);
        // And a policy refusal is blocked end to end.
        assert!(enforce(
            UnreachablePolicy::FailOpen,
            GateOutcome::Remote(classify_response(Some(&err(MarshalError::PolicyRefused(
                s()
            )))))
        )
        .is_err());
    }

    const P: &str = "el0:arm-demo";

    #[test]
    fn esim_json_is_byte_identical_to_the_old_hardcoded_format() {
        // The exact string `marshal_transport` built before generalization.
        let (action, slot, profile) = ("enable", 0usize, 0u8);
        let old = format!(
            r#"{{"kerkese_version":"1.0","dry_run":true,"action":{{"type":"esim.{action}","slot":{slot},"profile":{profile}}},"actor":{{"user_id":"{P}","role":"operator"}},"execution_id":"esim-{action}-{slot}-{profile}"}}"#
        );
        let new = MarshalAction::Esim {
            op: "enable",
            slot: 0,
            profile: 0,
        }
        .kerkese_json(P);
        assert_eq!(new, old);
        assert_eq!(
            new,
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"esim.enable","slot":0,"profile":0},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"esim-enable-0-0"}"#
        );
    }

    #[test]
    fn esim_label_is_unchanged() {
        let a = MarshalAction::Esim {
            op: "delete",
            slot: 2,
            profile: 7,
        };
        assert_eq!(a.label(), "delete slot=2 profile=7");
        assert_eq!(a.action_type(), "esim.delete");
        assert_eq!(a.execution_id(), "esim-delete-2-7");
    }

    #[test]
    fn mvno_bind_json_and_label() {
        let a = MarshalAction::MvnoBind {
            account: 0,
            slot: 0,
            profile: 0,
        };
        assert_eq!(
            a.kerkese_json(P),
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.bind_profile","account":0,"slot":0,"profile":0},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-bind-0-0-0"}"#
        );
        assert_eq!(a.label(), "mvno.bind_profile account=0 slot=0 profile=0");
    }

    #[test]
    fn mvno_suspend_and_reactivate_json_and_label() {
        let s = MarshalAction::MvnoSuspend { account: 3 };
        assert_eq!(
            s.kerkese_json(P),
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.suspend_account","account":3},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-suspend-3"}"#
        );
        assert_eq!(s.label(), "mvno.suspend_account account=3");
        let r = MarshalAction::MvnoReactivate { account: 3 };
        assert_eq!(
            r.kerkese_json(P),
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"mvno.reactivate_account","account":3},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"mvno-reactivate-3"}"#
        );
        assert_eq!(r.label(), "mvno.reactivate_account account=3");
    }

    #[test]
    fn data_reset_usage_json_and_label() {
        let a = MarshalAction::DataResetUsage { account: 0 };
        assert_eq!(a.action_type(), "data.reset_usage");
        assert_eq!(
            a.action_json(),
            r#"{"type":"data.reset_usage","account":0}"#
        );
        assert_eq!(a.execution_id(), "data-reset-0");
        assert_eq!(a.label(), "data.reset_usage account=0");
        assert_eq!(
            a.kerkese_json(P),
            r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"data.reset_usage","account":0},"actor":{"user_id":"el0:arm-demo","role":"operator"},"execution_id":"data-reset-0"}"#
        );
        let big = MarshalAction::DataResetUsage { account: u64::MAX };
        assert_eq!(big.execution_id(), "data-reset-18446744073709551615");
    }

    #[test]
    fn large_account_ids_render_in_full() {
        let a = MarshalAction::MvnoSuspend { account: u64::MAX };
        assert_eq!(a.execution_id(), "mvno-suspend-18446744073709551615");
    }
}
