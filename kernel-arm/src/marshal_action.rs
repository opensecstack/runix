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
}

impl MarshalAction<'_> {
    /// The Kerkese `action.type` string.
    pub fn action_type(&self) -> String {
        match self {
            MarshalAction::Esim { op, .. } => format!("esim.{op}"),
            MarshalAction::MvnoBind { .. } => String::from("mvno.bind_profile"),
            MarshalAction::MvnoSuspend { .. } => String::from("mvno.suspend_account"),
            MarshalAction::MvnoReactivate { .. } => String::from("mvno.reactivate_account"),
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
            MarshalAction::MvnoSuspend { account } | MarshalAction::MvnoReactivate { account } => {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn large_account_ids_render_in_full() {
        let a = MarshalAction::MvnoSuspend { account: u64::MAX };
        assert_eq!(a.execution_id(), "mvno-suspend-18446744073709551615");
    }
}
