//! Boot-time proof that `runix_mobile::selection::select_network` is driven
//! by the *live* account registry (Beta item 3.3), in the same role
//! `load_proof.rs` / `scheduler::prove_scheduling` play for their subsystems.
//!
//! There is no modem/RIL candidate source in `kernel-arm` yet, so the visible
//! networks and the plan's allow-list below are a small fixed list --
//! **DEMO DATA ONLY**. What is real is the part this slice wires up: the
//! `SelectionInput::standing` field comes from `mvno::standing_in`, i.e. from
//! a registry account's actual status, not a literal. The
//! proof runs entirely at EL1 with no syscall; the real selection call site
//! (an attach path that consults the decision before bringing up the radio)
//! arrives with the modem work.
//!
//! This is a **self-contained proof of the pure logic** (the registry's
//! status machine feeding `select_network`), run on its *own local*
//! `AccountRegistry` with its own demo account -- not on the live global
//! registry in `mvno.rs`. It therefore needs no WORM audit and cannot
//! disturb live state (the global account 0 is never touched, and the WORM
//! entry counts printed later are unaffected). The live registry path is
//! proven by the EL0 walk (`el0.rs`: suspend/reactivate/bind via syscalls),
//! not here. The local account is "account 0" of the local registry.

use alloc::vec;

use runix_mobile::account::{AccountRegistry, PlanId, ProfileKey, ProfileLifecycle, SubscriberId};
use runix_mobile::selection::{
    select_network, Candidate, NetworkId, RefusalReason, Selection, SelectionInput, SelectionReason,
};

use crate::serial_println;

const HOME: NetworkId = NetworkId::new(310, 260);
const PARTNER: NetworkId = NetworkId::new(310, 410);
const ABROAD: NetworkId = NetworkId::new(262, 1);
/// Visible but not in the plan's allow-list: must never be chosen despite
/// the strongest signal.
const OTHER: NetworkId = NetworkId::new(999, 99);

fn input_for(reg: &AccountRegistry, account: u64) -> Option<SelectionInput> {
    Some(SelectionInput {
        standing: crate::mvno::standing_in(reg, account)?,
        allowed: vec![HOME, PARTNER, ABROAD],
        preferred: None,
        roaming_allowed: false,
        candidates: vec![
            Candidate {
                network: OTHER,
                signal: -40,
                is_home: false,
            },
            Candidate {
                network: ABROAD,
                signal: -50,
                is_home: false,
            },
            Candidate {
                network: HOME,
                signal: -70,
                is_home: true,
            },
        ],
    })
}

fn describe(s: &Selection) -> alloc::string::String {
    match s {
        Selection::Allowed { network, reason } => {
            alloc::format!("Allowed {}/{} ({:?})", network.mcc, network.mnc, reason)
        }
        Selection::Refused(r) => alloc::format!("Refused ({:?})", r),
    }
}

/// Runs the selection proof on a local registry (see the module doc comment);
/// never touches the global registry in `mvno.rs`.
pub fn prove_selection() {
    let mut pass = true;
    let mut reg = AccountRegistry::new();
    // Nothing is bound, so the lifecycle view is never consulted for a real
    // profile; `None` ("unknown") is the fail-closed answer regardless.
    let no_lifecycle = |_: ProfileKey| -> Option<ProfileLifecycle> { None };
    let account = match reg.open_account(SubscriberId(0xD0_0002), PlanId(1)) {
        Ok(id) => id.0,
        Err(e) => {
            serial_println!(
                "Runix ARM kernel: MVNO network selection FAILED (open local account: {:?})",
                e
            );
            serial_println!("Runix ARM kernel: MVNO network selection FAILED");
            return;
        }
    };

    let active = input_for(&reg, account).map(|i| select_network(&i));
    match &active {
        Some(s) => serial_println!(
            "Runix ARM kernel: MVNO network selection account {} Active -> {}",
            account,
            describe(s)
        ),
        None => serial_println!(
            "Runix ARM kernel: MVNO network selection FAILED (no such account {})",
            account
        ),
    }
    // Roaming is off in the demo plan, so the only eligible network is HOME
    // even though OTHER and ABROAD have stronger signal.
    pass &= active
        == Some(Selection::Allowed {
            network: HOME,
            reason: SelectionReason::HomeNetwork,
        });

    let suspended = match reg.suspend(runix_mobile::account::AccountId(account), &no_lifecycle) {
        Ok(forced) => {
            pass &= forced.is_empty();
            input_for(&reg, account).map(|i| select_network(&i))
        }
        Err(e) => {
            serial_println!(
                "Runix ARM kernel: MVNO network selection FAILED (suspend account {}: {:?})",
                account,
                e
            );
            pass = false;
            None
        }
    };
    if let Some(s) = &suspended {
        serial_println!(
            "Runix ARM kernel: MVNO network selection account {} Suspended -> {}",
            account,
            describe(s)
        );
    }
    pass &= suspended == Some(Selection::Refused(RefusalReason::AccountSuspended));

    if pass {
        serial_println!("Runix ARM kernel: MVNO network selection PASS");
    } else {
        serial_println!("Runix ARM kernel: MVNO network selection FAILED");
    }
}
