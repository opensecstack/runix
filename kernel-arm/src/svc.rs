//! `SVC` syscall dispatch -- the ARM-side analogue of
//! `kernel/src/syscall.rs::dispatch` on the x86_64 side. Reached from
//! `el1_vectors.rs`'s vector-8 `SVC` handling; see that module's doc
//! comment for how the syscall number/arg actually get here.
//!
//! Ten syscalls, matching `el0.rs`'s demo exactly (kept in sync by hand,
//! not shared constants -- see `el0.rs`'s own doc comment on why):
//! - `SYS_WRITE`: unconditional -- proves the `SVC` gate itself works,
//!   the same role `kernel/src/syscall.rs`'s `SYS_WRITE` plays for `int
//!   0x80` on the x86_64 side.
//! - `SYS_RIL_ACCESS`: capability-gated through `capabilities::check`,
//!   a bare yes/no decision -- proves the check itself distinguishes an
//!   authorized channel from one it isn't.
//! - `SYS_RIL_SEND`/`SYS_RIL_RECV`: the same capability check, but now
//!   gating real per-channel I/O (`ril_channel.rs`) instead of a bare
//!   decision -- re-checked on *every* operation, not cached from a prior
//!   "open" call, so revoking a capability mid-session (not exercised by
//!   `el0_demo` today, but the model this supports) would deny the very
//!   next `SEND`/`RECV` on that channel, not just a future "open." This
//!   is the RIL isolation boundary, not memory isolation (which `mmu.rs`'s
//!   own doc comment already says doesn't exist at this granularity yet).
//! - `SYS_SIM_CREATE`/`SYS_SIM_INSTALL`/`SYS_SIM_ENABLE`/`SYS_SIM_DISABLE`/
//!   `SYS_SIM_DELETE`/`SYS_SIM_STATUS`: the *same* capability check applied
//!   to a different resource kind (`sim:...`, not `ril:{channel}`) gating a
//!   real state machine (`sim.rs`'s eSIM profile lifecycle) instead of a
//!   byte mailbox -- proving the capability boundary is uniform across
//!   resource kinds, not something special-cased for RIL. This is Beta
//!   mobile's "eSIM lifecycle" roadmap item, succeeding Alpha's
//!   three-syscall `PROVISION`/`ACTIVATE`/`STATUS` slot-level set (see
//!   `docs/BETA_MOBILE_PROGRESS.md`'s Item 1).
//!
//! # Three things worth knowing about the SIM set specifically
//!
//! **Why it needed a third syscall argument.** `SYS_SIM_INSTALL` carries
//! `slot`, `profile_id`, *and* `identity` at once -- the first operation
//! here to need three. `el1_vectors.rs`'s gate was widened from two
//! arguments to three rather than bit-packing `slot`/`profile_id` into one
//! register; see that module's doc comment for the derivation and the
//! reasoning.
//!
//! **Why `DELETE` checks a different capability resource.** Every other SIM
//! syscall checks `capabilities::sim_profile_resource(slot, profile)`;
//! `SYS_SIM_DELETE` checks `capabilities::sim_delete_resource(slot, profile)`
//! instead -- a wholly separate resource string, so holding general profile
//! access (status, enable, disable) does *not* confer the authority to
//! irreversibly destroy the profile. `SYS_SIM_CREATE` is the one exception
//! in the other direction: it checks slot-level `sim_resource(slot)`,
//! because the profile it would scope to does not exist yet at check time.
//!
//! **Why `ENABLE` and `DELETE` route through a MARSHAL gate and the others
//! don't.** Those two are the consequential pair: enabling a profile
//! silently demotes whichever profile was the slot's active subscription
//! (see `sim.rs`'s exactly-one-`Enabled` invariant), and deleting one is
//! irreversible. Both therefore go through `esim_marshal::evaluate` +
//! `esim_marshal::enforce` before the real `sim::*` call, honoring
//! `Refuse`/`HardStop` as a denial rather than logging and proceeding.
//! `esim_marshal` is a **fail-open stub today** -- `evaluate` always returns
//! `Unreachable` because `kernel-arm` has no MARSHAL transport of any kind
//! yet, which is the documented Option B behavior in
//! `docs/MARSHAL-ENFORCEMENT-POLICY.md`, not a shortcut. What that file
//! describes is the policy this mirrors; `esim_marshal.rs`'s own doc comment
//! says exactly what changes once a real transport exists. The gate is wired
//! in now so the call sites are already correct when that day comes.
//!
//! Independently of the gate, every real lifecycle transition
//! (`INSTALL`/`ENABLE`/`DISABLE`/`DELETE`) appends an entry to a
//! `citadel_integration::WormLog` -- the shared tamper-evident audit chain,
//! not a second logging path of this module's own. See [`audit_transition`].

use alloc::format;
use spin::Mutex;

use runix_citadel_integration::WormLog;

use crate::esim_marshal::{self, MarshalEnforcementError};
use crate::serial::write_byte;
use crate::serial_println;
use crate::sim::{ProfileState, SimError};

pub const SYS_WRITE: u64 = 1;
pub const SYS_RIL_ACCESS: u64 = 2;
pub const SYS_RIL_SEND: u64 = 3;
pub const SYS_RIL_RECV: u64 = 4;
pub const SYS_SIM_CREATE: u64 = 5;
pub const SYS_SIM_INSTALL: u64 = 6;
pub const SYS_SIM_ENABLE: u64 = 7;
pub const SYS_SIM_DISABLE: u64 = 8;
pub const SYS_SIM_DELETE: u64 = 9;
pub const SYS_SIM_STATUS: u64 = 10;

/// `SYS_RIL_RECV`'s return-value convention: `0..=255` is a received byte,
/// `256`/`257` are out-of-band sentinels distinct from any real byte value
/// (unlike `SYS_RIL_ACCESS`/`SYS_RIL_SEND`, which only ever report
/// success/denied, `RECV` also has to report "authorized, but nothing sent
/// yet" as a third, distinct outcome).
const RIL_RECV_EMPTY: u64 = 256;
const RIL_RECV_DENIED: u64 = 257;

/// `SYS_SIM_STATUS`'s return-value convention: `0..=3` is a real profile
/// state (see `sim::ProfileState::as_status_code` -- four states now, so
/// `3` is `Deleted` and no longer available as a sentinel), `4` is
/// denied/failed -- distinct from any real state code, same reasoning as
/// `RIL_RECV_EMPTY`/`RIL_RECV_DENIED`.
const SIM_STATUS_DENIED: u64 = 4;

/// `SYS_SIM_CREATE`'s return-value convention: `0..=255` is the newly
/// allocated profile's ID (`sim::EsimProfile::id` is a `u8`, so every
/// value in that range is a legitimate answer), `256` is denied/failed --
/// the first value outside the `u8` range, same "sentinel outside the real
/// value range" convention `RIL_RECV_EMPTY`/`RIL_RECV_DENIED` use. A plain
/// `1` would have been indistinguishable from "profile 1 was created."
const SIM_CREATE_FAILED: u64 = 256;

/// The audit chain every real eSIM lifecycle transition appends to.
///
/// `Option`-wrapped and lazily initialized rather than constructed inline,
/// because `WormLog::new()` is not a `const fn` (it is `Default`-derived
/// over a `Vec`, and derived `Default` impls aren't `const`). That rules
/// out the shape `capabilities.rs`'s `CURRENT_CAPABILITIES` uses
/// (`Mutex::new(Vec::new())`, where the inner constructor *is* `const`),
/// so this takes the next-simplest thing that needs no extra dependency:
/// `None` until [`audit_transition`]'s first call. The `Mutex` is the same
/// `spin::Mutex` used everywhere else in this crate.
static ESIM_WORM_LOG: Mutex<Option<WormLog>> = Mutex::new(None);

/// Appends one eSIM lifecycle transition to [`ESIM_WORM_LOG`].
///
/// `from`/`to` are the *intended* transition for the operation that ran
/// (`install` is `Created -> Disabled`, `enable` is `Disabled -> Enabled`,
/// `disable` is `Enabled -> Disabled`, `delete` is `Disabled -> Deleted`),
/// derived from which operation was attempted rather than by reading
/// `sim::profile_state` before and after. That's deliberate: a
/// before-and-after read cannot be taken atomically with the transition
/// itself (`sim.rs` takes and releases its `SLOTS` lock inside each
/// public function), so the pair could in principle straddle another
/// context's transition and record a from/to that never happened. The
/// intended transition plus `result` is strictly more honest -- a rejected
/// operation is recorded as `authorized: false` with `sim.rs`'s own error
/// as the reason, which already carries the actual `from` state for a
/// `WrongState` rejection.
fn audit_transition(
    slot: usize,
    profile_id: u8,
    from: ProfileState,
    to: ProfileState,
    result: &Result<(), SimError>,
) {
    let subject = crate::capabilities::sim_profile_resource(slot, profile_id);
    let (authorized, reason) = match result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(format!("{e}"))),
    };
    let mut guard = ESIM_WORM_LOG.lock();
    guard
        .get_or_insert_with(WormLog::new)
        .record_lifecycle_transition(
            &subject,
            &format!("{from:?}"),
            &format!("{to:?}"),
            authorized,
            reason,
        );
}

/// Reads the ARM generic timer's physical counter -- this crate's only
/// available "now," in the total absence of an RTC or the x86_64 kernel's
/// PIT-tick counter (`interrupts::ticks()`). Good enough to prove a
/// capability's expiry window is actually consulted, not a claim that
/// this is wall-clock time.
pub fn now_ticks() -> u64 {
    let cntpct: u64;
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) cntpct);
    }
    cntpct
}

/// The generic timer's actual tick rate (`CNTFRQ_EL0`, fixed by the
/// platform, not something this crate configures). `capabilities`'s
/// expiry window is sized off this rather than a fixed tick count -- a
/// fixed count picked without checking this first (`1_000_000`, tried
/// initially) turned out to be under a millisecond of real time on this
/// platform's frequency, which heap init plus a handful of UART prints
/// between issuance and the first check comfortably exceeds, making
/// every demo token "expire" before `el0_demo` ever got to use it.
pub fn frequency_hz() -> u64 {
    let cntfrq: u64;
    unsafe {
        core::arch::asm!("mrs {}, CNTFRQ_EL0", out(reg) cntfrq);
    }
    cntfrq
}

/// Dispatches one syscall. `num`/`arg1`/`arg2`/`arg3` are EL0's
/// `x0`/`x1`/`x2`/`x3` at the moment of `svc #0` -- three arguments, not
/// the two this ABI originally carried, because `SYS_SIM_INSTALL` needs
/// `slot`, `profile_id`, and `identity` together (see this module's doc
/// comment, and `el1_vectors.rs`'s for how the third one actually gets
/// here). Syscalls that don't use `arg3` simply ignore it; nothing about
/// their behavior changed when the ABI widened.
///
/// Returns the value that becomes EL0's new `x0`
/// once `el1_vectors.rs`'s epilogue `eret`s back -- `0` for success,
/// nonzero for "denied"/"unknown," the same coarse convention
/// `kernel/src/syscall.rs::dispatch` uses (`u64::MAX` for "denied," here
/// `1` -- picked distinct from `0`/success, not required to match the
/// x86_64 side's exact sentinel; `SYS_RIL_RECV` has its own wider
/// convention, see `RIL_RECV_EMPTY`/`RIL_RECV_DENIED`;
/// `SYS_SIM_CREATE`/`SYS_SIM_STATUS` likewise, see
/// `SIM_CREATE_FAILED`/`SIM_STATUS_DENIED`).
pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    match num {
        SYS_WRITE => {
            write_byte(arg1 as u8);
            0
        }
        SYS_RIL_ACCESS => {
            let channel = arg1 as usize;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => {
                    serial_println!(
                        "\nSVC: SYS_RIL_ACCESS channel {} authorized (capability check passed)",
                        channel
                    );
                    0
                }
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_ACCESS channel {} DENIED ({})", channel, e);
                    1
                }
            }
        }
        SYS_RIL_SEND => {
            let channel = arg1 as usize;
            let byte = arg2 as u8;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => match crate::ril_channel::send(channel, byte) {
                    Ok(()) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_SEND channel {} byte {:#x} authorized",
                            channel,
                            byte
                        );
                        0
                    }
                    Err(()) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_SEND channel {} DENIED (no such channel)",
                            channel
                        );
                        1
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_SEND channel {} DENIED ({})", channel, e);
                    1
                }
            }
        }
        SYS_RIL_RECV => {
            let channel = arg1 as usize;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => match crate::ril_channel::recv(channel) {
                    Some(byte) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_RECV channel {} authorized, byte {:#x}",
                            channel,
                            byte
                        );
                        byte as u64
                    }
                    None => {
                        serial_println!(
                            "\nSVC: SYS_RIL_RECV channel {} authorized, nothing pending",
                            channel
                        );
                        RIL_RECV_EMPTY
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_RECV channel {} DENIED ({})", channel, e);
                    RIL_RECV_DENIED
                }
            }
        }
        SYS_SIM_CREATE => {
            let slot = arg1 as usize;
            // Slot-level `sim_resource`, not `sim_profile_resource`: there
            // is no profile to scope the check to until this call allocates
            // one. See this module's doc comment.
            match check(&crate::capabilities::sim_resource(slot)) {
                Ok(()) => match crate::sim::create(slot) {
                    Ok(profile_id) => {
                        serial_println!(
                            "\nSVC: SYS_SIM_CREATE slot {} authorized, profile {}",
                            slot,
                            profile_id
                        );
                        profile_id as u64
                    }
                    Err(e) => {
                        serial_println!("\nSVC: SYS_SIM_CREATE slot {} FAILED ({})", slot, e);
                        SIM_CREATE_FAILED
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_SIM_CREATE slot {} DENIED ({})", slot, e);
                    SIM_CREATE_FAILED
                }
            }
        }
        SYS_SIM_INSTALL => {
            let slot = arg1 as usize;
            let profile_id = arg2 as u8;
            let identity = arg3;
            match check(&crate::capabilities::sim_profile_resource(slot, profile_id)) {
                Ok(()) => {
                    let result = crate::sim::install(slot, profile_id, identity);
                    audit_transition(
                        slot,
                        profile_id,
                        ProfileState::Created,
                        ProfileState::Disabled,
                        &result,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_INSTALL slot {} profile {} identity {:#x} authorized",
                                slot,
                                profile_id,
                                identity
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_INSTALL slot {} profile {} FAILED ({})",
                                slot,
                                profile_id,
                                e
                            );
                            1
                        }
                    }
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_SIM_INSTALL slot {} profile {} DENIED ({})",
                        slot,
                        profile_id,
                        e
                    );
                    1
                }
            }
        }
        SYS_SIM_ENABLE => {
            let slot = arg1 as usize;
            let profile_id = arg2 as u8;
            match check(&crate::capabilities::sim_profile_resource(slot, profile_id)) {
                Ok(()) => {
                    // The MARSHAL gate, between the capability check and the
                    // real transition: enabling demotes whichever profile was
                    // this slot's active subscription, so it is one of the two
                    // consequential operations here (see this module's doc
                    // comment). A `Refuse`/`HardStop` denies the syscall
                    // outright -- `sim::enable` is never reached, exactly as
                    // for a capability denial.
                    let outcome = esim_marshal::evaluate("enable", slot, profile_id);
                    if let Err(MarshalEnforcementError::Blocked(blocked)) =
                        esim_marshal::enforce(outcome)
                    {
                        serial_println!(
                            "\nSVC: SYS_SIM_ENABLE slot {} profile {} DENIED (MARSHAL {:?})",
                            slot,
                            profile_id,
                            blocked
                        );
                        return 1;
                    }
                    let result = crate::sim::enable(slot, profile_id);
                    audit_transition(
                        slot,
                        profile_id,
                        ProfileState::Disabled,
                        ProfileState::Enabled,
                        &result,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_ENABLE slot {} profile {} authorized",
                                slot,
                                profile_id
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_ENABLE slot {} profile {} FAILED ({})",
                                slot,
                                profile_id,
                                e
                            );
                            1
                        }
                    }
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_SIM_ENABLE slot {} profile {} DENIED ({})",
                        slot,
                        profile_id,
                        e
                    );
                    1
                }
            }
        }
        SYS_SIM_DISABLE => {
            let slot = arg1 as usize;
            let profile_id = arg2 as u8;
            // No MARSHAL gate: disabling is the *recoverable* direction (the
            // profile stays installed and can be re-enabled), so it isn't in
            // the consequential set the gate covers. Still audited, because
            // "the slot lost its active subscription" is worth a WORM entry
            // regardless of whether it needed governance approval.
            match check(&crate::capabilities::sim_profile_resource(slot, profile_id)) {
                Ok(()) => {
                    let result = crate::sim::disable(slot, profile_id);
                    audit_transition(
                        slot,
                        profile_id,
                        ProfileState::Enabled,
                        ProfileState::Disabled,
                        &result,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_DISABLE slot {} profile {} authorized",
                                slot,
                                profile_id
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_DISABLE slot {} profile {} FAILED ({})",
                                slot,
                                profile_id,
                                e
                            );
                            1
                        }
                    }
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_SIM_DISABLE slot {} profile {} DENIED ({})",
                        slot,
                        profile_id,
                        e
                    );
                    1
                }
            }
        }
        SYS_SIM_DELETE => {
            let slot = arg1 as usize;
            let profile_id = arg2 as u8;
            // `sim_delete_resource`, *not* `sim_profile_resource`: holding
            // general profile access must not imply delete authority. See
            // this module's doc comment and `capabilities.rs`'s own on that
            // function.
            match check(&crate::capabilities::sim_delete_resource(slot, profile_id)) {
                Ok(()) => {
                    // Same MARSHAL gate as enable, for the other half of the
                    // consequential pair -- deletion is irreversible.
                    let outcome = esim_marshal::evaluate("delete", slot, profile_id);
                    if let Err(MarshalEnforcementError::Blocked(blocked)) =
                        esim_marshal::enforce(outcome)
                    {
                        serial_println!(
                            "\nSVC: SYS_SIM_DELETE slot {} profile {} DENIED (MARSHAL {:?})",
                            slot,
                            profile_id,
                            blocked
                        );
                        return 1;
                    }
                    let result = crate::sim::delete(slot, profile_id);
                    audit_transition(
                        slot,
                        profile_id,
                        ProfileState::Disabled,
                        ProfileState::Deleted,
                        &result,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_DELETE slot {} profile {} authorized",
                                slot,
                                profile_id
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_SIM_DELETE slot {} profile {} FAILED ({})",
                                slot,
                                profile_id,
                                e
                            );
                            1
                        }
                    }
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_SIM_DELETE slot {} profile {} DENIED ({})",
                        slot,
                        profile_id,
                        e
                    );
                    1
                }
            }
        }
        SYS_SIM_STATUS => {
            let slot = arg1 as usize;
            let profile_id = arg2 as u8;
            // Read-only: no MARSHAL gate and no audit entry (nothing
            // transitioned), just the capability check.
            match check(&crate::capabilities::sim_profile_resource(slot, profile_id)) {
                Ok(()) => match crate::sim::profile_state(slot, profile_id) {
                    Ok(state) => {
                        serial_println!(
                            "\nSVC: SYS_SIM_STATUS slot {} profile {} authorized, state {:?}",
                            slot,
                            profile_id,
                            state
                        );
                        state.as_status_code()
                    }
                    Err(e) => {
                        serial_println!(
                            "\nSVC: SYS_SIM_STATUS slot {} profile {} FAILED ({})",
                            slot,
                            profile_id,
                            e
                        );
                        SIM_STATUS_DENIED
                    }
                },
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_SIM_STATUS slot {} profile {} DENIED ({})",
                        slot,
                        profile_id,
                        e
                    );
                    SIM_STATUS_DENIED
                }
            }
        }
        _ => u64::MAX,
    }
}

fn check(resource: &str) -> Result<(), runix_capability_manager::CapabilityError> {
    crate::capabilities::check(resource, now_ticks())
}
