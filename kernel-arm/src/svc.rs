//! `SVC` syscall dispatch -- the ARM-side analogue of
//! `kernel/src/syscall.rs::dispatch` on the x86_64 side. Reached from
//! `el1_vectors.rs`'s vector-8 `SVC` handling; see that module's doc
//! comment for how the syscall number/arg actually get here.
//!
//! Fifteen syscalls for EL0 callers (plus three EL1-continuation ones, see
//! `SYS_EL0_PROOF_DONE` and friends), matching `el0.rs`'s demo exactly (kept
//! in sync by hand, not shared constants -- see `el0.rs`'s own doc comment on
//! why):
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
//! - `SYS_IPC_SEND`/`SYS_IPC_RECV`: the same capability check again, now
//!   over a *general-purpose* byte channel (`ipc_channel.rs`) rather than a
//!   resource kind with a specific meaning -- the ARM analogue of
//!   `kernel/src/syscall.rs`'s `SYS_IPC_SEND`/`SYS_IPC_RECV`. Structurally
//!   identical to the RIL pair above (per-call check, denial distinguishable
//!   from success), over its own separately-addressed channel space and its
//!   own `ipc:{channel}` resource strings, so an `ipc:` grant never reaches
//!   RIL traffic or vice versa. No session/response-capability machinery
//!   (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`): that design solves
//!   concurrent-client reply mixups, and this crate has one EL0 context --
//!   see `ipc_channel.rs`'s doc comment.
//! - `SYS_MVNO_BIND` (16) / `SYS_MVNO_SUSPEND` (17) / `SYS_MVNO_REACTIVATE`
//!   (18): the MVNO account layer (Beta item 3.3, `mvno.rs` wrapping
//!   `runix_mobile::account`). Same per-call capability check, over
//!   `mvno:account:{id}` (bind, reactivate) and a *separately scoped*
//!   `mvno:suspend:{id}` (suspend cuts service, so it is scoped apart from
//!   general account access exactly as delete is from general profile
//!   access). `BIND` additionally requires the profile's own
//!   `sim:{slot}:{profile}` capability (both checked every call; the DENIED
//!   line names the failing resource), so account access alone cannot claim
//!   a profile. Arguments: `BIND(account, slot, profile)`, `SUSPEND(account)`,
//!   `REACTIVATE(account)`; return `0` on success, `1` on denial or failure.
//!   Every applied change is appended to the same WORM chain as the eSIM
//!   transitions. **Known, tracked gap: these three are capability-gated and
//!   audited but NOT MARSHAL-gated yet** -- `esim_marshal::evaluate`
//!   hardcodes `esim.{action}` slot/profile envelopes, so generalizing it
//!   (with the upstream rbacMap and `citadel_proxy` policy) is Beta item 3.4.
//!   Documented here rather than papered over; CLAUDE.md requires privileged
//!   actions to flow through MARSHAL and these will once 3.4 lands.
//!
//! # The MVNO gate on `SYS_SIM_ENABLE`
//!
//! After its capability check and *before* the MARSHAL round trip,
//! `SYS_SIM_ENABLE` asks `mvno::gate_enable`: the profile must be bound to an
//! `Active` account. An **unbound** profile is refused (fail closed), as is
//! one whose owner is Suspended or Closed
//! (`SVC: SYS_SIM_ENABLE ... DENIED (MVNO <error>)`). It runs first because
//! it is a cheap, deterministic local check -- no point spending a network
//! round trip to MARSHAL on a request that cannot succeed. `SYS_SIM_DELETE`
//! releases the profile's binding after a successful delete so the account's
//! capacity frees. `SYS_MVNO_SUSPEND` applies the registry's forced-disable
//! list itself (the registry cannot) and then re-audits the invariant; see
//! `mvno.rs` for the lock order (registry -> sim, never the reverse).
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
use alloc::string::String;
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
pub const SYS_IPC_SEND: u64 = 11;
pub const SYS_IPC_RECV: u64 = 12;
/// "This EL0 excursion is finished; resume my EL1 continuation" -- the one
/// syscall `el0_proof.rs`'s EL0 process needs in order to hand control back
/// to EL1 at all, and the only one added for it.
///
/// Deliberately **not** a general `SYS_YIELD` (the shape
/// `kernel/src/syscall.rs` has on the x86_64 side): it does not reschedule,
/// does not return to EL0, carries no capability check, and names no
/// resource. Its entire authority is "end the caller's own EL0 run and
/// resume the EL1 frame that started it", so there is nothing for a
/// capability to gate and no privileged action to route through MARSHAL.
/// With no excursion in flight it is an unknown syscall and returns
/// `u64::MAX` like any other -- `el0_proof::finish` enforces that, not this
/// dispatch table. A real `SYS_YIELD` is the next scheduling slice's work;
/// see `el0_proof.rs`'s doc comment for why keeping the two separate is the
/// honest split rather than a stopgap.
pub const SYS_EL0_PROOF_DONE: u64 = 13;

/// "This EL0 excursion is finished; resume my EL1 continuation" --
/// `tcp_proof.rs`'s own result-reporting syscall, structurally the twin of
/// [`SYS_EL0_PROOF_DONE`] (same `el0_exec` one-shot continuation mechanism,
/// same "claim, record, resume -- never routed through a capability check
/// or MARSHAL" authority) but kept as a *separate* number rather than
/// reused, for two reasons that both matter: the result shape differs
/// ([`SYS_EL0_PROOF_DONE`] reports three observed bytes in `x1`/`x2`/`x3`;
/// this reports one flat `net-driver-host-arm::ProofResult` code in `x1`
/// alone), and the continuation each resumes is a different proof's --
/// `el0_proof::finish` and `tcp_proof::finish` each only know how to
/// interpret *their own* payload and resume *their own* caller's EL1 frame,
/// so collapsing them into one syscall number would mean one of the two
/// handlers guessing at a payload shape that isn't actually its own. Same
/// "unknown syscall with no excursion in flight" `u64::MAX` fallback as
/// [`SYS_EL0_PROOF_DONE`] -- see `tcp_proof::finish`'s own doc comment.
pub const SYS_NET_PROOF_DONE: u64 = 14;

/// "This EL0 excursion is finished; resume my EL1 continuation" --
/// `marshal_transport.rs`'s own result-reporting syscall, structurally the
/// third twin of [`SYS_EL0_PROOF_DONE`]/[`SYS_NET_PROOF_DONE`] (same
/// `el0_exec` one-shot continuation mechanism, same "claim, record,
/// resume -- never routed through a capability check or MARSHAL"
/// authority), kept as its own number for the same reason
/// [`SYS_NET_PROOF_DONE`] is kept separate from [`SYS_EL0_PROOF_DONE`]: a
/// different result shape (`x1` = status, `x2` = `response_len`, where
/// [`SYS_NET_PROOF_DONE`] reports one flat code in `x1` alone) resumed by a
/// different caller's continuation (`marshal_transport::finish`, which
/// knows nothing about `tcp_proof.rs`'s or `el0_proof.rs`'s own payload
/// shapes, and vice versa). Same "unknown syscall with no excursion in
/// flight" `u64::MAX` fallback as the other two.
pub const SYS_MARSHAL_PROOF_DONE: u64 = 15;

/// `SYS_MVNO_BIND(account, slot, profile)`: bind an eSIM profile to an
/// account. Capabilities: BOTH `mvno_account_resource(account)` and
/// `sim_profile_resource(slot, profile)` (either missing denies). See this module's
/// doc comment for the (tracked) absence of a MARSHAL gate.
pub const SYS_MVNO_BIND: u64 = 16;
/// `SYS_MVNO_SUSPEND(account)`: `Active -> Suspended`, force-disabling every
/// Enabled profile the account owns. Capability:
/// `mvno_suspend_resource(account)` -- scoped apart from general account
/// access.
pub const SYS_MVNO_SUSPEND: u64 = 17;
/// `SYS_MVNO_REACTIVATE(account)`: `Suspended -> Active`. Capability:
/// `mvno_account_resource(account)`.
pub const SYS_MVNO_REACTIVATE: u64 = 18;

/// `SYS_RIL_RECV`'s return-value convention: `0..=255` is a received byte,
/// `256`/`257` are out-of-band sentinels distinct from any real byte value
/// (unlike `SYS_RIL_ACCESS`/`SYS_RIL_SEND`, which only ever report
/// success/denied, `RECV` also has to report "authorized, but nothing sent
/// yet" as a third, distinct outcome).
const RIL_RECV_EMPTY: u64 = 256;
const RIL_RECV_DENIED: u64 = 257;

/// `SYS_IPC_RECV`'s return-value convention -- the same three-outcome shape
/// (`0..=255` a real byte, then two out-of-band sentinels) as
/// `RIL_RECV_EMPTY`/`RIL_RECV_DENIED`, and deliberately the same *values*:
/// the two syscalls are structurally identical and an EL0 caller reads them
/// with the same comparison, so giving `IPC_RECV` different sentinel numbers
/// would be a gratuitous second convention to remember. Kept as separate
/// named constants rather than reusing the `RIL_*` ones so neither syscall's
/// convention can be changed by accident while editing the other's.
const IPC_RECV_EMPTY: u64 = 256;
const IPC_RECV_DENIED: u64 = 257;

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

/// The `principal` passed to `esim_marshal::evaluate` at both its call
/// sites below.
///
/// This is a **placeholder**, not a real identity lookup: `check()` (this
/// module's own wrapper around `capabilities::check`) only ever returns
/// `Result<(), CapabilityError>`, never the `CapabilityToken` it matched,
/// so there is no token in hand at either call site to pull a real
/// `subject` out of (`CapabilityToken` does carry one — see
/// `capability-manager/src/lib.rs` — but it isn't surfaced here). Rather
/// than invent a return-value plumbing change to `check()` for a crate
/// that has exactly one EL0 context today (`capabilities.rs`'s own doc
/// comment: "one flat set of capabilities," not a per-thread/per-process
/// model), this names that one context the same way
/// `capabilities::issue_and_hold`'s only caller does for its demo
/// token's `subject`. This becomes a real per-caller value once
/// `kernel-arm` grows a per-context/per-thread capability model — at
/// that point, thread the matched token's `subject` through from
/// `check()`'s call site instead of hardcoding this.
const ESIM_MARSHAL_PRINCIPAL: &str = "el0:arm-demo";

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
    audit_event(
        &subject,
        &format!("{from:?}"),
        &format!("{to:?}"),
        authorized,
        reason,
    );
}

/// The subject-and-strings form of [`audit_transition`], for transitions that
/// are not a `sim::ProfileState` change: MVNO account status changes
/// (subject `mvno:account:{id}`, `Active -> Suspended`) and profile
/// bind/unbind (subject the profile's `sim:{slot}:{profile}` resource,
/// `Unbound -> Bound(account N)`). Same chain ([`ESIM_WORM_LOG`]), same
/// "intended transition plus the outcome, recorded at the syscall boundary
/// only" philosophy as [`audit_transition`] -- `mvno.rs`'s data model never
/// logs. A refused change is recorded `authorized: false` with the
/// registry's error as the reason.
fn audit_event(subject: &str, from: &str, to: &str, authorized: bool, reason: Option<String>) {
    let mut guard = ESIM_WORM_LOG.lock();
    guard
        .get_or_insert_with(WormLog::new)
        .record_lifecycle_transition(subject, from, to, authorized, reason);
}

/// `(entry count, chain verifies)` for [`ESIM_WORM_LOG`] -- printed after the
/// suspend handshake so the audit trail is visible in the serial log, not
/// just asserted.
fn audit_chain_summary() -> (usize, bool) {
    let guard = ESIM_WORM_LOG.lock();
    match guard.as_ref() {
        Some(log) => (log.entries().len(), log.verify_chain()),
        None => (0, true),
    }
}

/// Maps a registry result to [`audit_event`]'s `(authorized, reason)`.
fn audit_outcome<T>(r: &Result<T, runix_mobile::account::AccountError>) -> (bool, Option<String>) {
    match r {
        Ok(_) => (true, None),
        Err(e) => (false, Some(format!("{e:?}"))),
    }
}

/// Releases `(slot, profile_id)`'s MVNO binding after a successful
/// `sim::delete` so the owning account's capacity frees (kernel-applied, like
/// the suspend path's forced disable). A profile that was never bound has
/// nothing to release and is silent. Called with no lock held.
fn release_binding_after_delete(slot: usize, profile_id: u8) {
    let subject = crate::capabilities::sim_profile_resource(slot, profile_id);
    match crate::mvno::unbind(slot, profile_id) {
        Ok(None) => {}
        Ok(Some(owner)) => {
            audit_event(
                &subject,
                &format!("Bound(account {})", owner.0),
                "Unbound",
                true,
                None,
            );
            serial_println!(
                "\nSVC: SYS_SIM_DELETE slot {} profile {} unbound from account {}",
                slot,
                profile_id,
                owner.0
            );
        }
        Err(e) => {
            audit_event(&subject, "Bound", "Unbound", false, Some(format!("{e:?}")));
            serial_println!(
                "\nSVC: SYS_SIM_DELETE slot {} profile {} unbind FAILED ({:?})",
                slot,
                profile_id,
                e
            );
        }
    }
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
                    // The MVNO gate (Beta item 3.3), first after the
                    // capability check: the profile must be bound to an
                    // Active account. Unbound is refused (fail closed), as is
                    // a Suspended/Closed owner. Cheap and local, so it runs
                    // *before* the MARSHAL round trip -- no network call for
                    // a request that cannot succeed. `sim::enable` is never
                    // reached on denial.
                    if let Err(e) = crate::mvno::gate_enable(slot, profile_id) {
                        serial_println!(
                            "\nSVC: SYS_SIM_ENABLE slot {} profile {} DENIED (MVNO {:?})",
                            slot,
                            profile_id,
                            e
                        );
                        return 1;
                    }
                    // The MARSHAL gate, between the MVNO gate and the
                    // real transition: enabling demotes whichever profile was
                    // this slot's active subscription, so it is one of the two
                    // consequential operations here (see this module's doc
                    // comment). A `Refuse`/`HardStop` denies the syscall
                    // outright -- `sim::enable` is never reached, exactly as
                    // for a capability denial.
                    let outcome =
                        esim_marshal::evaluate("enable", slot, profile_id, ESIM_MARSHAL_PRINCIPAL);
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
                    let outcome =
                        esim_marshal::evaluate("delete", slot, profile_id, ESIM_MARSHAL_PRINCIPAL);
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
                            release_binding_after_delete(slot, profile_id);
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
        SYS_IPC_SEND => {
            let channel = arg1 as usize;
            let byte = arg2 as u8;
            match check(&crate::capabilities::ipc_resource(channel)) {
                Ok(()) => match crate::ipc_channel::send(channel, byte) {
                    Ok(()) => {
                        serial_println!(
                            "\nSVC: SYS_IPC_SEND channel {} byte {:#x} authorized",
                            channel,
                            byte
                        );
                        0
                    }
                    Err(()) => {
                        serial_println!(
                            "\nSVC: SYS_IPC_SEND channel {} DENIED (no such channel)",
                            channel
                        );
                        1
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_IPC_SEND channel {} DENIED ({})", channel, e);
                    1
                }
            }
        }
        SYS_IPC_RECV => {
            let channel = arg1 as usize;
            match check(&crate::capabilities::ipc_resource(channel)) {
                Ok(()) => match crate::ipc_channel::recv(channel) {
                    Some(byte) => {
                        serial_println!(
                            "\nSVC: SYS_IPC_RECV channel {} authorized, byte {:#x}",
                            channel,
                            byte
                        );
                        byte as u64
                    }
                    None => {
                        serial_println!(
                            "\nSVC: SYS_IPC_RECV channel {} authorized, nothing pending",
                            channel
                        );
                        IPC_RECV_EMPTY
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_IPC_RECV channel {} DENIED ({})", channel, e);
                    IPC_RECV_DENIED
                }
            }
        }
        SYS_MVNO_BIND => {
            let account = arg1;
            let slot = arg2 as usize;
            let profile_id = arg3 as u8;
            // Two capabilities, both checked on every call (no short-circuit
            // past the second): the account's own `mvno:account:{id}` AND the
            // profile's `sim:{slot}:{profile}`, so holding account access
            // alone cannot claim a profile the caller has no authority over.
            // Either failing denies, and the DENIED line names which.
            // Capability and audit only -- NOT MARSHAL-gated yet; known,
            // tracked gap (Beta item 3.4), see this module's doc comment.
            let account_res = crate::capabilities::mvno_account_resource(account);
            let profile_res = crate::capabilities::sim_profile_resource(slot, profile_id);
            let account_check = check(&account_res);
            let profile_check = check(&profile_res);
            let authority = match (account_check, profile_check) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(e), Ok(())) => Err(format!("resource {account_res}: {e}")),
                (Ok(()), Err(e)) => Err(format!("resource {profile_res}: {e}")),
                (Err(a), Err(p)) => Err(format!(
                    "resource {account_res}: {a}; resource {profile_res}: {p}"
                )),
            };
            match authority {
                Ok(()) => {
                    let result = crate::mvno::bind(account, slot, profile_id);
                    let (authorized, reason) = audit_outcome(&result);
                    audit_event(
                        &crate::capabilities::sim_profile_resource(slot, profile_id),
                        "Unbound",
                        &format!("Bound(account {account})"),
                        authorized,
                        reason,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_MVNO_BIND account {} slot {} profile {} authorized",
                                account,
                                slot,
                                profile_id
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_MVNO_BIND account {} slot {} profile {} FAILED ({:?})",
                                account,
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
                        "\nSVC: SYS_MVNO_BIND account {} slot {} profile {} DENIED ({})",
                        account,
                        slot,
                        profile_id,
                        e
                    );
                    1
                }
            }
        }
        SYS_MVNO_SUSPEND => {
            let account = arg1;
            // `mvno_suspend_resource`, *not* `mvno_account_resource`: holding
            // general account access must not imply the authority to cut
            // service. Capability and audit only -- NOT MARSHAL-gated yet
            // (Beta item 3.4), see this module's doc comment.
            match check(&crate::capabilities::mvno_suspend_resource(account)) {
                Ok(()) => suspend_account(account),
                Err(e) => {
                    serial_println!("\nSVC: SYS_MVNO_SUSPEND account {} DENIED ({})", account, e);
                    1
                }
            }
        }
        SYS_MVNO_REACTIVATE => {
            let account = arg1;
            // Capability and audit only -- NOT MARSHAL-gated yet (Beta item
            // 3.4), see this module's doc comment.
            match check(&crate::capabilities::mvno_account_resource(account)) {
                Ok(()) => {
                    let result = crate::mvno::reactivate(account);
                    let (authorized, reason) = audit_outcome(&result);
                    audit_event(
                        &crate::capabilities::mvno_account_resource(account),
                        "Suspended",
                        "Active",
                        authorized,
                        reason,
                    );
                    match result {
                        Ok(()) => {
                            serial_println!(
                                "\nSVC: SYS_MVNO_REACTIVATE account {} authorized",
                                account
                            );
                            0
                        }
                        Err(e) => {
                            serial_println!(
                                "\nSVC: SYS_MVNO_REACTIVATE account {} FAILED ({:?})",
                                account,
                                e
                            );
                            1
                        }
                    }
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_MVNO_REACTIVATE account {} DENIED ({})",
                        account,
                        e
                    );
                    1
                }
            }
        }
        // The one arm that may not return to EL0 (see this constant's doc
        // comment and `el0_proof::finish`): on the proof path it resumes an
        // EL1 continuation and never comes back here; with no excursion in
        // flight it falls through to the same `u64::MAX` an unknown syscall
        // gets.
        SYS_EL0_PROOF_DONE => crate::el0_proof::finish(arg1, arg2, arg3),
        // Same "may not return to EL0" shape as SYS_EL0_PROOF_DONE's arm
        // above, for `tcp_proof.rs`'s own continuation instead.
        SYS_NET_PROOF_DONE => crate::tcp_proof::finish(arg1),
        // Same "may not return to EL0" shape as the two arms above, for
        // `marshal_transport.rs`'s own continuation instead -- see
        // `SYS_MARSHAL_PROOF_DONE`'s own doc comment for the two-value
        // payload.
        SYS_MARSHAL_PROOF_DONE => crate::marshal_transport::finish(arg1, arg2),
        _ => u64::MAX,
    }
}

/// The suspend handshake (see `mvno.rs`'s doc comment): the registry flips
/// the account to `Suspended` and hands back the profiles that must be forced
/// `Enabled -> Disabled`; this applies them, audits each, then re-verifies
/// the "no Enabled profile under a non-Active account" invariant against live
/// `sim.rs` state. The window is never left unreported: a non-empty audit is a
/// loud `FAILED` line and a nonzero return.
///
/// Lock order: `mvno::suspend` takes the registry lock (and, via the
/// lifecycle view, the sim lock inside it) and has released both on return;
/// the `sim::disable` calls below then take only the sim lock. Never
/// registry-while-holding-sim.
fn suspend_account(account: u64) -> u64 {
    let account_subject = crate::capabilities::mvno_account_resource(account);
    let result = crate::mvno::suspend(account);
    let (authorized, reason) = audit_outcome(&result);
    audit_event(&account_subject, "Active", "Suspended", authorized, reason);
    let forced = match result {
        Ok(forced) => forced,
        Err(e) => {
            serial_println!(
                "\nSVC: SYS_MVNO_SUSPEND account {} FAILED ({:?})",
                account,
                e
            );
            return 1;
        }
    };
    serial_println!(
        "\nSVC: SYS_MVNO_SUSPEND account {} authorized ({} Enabled profile(s) to force-disable)",
        account,
        forced.len()
    );

    let mut ok = true;
    for k in forced {
        let disabled = crate::sim::disable(k.slot, k.profile);
        // Distinguishable from an operator-requested DISABLE in the chain.
        let (authorized, reason) = match &disabled {
            Ok(()) => (true, None),
            Err(e) => (false, Some(format!("{e}"))),
        };
        audit_event(
            &crate::capabilities::sim_profile_resource(k.slot, k.profile),
            "Enabled",
            "Disabled (forced by MVNO suspend)",
            authorized,
            reason,
        );
        match disabled {
            Ok(()) => serial_println!(
                "SVC: SYS_MVNO_SUSPEND account {} forced disable slot {} profile {} ok",
                account,
                k.slot,
                k.profile
            ),
            Err(e) => {
                ok = false;
                serial_println!(
                    "SVC: SYS_MVNO_SUSPEND account {} forced disable slot {} profile {} FAILED ({})",
                    account,
                    k.slot,
                    k.profile,
                    e
                );
            }
        }
    }

    let leaked = crate::mvno::audit();
    let (entries, chain_ok) = audit_chain_summary();
    if leaked.is_empty() {
        serial_println!(
            "SVC: SYS_MVNO_SUSPEND account {} audit clean (no Enabled profile under a non-Active account; WORM entries {}, chain verified {})",
            account,
            entries,
            chain_ok
        );
    } else {
        ok = false;
        for k in &leaked {
            serial_println!(
                "SVC: SYS_MVNO_SUSPEND account {} AUDIT FAILED: slot {} profile {} is Enabled under a non-Active account",
                account,
                k.slot,
                k.profile
            );
        }
    }
    if ok && chain_ok {
        0
    } else {
        1
    }
}

fn check(resource: &str) -> Result<(), runix_capability_manager::CapabilityError> {
    crate::capabilities::check(resource, now_ticks())
}
