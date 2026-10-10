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
//!   transitions. **All three are MARSHAL-gated (Beta item 3.4)** through the
//!   same enforcement the eSIM pair uses (`esim_marshal::enforce`, fed by
//!   `marshal_transport::evaluate` with a `MarshalAction`): bind claims
//!   ownership of a profile, suspend cuts service, reactivate re-grants it,
//!   so each is evaluated as `mvno.bind_profile` / `mvno.suspend_account` /
//!   `mvno.reactivate_account`. Order is capability checks, then MARSHAL
//!   evaluate + enforce, then (only then) the registry mutation. A
//!   `Refuse`/`HardStop` prints `SVC: SYS_MVNO_<X> account A [...] DENIED
//!   (MARSHAL <Outcome>)`, returns `1`, and leaves the registry untouched (no
//!   WORM entry, no forced disable); `Unreachable` (no proxy configured, or
//!   it did not answer) is fail-open exactly as for eSIM, while a *local*
//!   failure of the evaluation machinery (see below) is fail-closed:
//!   `DENIED (MARSHAL local failure: <reason>)`, returns `1`, state untouched,
//!   and a WORM entry `authorized=false` records the denial. The evaluation runs
//!   **before** the registry lock is taken and holds no lock at all -- it may
//!   drive a nested EL0 excursion (see `marshal_transport::evaluate`), which
//!   must never happen under a spin lock. Status reads are not gated.
//!
//! - `SYS_DATA_ACCOUNT` (19) / `SYS_DATA_SESSION_OPEN` (20) /
//!   `SYS_DATA_SESSION_CLOSE` (21) / `SYS_DATA_RECONCILE` (22): the data policy
//!   layer (Beta item 4.3, `data.rs` + the lib-side `data_state.rs`/
//!   `data_codes.rs`, wrapping `runix_mobile::policy` and `::reconcile`).
//!   Same per-call capability check, over three separately scoped resources:
//!   `data:usage:{account}` (the usage FEED), `data:session:{account}`
//!   (open/close) and `data:reconcile`. The feed is scoped apart from session
//!   access because it is privileged: it can push an account over its cap
//!   (denying service) and over the escalation threshold (the engine then
//!   asks for suspension), so the right to open or close sessions must not
//!   imply the right to meter the account.
//!
//!   ```text
//!   num  syscall                      args (x1, x2, x3)                capability
//!   19   SYS_DATA_ACCOUNT             account, bytes                   data:usage:{account}
//!   20   SYS_DATA_SESSION_OPEN        account, slot, profile|roam<<8   data:session:{account}
//!   21   SYS_DATA_SESSION_CLOSE       account, slot, profile           data:session:{account}
//!   22   SYS_DATA_RECONCILE           (none)                           data:reconcile
//!   ```
//!
//!   Returns (encodings pinned and tested in `data_codes.rs`): `ACCOUNT` ->
//!   `0` none / `1` notify / `2` throttle / `3` suspend-account REQUESTED
//!   (`>= 4` is a refusal); `SESSION_OPEN` -> `0` allow / `1` allow-throttled
//!   / `2..=6` the engine's deny reasons (suspended, closed, profile not
//!   enabled, roaming not allowed, cap exceeded) / `7..=13` kernel-side
//!   refusals (no capability, no entitlement, no such account, profile not
//!   bound to this account, unknown profile, malformed argument, table full);
//!   `SESSION_CLOSE` -> `0` closed / `1` denied / `2` not open / `3` bad
//!   argument; `RECONCILE` -> the incident count (`u64::MAX` = denied). The
//!   third `SESSION_OPEN` argument packs `profile` in bits 0..=7 and the
//!   roaming flag in bit 8 (the ABI has three argument registers and the call
//!   needs four values; the profile id is a `u8`; reserved bits are rejected).
//!
//!   **Not MARSHAL-gated, by design.** The policy engine only REQUESTS and the
//!   reconciler only OBSERVES; a request is carried out by the CALLER through
//!   an existing governed syscall under its OWN capability (for a
//!   `SuspendAccount` request that is `SYS_MVNO_SUSPEND`: capability, MARSHAL,
//!   WORM). The data syscalls never suspend, disable, close or mutate
//!   account/profile state in response to a request -- they update a usage
//!   counter or the session table and read policy, which are not
//!   governance-consequential state changes. So no new MARSHAL action type
//!   exists and the walk's evaluation count is unchanged. They ARE audited:
//!   every decision, every refusal after the capability check, every request
//!   the engine makes (worded as a REQUEST, not an action) and every
//!   reconciler incident goes to the same WORM chain. See `data.rs` for the
//!   fuller argument and the lock order (registry -> sim -> data; data is a
//!   leaf).
//!
//!   `SYS_DATA_RECONCILE` is structurally read-only: it builds a snapshot
//!   from copies of live state, hands it to the pure `reconcile`, prints and
//!   WORM-records each incident as EVIDENCE (`authorized=false` with an
//!   explicit "not a denial" reason: the observed state is not the expected,
//!   authorized one), and its only write is the usage table's `last_used`
//!   bookkeeping, done after the snapshot is built. It calls no `mvno::`/
//!   `sim::` mutator and no `data::` mutator other than `mark_observed`.
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
//! The gate is `esim_marshal::evaluate` (the real transport,
//! `marshal_transport::evaluate`) then `esim_marshal::enforce`, and its
//! policy is split precisely: the remote MARSHAL being *unreachable* (no
//! proxy configured, no device, connect failure/timeout, no report within the
//! bounded budget, undecodable reply) is `Remote(Unreachable)` and fail-open
//! (Option B, `docs/MARSHAL-ENFORCEMENT-POLICY.md`); the kernel *failing to
//! run the evaluation at all* (process setup failing incl. out of memory,
//! thread spawn failing, the EL0 excursion faulting) is a `LocalFailure` and
//! fails **closed** for every gated syscall here (both eSIM ops and the three
//! MVNO ones), because a hostile EL0 could otherwise exhaust resources by
//! looping on governed syscalls and bypass MARSHAL. A local-failure denial is
//! WORM-audited via [`enforce_gate`] (it is a security-relevant denial but not
//! a remote governance decision); `Refuse`/`HardStop` denials are unchanged.
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
use runix_kernel_arm::marshal_action::GateOutcome;
use runix_kernel_arm::marshal_action::MarshalAction;

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
/// `sim_profile_resource(slot, profile)` (either missing denies), then the
/// MARSHAL gate (`mvno.bind_profile`). See this module's doc comment.
pub const SYS_MVNO_BIND: u64 = 16;
/// `SYS_MVNO_SUSPEND(account)`: `Active -> Suspended`, force-disabling every
/// Enabled profile the account owns. Capability:
/// `mvno_suspend_resource(account)` -- scoped apart from general account
/// access; then the MARSHAL gate (`mvno.suspend_account`).
pub const SYS_MVNO_SUSPEND: u64 = 17;
/// `SYS_MVNO_REACTIVATE(account)`: `Suspended -> Active`. Capability:
/// `mvno_account_resource(account)`; then the MARSHAL gate
/// (`mvno.reactivate_account`).
pub const SYS_MVNO_REACTIVATE: u64 = 18;

/// `SYS_DATA_ACCOUNT(account, bytes)`: feed `bytes` of usage into the
/// account's counter, assess it, WORM-audit the decision and return the
/// engine's request as a code (`data_codes::action_request_code`). Capability:
/// `data_usage_resource(account)` -- the privileged feed. Not MARSHAL-gated;
/// performs no suspension (see this module's doc comment).
pub const SYS_DATA_ACCOUNT: u64 = 19;
/// `SYS_DATA_SESSION_OPEN(account, slot, profile | roaming<<8)`: ask the
/// policy engine whether `account` may use data on a profile bound to it;
/// record the session iff allowed. Capability: `data_session_resource(account)`.
pub const SYS_DATA_SESSION_OPEN: u64 = 20;
/// `SYS_DATA_SESSION_CLOSE(account, slot, profile)`: the caller removing a
/// session (carrying out a restriction). Capability: `data_session_resource`.
pub const SYS_DATA_SESSION_CLOSE: u64 = 21;
/// `SYS_DATA_RECONCILE()`: read-only reconciliation of live state against
/// policy; incidents are printed and WORM-recorded, nothing is corrected.
/// Capability: `data_reconcile_resource()`.
pub const SYS_DATA_RECONCILE: u64 = 22;

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

/// The `principal` passed to every MARSHAL evaluation below (the eSIM pair
/// via `esim_marshal::evaluate`, the three MVNO syscalls via
/// [`marshal_gate`]).
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
const MARSHAL_PRINCIPAL: &str = "el0:arm-demo";

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
                        esim_marshal::evaluate("enable", slot, profile_id, MARSHAL_PRINCIPAL);
                    if let Err(blocked) = enforce_gate(
                        outcome,
                        &crate::capabilities::sim_profile_resource(slot, profile_id),
                        &format!("{:?}", ProfileState::Disabled),
                        &format!("{:?}", ProfileState::Enabled),
                    ) {
                        serial_println!(
                            "\nSVC: SYS_SIM_ENABLE slot {} profile {} DENIED ({})",
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
                        esim_marshal::evaluate("delete", slot, profile_id, MARSHAL_PRINCIPAL);
                    if let Err(blocked) = enforce_gate(
                        outcome,
                        &crate::capabilities::sim_profile_resource(slot, profile_id),
                        &format!("{:?}", ProfileState::Disabled),
                        &format!("{:?}", ProfileState::Deleted),
                    ) {
                        serial_println!(
                            "\nSVC: SYS_SIM_DELETE slot {} profile {} DENIED ({})",
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
            // After the capability checks: the MARSHAL gate
            // (`mvno.bind_profile`), then the registry mutation. See this
            // module's doc comment.
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
                    // Evaluated before `mvno::bind` takes the registry lock;
                    // no lock is held across the (possibly EL0-excursion)
                    // evaluation. A block leaves the registry untouched.
                    if let Err(blocked) = marshal_gate(
                        &MarshalAction::MvnoBind {
                            account,
                            slot,
                            profile: profile_id,
                        },
                        &crate::capabilities::sim_profile_resource(slot, profile_id),
                        "Unbound",
                        &format!("Bound(account {account})"),
                    ) {
                        serial_println!(
                            "\nSVC: SYS_MVNO_BIND account {} slot {} profile {} DENIED ({})",
                            account,
                            slot,
                            profile_id,
                            blocked
                        );
                        return 1;
                    }
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
            // service. Then the MARSHAL gate (`mvno.suspend_account`),
            // evaluated before `suspend_account` touches the registry.
            match check(&crate::capabilities::mvno_suspend_resource(account)) {
                Ok(()) => {
                    if let Err(blocked) = marshal_gate(
                        &MarshalAction::MvnoSuspend { account },
                        &crate::capabilities::mvno_account_resource(account),
                        "Active",
                        "Suspended",
                    ) {
                        serial_println!(
                            "\nSVC: SYS_MVNO_SUSPEND account {} DENIED ({})",
                            account,
                            blocked
                        );
                        return 1;
                    }
                    suspend_account(account)
                }
                Err(e) => {
                    serial_println!("\nSVC: SYS_MVNO_SUSPEND account {} DENIED ({})", account, e);
                    1
                }
            }
        }
        SYS_MVNO_REACTIVATE => {
            let account = arg1;
            // Capability check, then the MARSHAL gate
            // (`mvno.reactivate_account`), then the registry mutation.
            match check(&crate::capabilities::mvno_account_resource(account)) {
                Ok(()) => {
                    if let Err(blocked) = marshal_gate(
                        &MarshalAction::MvnoReactivate { account },
                        &crate::capabilities::mvno_account_resource(account),
                        "Suspended",
                        "Active",
                    ) {
                        serial_println!(
                            "\nSVC: SYS_MVNO_REACTIVATE account {} DENIED ({})",
                            account,
                            blocked
                        );
                        return 1;
                    }
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
        SYS_DATA_ACCOUNT => data_account(arg1, arg2),
        SYS_DATA_SESSION_OPEN => data_session_open(arg1, arg2 as usize, arg3),
        SYS_DATA_SESSION_CLOSE => data_session_close(arg1, arg2 as usize, arg3),
        SYS_DATA_RECONCILE => data_reconcile(),
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

/// Appends the WORM entry for a data-session decision or refusal. Subject is
/// the session resource (`data:session:{account}`); the transition is the
/// session's `Closed -> Open...` intent, `authorized` says whether it
/// happened, and `reason` carries the replayable description.
fn audit_data_session(account: u64, authorized: bool, to: &str, reason: String) {
    audit_event(
        &crate::capabilities::data_session_resource(account),
        "Closed",
        to,
        authorized,
        Some(reason),
    );
}

/// `SYS_DATA_ACCOUNT(account, bytes)`: the usage feed. Capability
/// `data:usage:{account}` (privileged -- see this module's doc comment), then
/// the entitlement (DEMO table; unknown account fails closed), then the
/// counter update, then the engine's `evaluate_usage`. The decision and, when
/// the engine escalates, the REQUEST are WORM-audited; the request is returned
/// as a code for the caller to act on. This function performs none of it: no
/// suspension, no disable, no session close.
fn data_account(account: u64, bytes: u64) -> u64 {
    use runix_kernel_arm::data_codes::{
        action_request_code, demo_entitlement, describe_usage_assessment, USAGE_DENIED,
        USAGE_NO_ENTITLEMENT, USAGE_NO_SUCH_ACCOUNT, USAGE_TABLE_FULL,
    };
    let resource = crate::capabilities::data_usage_resource(account);
    if let Err(e) = check(&resource) {
        serial_println!("\nSVC: SYS_DATA_ACCOUNT account {} DENIED ({})", account, e);
        return USAGE_DENIED;
    }
    let Some(entitlement) = demo_entitlement(account) else {
        audit_event(
            &resource,
            "Metered",
            "Metered",
            false,
            Some(String::from(
                "refused: no data entitlement for this account",
            )),
        );
        serial_println!(
            "\nSVC: SYS_DATA_ACCOUNT account {} DENIED (no data entitlement for this account)",
            account
        );
        return USAGE_NO_ENTITLEMENT;
    };
    if crate::mvno::standing(account).is_none() {
        audit_event(
            &resource,
            "Metered",
            "Metered",
            false,
            Some(String::from("refused: no such account in the registry")),
        );
        serial_println!(
            "\nSVC: SYS_DATA_ACCOUNT account {} DENIED (no such account)",
            account
        );
        return USAGE_NO_SUCH_ACCOUNT;
    }
    let (before, after) = match crate::data::feed_usage(account, bytes) {
        Ok(v) => v,
        Err(_) => {
            audit_event(
                &resource,
                "Metered",
                "Metered",
                false,
                Some(String::from("refused: usage table full, bytes not counted")),
            );
            serial_println!(
                "\nSVC: SYS_DATA_ACCOUNT account {} bytes {} FAILED (usage table full)",
                account,
                bytes
            );
            return USAGE_TABLE_FULL;
        }
    };
    let assessment = runix_mobile::policy::evaluate_usage(&entitlement, &after);
    let described = describe_usage_assessment(&entitlement, &after, &assessment);
    audit_event(
        &resource,
        &format!("used {}", before.used_bytes),
        &format!("used {}", after.used_bytes),
        true,
        Some(format!("usage fed {bytes} bytes; {described}")),
    );
    if let Some(request) = assessment.escalation {
        // Worded as a REQUEST on purpose: authorized=true records that the
        // feed was authorized and the engine's advice was issued, NOT that
        // anything was done. The `to` state is not a state name an auditor
        // could mistake for a completed transition (the real suspension, if
        // the caller makes it, is its own MARSHAL-gated `Active -> Suspended`
        // entry on `mvno:account:{id}`).
        audit_event(
            &resource,
            &format!("band {:?}", assessment.band),
            &format!("REQUEST {request:?} (advisory; nothing was performed by this syscall)"),
            true,
            Some(String::from(
                "policy engine request to the caller, to be carried out through the governed path",
            )),
        );
    }
    let code = action_request_code(assessment.escalation);
    serial_println!(
        "\nSVC: SYS_DATA_ACCOUNT account {} bytes {} authorized ({}; returns request code {})",
        account,
        bytes,
        described,
        code
    );
    code
}

/// `SYS_DATA_SESSION_OPEN(account, slot, profile | roaming<<8)`. Capability
/// `data:session:{account}`; then every input the engine needs is read from
/// LIVE state, never taken from the caller: standing from the MVNO registry,
/// lifecycle from `sim::profile_state`, usage from the data table, plan from
/// the DEMO entitlement table; only the network class comes from the caller
/// (there is no modem to ask yet). The profile MUST be bound to this account
/// -- an unbound or foreign profile is refused (fail closed) before the engine
/// is consulted, so an account cannot open a session on someone else's SIM.
/// The session is recorded iff the engine allows it.
fn data_session_open(account: u64, slot: usize, packed: u64) -> u64 {
    use runix_kernel_arm::data_codes::{
        demo_entitlement, describe_session_record, lifecycle_for_data, session_decision_code,
        standing_for_data, unpack_profile_roaming, SESSION_FAILED_TABLE_FULL,
        SESSION_REFUSED_BAD_ARGUMENT, SESSION_REFUSED_CAPABILITY, SESSION_REFUSED_NO_ENTITLEMENT,
        SESSION_REFUSED_NO_SUCH_ACCOUNT, SESSION_REFUSED_PROFILE_NOT_BOUND,
        SESSION_REFUSED_UNKNOWN_PROFILE,
    };
    use runix_kernel_arm::data_state::SessionRecorded;
    use runix_mobile::policy::{DenyReason, SessionDecision};

    let resource = crate::capabilities::data_session_resource(account);
    if let Err(e) = check(&resource) {
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} DENIED ({})",
            account,
            slot,
            e
        );
        return SESSION_REFUSED_CAPABILITY;
    }
    let Some((profile, roaming)) = unpack_profile_roaming(packed) else {
        audit_data_session(
            account,
            false,
            "Open",
            format!("refused: malformed packed argument {packed:#x}"),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} FAILED (malformed profile/roaming argument {:#x}: only bits 0..=8 are defined)",
            account,
            slot,
            packed
        );
        return SESSION_REFUSED_BAD_ARGUMENT;
    };
    let Some(entitlement) = demo_entitlement(account) else {
        audit_data_session(
            account,
            false,
            "Open",
            format!("refused: no data entitlement for account {account}"),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} DENIED (no data entitlement for this account)",
            account,
            slot,
            profile
        );
        return SESSION_REFUSED_NO_ENTITLEMENT;
    };
    let Some(status) = crate::mvno::standing(account) else {
        audit_data_session(
            account,
            false,
            "Open",
            format!("refused: no such account {account}"),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} DENIED (no such account)",
            account,
            slot,
            profile
        );
        return SESSION_REFUSED_NO_SUCH_ACCOUNT;
    };
    // Binding check before the lifecycle read, so a profile that is not this
    // account's reveals nothing about its state through a different code.
    let owner = crate::mvno::owner_of(slot, profile);
    if owner != Some(account) {
        let who = match owner {
            None => String::from("bound to no account"),
            Some(o) => format!("bound to account {o}"),
        };
        audit_data_session(
            account,
            false,
            "Open",
            format!("refused: slot {slot} profile {profile} is {who}, not account {account}"),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} DENIED (profile not bound to this account: {})",
            account,
            slot,
            profile,
            who
        );
        return SESSION_REFUSED_PROFILE_NOT_BOUND;
    }
    let lifecycle = match crate::sim::profile_state(slot, profile) {
        Ok(state) => lifecycle_for_data(state),
        Err(e) => {
            audit_data_session(
                account,
                false,
                "Open",
                format!("refused: no lifecycle for slot {slot} profile {profile} ({e})"),
            );
            serial_println!(
                "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} DENIED (unknown profile: {})",
                account,
                slot,
                profile,
                e
            );
            return SESSION_REFUSED_UNKNOWN_PROFILE;
        }
    };

    // Registry and sim locks are released; one short, pure critical section
    // under the leaf data lock decides and records.
    let outcome = crate::data::decide_and_open(
        account,
        slot,
        profile,
        roaming,
        standing_for_data(status),
        lifecycle,
        entitlement,
    );
    let described = describe_session_record(&outcome.record);
    match (outcome.record.decision, outcome.recorded) {
        (SessionDecision::Deny(reason), _) => {
            audit_data_session(
                account,
                false,
                "Open",
                format!("denied {reason:?}; {described}"),
            );
            // Name the cause first (CI greps the reason right after DENIED).
            let cause = match reason {
                DenyReason::ProfileNotEnabled(state) => format!("ProfileNotEnabled({state:?})"),
                other => format!("{other:?}"),
            };
            serial_println!(
                "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} DENIED ({}; {})",
                account,
                slot,
                profile,
                cause,
                described
            );
            session_decision_code(outcome.record.decision)
        }
        (_, SessionRecorded::TableFull) => {
            audit_data_session(
                account,
                false,
                "Open",
                format!("allowed by policy but not recorded: session table full; {described}"),
            );
            serial_println!(
                "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} FAILED (data session table full; {})",
                account,
                slot,
                profile,
                described
            );
            SESSION_FAILED_TABLE_FULL
        }
        (decision, _) => {
            let to = if decision == SessionDecision::AllowThrottled {
                "Open (throttled)"
            } else {
                "Open"
            };
            audit_data_session(account, true, to, format!("allowed; {described}"));
            serial_println!(
                "\nSVC: SYS_DATA_SESSION_OPEN account {} slot {} profile {} authorized ({:?}; {})",
                account,
                slot,
                profile,
                decision,
                described
            );
            // `Allow` is 0 and `AllowThrottled` is 1 (pinned in data_codes).
            session_decision_code(decision)
        }
    }
}

/// `SYS_DATA_SESSION_CLOSE(account, slot, profile)`: removes the session. This
/// is the CALLER carrying out a restriction (or finishing normally) -- the
/// policy path never does it for them -- and it is audited like any other
/// change to what the account may do. It can only ever narrow access, which
/// is why the same `data:session:{account}` capability as OPEN suffices.
fn data_session_close(account: u64, slot: usize, arg: u64) -> u64 {
    use runix_kernel_arm::data_codes::{
        unpack_profile_roaming, CLOSE_BAD_ARGUMENT, CLOSE_DENIED, CLOSE_NOT_OPEN, CLOSE_OK,
    };
    if let Err(e) = check(&crate::capabilities::data_session_resource(account)) {
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_CLOSE account {} slot {} DENIED ({})",
            account,
            slot,
            e
        );
        return CLOSE_DENIED;
    }
    // Plain profile id: the roaming bit has no meaning for a close, and a
    // caller that sets it is confused about which call it is making.
    let Some((profile, false)) = unpack_profile_roaming(arg) else {
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_CLOSE account {} slot {} FAILED (malformed profile argument {:#x})",
            account,
            slot,
            arg
        );
        return CLOSE_BAD_ARGUMENT;
    };
    if crate::data::close_session(account, slot, profile) {
        audit_event(
            &crate::capabilities::data_session_resource(account),
            "Open",
            "Closed (by caller via SYS_DATA_SESSION_CLOSE)",
            true,
            Some(format!("slot {slot} profile {profile}")),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_CLOSE account {} slot {} profile {} authorized (closed by the caller)",
            account,
            slot,
            profile
        );
        CLOSE_OK
    } else {
        audit_event(
            &crate::capabilities::data_session_resource(account),
            "Closed",
            "Closed",
            false,
            Some(format!(
                "slot {slot} profile {profile}: no such open session"
            )),
        );
        serial_println!(
            "\nSVC: SYS_DATA_SESSION_CLOSE account {} slot {} profile {} FAILED (no such open session)",
            account,
            slot,
            profile
        );
        CLOSE_NOT_OPEN
    }
}

/// `SYS_DATA_RECONCILE()`: read-only reconciliation. Capability
/// `data:reconcile`.
///
/// STRUCTURALLY READ-ONLY. The body is: (1) build an immutable `Observed`
/// snapshot from COPIES of live state (`data::snapshot_for_reconcile`), (2)
/// call the pure `runix_mobile::reconcile::reconcile` on it, (3) print and
/// WORM-record each incident, (4) `data::mark_observed` -- the usage table's
/// `last_used` bookkeeping, the reconciler's own memory of what it saw. It
/// calls no `mvno::` or `sim::` function that mutates, and no `data::`
/// function other than `mark_observed`; it holds no lock while auditing. So it
/// cannot change an account's standing, a profile's lifecycle, a usage counter
/// or a session. Correction is a separate, governed, operator-initiated act
/// (e.g. `SYS_MVNO_SUSPEND`, `SYS_DATA_SESSION_CLOSE`): the reconciler's job
/// is to make sure nobody can say "we did not know".
///
/// WORM arguments for an incident: it is EVIDENCE, not a denial and not a
/// transition. `authorized` is `false` because the observed state is not the
/// expected, policy-authorized one; `from`/`to` are `expected <fact>` /
/// `observed <fact>`; the reason says in words that this is reconciler
/// evidence, that it is not a denial, and that nothing was corrected.
fn data_reconcile() -> u64 {
    use runix_kernel_arm::data_codes::RECONCILE_DENIED;
    let resource = crate::capabilities::data_reconcile_resource();
    if let Err(e) = check(&resource) {
        serial_println!("\nSVC: SYS_DATA_RECONCILE DENIED ({})", e);
        return RECONCILE_DENIED;
    }
    let (observed, usage_rows) = crate::data::snapshot_for_reconcile();
    let incidents = runix_mobile::reconcile::reconcile(&observed);
    serial_println!(
        "\nSVC: SYS_DATA_RECONCILE snapshot: {} account(s), {} profile(s), {} session(s)",
        observed.accounts.len(),
        observed.profiles.len(),
        observed.sessions.len()
    );
    for incident in &incidents {
        audit_event(
            &format!("{}:{}", resource, incident.subject),
            &format!("expected {}", incident.expected),
            &format!("observed {}", incident.observed),
            false,
            Some(format!(
                "RECONCILER EVIDENCE (observed drift, not a denial; nothing was corrected): {}",
                incident.kind
            )),
        );
        serial_println!(
            "SVC: SYS_DATA_RECONCILE incident {} (WORM-recorded as evidence; nothing corrected)",
            incident
        );
    }
    // After the snapshot was built and the incidents recorded.
    crate::data::mark_observed(&usage_rows);
    let (entries, chain_ok) = audit_chain_summary();
    serial_println!(
        "SVC: SYS_DATA_RECONCILE authorized ({} incident(s); WORM entries {}, chain verified {})",
        incidents.len(),
        entries,
        chain_ok
    );
    incidents.len() as u64
}

fn check(resource: &str) -> Result<(), runix_capability_manager::CapabilityError> {
    crate::capabilities::check(resource, now_ticks())
}

/// Applies the shared enforcement to one evaluation outcome. A *local
/// failure* denial (the kernel could not run the evaluation; fail closed) is
/// additionally appended to the WORM chain as `authorized: false` with the
/// reason, against the intended transition `subject: from -> to`, since it is
/// a security-relevant denial that is not a remote governance decision.
/// `Refuse`/`HardStop` denials are left exactly as they were (no audit entry).
fn enforce_gate(
    outcome: GateOutcome,
    subject: &str,
    from: &str,
    to: &str,
) -> Result<(), MarshalEnforcementError> {
    let result = esim_marshal::enforce(outcome);
    if let Err(blocked @ MarshalEnforcementError::Local(_)) = &result {
        audit_event(subject, from, to, false, Some(format!("{blocked}")));
        let (entries, chain_ok) = audit_chain_summary();
        serial_println!(
            "SVC: {} denial audited to WORM ({} -> {}, authorized=false; entries {}, chain verified {})",
            blocked,
            from,
            to,
            entries,
            chain_ok
        );
    }
    result
}

/// The MARSHAL gate for the MVNO syscalls: evaluates `action` (building the
/// Kerkese request via `MarshalAction`) and applies the shared enforcement
/// ([`enforce_gate`]: `Refuse`/`HardStop` and local evaluation failures block,
/// `Unreachable` and `Execute` pass). `Err` carries the blocking reason for
/// the DENIED line. `subject`/`from`/`to` describe the intended transition for
/// the local-failure audit entry.
///
/// Must be called with **no lock held** -- `marshal_transport::evaluate` can
/// drive a nested EL0 excursion. Callers therefore evaluate before taking the
/// `mvno` registry lock (which every `mvno::*` call takes internally).
fn marshal_gate(
    action: &MarshalAction<'_>,
    subject: &str,
    from: &str,
    to: &str,
) -> Result<(), MarshalEnforcementError> {
    let outcome = crate::marshal_transport::evaluate(action, MARSHAL_PRINCIPAL);
    enforce_gate(outcome, subject, from, to)
}
