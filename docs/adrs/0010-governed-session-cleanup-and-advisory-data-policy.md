# 0010: Governed paths close the data sessions they end; the usage feed meters only Active, bound accounts; the policy engine stays advisory

**Status**: Accepted 2026-10-18. Closes THREAT_MODEL gaps 17 and 21 and records
the decision for the policy engine's "act on its own advice" question (called
M3-c in the Beta plan). Builds on
[0001](0001-data-syscalls-not-marshal-gated.md) and
[0009](0009-bounded-worm-chain-and-denial-auditing.md).

## Context

The data layer (`kernel-arm/src/data.rs`, `data_state.rs`, `data_codes.rs`)
keeps two pieces of state next to the MVNO registry and the eSIM slots: a usage
counter per account and a table of open data sessions
(`MAX_DATA_SESSIONS` = 16). The policy engine (`runix_mobile::policy`) only
REQUESTS; the reconciler only OBSERVES; whatever acts, acts through a governed
syscall under its own capability (0001).

Two holes followed from that split, found by reading the code:

1. **Session rows outlived the thing that justified them.** A session is
   recorded only when an Active account's Enabled, bound profile allowed it.
   `SYS_MVNO_SUSPEND` force-disables the account's profiles but touched no
   session; the delete path only unbound the profile; an operator
   `SYS_SIM_DISABLE` only disabled it. The only way a row left the table was an
   explicit `SYS_DATA_SESSION_CLOSE` by the caller. Stale rows were not just
   untidy: enough of them made new, policy-allowed sessions fail with the
   table-full code (13), and the reconciler could do nothing but report the
   `session-without-enabled-profile` finding forever. The EL0 walk demonstrated
   the leak on purpose.
2. **The usage feed metered anyone.** `SYS_DATA_ACCOUNT` checked the capability,
   the entitlement and that the account exists. Bytes were therefore counted for
   Suspended and Closed accounts and for accounts that own no profile.

## Decision

### 1. Session cleanup belongs to the governed caller, not the engine

When a governed path ends the precondition of a session, that same path drops
the session rows, in the same syscall, after its own state change and with no
lock held:

| Governed path | Cleanup |
|---|---|
| `SYS_MVNO_SUSPEND` (capability + MARSHAL `mvno.suspend_account`), after the forced-disable loop | every session of the suspended account |
| `SYS_SIM_DELETE` success (capability + MARSHAL `esim.delete`), after `unbind` | every session on the deleted `(slot, profile)` |
| `SYS_SIM_DISABLE` success (operator; capability, audited, no MARSHAL gate) | every session on the disabled `(slot, profile)` |

The operator disable is included because the code confirms it left rows: it
called `sim::disable` and nothing else. A session on a Disabled profile is the
same stale state the reconciler already calls an incident, and disabling is the
restrictive direction, so closing the session narrows access and cannot lift
anything. (Reached only by an Enabled profile: the profile's open sessions
exist only while it is Enabled, so a disable that succeeds is exactly the case
that can have rows. The delete path is defense in depth: delete needs a
Disabled profile, so any row was already closed by the disable or the suspend;
it is covered by host tests and by reading the code, not by a boot.)

Mechanism: `DataState::close_sessions_for_account(account)` and
`close_sessions_for_profile(slot, profile)` are pure, return the removed rows,
and leave every other row (other accounts, other profiles) alone. `data.rs`
wraps them under the leaf `DATA` lock; `svc.rs` calls them from the three
paths. No new lock-order edge: the registry -> sim -> data order is unchanged
(`DATA` is the leaf; each call is made with the registry and sim locks released
and the data lock is released before the audit).

Audit: one `DataActivity` entry per closed row (`Open -> Closed (kernel cleanup
after MVNO suspend | operator SIM disable | SIM delete)`, reason `slot S profile
P`) plus one serial line per row. No new audit class; at most
`MAX_DATA_SESSIONS` rows exist, so one cleanup cannot exceed the class's
quota of 64 (ADR 0009 counts and summarises any overflow). A caller who closes a
session afterwards gets `CLOSE_NOT_OPEN`, audited as a `Rejected` event.

Why this is not the engine acting on its own advice: the cleanup is performed by
a syscall that is already capability-gated and, for suspend and delete,
MARSHAL-gated, and it removes DERIVED state whose only justification the same
syscall has just revoked; it is the same category as the forced disable that
already sits in that code. No `ActionRequest` reaches any of this code, and
`decide_and_open` still never closes a row (a deny leaves an open session
alone).

### 2. The usage feed: Active and bound only

`SYS_DATA_ACCOUNT` now refuses, after the capability, entitlement and existence
checks and before any counter is touched:

- an account whose standing is not Active: `USAGE_NOT_ACTIVE` (8);
- an Active account that owns no bound profile: `USAGE_NO_PROFILE` (9).

Standing is checked first (`data_codes::usage_feed_refusal`, pure and host
tested; `mvno::has_bound_profile` is a thin wrapper over the registry's
`profiles_of`). Each refusal is a `Rejected` audit entry and a serial line
(`DENIED (...; returns code N)`); neither is a capability denial, so the
`cap-denial.data` counts are unchanged.

**Suspended is refused, not counted.** A Suspended account has no Enabled
profile and, since decision 1, no session: there is no service whose use could
be metered, so a feed that arrives is a stale or confused meter. Counting it
would move a counter the reconciler treats as evidence, could make a later
reactivation start over cap, and would let a feeder generate escalation
requests against an account that is already restricted. Closed is the same.
The alternative, counting but flagging, was rejected because it keeps an
unattributable number in the one table whose job is to be attributable. The cost
is that bytes a real meter reports late (after the suspension) are not
recorded; they are reported to the feeder by a distinct code and recorded in the
audit chain with their size, not silently dropped.

Not claimed: a binding check proves that the account owns a profile, not that
the bytes passed over it, and not that the feeder is honest. The feed's
bytes are still an unauthenticated number from a caller holding
`data:usage:{account}`.

### 3. The policy engine stays advisory (M3-c)

No code performs an `ActionRequest`. The engine's `SuspendAccount` is still
returned as code 3 to the caller, and the EL0 walk's `SYS_MVNO_SUSPEND` is the
caller's act through the governed path (capability, MARSHAL, WORM), exactly as
before. The cleanup in decision 1 follows a suspension; it does not perform one.

Revisit when both of the following hold, and not before:

- usage is **measured** (a modem-side or driver-side meter whose bytes are
  authenticated), not a number a capability holder reports; acting on a forged
  number would turn the feed into a way to suspend someone else's account, and
- the kernel has an **operator identity** (the same blocker as
  [0007](0007-dry-run-true-stays-until-operator-identity.md)), so a
  kernel-initiated suspension has an actor MARSHAL's separation-of-duties rules
  can accept, instead of a kernel acting as its own approver.

## Consequences

Better:

- Suspending an account, deleting a profile or disabling it frees its sessions
  at once; the table-full exhaustion through stale rows is closed for these
  paths, and the reconciler no longer reports a leak the kernel itself created.
- The usage counter takes bytes only for an Active account with a profile.
- The decisions about acting on advice are written down with their triggers.

Worse, or left open:

- **A stale row can still exist** if a path that ends a session's precondition
  is added later without calling the cleanup (the same maintenance hazard as
  the suspend's forced-disable list). The reconciler's
  `session-without-enabled-profile` is the backstop and stays.
- **Reactivation does not restore sessions.** A reactivated account must open
  new ones (profiles also stay Disabled until re-enabled, as before).
- **Cleanup is at the moment of the action only.** Nothing sweeps the table on a
  timer, and a failed forced disable still closes the suspended account's rows.
- The feed refusal reveals standing and binding to a feeder: both codes are
  distinct on purpose, and the feeder already holds the account's usage
  capability.
- Demo accounts: account 1 is the walk's Active-but-unbound account, so it is
  issued `data:usage:1` (the feed only), which is DEMO DATA like the rest.

## Residual gaps

- **The reconciler is a backstop only when someone calls it.** `SYS_DATA_RECONCILE`
  runs when a caller asks; nothing schedules it, so a row leaked by a future path
  stays unreported until the next call.
- **The boot walk no longer demonstrates the backstop.** It used to leave a
  session open on a Disabled profile on purpose and show the reconciler's
  `session-without-enabled-profile` finding; the cleanup removes that leak, so
  that incident is now exercised by host tests only (`data_state` / reconcile
  tests), not by a boot. CI asserts it never appears in the plain boots.
- **The three paths are the whole list today** (the only callers of
  `sim::disable`, `sim::delete` and `mvno::suspend` in `svc.rs`), found by
  reading the code, not enforced by the type system. The delete path is
  exercised by host tests only: the profile must be Disabled to be deleted, so
  its rows were already closed by the disable or the suspend.
- **No modem or driver session exists.** A row is the kernel's bookkeeping; closing
  it does not tear down any real bearer, because there is none yet.
- **The feed stays unauthenticated** (see decision 2): standing and binding checks
  narrow who can be metered, not whether the byte count is true.

## Alternatives considered

- **Have the policy engine or the reconciler close stale sessions.** Rejected:
  the reconciler is structurally read-only, and an engine that mutates state in
  response to its own request erases the line 0001 draws.
- **Cleanup in `sim.rs` or `data_state.rs` triggered by state change.** Rejected:
  both are deliberately ignorant of accounts and of each other, and a hidden
  callback would add the lock edge the current design avoids.
- **Leave operator disable alone.** Rejected: it leaves exactly the row the
  suspend path now cleans, so the leak would remain one syscall away.
- **Count Suspended usage and let the reconciler flag it.** Rejected, see
  decision 2.
