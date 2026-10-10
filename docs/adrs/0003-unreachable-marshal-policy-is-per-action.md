# 0003: What happens when MARSHAL is unreachable is decided per action

**Status**: Accepted for `data.reset_usage` (fail-closed). Open for the other
gated mobile actions, which keep their existing fail-open behaviour until the
maintainers decide otherwise. Accepted 2026-10-11. Refines
[0002](0002-usage-reset-is-marshal-gated.md).

## Context

Every MARSHAL-gated mobile syscall (`esim.enable`, `esim.delete`,
`mvno.bind_profile`, `mvno.suspend_account`, `mvno.reactivate_account`,
`data.reset_usage`) asks a proxy for a verdict. The evaluation can end four ways:

- a remote verdict: `Execute`, or `Refuse` / `HardStop`;
- the remote could not be reached or gave no usable answer
  (`Unreachable`: no proxy configured, no network device, connect failure or
  timeout, an undecodable reply);
- the kernel could not run the evaluation at all (`LocalFailure`: process setup
  including out of memory, thread spawn, an EL0 fault);
- (for the proxy's own policy refusals) a `Refuse`, via `PolicyRefused`.

Refuse, HardStop and LocalFailure have always blocked. `Unreachable` was
uniformly treated as **allow** ("fail-open"), by the policy recorded in
`docs/MARSHAL-ENFORCEMENT-POLICY.md` (Option B). Two things made that policy
uncomfortable once the data reset existed:

1. **Fail-open is a bypass lever.** While the proxy is unreachable, every gated
   operation proceeds ungoverned. An attacker who can make the link fail (drop a
   connection, exhaust the path) turns the gate off for the operations they pick.
2. **A uniform answer is wrong in both directions.** A phone that must enable an
   eSIM profile to *get* connectivity cannot ask a remote gate for permission
   first, so fail-closed there would deadlock bootstrapping. But a usage reset
   restores service to an account that policy had cut off; it has no safe
   default, and "we could not ask, so yes" is the wrong answer.

## Decision

1. **The policy is a per-action property, decided in one exhaustive `match`.**
   `MarshalAction::unreachable_policy()` (`kernel-arm/src/marshal_action.rs`,
   pure and host-tested) returns `FailOpen` or `FailClosed` for every action.
   Because the match is exhaustive, a new gated action cannot compile without
   choosing, and flipping an existing action is a one-line change that shows up
   in review. It is a compile-time table, deliberately **not** a runtime or
   configuration switch: a switch that turns the gate off is itself an attack
   surface.
2. **Current table**

   | Action | When MARSHAL is unreachable | Reason |
   |---|---|---|
   | `data.reset_usage` | **FailClosed** | Restores service; no safe default. |
   | `esim.enable`, `esim.delete` | FailOpen (unchanged) | See "Open" below. |
   | `mvno.bind_profile` | FailOpen (unchanged) | See "Open" below. |
   | `mvno.suspend_account`, `mvno.reactivate_account` | FailOpen (unchanged) | See "Open" below. |

3. **A fail-closed denial is the kernel's own decision and is audited.** It
   prints `DENIED (MARSHAL unreachable: fail-closed for this action)`, leaves
   state untouched, returns a distinct code, and is written to the WORM chain
   with `authorized=false`, like the existing local-failure denials. It is not
   dressed up as a remote verdict.
4. **Every gated success records the verdict that allowed it**, in both the WORM
   entry and the serial line: `MARSHAL verdict: Execute`, or
   `MARSHAL verdict: Unreachable (fail-open: not governed)`. An auditor can now
   tell a governed action from one that proceeded because the gate could not be
   reached.

## Consequences

Better:

- A usage reset can no longer be obtained by making MARSHAL unreachable.
- The chain no longer hides the difference between "MARSHAL said yes" and
  "MARSHAL was not asked".
- The remaining fail-open actions are a visible, reviewable list rather than an
  implicit global default.

Worse, or left open:

- **Offline operation of a reset is gone.** With no proxy configured (the plain
  boot configurations) a reset is denied. That is the intended behaviour and the
  CI plain-boot steps now assert it, but it means a reset needs a reachable
  MARSHAL.
- **The other five actions are still ungoverned when MARSHAL is unreachable.**
  This ADR does not close that; see below.
- A fail-closed action turns an outage of the proxy into a refused operation,
  so the proxy's availability now matters for resets.

## Open decisions (for the maintainers)

These are the actions still on `FailOpen`. The table is a one-line change per
row, so the decision is cheap to implement once made; the real cost is the
availability trade-off.

| Action | Case for FailClosed | Case for FailOpen |
|---|---|---|
| `esim.delete` | Irreversible. The strongest remaining candidate. | An offline user cannot remove a broken profile. |
| `mvno.bind_profile` | Claims ownership of a profile for an account. | Provisioning on a device that is offline. |
| `mvno.suspend_account` | Cuts a subscriber's service; abuse is a denial-of-service lever. | Suspension is the *restrictive* direction; allowing it when unsure fails safe for the operator. |
| `mvno.reactivate_account` | Restores service, the same shape as the reset. | An offline operator cannot restore a wrongly suspended account. |
| `esim.enable` | Switches the active subscription. | **Bootstrap deadlock**: enabling a profile can be what provides the connectivity needed to reach MARSHAL. Keep fail-open unless a bootstrap exception is designed. |

A middle path worth designing before flipping anything: time-limited offline
grants (a recent `Execute` for the same action and account allows a bounded
number of offline uses), which keeps a phone usable offline without letting an
outage act as a blanket allow. That needs a clock and a place to keep the grant,
neither of which exists yet.

## Alternatives considered

- **Everything fail-closed.** Rejected: the eSIM-enable bootstrap deadlock above,
  and an unreachable proxy would then disable the whole subscription lifecycle.
- **Everything fail-open (the previous state).** Rejected for the reset: it
  makes the reset ungatable by anyone who can break the link.
- **A runtime or build-time configuration flag per deployment.** Rejected for
  now: a switch that disables governance is an attack surface, and the table is
  small enough to review in code.
- **Treating `Unreachable` as `Refuse` for all actions but allowing an
  explicit operator override.** Not built; it needs an authenticated override
  channel that does not exist.

## Revisit when

- A bootstrap exception or time-limited offline grant is designed, which is what
  would make fail-closed viable for `esim.enable` and the others.
- The maintainers decide any row of the open-decision table.
- The MARSHAL principal stops being a placeholder (per-process identity).
- A new gated action is added; the exhaustive match forces the choice, and this
  record should gain a row.

## References

- `kernel-arm/src/marshal_action.rs` (`UnreachablePolicy`,
  `MarshalAction::unreachable_policy`, `enforce`, `verdict_text`)
- `kernel-arm/src/svc.rs` (`enforce_gate`, `marshal_gate`, the gated syscalls)
- `kernel-arm/src/data_codes.rs` (`RESET_DENIED_UNREACHABLE`)
- `.github/workflows/ci.yml` (the plain-boot steps assert the fail-closed reset;
  the Refuse and Execute steps assert the recorded verdicts)
- `docs/MARSHAL-ENFORCEMENT-POLICY.md` (Option B, the original fail-open policy)
- [0001](0001-data-syscalls-not-marshal-gated.md),
  [0002](0002-usage-reset-is-marshal-gated.md), `docs/STATUS.md` "Mobile Beta"
