# 0008: `esim.delete` and `mvno.reactivate_account` fail closed when MARSHAL is unreachable

**Status**: Accepted 2026-10-17. Decides two rows of the open-decision table in
[0003](0003-unreachable-marshal-policy-is-per-action.md).

## Context

ADR 0003 made the "MARSHAL is unreachable" policy a per-action table
(`MarshalAction::unreachable_policy()` in `kernel-arm/src/marshal_action.rs`) and
flipped only `data.reset_usage` to `FailClosed`. It left five actions on
`FailOpen` and listed the case for and against each. Two of those cases are
one-sided enough to decide now:

- **`esim.delete`** is irreversible. `Deleted` is terminal in `sim.rs`; there is
  no undelete. A gate that can be switched off by dropping the network, guarding
  an action that cannot be undone, is the worst combination in the table.
- **`mvno.reactivate_account`** restores service to an account that was
  suspended. It has the same shape as the usage reset: "we could not ask, so
  yes" lifts a restriction that someone imposed deliberately.

## Decision

1. `MarshalAction::unreachable_policy()` returns `FailClosed` for
   `Esim { op: "delete", .. }` and for `MvnoReactivate { .. }`. The `Esim` arm is
   split on `op`; the `delete` arm comes first and the remaining `Esim` arm
   (enable) stays `FailOpen`.
2. The denial path is the existing one (ADR 0003, point 3): the syscall prints
   `DENIED (MARSHAL unreachable: fail-closed for this action)`, state is left
   untouched, and the denial is WORM-audited with `authorized=false`. No new
   authorization or logging path was added.
3. **Still `FailOpen`, with reasons**

   | Action | Why it stays open |
   |---|---|
   | `esim.enable` | Bootstrap: enabling a profile can be what provides the connectivity needed to reach MARSHAL, so failing closed could deadlock a phone that has no other route. Revisit only with a designed bootstrap exception. |
   | `mvno.suspend_account` | The restrictive direction. Refusing to cut service because the gate is down would help an abuser; allowing it when unsure fails safe for the operator. |
   | `mvno.bind_profile` | **Decided 2026-10-18: stays FailOpen.** Binding is a prerequisite of enabling: `mvno::gate_enable` returns `NotBound` for an unbound profile (`kernel-arm/src/mvno.rs`, asserted in the boot walk), so a profile cannot be enabled until it has been bound. `esim.enable` is fail-open because enabling may be what gives a fresh device the connectivity to reach MARSHAL. If `bind_profile` failed closed, a device provisioned offline could never bind and so could never enable, which would make the `esim.enable` exemption pointless. Revisit together with `esim.enable` (a bootstrap exception or time-limited offline grants), or if first provisioning is guaranteed to happen online. |

4. **Out of scope: x86 `grid_sandbox::spawn_instance`.** It also has an
   "unreachable" case, but flipping it would break every dev and CI boot that
   has no MARSHAL configured, because it cannot distinguish "unreachable" from
   "not configured". It is a separate decision.

## Consequences

Better:

- Neither a delete nor a reactivation can be obtained by making MARSHAL
  unreachable. The fail-open list shrinks to three actions, each with a stated
  reason.
- Deletion denials and reactivation denials are in the WORM chain.

Worse, or left open:

- **Availability cost.** An operator who is offline cannot reactivate a wrongly
  suspended account, and an offline user cannot delete a broken profile. Both
  now need a reachable MARSHAL. In the plain-boot CI configurations (no proxy)
  both are denied, and the EL0 demo walk reflects that (the account stays
  Suspended and the profile is never deleted in those boots).
- **Not a fix for the link itself.** The proxy link is still unauthenticated, so
  a forged well-formed `Execute` still passes for every governed action (the
  unauthenticated verdict: [BETA_CRITERIA.md](BETA_CRITERIA.md) "Not claimed" 14,
  and [0006](0006-a-reachable-but-faulty-marshal-reply-fails-closed.md)). A stall
  is also still a bypass, but only for the three actions that stay fail-open: a
  reply that is still incomplete when the kernel's wait budget ends is
  `Unreachable`, which admits `esim.enable`, `mvno.bind_profile` and
  `mvno.suspend_account`, and denies `esim.delete`, `mvno.reactivate_account` and
  `data.reset_usage`. Neither the forgery nor the stall is addressed here.
- A time-limited offline grant (see 0003) would reduce the availability cost; it
  is not built.

## Alternatives considered

- **Leave both open until an offline-grant mechanism exists.** Rejected: the cost
  of a gate that an outsider can disable is highest exactly for an irreversible
  action and for lifting a restriction.
- **Flip all five.** Rejected for `esim.enable` (bootstrap deadlock, 0003).
  `mvno.suspend_account` is rejected on direction of effect, and
  `mvno.bind_profile` is rejected because binding is a prerequisite of enabling
  (see the table above).

## Revisit when

- A bootstrap exception or offline grant is designed (could re-open `enable`,
  and relax the availability cost of these two).
- First provisioning of a device is guaranteed to happen with MARSHAL reachable, or a
  bootstrap exception is designed for `esim.enable`: `mvno.bind_profile` should then be
  reconsidered together with it.
- `grid_sandbox::spawn_instance` gets a distinguishable "not configured" state.

## References

- `kernel-arm/src/marshal_action.rs` (`unreachable_policy`,
  `unreachable_policy_table_is_pinned`)
- `kernel-arm/src/svc.rs` (`enforce_gate`), `kernel-arm/src/el0.rs` (the demo
  walk)
- `.github/workflows/ci.yml` (the two plain-boot steps assert the denials)
- [0003](0003-unreachable-marshal-policy-is-per-action.md),
  [0002](0002-usage-reset-is-marshal-gated.md),
  [0006](0006-a-reachable-but-faulty-marshal-reply-fails-closed.md)
