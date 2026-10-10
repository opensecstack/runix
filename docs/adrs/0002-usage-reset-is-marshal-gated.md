# 0002: The usage-period reset is the one MARSHAL-gated data action

**Status**: Accepted, 2026-10-11. Amends [0001](0001-data-syscalls-not-marshal-gated.md)
(which stays in force for every other data syscall). Refined by
[0003](0003-unreachable-marshal-policy-is-per-action.md): decision 4 below, as
first written, said an unreachable MARSHAL lets a reset through; it no longer
does (the reset is fail-closed), and the text now says so.

## Context

ADR 0001 decided that the mobile data syscalls (feed usage, open and close a
session, reconcile) are capability-checked and WORM-audited but not
MARSHAL-gated, because they update a counter or a table and read policy; the one
consequential effect a policy decision can lead to, suspension, stays behind its
own gate. It listed a usage-period reset among its revisit triggers: "whoever
holds it can lift a cap, which makes it a consequential, governable action."

That gap was real. An account past its data cap stayed denied until reboot,
because the pure `reset_usage()` existed in `mobile/src/policy.rs` but nothing
could call it. Adding a way to call it creates exactly the lever ADR 0001
warned about: restoring service to an account the policy had cut off. Unlike the
usage feed, which can only push an account toward a denial, a reset moves the
other way and is where fraud or an operator mistake would hurt the subscriber
relationship or the business.

## Decision

1. **`SYS_DATA_RESET(account)` (syscall 23) is MARSHAL-gated.** It is the one
   data syscall that is. Its action type is `data.reset_usage`, with the request
   body `{"type":"data.reset_usage","account":A}`. It is a new
   `MarshalAction::DataResetUsage` variant, evaluated through the same transport
   and the same enforcement as the eSIM and MVNO actions.
2. **Order of checks.** Capability, then account and entitlement existence, then
   the MARSHAL gate, then the mutation, then the audit.
   - The capability is `data:reset:{account}`, a scope separate from usage
     feed, session access and reconciliation, so holding any of those does not
     confer the right to lift a cap.
   - The existence checks run before the gate so a reset that cannot happen
     costs no network round trip, the same reasoning as `mvno::gate_enable`
     ahead of the eSIM enable gate.
   - No lock is held across the MARSHAL evaluation, because it can run a nested
     EL0 excursion.
3. **The mutation is minimal.** It sets the account's usage counter to zero with
   the pure `reset_usage()` and clears the reconciler's last-seen usage, which is
   how a legitimate period reset is signalled so the reconciler does not report
   a usage regression. It does not close sessions, change account standing, or
   touch profiles. The before and after byte counts go to the WORM chain.
4. **The failure policy.** A Refuse or HardStop denies the reset and leaves
   usage unchanged. A local failure of the evaluation machinery fails closed and
   is audited. An unreachable MARSHAL **also fails closed for the reset**
   (decided in [0003](0003-unreachable-marshal-policy-is-per-action.md); this
   record first shipped with the reset failing open like every other gated
   action, which let anyone who could break the link obtain a reset). The reset
   is the only gated mobile action with this property today.
5. **ADR 0001's guarantee is narrowed, not dropped.** There is still no gating
   of any other data syscall. The CI tripwire that used to forbid any
   `MARSHAL evaluation for data` line now allows exactly one label,
   `data.reset_usage`, and requires exactly one such line per boot. A stray
   evaluation for any other data action still fails the build.
6. **Governance plumbing.** `citadel_proxy` recognizes the action (requires
   `account`; rejects `slot`, `profile`, `module_id`, `instance_id`) and
   attributes its WORM entry to module `data`. The upstream CITADEL `rbacMap`
   needs a `data.reset_usage` entry in both the admin and operator lists; that
   entry was prepared as a separate change and, at the time of writing, had not
   been merged upstream.

## Consequences

Better:

- An over-cap account can be restored without a reboot, and the act of
  restoring it is governed, capability-scoped and audited.
- The engine's invariant is intact: the engine still only requests, and the
  reset is a separate caller-initiated action under its own capability.
- The reconciler stays quiet about a legitimate reset, and still reports a real
  usage regression.

Worse, or left open:

- **A reset needs a reachable MARSHAL.** Since [0003](0003-unreachable-marshal-policy-is-per-action.md)
  the reset is fail-closed: with the proxy unreachable (or no proxy configured,
  as in the plain boot configurations) the reset is denied. This closes what
  this record first listed as the most consequential reset-specific weakness (a
  reset proceeding ungoverned because the link was broken), at the price that a
  proxy outage now refuses resets.
- **Usage is still caller-asserted.** Resetting the counter does not make the
  numbers measured; a holder of the usage-feed capability can still misreport.
- **Nothing resets automatically.** A billing-period boundary still needs a
  caller to issue the reset; the kernel has no timer-driven actor. (A pure
  billing-period model and a read-only `SYS_DATA_PERIOD` now let a caller learn
  that a period has elapsed and that a reset is requested; carrying it out is
  still a governed caller action.)
- **One more MARSHAL evaluation per boot** (eight, up from seven), a measured
  cost of roughly half a second of host CPU.
- **Upstream dependency.** Until the `rbacMap` entry is merged, a live CITADEL
  hard-REFUSEs `data.reset_usage` at Gate 2. CI's mock CITADEL always answers
  `EXECUTE`, so CI cannot see this.

## Alternatives considered

- **Leave the reset ungated like the other data syscalls.** Rejected. It lifts a
  cap, which is the consequential direction ADR 0001 reserved.
- **Reset on a schedule inside the kernel.** Rejected: it would be an ungoverned
  writer unless it routed through the same gate, and the kernel has no
  timer-driven actor to carry it. (The period model needed to know *when* a
  reset is due now exists as pure data; see the note under Consequences.)
- **Let the engine request a reset.** Rejected. A reset is not something the
  engine should ever suggest on its own; the engine requests restrictions, and
  lifting one is an operator or billing decision.
- **Expose the reset through the usage-feed capability.** Rejected: a holder of
  the feed could then both push an account over its cap and lift it again.

## Revisit when

- A periodic or billing-period reset trigger is added; it must go through this
  same gate, under its own identity.
- Real metering exists, so usage stops being caller-asserted.
- The MARSHAL principal stops being a placeholder (per-process identity), which
  changes who a reset is evaluated as.
- The fail-open-on-unreachable policy is reconsidered for any gated mobile
  action; this one is the strongest argument for treating a reset differently.

## References

- `kernel-arm/src/svc.rs` (`SYS_DATA_RESET`), `kernel-arm/src/data.rs`,
  `kernel-arm/src/data_state.rs`, `kernel-arm/src/data_codes.rs`,
  `kernel-arm/src/marshal_action.rs` (`DataResetUsage`),
  `kernel-arm/src/capabilities.rs` (`data_reset_resource`)
- `desktop/src/citadel/policy.rs`, `desktop/src/citadel/proxy.rs`
- `mobile/src/policy.rs` (`reset_usage`), `mobile/src/reconcile.rs`
- `.github/workflows/ci.yml` (the narrowed tripwire, the Refuse and Execute
  reset assertions)
- [0001](0001-data-syscalls-not-marshal-gated.md), `docs/STATUS.md` "Data policy
  engine"
