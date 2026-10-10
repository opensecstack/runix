# 0001: Data policy syscalls are not MARSHAL-gated; the engine only requests

**Status**: Accepted, 2026-10-10 (Beta item 4, the mobile data policy engine).
Amended by [0002](0002-usage-reset-is-marshal-gated.md): the usage-period reset,
which this record named as a revisit trigger, is the one data syscall that is
MARSHAL-gated. Everything below still holds for every other data syscall.

## Context

The mobile side routes its *consequential* state changes through a CITADEL
MARSHAL gate: eSIM enable and delete, and MVNO bind, suspend and reactivate
(`kernel-arm/src/marshal_action.rs`, `docs/STATUS.md` "Mobile Beta"). Each gated
call costs a real network round trip to a MARSHAL proxy, run in a fresh EL0
process, and its outcome is `Execute`, `Refuse`, `HardStop`, or a fail-open or
fail-closed result when the evaluation itself cannot be completed.

Item 4 adds a data policy engine (`mobile/src/policy.rs`) and a reconciler
(`mobile/src/reconcile.rs`), exposed through four syscalls in `kernel-arm`:
`SYS_DATA_ACCOUNT` (feed usage), `SYS_DATA_SESSION_OPEN`,
`SYS_DATA_SESSION_CLOSE`, and `SYS_DATA_RECONCILE` (numbers 19 to 22). The
question this record settles is whether those syscalls, and the engine's
decisions, should themselves be MARSHAL-gated, and who is allowed to act on a
policy decision such as "this account's usage is anomalous, suspend it".

Two constraints made the answer non-obvious:

- CLAUDE.md requires that privileged actions flow through MARSHAL and that no
  parallel authorization or logging path exist. A new family of syscalls that
  skips the gate needs a stated reason, not silence.
- The usage feed is called often and by design from the data path, so a network
  round trip per call would be both slow and a new availability dependency on
  the MARSHAL proxy.

## Decision

1. **The policy engine is pure, stateless and advisory.** It is a set of
   functions of (entitlement, usage, standing, lifecycle, network class) with no
   I/O, clock or stored state, so every decision can be replayed from its
   inputs. It returns an `ActionRequest` (for example `SuspendAccount`). It holds
   no authority and performs no action.
2. **A request is carried out by the caller, through the existing governed
   path, under the caller's own capability.** The data syscalls never suspend,
   disable or close anything in response to a request. In the boot walk the
   anomalous-usage request is carried out by the existing, MARSHAL-gated
   `SYS_MVNO_SUSPEND`.
3. **The data syscalls are capability-checked on every call and WORM-audited,
   but not MARSHAL-gated, and there are no `data.*` MARSHAL action types.** They
   read policy and update a usage counter or a session table. They do not change
   account or profile lifecycle state. The one consequential effect a policy
   decision can lead to, suspension, stays behind its own gate.
4. **The reconciler observes and reports only.** `reconcile(&Observed)` takes a
   shared reference and returns descriptive incidents. `SYS_DATA_RECONCILE`
   WORM-records them as evidence and mutates nothing except its own
   last-seen-usage bookkeeping.
5. **The usage feed is a privileged write with its own capability scope**
   (`data:usage:{account}`), separate from session access
   (`data:session:{account}`) and from reconciliation (`data:reconcile`), because
   asserting usage can push an account over its cap and so deny service.
6. **"No data action reaches MARSHAL" is enforced two ways.** `MarshalAction` has
   no data variant, so the code cannot build such a request. CI also fails if a
   `MARSHAL evaluation for data` line ever appears in a boot log. The CI check is
   a tripwire on the log label, not a proof; the structural guarantee is the
   missing variant.

## Consequences

Better:

- No new MARSHAL action types, so no new upstream `rbacMap` entries and no new
  `citadel_proxy` policy shapes for this feature.
- The data path has no runtime dependency on the MARSHAL proxy being reachable.
- A policy bug can request a bad action but cannot perform one: a wrong request
  still has to pass the caller's capability and the MARSHAL gate.
- Decisions are replayable, so an audit can recompute any recorded decision.

Worse, or left open (each is a recorded known gap in `docs/STATUS.md`):

- **Policy alone enforces nothing.** A caller that ignores a `SuspendAccount`
  request leaves the system exactly as it was. The reconciler surfaces that as
  `AnomalousUsageNoEscalation`, but only when someone calls it; nothing runs it
  periodically.
- **Usage is caller-asserted.** The holder of `data:usage:{id}` states how many
  bytes were used and nothing measures it, so it can lie in either direction.
- **A denied session cuts off no traffic**, because there is no real data path
  yet. A `Deny` is a bookkeeping fact until one exists.
- **There is no governed usage-period reset**, so an account past its cap stays
  denied until reboot.
- **The audit is not total.** Decisions, requests and incidents are on the WORM
  chain; capability denials and a few malformed-argument refusals are serial-only.
- `PolicyDecisionRecord::replays()` detects an internally inconsistent record,
  not a fully recomputed forgery, and the kernel records a text description on
  the chain rather than the struct.

## Alternatives considered

- **Gate every data syscall with MARSHAL.** Rejected. It adds a network round
  trip and a MARSHAL dependency to a high-frequency path, and it gates operations
  that change no lifecycle state. The consequential step is already gated where
  it happens.
- **Let the engine execute its own requests** (auto-suspend on anomalous usage).
  Rejected. The engine would become a writer that sits outside the capability
  check and the MARSHAL gate, which is the parallel authorization path CLAUDE.md
  forbids.
- **A self-correcting reconciler.** Rejected for the same reason. Correcting
  drift is a separate, governed, operator-initiated action; a reconciler that
  heals itself is an ungoverned writer, and it would hide the drift it should
  report.
- **Add `data.*` MARSHAL action types for the feed and session open.** Rejected
  for now as cost without benefit (see the first alternative). It is the first
  thing to reconsider if the trigger below fires.

## Revisit when

- A real data path or metering exists, so a `Deny` can actually cut traffic and
  the usage feed stops being caller-asserted.
- A usage-period reset is added, because whoever holds it can lift a cap, which
  makes it a consequential, governable action.
- Per-sandbox-tier (T1, T2, T3) traffic policy is added, which puts an app
  identity on the data path.
- A periodic or event-driven reconciler trigger is added.
- The MARSHAL principal stops being a placeholder (per-process identity), which
  changes who a request is carried out as.

## References

- `mobile/src/policy.rs`, `mobile/src/reconcile.rs`
- `kernel-arm/src/svc.rs` (syscalls 19 to 22), `kernel-arm/src/data.rs`,
  `kernel-arm/src/data_codes.rs`, `kernel-arm/src/data_state.rs`
- `kernel-arm/src/marshal_action.rs` (`MarshalAction` has no data variant)
- `.github/workflows/ci.yml` (the "no data action is ever sent to MARSHAL" check)
- `docs/STATUS.md`, "Mobile Beta" and its "Data policy engine" subsection
- Commits 1660232 (engine and reconciler) and aef10bd (kernel wiring)
