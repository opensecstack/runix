# 0004: A usage reset before the billing period ends needs its own capability

**Status**: Accepted 2026-10-11. Refines
[0002](0002-usage-reset-is-marshal-gated.md) and closes gap 26 of the mobile
threat model.

## Context

`SYS_DATA_RESET` zeroes an account's usage counter and starts a new billing
period. ADR 0002 gated it behind MARSHAL because it lifts a cap. It did not look
at the billing period, so a holder of `data:reset:{account}` could reset any
account at any time, any number of times. The period work (`SYS_DATA_PERIOD`)
already told callers when a reset was due, but nothing enforced it.

A reset is also the only way to restore service to an over-cap account, so
"refuse unless the period has elapsed" on its own would remove a legitimate
operator action, such as restoring service after a mid-period top-up.

## Decision

Split the power in two:

- **Normal reset**, capability `data:reset:{account}`: allowed only when the
  account's billing period has elapsed. A successful reset installs a new active
  period, so a normal reset can happen at most once per period.
- **Early reset**, capability `data:reset-early:{account}`, selected by the
  syscall's second argument (`1`): allowed in an active period as well. It is a
  separately grantable override, and its audit entry says so.

Both use the same MARSHAL action, `data.reset_usage`, and both are fail-closed
when MARSHAL is unreachable (ADR 0003). No new action type is needed, so no
upstream CITADEL change is required.

The period check runs before the MARSHAL gate, so a refused reset costs no round
trip. A period refusal is WORM-audited with `authorized=false` and starts no
period. A clock before the period start is refused for both modes. An unknown
mode is refused first.

The decision itself is a pure function, `mobile::period::reset_permitted`, so it
is host-tested without a boot.

## Consequences

- A holder of only the normal capability can no longer reset early or twice in a
  period. Early resets are rarer, separately authorized and visibly flagged in
  the chain.
- The early capability is as powerful as the old unrestricted reset. Whoever
  holds it, and can obtain an `Execute` verdict, can still reset repeatedly.
  Today the EL0 demo holds every token (the flat capability set, gap 5), so the
  split is proven by a denial proof for an account without the early token, not
  by a real privilege boundary.
- **An account with no billing period can still be reset repeatedly**, as before.
  There is nothing to gate against. This remains a gap.
- The period is still counted from boot, not the calendar (gap 29), and nothing
  polls it (gap 28). This decision does not change either.
- The demo gains an extra DEMO-only account with a one-day period, so the
  "period still active" refusal is deterministic in CI.

## Alternatives considered

- **Require an elapsed period for every reset, no override.** Strictest, but it
  removes the mid-period restore-service action that ADR 0002 intends the gate to
  allow.
- **One reset per period, one capability.** Closes the "repeatedly" half only.
  An early reset would stay available to anyone holding the single capability.
- **Leave it as documented and rely on the MARSHAL gate.** Rejected: the gate
  decides whether to allow a reset, but nothing told it that this one was early
  or repeated, so the audit trail could not distinguish the two.
- **A new MARSHAL action type for the early reset.** It would let CITADEL policy
  treat the override differently, but needs an upstream `rbacMap` entry. Worth
  revisiting once the operator-identity work lands.

## Revisit when

- The capability set stops being flat (gap 5), so the early capability can be
  withheld from a real caller.
- CITADEL grows a distinct action for the override, or a real operator identity
  exists to authorize it.
- Billing periods are tied to the calendar (gap 29) or polled by a daemon
  (gap 28), which changes what "elapsed" means.
- Accounts without a billing period need a reset limit.
