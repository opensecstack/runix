# 0005: A reset on a no-period account installs a period, and early resets have a cooldown

**Status**: Accepted 2026-10-11. Refines
[0004](0004-early-usage-reset-has-its-own-capability.md), which left two limits
open.

## Context

[0004](0004-early-usage-reset-has-its-own-capability.md) gated a normal reset on
the billing period and moved the mid-period override behind its own capability.
It left two things open:

1. An account with **no billing period** had nothing to gate against, so it could
   be reset repeatedly.
2. The **early capability** was as powerful as the old unrestricted reset. Holding
   `data:reset-early:{id}` and getting an `Execute` verdict allowed any number of
   back-to-back early resets.

## Decision

- **First reset installs a period.** The first reset on an entitled account that
  has no billing period is still allowed, and it installs a period starting at the
  reset tick. The length is DEMO DATA ONLY (the one-day demo constant). From then
  on the account is gated like any other: a normal reset needs the period to have
  elapsed, and a mid-period reset needs the early capability. The WORM reason and
  serial line say a period was installed because none existed.
- **Early resets have a cooldown.** The kernel records the tick of the last
  applied reset per account (normal or early). An early reset is refused if any
  reset was applied to that account less than the cooldown ago (a DEMO constant,
  one hour). Exactly at the boundary is allowed. A rewound counter (`now` before
  the recorded tick) is refused with the full cooldown, so it cannot underflow or
  allow a reset. A normal reset is not subject to the cooldown, because it already
  needs an elapsed period.
- Both checks run before the MARSHAL gate, are WORM-audited with
  `authorized=false` on refusal, and start no period. The decision stays a pure,
  host-tested function (`mobile::period::reset_permitted_at`). The new return code
  is `10`, early-reset cooldown.

## Consequences

- Repeated resets of any account now need either an elapsed period or the early
  capability, and early resets cannot be issued back to back.
- **The flat capability set (gap 5) is not fixed.** Every EL0 context still holds
  every token, so the early capability is not actually withheld from anyone today.
  The cooldown limits how fast it can be used; it does not limit who holds it.
  Per-context capability sets are a larger change and are out of scope here.
- The last-reset record is in memory and is lost on reboot, like the rest of the
  data state. After a reboot the cooldown starts over.
- The cooldown is measured from the last applied reset, not from the period start.
  Measuring from the period start would have refused every early reset during the
  first hour after boot, which the demo and CI need to exercise.
- A period installed for a no-period account uses a demo length. Real plans need a
  real source for that length, which does not exist yet.
- The period is still counted from boot, not the calendar (gap 29), and nothing
  polls it (gap 28).

## Alternatives considered

- **Refuse normal resets on no-period accounts, early only.** Early resets would
  still start no period, so they would stay repeatable.
- **Refuse every reset on a no-period account.** Strictest, but it strands an
  account that nothing assigns a period to.
- **Cap early resets per account per window.** Stronger than a cooldown, but it
  needs a counter and a window that also reset on reboot.
- **Document only.** Rejected for the cooldown: the cost of the cooldown is small
  and it removes the back-to-back case entirely.

## Revisit when

- The capability set stops being flat (gap 5), so the early capability can be
  withheld from a real caller.
- Plans carry a real billing-period length, replacing the demo constant.
- Data state is persisted, so the last-reset record survives a reboot.
- The cooldown needs to vary by plan or by operator.
