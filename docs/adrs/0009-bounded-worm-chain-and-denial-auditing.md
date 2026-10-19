# 0009: The kernel-arm WORM chain is bounded per event class, and denials are audited into it

**Status**: Accepted 2026-10-17. Closes the audit-growth half of threat-model gaps 18 and 19
and most of gap 7 for `kernel-arm`; see "Residual gaps" for what stays open.

## Context

`kernel-arm/src/svc.rs` appended every audited decision to one unbounded
`citadel_integration::WormLog` (the `ESIM_WORM_LOG` static). That created two problems that
pulled in opposite directions:

- **Growth (gap 18).** A caller holding any capability that reaches an audited path (a data
  usage or session capability, an eSIM capability for a refused install or disable) could
  repeat the call and grow the in-memory chain without limit. `SYS_DATA_RECONCILE` also
  re-recorded the same incident on every call while the drift persisted. The likely end state
  is exhaustion of the 4 MiB kernel heap; allocation failure behaviour was never verified.
- **Missing denials (gap 7).** The honest fix for the growth was to not audit repeatable
  refusals, so they were serial-only: capability denials on the eSIM, MVNO and data syscalls,
  the MVNO enable gate's refusal, and a reachable MARSHAL's `Refuse`/`HardStop` (the
  `enforce_gate` function audited only `Local`, `Unreachable` and `Faulty`). A reviewer
  reading the chain saw what happened and some refusals, not every refusal.
- **Clean reconcile passes (gap 19)** left no record at all, so "the reconciler ran and found
  nothing" could not be shown from the chain.

Auditing denials is only safe once the chain cannot be grown by whoever causes them, so the
bound comes first and the denial auditing is built on it.

## Decision

1. **The chain stays one hash-chained `WormLog`, append-only. Nothing is deleted, edited or
   re-linked**, so `verify_chain` keeps its meaning for every entry the chain holds. The bound
   is on how many entries each event class may append. It lives in a new host-testable module,
   `kernel-arm/src/audit_chain.rs` (`BoundedAudit`), and `svc.rs`'s `audit_event` is the only
   writer.

2. **Ten event classes, each with a fixed quota of individual entries.** Classes do not borrow
   from one another.

   | Class | Quota | What goes in it |
   |---|---|---|
   | `applied` | 128 | Governed state changes that happened: eSIM transitions, MVNO bind / suspend / reactivate, forced disable, unbind, applied usage reset. Reserved headroom: no denial, rejection, metering or reconciler class can consume it. |
   | `data-activity` | 64 | Authorized data events that are not governed state changes: usage feeds, advisory requests, session open / close, the billing-period request. Kept out of `applied` because they are high frequency. |
   | `gate-blocked` | 24 | A reachable MARSHAL's `Refuse` or `HardStop` (new). |
   | `gate-fail-closed` | 24 | The kernel's own blocks: local evaluation failure, unreachable under a fail-closed action, faulty reply. |
   | `cap-denial.esim` / `.mvno` / `.data` | 16 each | Capability denials (new), split by syscall family so a flood on one family cannot hide another. |
   | `rejected` | 48 | A request refused after the capability check passed: state-machine or registry errors, data-layer refusals, the MVNO enable gate's refusal (new). |
   | `incident` | 32 | Reconciler evidence. |
   | `clean-pass` | 8 | "A reconcile pass ran clean" (new), on a state change only. |

3. **When a class is out of quota the event is coalesced, never silently dropped.** Per class
   the kernel keeps a counter (`dropped`) and the most recent reason (cut to 120 bytes). A
   **summary entry** is appended to the chain when `dropped` first reaches 1 and again each
   time the threshold quadruples (1, 4, 16, 64, ... up to 8 commits per class). It states the
   class, the count so far, the quota, how many were recorded individually and the last reason,
   with `authorized=false`, under the subject `audit:summary:<class>`. Summary entries have
   their own reserved room (8 per class), separate from the class quotas, so a saturated class
   can always say that it is saturated.

4. **The total is a compile-time constant:** `TOTAL_CAPACITY` = sum of quotas (376) + 10 x 8
   summary slots = **456 entries**. `BoundedAudit::verify` checks the hash chain **and** the
   bound's books: the chain holds exactly the entries the counters say were appended, no class
   is over quota, no class committed more than 8 summaries, every committed summary is in the
   chain, and the total is within the constant. The "chain verified" value on every serial
   line that already printed it is now this stronger check.

5. **Coalescing is visible on the serial log.** Every coalesced event prints
   `SVC: WORM class <name> coalesced: ...`; a summary commit prints the count and the last
   reason with the entry total; the reconcile syscall ends with
   `SVC: WORM chain bound: entries N/456, coalesced events M, chain verified V` and one line
   per class that has coalesced anything. A call site's own "audited to WORM" confirmation is
   printed only when the entry really was appended.

6. **Denials are audited, using those classes.**
   - `enforce_gate` audits `Refuse` and `HardStop` (class `gate-blocked`) in addition to
     `Local`, `Unreachable` and `Faulty` (class `gate-fail-closed`). The confirmation line is
     the existing `SVC: <blocked> denial audited to WORM (<from> -> <to>, authorized=false;
     entries N, chain verified V)`, so for a Refuse it reads `MARSHAL Refuse denial audited ...`.
   - Capability denials on every eSIM syscall (create, install, enable, disable, delete,
     status), the three MVNO syscalls and the six data syscalls write an `authorized=false`
     entry (subject = the resource that was checked, reason = the syscall and the capability
     error) after the unchanged `DENIED` line, and print
     `SVC: <syscall> <args> capability denial audited to WORM (authorized=false, class
     cap-denial.<family>; entries N, chain verified V)`.
   - The MVNO `gate_enable` refusal writes an `authorized=false` entry (class `rejected`) and
     prints `... MVNO gate refusal audited to WORM (...)`.
   - The existing `DENIED` / `FAILED` / `REFUSED` serial lines are unchanged.

7. **Reconciler dedupe (gap 18).** `ReconcileMemory` keeps the key set of the previous pass
   (not a log; bounded by what one pass can report). An incident is WORM-recorded the first
   time a pass reports it, and again only if it stopped being reported and came back or is a
   different finding. A persistent finding prints a serial line on every pass
   (`... (unchanged since the previous pass: already WORM-recorded, not repeated; ...)`) and
   costs no entry. The key names what was found and omits what merely changes from call to
   call: a period incident's `observed` is the current tick, so the key is
   `(kind, account, expected)`; an ordinary incident's key includes its observed fact, so a
   usage counter that keeps rising is a new finding each time it changes (still bounded by the
   `incident` quota).

8. **Clean reconcile passes (gap 19).** A pass with no incident appends one `clean-pass` entry
   when the previous pass was not clean (or it is the first pass), with the running clean-pass
   number. Each further consecutive clean pass is counted by the same coalescing mechanism, so
   the chain shows the first clean pass and a counted summary, never one entry per pass. The
   serial line states which happened (`clean pass #N WORM-recorded` or `clean pass #N
   coalesced`).

## Consequences

Better:

- The chain cannot be grown without limit by any caller: 456 entries at most, with an
  accounting check that fails `verify` if the books do not balance. At roughly a few hundred
  bytes per entry this is far below the 4 MiB heap (the entry size was not measured).
- Denials that were serial-only are now in the tamper-evident chain: capability denials,
  Refuse / HardStop, and the MVNO enable gate refusal.
- Governed state changes have room that no refusal flood can take.
- Repeated reconcile calls no longer re-record the same incident, and a clean pass is
  evidenced.

Worse, or left open: see below.

## Residual gaps

- **First-N retention, not most-recent.** A class keeps its first `quota` events. A caller
  that exhausts a class with harmless events (for example repeated denials on the same
  family) leaves a later, genuine one visible only as a count and a last reason, and the
  summary schedule means the committed count can lag the true count by up to 3x between
  commits. The live counters exist in memory and on the serial log only. Splitting capability
  denials by family and the Refuse / HardStop class from the fail-closed class limits the
  cross-contamination; it does not remove the within-class effect.
- **`applied` can itself be exhausted.** A holder who can repeat governed changes (for example
  disable then enable) can use up the 128-entry quota; later changes are then counted and
  summarised, not individually recorded. They are not refused: this design does not make audit
  a precondition for the action ("audit or deny" would turn exhaustion of the log into a
  denial-of-service lever and was not built).
- **The quotas are global, not per caller.** There is one EL0 context today. A per-caller
  quota needs the per-context capability model (gap 11 stays open for non-audit resources).
- **Still serial-only:** capability denials on the RIL and IPC syscalls, a malformed
  `SYS_DATA_SESSION_CLOSE` argument, an unknown reset mode, and the no-period refusal of
  `SYS_DATA_PERIOD`. These could now be added under a quota; they were out of scope.
- **The serial log is unbounded.** Every call still prints its own lines. Bounding the chain
  does not bound the UART traffic.
- **Gap 8 is unchanged.** The chain is still process-local, unsigned and volatile; the bound
  limits its size, it does not make it tamper-proof against an EL1 writer.
- **Not exercised in the plain boots:** the Refuse / HardStop audit needs a verdict from the
  other end of the link. The `Refuse` assertions are in the two "MARSHAL REFUSE" CI steps,
  which use `arm_marshal_selective_listener.py` (a stand-in, not a MARSHAL proxy); only the
  `HardStop` assertion runs against the real `citadel_proxy` (the 403 step). They were derived
  from the code, not run in the environment that wrote this change.
- **Reconciler incident dedupe is not asserted in CI.** The demo walk reports each incident
  once, so only the host tests in `audit_chain.rs` exercise dedupe. The same is true of the
  saturation behaviour (quota, headroom, coalescing, summaries, clean-pass coalescing): it is
  proven by host tests, not by a boot, because the demo walk uses well under every quota.

## Alternatives considered

- **Drop or overwrite old entries (a ring buffer).** Rejected: it breaks `verify_chain` (the
  first entry no longer links to the all-zero hash) or silently loses evidence, which is what
  this change exists to prevent.
- **One global cap with first-come space.** Rejected: whoever floods first would take the room
  for governed state changes.
- **Per-class cap without summaries.** Rejected: a saturated class would then be silent.
- **Audit-or-deny (refuse the action when its entry cannot be appended).** Not built, see
  `applied` above; it is the right call for a signed, off-box log and is worth revisiting with
  one.
- **Keep denials serial-only.** Rejected: that was the gap being closed.
- **Commit a summary on every coalesced event.** Rejected: that is the unbounded growth again.

## Revisit when

- A signed or off-box WORM sink exists (then "audit-or-deny" for `applied` becomes sensible,
  and the quotas can be revisited).
- A per-context capability model exists (per-caller quotas).
- The cost of a `verify` call matters (it hashes every entry, at most 456, on each line that
  prints a chain status).

## References

- `kernel-arm/src/audit_chain.rs` (`AuditClass`, `BoundedAudit`, `ReconcileMemory`,
  `TOTAL_CAPACITY`, and its host tests)
- `kernel-arm/src/svc.rs` (`audit_event`, `audit_capability_denial`, `enforce_gate`,
  `data_reconcile`)
- `.github/workflows/ci.yml` (both plain-boot steps assert the capability-denial, gate-refusal
  and clean-pass lines; the two MARSHAL REFUSE steps assert the Refuse audit against a
  stand-in listener and the 403 step asserts the HardStop audit against the real proxy)
- [0003](0003-unreachable-marshal-policy-is-per-action.md),
  [0006](0006-a-reachable-but-faulty-marshal-reply-fails-closed.md),
  [0008](0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md)
