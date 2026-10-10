# Architecture decision records

Short records of decisions that cross crate or trust boundaries and that a
future reader could not safely reverse without knowing why they were made.
They answer one question: **what did we decide, and what would make us decide
differently?**

## How this differs from the other docs

| Doc | Answers |
|-----|---------|
| `docs/RFC-*.md` | A proposal under discussion: options, trade-offs, a recommendation. Written *before* the code. |
| `docs/adrs/NNNN-*.md` (here) | A decision that has been made and built. Short, stable, rarely edited. |
| [STATUS.md](../STATUS.md) | What is implemented and verified right now, in detail. Changes constantly. |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | The layer and crate structure the decisions sit inside. |

If a decision started life as an RFC, the ADR links back to it and records the
option that was actually taken. An ADR does not repeat STATUS.md's
implementation detail; it points at it.

## Format

One file per decision, `NNNN-short-kebab-title.md`, numbered in order and never
renumbered. Sections:

- **Status**: `Accepted`, `Superseded by NNNN`, or `Deprecated`, with a date.
- **Context**: the forces at play, including the constraint that made the
  decision non-obvious.
- **Decision**: what was decided, stated so it can be checked against the code.
- **Consequences**: what gets better, and, just as important, what gets worse
  or is left as a known gap.
- **Alternatives considered**: what was rejected and why.
- **Revisit when**: the concrete events that should reopen the decision.

Do not edit an accepted ADR to change its decision. Write a new one that
supersedes it, and mark the old one `Superseded by NNNN`. Fixing a factual error
or a broken link is fine.

## Index

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-data-syscalls-not-marshal-gated.md) | Data policy syscalls are not MARSHAL-gated; the engine only requests | Accepted (2026-10-10); amended by 0002 |
| [0002](0002-usage-reset-is-marshal-gated.md) | The usage-period reset is the one MARSHAL-gated data action | Accepted (2026-10-11) |
| [0003](0003-unreachable-marshal-policy-is-per-action.md) | What happens when MARSHAL is unreachable is decided per action | Accepted for the reset; open for the other gated actions (2026-10-11) |
