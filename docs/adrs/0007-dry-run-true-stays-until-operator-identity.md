# 0007: Every MARSHAL request stays `dry_run: true` until operator identity exists

**Status**: Accepted 2026-10-17. Records a finding that qualifies the
"simulation request" wording in `docs/STATUS.md` and `docs/BETA_CRITERIA.md`
and the "400 on dry-run" hazard in [0006](0006-a-reachable-but-faulty-marshal-reply-fails-closed.md).

## Context

Every MARSHAL request Runix sends carries `"dry_run": true`. It is hardcoded
in both kernels: `build_spawn_kerkese_json` in `kernel/src/grid_sandbox.rs`
(line 208) and `MarshalAction::kerkese_json` in `kernel-arm/src/marshal_action.rs`
(line 160). The desktop proxy forwards the kernel's flag unchanged
(`desktop/src/citadel/proxy.rs`, line 399, `dry_run: envelope.dry_run`).
`desktop/src/citadel/policy.rs` only requires that the field deserialize (lines
405-408); it does not check its value. The proxy's verifier signature does not
cover the field: `canonical_payload` in `desktop/src/citadel/identity.rs`
(lines 229-243) signs the execution id, action, actors, SoD and timestamp, and
no `dry_run`.

Runix's documentation has described `dry_run: true` as a simulation request, not
a committed execution, which is why `docs/STATUS.md` said (in its dry-run
paragraph, since reworded to point here) that a real `EXECUTE` "would not be a
live approval". Two questions followed: whether
Runix should make the flag configurable, and whether a CITADEL that honours
`dry_run` as documented is a risk or a protection. The CITADEL source and
documentation were read to answer both.

What the CITADEL source does (`opensecstack/citadel/`, read-only, see
References):

- `Engine.Evaluate` (`internal/marshal/marshal.go`, lines 152-219) copies the
  flag into the Decision (`DryRun: k.DryRun`, line 158) and does not branch on it
  anywhere else. Gates 1 to 4 run as normal.
- Gate 5 is commented "unconditional" (line 201), and `gate5WORM` (lines
  496-527) appends the decision to the WORM chain with the redacted Kerkese. A
  dry-run request therefore produces a full evaluation and a WORM entry.
- The HTTP handler (`internal/api/handlers/marshal.go`, lines 27-70) decodes the
  body and maps the outcome to a status: 200 for `Execute`, 403 for `Refuse` or
  `HardStop`, 500 for an engine error, 400 only for a body that does not decode.
  It has no `dry_run` check, so the handler never answers 400 for a dry-run
  request.

What the CITADEL documentation says, which the source does not match:

- `citadel/docs/dry-run.md` (lines 1-14 and 16-31) says a dry-run request skips
  Gate 5 and writes no WORM entry, and that the decision reports
  `worm_entry_id` as null.
- `citadel/docs/marshal-engine.md` (lines 216-225) and `kerkese-spec.md` (lines
  89-98) say the same.
- `citadel/docs/dry-run.md` (lines 111-117) and `configuration.md` (line 92) say
  `CITADEL_DRY_RUN_ALLOWED=false` makes a production CITADEL answer any
  `dry_run: true` Kerkese with HTTP 400, `{ "error": "dry_run is not allowed in
  this environment" }`. `troubleshooting.md` (lines 113-118) attaches this to
  "v1.1+".

Searching the whole `opensecstack` checkout for `CITADEL_DRY_RUN_ALLOWED` finds
only those documents. Searching the Go sources for `DRY_RUN` finds the
`DryRun` struct tags (`types.go` lines 21 and 97), `marshal.go` line 158, one
test (`TestEvaluate_DryRun_NoBlock`, `marshal_test.go` line 562, which checks
only that the flag is echoed), and environment variables in other services'
configuration packages (`securelab`, `openscrub`, `opencsirt`, `community`,
`apiguard`). None of those is read by the `citadel/` server. The gate on the 400
is therefore documented and not implemented in the audited tree.

## Decision

1. **Keep `dry_run: true` on every Runix MARSHAL request.** It stays hardcoded in
   `build_spawn_kerkese_json` and `MarshalAction::kerkese_json`. It is not a
   runtime or configuration setting, for the same reason as ADR 0003's table: a
   switch that changes what MARSHAL records is itself a lever.
2. **Flip it to `false` only together with a real operator identity.** Runix has
   no operator `actor_token` and no operator signature (`sig_operator`); nothing
   constructs them, and the principal on mobile is the placeholder
   `el0:arm-demo` (`docs/ROADMAP.md`, "Operator identity"; `docs/BETA_CRITERIA.md`
   "Not claimed" 1). A `false` request would be a real evaluation under a demo
   principal, so any record it wrote would sit in a production chain as if an
   operator had asked for the action. That is the RC-scope item in ROADMAP.

## Consequences

Better:

- The flag cannot be turned off by configuration, so the request shape cannot
  drift from what the audited CITADEL source and the Runix tests exercise.

Worse, or left open:

- **The premise is weaker than "dry-run is a simulation".** In the audited source
  a `dry_run: true` request is still evaluated in full and appended to the WORM
  chain (Gate 5 is unconditional). Keeping the flag at `true` does not keep
  records out of a chain. A deployed CITADEL that runs this source would already
  write one WORM entry per Runix request, under `el0:arm-demo`. The mock CITADEL
  servers in CI cannot show this. Anyone pointing Runix at a shared CITADEL should
  assume its chain receives these entries.
- **Gap 9 (`dry_run` meaning, the Beta A4 item) stays open, now characterised.**
  Runix cannot tell from its own side whether a given CITADEL honours the flag
  as documented (no `CITADEL_DRY_RUN_ALLOWED` in the audited code) or as the
  source does. The answer depends on the deployed build, which was not checked.
- **Availability hazard, unchanged in kind.** If a deployment does enforce
  `CITADEL_DRY_RUN_ALLOWED=false`, every gated action gets a 400, which is a
  faulty reply, so all six mobile actions and x86 `spawn_instance` fail closed
  (ADR 0006). That is the safe direction but a total outage of those actions. It
  is a possibility, not an observed behaviour.
- A dry-run EXECUTE is non-binding by the CITADEL documentation, and Runix's
  verdict is unauthenticated (ADR 0006). Neither is a reason to rely on an
  `Execute` as authorization.

## Alternatives considered

- **Make `dry_run` configurable per deployment.** Rejected for now. A setting that
  switches the request to a recorded evaluation would be a runtime lever with
  no operator identity behind it.
- **Send `dry_run: false` now, to get the documented "real" semantics.** Rejected.
  It would create real-looking records under a placeholder principal in a chain
  that may be production, and it would still not authorize anything, because the
  operator token is missing and the verdict is unsigned.

## Revisit when

- Operator identity lands (`actor_token`, `sig_operator`, key custody; ROADMAP
  RC scope). This is the point where the flag can be considered for `false`, as a
  separate, reviewed change.
- A deployed CITADEL is shown to enforce `CITADEL_DRY_RUN_ALLOWED`, or to skip
  Gate 5 for dry-run requests. Either result changes the "WORM entry" consequence
  above and should update this record.
- A verdict starts being relied on as authorization, by anything other than the
  CI mocks. At that point the dry-run flag is no longer a harmless simulation
  marker.
- The CITADEL source tree changes so that `dry_run` is handled differently from
  the checkout read for this record.

## References

Runix (verified against the working tree, 2026-10-17):

- `kernel/src/grid_sandbox.rs` (`build_spawn_kerkese_json`, line 208)
- `kernel-arm/src/marshal_action.rs` (`kerkese_json`, line 160)
- `desktop/src/citadel/proxy.rs` (line 399, forwards `envelope.dry_run`)
- `desktop/src/citadel/policy.rs` (lines 405-408, presence check only)
- `desktop/src/citadel/identity.rs` (`canonical_payload`, lines 229-243)
- `docs/STATUS.md` (the dry-run paragraph in the MARSHAL gate section; the old
  "dry-run is a simulation request" wording was replaced after this ADR)
- `docs/ROADMAP.md` ("Operator identity", RC scope)
- `docs/BETA_CRITERIA.md` ("Not claimed" 1, 14)
- [0003](0003-unreachable-marshal-policy-is-per-action.md),
  [0006](0006-a-reachable-but-faulty-marshal-reply-fails-closed.md)

CITADEL (`opensecstack/opensecstack/citadel/`, read-only; the checkout's
commit was not recorded and git history was not read):

- `internal/marshal/marshal.go` (`Evaluate`, lines 152-219; `DryRun` echo, line
  158; unconditional Gate 5, lines 201-205; `gate5WORM`, lines 495-527)
- `internal/marshal/types.go` (`DryRun` JSON tags, lines 21 and 97)
- `internal/marshal/marshal_test.go` (`TestEvaluate_DryRun_NoBlock`, line 562)
- `internal/marshal/sig.go` (`v1|...` payload, line 14; no `dry_run`)
- `internal/api/handlers/marshal.go` (`ServeHTTP`, lines 27-70)
- `docs/dry-run.md` (lines 1-31, 111-117), `docs/marshal-engine.md` (lines
  214-225), `docs/kerkese-spec.md` (lines 89-98), `docs/configuration.md` (lines
  91-92), `docs/operator-runbook.md` (lines 117-124), `docs/troubleshooting.md`
  (lines 113-118)

## Not verified

- Git history of CITADEL, and which commit or release the checkout matches.
- Any deployed CITADEL instance: whether it sets `CITADEL_DRY_RUN_ALLOWED`, and
  whether it writes WORM entries for dry-run requests.
- Other CITADEL builds or the sinauth service, which may implement the setting.
- Whether `citadel/` has any code path outside `internal/marshal` and
  `internal/api/handlers` that changes how a Kerkese is evaluated or stored. The
  search covered the whole `citadel/` tree for `DRY_RUN` and `dry_run` and found
  nothing else.
- The HTTP status code the CITADEL gateway in front of the handler returns, if
  one exists. The handler's own codes are read above.
