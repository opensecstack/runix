# RFC: who is the Verifier for an automated, kernel-driven Kerkese submission?

**Status**: proposal for repo owner review. No code written yet. This is the gate
before `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s Option B can mean anything in
practice — Path 3 of that doc's verification plan (a reachable MARSHAL actually
refusing a real submission) is untestable against a real CITADEL deployment
until this is resolved, independent of rbacMap coverage.

## Context

`kernel/src/grid_sandbox.rs`'s shadow-mode evaluation builds a Kerkese envelope
by hand for every `spawn_instance` call:

```rust
let kerkese_json = format!(
    r#"{{"kerkese_version":"1.0","dry_run":true,"action":{{"type":"grid_sandbox.spawn_instance","module_id":"{module_id}","instance_id":"{instance_id}"}},"actor":"kernel","verifier":"kernel","execution_id":"{instance_id}"}}"#
);
```

Checked against CITADEL's real `Kerkese` type
(`opensecstack/opensecstack/citadel/internal/marshal/types.go`), this has two
independent problems:

1. **Shape**: `actor`/`verifier` are bare strings. The real type is:
   ```go
   type KerkeseActor struct {
       UserID string `json:"user_id"`
       Role   string `json:"role"`
       Email  string `json:"email,omitempty"`
   }
   type KerkeseVerifier struct {
       UserID string `json:"user_id"`
       Role   string `json:"role"`
       Email  string `json:"email,omitempty"`
   }
   ```
   A bare string won't unmarshal into either struct — this envelope fails to
   parse against a real CITADEL deployment, full stop, before SoD is even
   evaluated. There's also no `sod` block (`KerkeseSoD{OperatorUserID,
   VerifierUserID}`), which is what Gate 3 actually keys its same-identity
   check on — not `actor`/`verifier` directly.

2. **Identity**: even with the shape fixed, filling in real `KerkeseActor`/
   `KerkeseVerifier` values both identifying "kernel" trips Gate 3 (`NDS`) in
   `citadel/internal/marshal/marshal.go`:
   ```go
   if k.SoD.OperatorUserID == k.SoD.VerifierUserID {
       g.Status = GateHardStop
       g.Reason = "NDS_SAME_IDENTITY: operator and verifier are the same user"
       return g
   }
   ```
   This check is unconditional — it doesn't depend on `EnforceIdentity` or
   `EnforceSignatures` being turned on (unlike the token/signature checks
   further down in the same gate), so there is no deployment configuration
   that makes same-identity submissions pass. There's also a same-role-group
   check (`roleGroupMap`: `admin`/`operator` → `privileged`, `analyst`/
   `viewer` → `standard`, `auditor` → `oversight`, anything else → `unknown`,
   and `unknown == unknown` is explicitly *not* treated as a match) — but that
   check is moot here since the identity check alone already hard-stops.

Neither problem is a maturity gap on CITADEL's side (unlike the rbacMap
coverage gap this session's parallel task addressed) — CITADEL is behaving
exactly as designed. The gap is that Runix's own construction assumes a
single automated principal can both request and approve an action, which
Kerkese's Gate 3 exists specifically to rule out.

## The real question

Kerkese's SoD model assumes two humans: an Operator making a change and a
Verifier approving it. `spawn_instance` runs inside the kernel, synchronously,
on every module spawn, with no human anywhere in that path — there is
nothing today that plays the Verifier's role in Runix's own architecture.
"Set verifier's user_id to something else" doesn't answer this; it just picks
which non-answer to hard-code.

## Options

### Option A: a second, code-distinct principal — the desktop `citadel_proxy`

**Design**: the kernel remains the sole Operator (`actor`), asserting "I am
requesting this spawn." The user-space `citadel_proxy` binary
(`desktop/src/bin/citadel_proxy.rs`) — a genuinely separate process, separate
trust boundary, separate binary, already the one thing standing between the
kernel and the network — becomes the Verifier: it inspects the forwarded
request against Runix's own local policy (does this module have a valid
`InstanceManifestEntry`? is the requested tier consistent with the module's
signed tier?) *before* relaying to CITADEL, and only then attaches its own
`KerkeseVerifier` identity (and, once signing is wired up, its own
`sig_verifier`) to the envelope.

**Why this is a real answer, not a relabeling**: the proxy today
(`desktop/src/citadel/proxy.rs`) is a dumb byte-forwarder — it doesn't parse
or modify `kerkese_json` at all. Making it inspect-and-attest before forward
is a genuine second check by a genuinely different piece of code, running in
a different address space and privilege context than the kernel that
initiated the request. That's a real, if automated, Operator/Verifier split
— not two labels on the same actor.

**Cost**: the proxy needs its own local policy logic (today it has none) and
its own signing key distinct from any key `kernel/` holds — if the same key
signed both roles, `verifyVerifierSignature` in CITADEL's Gate 3 would still
be checking a signature that traces back to the same root of trust as the
Operator's, which is weaker than true SoD even if it satisfies the
`OperatorUserID != VerifierUserID` check literally. Needs its own ADR on key
provisioning, not just envelope shape.

### Option B: human-gated first-run, cached thereafter

**Design**: the *first* time a given `(module_id, tier)` combination is
spawned, the desktop shell prompts a human to approve it (the human becomes
`verifier`); the resulting decision is cached (keyed on module hash + tier)
so every subsequent spawn of the same authorized combination doesn't need a
fresh human touch. Analogous to a permission-request model (think: "Allow
this app to run at T2?" asked once, remembered after).

**Cost**: breaks full automation for the *first* spawn of anything new,
including in CI/QEMU test runs with no human present — those environments
would need either a standing pre-approval fixture or the whole first-run path
disabled in test builds, which reintroduces exactly the "special-case
Alpha/CI vs. real deployment" problem `docs/MARSHAL-ENFORCEMENT-POLICY.md`
argued against for the fail-open/fail-closed question. Also unclear how this
interacts with T1 Critical's <300ms MARSHAL real-time constraint — a cached
decision is fine, but the cache-miss path can't block on a human within
300ms, so T1 spawns would need their own carve-out regardless.

### Option C: argue automated spawns are out of Kerkese's scope; use a different action class

**Design**: accept that Kerkese/Gate 3 SoD is fundamentally a two-human-
principal governance primitive, and that `grid_sandbox.spawn_instance` — a
high-frequency, fully automated, kernel-internal decision — was never the
right thing to route through it. Keep boot-time/instance authorization
exactly as it is today (offline signature verification via `BootAllowlist`/
`InstanceAllowlist`, which already has a real, working trust model with no
SoD gap) as the actual gate, and treat the MARSHAL round-trip as informational
telemetry sent *after* the fact (WORM-adjacent audit logging of "this spawn
happened, here's its manifest") rather than a pre-spawn approval gate at all.

**Cost**: this is close to what shadow mode already does today, so it reads
as "give up on real MARSHAL enforcement for this call site" rather than a
genuine resolution — it would mean `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s
whole fail-open/fail-closed question is moot for `spawn_instance`
specifically, and real enforcement only ever applies to some *other*,
not-yet-identified call site that has an actual human in its path (e.g. a
future "install a new third-party module" flow initiated from desktop UI,
where the installing human is a natural Operator and a second reviewer or a
policy service could be a natural Verifier). Worth naming explicitly rather
than discovering it by default once every other option turns out to be hard.

## Recommendation

**Option A**, with Option C kept explicitly in view as the fallback if Option
A's proxy-side policy logic turns out to be more than a thin check.

Reasoning:
1. **It's buildable on what already exists.** `citadel_proxy` is a real,
   separate process today — this extends it rather than inventing a new
   component.
2. **It doesn't sacrifice full automation.** Unlike Option B, no spawn ever
   blocks on a human, which matters for T1's <300ms constraint and for
   CI/QEMU determinism.
3. **It's honest about what SoD is buying.** Unlike Option C, it keeps a real
   pre-spawn gate rather than downgrading MARSHAL to audit-only for the one
   call site that exists today.
4. **It has a concrete, falsifiable next step**: give `citadel_proxy` its own
   signing key and a minimal local policy check (even "module has a valid
   `InstanceManifestEntry` for this tier" is a real, non-trivial check the
   proxy isn't doing today), fix the envelope shape to real
   `KerkeseActor`/`KerkeseVerifier`/`KerkeseSoD` structs, and re-run
   `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s Path 3 test against a mock server
   configured to actually evaluate Gate 3, not just Gate 2.

If proxy-side policy logic grows into something that duplicates
`InstanceAllowlist`'s job rather than adding a genuinely independent check,
that's the signal to fall back to Option C rather than keep adding logic to
make Option A's Verifier "real enough."

## What changes under Option A (prose only — no code written yet)

- `kernel/src/grid_sandbox.rs`'s hand-built `kerkese_json` `format!` needs to
  stop hard-coding `verifier`. The kernel only ever asserts `actor` — it
  should not claim a Verifier identity at all; that's the proxy's job to
  attach after its own check.
- `runix_ipc::marshal::MarshalRequest` (or a new field on it) needs a way for
  the *kernel* to send an envelope with `actor` populated and `verifier`/`sod`
  absent, distinct from what `HttpKerkeseTransport` actually sends to CITADEL
  once the proxy has filled in the Verifier side. This is a wire-contract
  change to the typed `ipc` crate, per CLAUDE.md's cross-boundary-payload
  rule — not a hand-rolled shape on either side.
- `desktop/src/citadel/proxy.rs` needs: (1) a local policy check against
  `InstanceAllowlist`/`BootAllowlist` state, (2) its own `SigningKey`,
  provisioned separately from any kernel-side key material, (3) logic to
  construct the real `KerkeseVerifier`/`KerkeseSoD`/`sig_verifier` fields and
  the full, correctly-shaped `Kerkese` envelope before forwarding.
- `citadel-integration::WormLog` should record the proxy's verification
  decision as its own evidence entry, distinct from the kernel's shadow
  evaluation entry — two principals, two log entries, matching the SoD split
  this whole RFC is trying to make real rather than nominal.

## Open questions

- Does the proxy's local policy check need its own key-provisioning story for
  Alpha/dev (self-signed, generated at first run) vs. a real deployment
  (provisioned by CITADEL's own release process, mirroring how
  `ModuleManifestEntry`'s signing key already works)? This is likely its own
  short ADR once Option A is accepted in principle.
- Does `sinauth`'s role taxonomy (`adrs/005-sinauth-identity-bridge.md` in
  `opensecstack/opensecstack`) need a new role (e.g. `"automation"` or
  `"service"`) added to `roleGroupMap` so an automated Verifier's role group
  is meaningfully distinct from the kernel Operator's, rather than both
  landing in `"unknown"`? Not load-bearing for the same-identity check (which
  fires regardless of role group), but relevant if CITADEL's own policy ever
  wants to treat automated approvals differently from human ones.
- CLAUDE.md does not currently state the "one identity can't satisfy both
  roles" rule that `citadel-integration/src/lib.rs`'s own doc comment
  attributes to it — worth confirming whether that line was removed at some
  point, or the comment is describing intent that was never actually landed
  in CLAUDE.md, and reconciling the two either way.

## References

- `kernel/src/grid_sandbox.rs` — the hand-built envelope this RFC responds to
- `citadel-integration/src/lib.rs` — "Why not a Kerkese/MARSHAL round-trip"
- `desktop/src/bin/citadel_proxy.rs`, `desktop/src/citadel/proxy.rs` — Option A's build target
- `opensecstack/opensecstack/citadel/internal/marshal/types.go` — real `Kerkese`/`KerkeseActor`/`KerkeseVerifier`/`KerkeseSoD` shapes
- `opensecstack/opensecstack/citadel/internal/marshal/marshal.go` — `gate3NDS`, `roleGroup`/`roleGroupMap`
- `docs/MARSHAL-ENFORCEMENT-POLICY.md` — the fail-open/fail-closed decision this RFC's resolution unblocks testing for
- `opensecstack/opensecstack#34` — RFC-0005, the still-open umbrella issue this would be posted as a follow-up to, once accepted here
