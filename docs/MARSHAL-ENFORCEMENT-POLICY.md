# MARSHAL runtime enforcement policy for grid sandbox spawning

This document proposes a failure-mode policy for turning `kernel/src/grid_sandbox.rs`'s
current shadow-mode MARSHAL evaluation into real enforcement — a decision that has
genuine security tradeoffs and needs explicit reasoning before code gets written.

**Status**: proposal for repo owner review. No code written yet. This is the gate
before any `spawn_instance` implementation changes.

## Context

Today, `spawn_instance` performs a shadow-mode (observe-only, never blocking) MARSHAL
evaluation of each instance spawn via `marshal_client::evaluate()`, records the outcome
in `WormLog`, and **never acts on the result** — every spawn succeeds regardless of
whether MARSHAL says `Execute`, `Refuse`, `HardStop`, or is entirely unreachable.

The framework exists:
- `ipc::marshal::{MarshalRequest, MarshalResponse, MarshalOutcome}` carry the wire
  contract between kernel and a user-space MARSHAL proxy.
- `citadel-integration::ShadowMarshalOutcome` (Execute/Refuse/HardStop/Unreachable)
  records what came back.
- No live CITADEL deployment exists in any dev/CI/QEMU scenario today, so proxy
  configuration defaults to `None` and shadow evaluation always logs `Unreachable`.

The question now is: when turning this into **real enforcement** (a follow-up task,
not yet written), what should `spawn_instance` do if MARSHAL returns `Refuse` or
`HardStop`? Or if the proxy is unreachable when it was configured?

## Decision: fail-closed or fail-open?

Two distinct policies are genuinely defensible. A third may exist but should be
grounded in what's actually implementable given `MarshalResponse`'s real shape and
`ShadowMarshalOutcome`'s four variants.

### Option A: fail-closed on ANY non-`Execute` outcome, including transport failure

**Policy**: If MARSHAL evaluation returns anything other than `Execute` — whether a
reachable `Refuse`/`HardStop` or an unreachable proxy — block the spawn and return
an error to the caller.

**Rationale**: strictest posture, no false positives. Every spawn that makes it to
the gate has proof of authorization, not just "we couldn't reach the proxy."

**Cost**: This would break every Runix boot everywhere, in every dev/CI/QEMU scenario,
starting today and lasting until a live CITADEL deployment is built, deployed, and
reachable from the kernel. Not theoretical — the default proxy configuration is `None`
(see `ShadowMarshalProxyConfig`'s doc comment), so every spawn would log `Unreachable`
and get blocked. Every boot would fail before reaching `user_hello`. This remains true
across all of Alpha and Beta development, potentially into RC — a real, months-long
developer friction event with no mitigation short of a deployable CITADEL instance.

Additionally: per `citadel/README.md`'s "Known limitations" section (in the sibling
`opensecstack/opensecstack` repo), even with a reachable MARSHAL deployed, most real
Kerkese submissions today `REFUSE` at Gate 2 due to rbacMap coverage gaps — a parallel
task this session is addressing narrowly for Runix's own action types (e.g.
`"grid_sandbox.spawn_instance"`), but the general gap remains for anything not yet
added. Enforcing fail-closed would mean every spawn in a dev deployment also gets
refused until *that* parallel work completes its own coverage additions.

### Option B: fail-open on transport failure; fail-closed only on a reachable `Refuse`/`HardStop`

**Policy**: If proxy configuration is `None` or unreachable (timeouts, no route,
connection refused), allow the spawn — preserve the "doesn't break anything when
unconfigured" property shadow-mode already has. If the proxy is reachable and returns
a real decision, honor it: `Execute` allows the spawn, `Refuse`/`HardStop` block it.

**Rationale**: Boots normally in today's universal case (no proxy configured). No
developer friction in Alpha/Beta. Real enforcement **teeth** once a deployment exists
and is configured — a spawn that MARSHAL actually refuses gets blocked, not silently
allowed. A real, reachable MARSHAL refusing is the signal that governance thinks
something is wrong; an unreachable proxy is a configuration/deployment issue, not a
governance issue.

**Tradeoff**: If the proxy becomes unreachable *after* being configured and working
correctly, spawns silently stop being gated until it's reachable again. This is the
"fail-open" piece. Mitigations exist (alert/page on an `Unreachable` outcome, recorded
in `WormLog` and sent upstream; see "Verification" below), but they're separate from
the gate itself.

## Recommendation

**Option B: fail-open on transport failure, fail-closed on reachable `REFUSE`/`HARD_STOP`.**

Reasoning:
1. **Does not break every Runix boot for months.** Allows real development and testing
   to proceed in Alpha/Beta without a live CITADEL instance. Option A would block this
   gate and everything downstream until a deployable CITADEL exists.
2. **Preserves the architectural discipline.** Shadow mode is currently "observe-only,
   never gate." Option B turns it into real enforcement but keeps the "don't gate on
   things you can't reach" property — a natural, testable line rather than "gate on
   configuration=unconfigured, which is a footgun."
3. **Aligns with the bootstrapping timeline.** Real MARSHAL enforcement is a Beta goal,
   not an Alpha goal (see ROADMAP.md). Option B lets Alpha use shadow mode as designed
   (observation, logging, visibility) while Beta can wire in the real proxy and start
   seeing enforcement. Option A conflates Alpha's "no proxy" with "proxy refused," a
   false equivalence that would require special-casing Alpha vs. Beta at the gate level.
4. **Risk model matches the constraint.** The real risk — "MARSHAL can't block a spawn
   that governance thinks is dangerous" — only happens if (1) a proxy is configured,
   (2) it's working, and (3) it returns `Refuse`/`HardStop` but we ignore it. Option B
   blocks that. The "proxy is unreachable" state is a deployment/infrastructure failure,
   not a governance failure, and should be handled by observability (WormLog + alerting)
   rather than fail-closed gates that prevent the whole system from working.

## Real blocking dependency: rbacMap coverage

Neither option is meaningful until CITADEL's Gate 2 recognizes Runix's action types.
Today, Kerkese envelopes submitted with `action: {type: "grid_sandbox.spawn_instance", ...}`
would likely `REFUSE` (if Gate 2 even evaluates them) purely because the rbacMap doesn't
have an entry for that action — nothing to do with the actual governance policy,
everything to do with "this action type doesn't exist yet in my reference table."

A parallel task in this session is addressing this: adding Runix-specific action types
to the rbacMap so Gate 2 can actually evaluate them. Until that lands and the real
CITADEL deployment recognizes `"grid_sandbox.spawn_instance"`, a reachable MARSHAL will
still likely `REFUSE` everything Runix asks, making Option B's "fail-closed on reachable
REFUSE" path untestable in practice.

Further down, if Runix's actor/verifier scheme (e.g., both set to `"kernel"`) doesn't
satisfy CITADEL's Separation-of-Duties requirement at Gate 3/NDS, even a valid action
type may be refused — a design issue, not a configuration gap, requiring a second RFC
to resolve. See `citadel-integration/src/lib.rs`'s "Why not a Kerkese/MARSHAL round-trip"
section and CLAUDE.md's Separation-of-Duties rule for the current state of that question.

**Implication**: Real enforcement testing (verifying that an actual `REFUSE` does block a
spawn) may not be possible until Beta, when the rbacMap work is complete and a real
MARSHAL deployment has the coverage. Verification should account for this — see below.

## What changes under Option B

This section describes, in prose, what code would need to change. **No actual code is
written yet.**

### `spawn_instance` return type and control flow

Currently, `spawn_instance` returns `Result<SpawnedInstance, CitadelError>`. `CitadelError`
covers only boot-time authorization failures (module not allowlisted, hash mismatch,
invalid signature).

Under Option B, `spawn_instance` needs a new, runtime-specific error variant for MARSHAL
enforcement failures. Two approaches:

1. **Extend `CitadelError`** with a new variant like `MarshalEnforcementBlocked(ShadowMarshalOutcome)`
   or `MarshalRefused`. Simple, but conflates boot-time and runtime governance failures
   into one enum — a design smell if this is the first of several runtime enforcement
   gates (IPC send to a T1 service, memory allocation under T3, etc.).

2. **New `MarshalEnforcementError` enum** (or one per subsystem) carrying the `ShadowMarshalOutcome`
   and any transport details. More scaffolding, but allows each enforcement point to
   own its own error semantics once more than one exists.

Either way, the happy path is unchanged: a successful spawn returns `Ok(SpawnedInstance)`.
The `Err` branch is new.

### Enforcement logic (pseudo-code structure)

```
spawn_instance(...):
  // Existing: fail-closed on boot-time auth
  tier = demo_authorize_instance(...)?  // unchanged

  // Existing: shadow evaluation for observation
  shadow_marshal_evaluate(...)  // unchanged, still observe-only

  // NEW: real enforcement gate
  enforce_marshal_decision(...)?  // new call, see below

  // Existing: continue loading and spawning
  elf = parse(...)
  space = AddressSpace::new()
  // ...rest unchanged
```

### The enforcement call

`enforce_marshal_decision()` is a new, internal function that:
1. Checks the proxy configuration (is it `None`?). If unconfigured, return `Ok(())` —
   fail-open, no enforcement.
2. If configured, attempts to contact the proxy. If unreachable (timeout, connection
   refused, etc.), return `Ok(())` — fail-open on transport failure.
3. If reachable and returns `Refuse` or `HardStop`, return `Err(MarshalEnforcementBlocked)`
   — fail-closed on a real, reachable refusal.
4. If reachable and returns `Execute`, return `Ok(())` — allow the spawn.

The proxy configuration comes from `SHADOW_MARSHAL_PROXY`, the same `Mutex<Option<...>>`
shadow evaluation already reads, so no new configuration surface is needed. Tests can
set it via `set_shadow_marshal_proxy()`, the same call shadow tests already use.

### Integration with existing error paths

The error must propagate back to the spawn caller (likely in `desktop/` user-space code
that iterated spawning multiple instances). The caller's job is then to decide: retry?
alert the user? fail fast? That's policy for the application layer, not the gate.

### `WormLog` side effects

No change to the existing shadow evaluation logging — it continues recording the outcome
observed, whether the gate then enforces it or not. If enforcement happens and blocks
a spawn, the gate's own error replaces any `WormLog` entry as the source of truth ("this
spawn was blocked by MARSHAL," not "the shadow evaluation said refuse, but we allowed it
anyway"). See verification section below for how this is tested.

## Verification

A real implementation would need to verify both the fail-open and fail-closed paths in
QEMU, matching this project's discipline of "always verify with a real boot, not just
in a unit test."

### Path 1: fail-open when proxy is unconfigured (Alpha/Beta happy case today)

Test: A spawn with `SHADOW_MARSHAL_PROXY = None` succeeds. Verify in QEMU by booting
and confirming `grid-sandbox-host` instances spawn and run normally. This is the
existing test suite (`kernel/tests/grid_sandbox_multi_instance.rs`, etc.) — should pass
unchanged.

### Path 2: fail-open when proxy is unreachable

Test: Configure `SHADOW_MARSHAL_PROXY` to a nonexistent address (e.g., `192.0.2.1:65432`,
an invalid example address). Spawn an instance and confirm it succeeds despite the proxy
being unreachable. Verify the `WormLog` records `ShadowMarshalOutcome::Unreachable` but
the spawn still completed. (This test already exists for shadow-mode observation
purposes — the gate-enforcement variant just confirms the enforcement side doesn't
break it.)

### Path 3: fail-closed when proxy is reachable and returns `REFUSE`

Test: Stand up a mock MARSHAL server in QEMU (same approach `kernel/tests/
grid_sandbox_marshal_shadow.rs` already uses for shadow-mode testing), configure it to
return `MarshalResponse::Decision { outcome: MarshalOutcome::Refuse, ... }`, and
attempt to spawn an instance. Verify the spawn fails with a `MarshalEnforcementBlocked`
error (or equivalent). Verify no ring-3 process was created (the spawn was blocked at
the gate, not started and then killed). Verify the `WormLog` records both the real
authorization success (from `demo_authorize_instance`) and the shadow evaluation's
`Refuse` outcome.

This path is blocked on the rbacMap work — a real MARSHAL won't know what
`"grid_sandbox.spawn_instance"` is yet, so the mock server is the only way to test
this path in Alpha/early Beta.

### Path 4: execution under a real-ish mock (future, Beta+)

Once the rbacMap work lands and a Beta MARSHAL deployment recognizes `grid_sandbox`
action types, re-run Path 3 against that real MARSHAL instead of a mock. Confirm a
spawn that the real MARSHAL would approve (`Execute` outcome) succeeds, and one it
would refuse actually gets blocked.

## Open questions and future work

- **Policy evolution**: This recommendation applies to `spawn_instance` specifically.
  When other runtime enforcement points are added (e.g., capability verification for
  an IPC send to a T1 service, or a memory-allocation request under T3), the same
  fail-open-on-unreachable policy should be applied consistently — this document
  should be cited as precedent, not re-derived per gate. If a later gate genuinely
  needs different semantics, that difference should be justified explicitly, not
  defaulted to silently.

- **Alerting and observability**: Fail-open means some spawns silently aren't gated
  when the proxy is unreachable. This is acceptable because `WormLog` records it, but
  observability needs to work — an operator/developer needs to be able to inspect the
  log and see "proxy was unreachable, so enforcement didn't happen." A future VIGIL
  health-monitoring integration would allow alerting on a stream of `Unreachable`
  outcomes, turning "silent" into "loudly observable."

- **Separation of Duties (SoD) resolution**: Current `spawn_instance` evaluations set
  both `actor` and `verifier` to `"kernel"`, which violates CITADEL's SoD principle
  at Gate 3/NDS (see `citadel-integration/src/lib.rs`'s section on this). This is a
  separate RFC-worthy decision. Until it's resolved, even a reachable MARSHAL may
  refuse all Runix actions on SoD grounds alone — an upper-layer problem unrelated
  to this enforcement-policy gate.

## References

- `kernel/src/grid_sandbox.rs` — current shadow-mode implementation
- `citadel-integration/src/lib.rs` — governance module doc, ShadowMarshalOutcome, WormLog
- `ipc/src/marshal.rs` — MarshalRequest/Response/Outcome wire contract
- `kernel/src/marshal_client.rs` — how shadow evaluation calls into the proxy
- `CLAUDE.md` — architecture rules, Separation of Duties
- `THREAT_MODEL.md` — what's currently enforced, what's not
- `ROADMAP.md` — MARSHAL integration targets (Beta goal)
