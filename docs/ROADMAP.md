# Runix roadmap

Target dates and phase scope — not current implementation state. For what's
actually built and verified today, see [STATUS.md](STATUS.md); for the
layer/crate split these phases build on, see [ARCHITECTURE.md](ARCHITECTURE.md).

| Phase | Target | Desktop | Mobile |
|-------|--------|---------|--------|
| Alpha | 2027 Q1 / Q2 | Microkernel boot, capability manager, basic IPC, WASM runtime, CITADEL stub | Same + ARM TrustZone boot, RIL isolation, basic SIM provisioning |
| Beta  | 2027 Q3 / Q4 | Grid sandbox isolation, user-space network stack, filesystem driver, MARSHAL integration | MVNO stack core, eSIM lifecycle, data policy engine, MARSHAL integration |
| RC    | 2028 Q1 / Q2 | Desktop shell, app framework, WORM boot chain, hardware attestation | Secure dialer, VoIP trunk, roaming governance, VIGIL health monitoring |
| v1.0  | 2028 Q3 / Q4 | NIS2/GDPR suite, secure update channel, full MARSHAL governance, EU CRA alignment | Full MVNO operations, NIS2 suite, network slicing, EU regulatory alignment |

We are currently in **Alpha** — see [STATUS.md](STATUS.md) for exactly what
of Alpha's scope (and beyond it) is done, in progress, or not started.

## Open questions

- **License**: workspace default stays Apache-2.0 through Alpha and Beta.
  **Decision: still deferred, but the deferral's own reasoning is now
  stale and worth re-checking soon.** The original reasoning was "there's
  no real governance logic in `citadel-integration` yet, so there's
  nothing whose license would meaningfully differ" — no longer true: the
  crate now has real, tested logic (`ModuleManifestEntry`/`BootAllowlist`,
  boot-time module authorization — see [STATUS.md](STATUS.md)). It's
  arguably still Apache-2.0-appropriate (boot-time signature verification
  isn't the MARSHAL/WORM *governance* logic the AGPL question was
  originally about), but that argument hasn't actually been made yet, just
  assumed by inertia. Revisit explicitly — either re-confirm Apache-2.0
  with real reasoning or switch — rather than letting "deferred until real
  logic exists" silently stay deferred now that real logic exists. Full
  MARSHAL/WORM runtime logic (once `opensecstack/sdk/rust` unblocks it —
  see below) is still the harder version of this question.
- **`repository` field**: resolved — `Cargo.toml` now points at the real
  remote (`https://github.com/opensecstack/runix`), matching `git remote
  origin`. No longer a placeholder.
- **SDK dependency**: `citadel-integration` will depend on
  `opensecstack/sdk/rust` once the real CITADEL binding is built. Until then
  it's a stub with no external dependency. `sdk/rust` now exists, but its
  `CITADELClient` doesn't unblock this yet — it's a WORM *event-delivery*
  client (`send_event`/`get_events`/`verify_chain`, async on Tokio +
  `reqwest`, needs a host OS), not a MARSHAL Kerkese submit/decision call,
  and it can't compile inside `kernel/`'s `no_std` freestanding target
  regardless. Tracked upstream:
  [opensecstack/opensecstack#34](https://github.com/opensecstack/opensecstack/issues/34).
  This is an external blocker, not something Runix's own roadmap controls.
