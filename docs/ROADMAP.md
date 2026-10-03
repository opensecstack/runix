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
  **Decision: re-confirmed Apache-2.0 for `citadel-integration` as it
  exists today, with an actual argument instead of the old "no real logic
  yet" deferral (no longer true — the crate now has real, tested logic:
  `ModuleManifestEntry`/`BootAllowlist`, boot-time module authorization —
  see [STATUS.md](STATUS.md)).**
  - **The reference point**: `opensecstack/opensecstack`'s own root
    `LICENSE` splits the ecosystem explicitly — "Governance Platforms
    (AGPL-3.0)" lists `citadel/` by name (the actual MARSHAL/WORM/VIGIL
    platform); "Tool Platforms (Apache 2.0)" lists `sdk/` and everything
    else. AGPL in that split marks the governance *decision engine*
    itself, not everything that happens to talk to it.
  - **What `citadel-integration` actually does today, per its own module
    doc** (`citadel-integration/src/lib.rs`'s "Why not a Kerkese/MARSHAL
    round-trip" section): boot-time module authorization is explicitly
    *not* a governance round-trip — no `Kerkese` submission, no
    Separation-of-Duties evaluation, no Gate logic. It's "a
    signature-verification problem... solved the same way
    `capability-manager` solves capability tokens: Ed25519 over a
    canonical string, verified entirely offline." `capability-manager`
    itself has never been in question for Apache-2.0 — verifying a
    pre-computed signature is the same category of code whether the
    thing being verified is a capability token or a module manifest
    entry, and that category isn't what opensecstack's own AGPL split is
    marking.
  - **So**: Apache-2.0 for `citadel-integration` as it stands is the
    correct call, not inertia — the actual governance logic (Kerkese
    evaluation, WORM audit chain, VIGIL health monitoring) lives entirely
    in the external `citadel/` platform (correctly AGPL-3.0 there) and
    has not been reimplemented here. Runix only verifies signatures that
    platform produced, the same relationship any client verifying a
    third-party signature has to the signer.
  - **Real revisit trigger, not a vague "later"**: if/when this crate
    grows actual MARSHAL policy/Gate evaluation logic client-side (not
    just signature verification against a pre-signed artifact) — re-run
    this analysis then. The dependency that used to block this
    (`opensecstack/sdk/rust`'s no-`std` Kerkese core) now exists — see the
    SDK-dependency entry below — but the logic itself hasn't been written;
    `citadel-integration`'s `KerkeseTransport`/`TransportError` today are
    only re-exported type definitions with zero implementations anywhere in
    this repo (see that entry). Crossing from "verifies a governance
    platform's output" into "reimplements governance platform logic" is
    still a materially different question this same reasoning doesn't
    answer, and still hasn't happened.
- **`repository` field**: resolved — `Cargo.toml` now points at the real
  remote (`https://github.com/opensecstack/runix`), matching `git remote
  origin`. No longer a placeholder.
- **SDK dependency — resolved (2026-10-01)**: `opensecstack/sdk/rust` cut
  `citadel-kerkese-core` as v1.0.0, a `no_std` + `alloc` core for building,
  signing, and submitting CITADEL MARSHAL Kerkese requests — built
  specifically for hosts like Runix's freestanding kernel that can't pull in
  Tokio/reqwest, verified against the Go reference implementation
  (`citadel/internal/marshal/{types,sig}.go`) with a known-answer test. This
  closes [opensecstack/opensecstack#34](https://github.com/opensecstack/opensecstack/issues/34),
  the external blocker the old text here described. `citadel-integration`
  already depends on it (`a3cbe2a`): its own locally-duplicated
  `KerkeseTransport` trait and `TransportError` enum were deleted and
  replaced with `pub use citadel_kerkese_core::{KerkeseTransport,
  TransportError}` — verified identical shape before swapping.
  - **What that change was, and wasn't**: purely a type-identity swap.
    Nothing calls `KerkeseTransport` anywhere in `citadel-integration` or
    `kernel/` — there was no implementation before, there's still none now.
    Boot-time module authorization is unaffected (still offline Ed25519
    verification, no network round-trip). It removed the reason Option 1
    below used to be blocked; it didn't advance Option 1 over Option 2.
  - **Option 1 (kernel-direct) vs. Option 2 (user-space proxy) is still
    fully open**, and is now the real decision, not a future one gated on a
    dependency that didn't exist. Option 2 is the one with a real,
    end-to-end-proven implementation today: `desktop/src/bin/citadel_proxy.rs`
    (`std`/`reqwest`/Tokio, real HTTP to CITADEL), reached from the kernel
    over `kernel/src/marshal_client.rs`'s session-based sockets IPC
    transport — see `kernel/tests/marshal_proxy_e2e.rs`. Option 1
    (`citadel-kerkese-core` used directly from `kernel/`, with no proxy
    hop) is now technically *possible* for the first time — `sdk/rust`'s
    own `examples/kernel_direct_sketch.rs` sketches the shape — but
    unimplemented: it would need a `no_std` HTTP(S) client inside the
    kernel, for which `tls-client` (built this session, currently
    consumer-less — see `docs/RFC-TLS-APPROACH.md`) would be the natural
    TLS layer. Current recommendation: keep `citadel_proxy` as the real
    transport (it works, and keeps `unsafe`/panic-abort kernel code out of
    TLS+HTTP+JSON parsing on a privileged path — see this repo's own stance
    in `kernel/Cargo.toml`'s `panic = "abort"` comment); treat kernel-direct
    as a deliberate future project specifically because it could give
    `tls-client` its first real consumer, not as a default migration target.
- **Operator identity for a real MARSHAL round trip — open, RC-scope, not
  started (2026-10-02).** A real CITADEL/MARSHAL deployment is reachable
  (independently verified: `/api/v1/health` returns `200` on both CITADEL
  and sinauth; `POST /api/v1/marshal/evaluate` returns a real, structured
  `REFUSE`/`HARD_STOP` Decision for an empty request, not a transport
  error) — see `docs/STATUS.md`'s own section on this. But no real
  `EXECUTE` is possible yet: Gate 1 (AuthN) needs an `actor_token`
  (sinauth-issued bearer JWT for the *operator* identity) and a
  `sig_operator` (Ed25519 signature checked against a key registered via
  `POST /api/v1/keys/register`), and nothing anywhere in this codebase
  constructs either — `HttpKerkeseTransport` adds zero credentials of its
  own (pure bytes-in/bytes-out), and `citadel_proxy` only ever attaches
  `sig_verifier` (its own Verifier-identity signature, per
  `docs/RFC-VERIFIER-IDENTITY.md`'s Option A).
  - **Deliberately not provisioned ahead of a design decision.** Seeding
    sinauth accounts and registering a key is ~20 minutes of infrastructure
    work, but it would sit unused until something is taught to carry
    operator-side credentials — and that's a real identity-architecture
    question, not a stub: where does an operator's bearer token come from
    at request time (kernel hands it to the proxy? the proxy holds a
    service-account identity and impersonates?), and where does an
    operator's private signing key live (almost certainly never inside the
    kernel — so where, and how does whatever signs with it avoid becoming a
    single point of total compromise for every operator identity it can
    sign as)? Resolve this first; provisioning before it would front-run
    the decision, not advance it.
  - **Not Beta scope.** The transport/enforcement layer this decision sits
    on top of (session-primitive IPC, `citadel_proxy`, `spawn_instance`'s
    real fail-open/fail-closed enforcement, the boot-time
    `RUNIX_MARSHAL_PROXY_ADDR` hook) is done and verified — see
    `docs/STATUS.md`. This is real identity integration against a live
    governance platform, squarely RC-scope work.
  - **Re-confirmed 2026-10-03, full per-gate trace, not just the HTTP
    status this time.** A real `POST /api/v1/marshal/evaluate` with an
    empty body against the same reachable deployment: `{"outcome":
    "REFUSE", "gates": [{"gate":1,"name":"AuthN","status":"WARN",
    "reason":"AUTH_FAIL: no actor_token provided for user_id=;
    AUTH_FAIL: no signing key registered for operator user_id="},
    {"gate":2,"name":"AuthZ","status":"FAIL","reason":"AUTHZ_FAIL: role
    \"\" is not permitted to perform \"\""},{"gate":3,"name":"NDS",
    "status":"HARD_STOP","reason":"NDS_SAME_IDENTITY: operator and
    verifier are the same user"},{"gate":4,"name":"AUGUR",
    "status":"PASS"},{"gate":5,"name":"WORM","status":"PASS"}]}`.
    Confirms the framing above precisely: Gate 1 only `WARN`s
    (`EnforceIdentity`/`EnforceSignatures` aren't set to strict on this
    deployment), so the outcome is actually decided by Gate 2 (empty
    role → `FAIL`, which has no soft mode) and Gate 3 (empty actor/
    verifier → same-identity `HARD_STOP` by construction, not a
    deliberate test of the real NDS check). Re-affirmed the "deliberately
    not provisioned" decision above rather than seeding sinauth accounts
    now: the actual next gap is that `citadel_proxy` has no code path
    that constructs `actor_token`/`sig_operator` at all (it only ever
    attaches `sig_verifier`), so provisioning operator accounts/keys
    today would produce infrastructure nothing can use until that's
    designed — the identity-architecture questions two bullets up are
    the real blocker, not missing accounts.
- **SDK dependency — supply-chain policy for when #34 unblocks this.** This
  dependency sits on the boot-time authorization path: a compromised or
  maliciously-updated version doesn't just add a bug, it can make MARSHAL
  approve what governance was supposed to refuse — a higher-value
  supply-chain target than a typical crate (see the xz-utils/liblzma
  backdoor for the shape of attack this is meant to survive: a patient,
  trusted-maintainer-over-years compromise of exactly this kind of
  dependency). Two things decided now, ahead of the dependency actually
  existing, so whoever adds it doesn't default to the convenient-but-risky
  form under deadline pressure:
  - **Pin to an exact `rev` (commit) or tag, never a floating branch.**
    `Cargo.lock` alone only stops *future* malicious commits from being
    picked up automatically on a `cargo update` — it does nothing if the
    specific version first pinned is already compromised, so this is
    necessary but not sufficient. `deny.toml`'s `[sources]` section
    enforces this mechanically: `allow-git` is empty today, so *any* git
    dependency fails CI closed until this file is updated (and reviewed)
    in the same change that adds one.
  - **Least-privilege capability scoping is the real mitigation, not
    pinning.** Whatever process ends up holding the SDK client (`kernel/`
    directly under Option 1, or a `desktop`/`mobile` user-space
    CITADEL-proxy under Option 2 — see the SDK-dependency entry above)
    must be granted only the capability token(s) it actually needs (e.g.
    "talk to this one network endpoint"), never broad/ambient access —
    the same rule this repo already applies everywhere else
    (`capability-manager`). This has to be designed into whichever RFC
    resolves #34's Option 1 vs Option 2 question, not retrofitted after a
    broad-access client already exists and works.
  - Every version bump of this specific dependency (once it exists)
    should get its diff actually read, not just waved through by CI —
    there's no independent third-party review forcing that scrutiny the
    way an active open-source community sometimes provides, since Runix
    and the SDK share a maintainer.
