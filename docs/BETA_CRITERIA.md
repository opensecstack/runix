# Beta exit criteria

[ROADMAP.md](ROADMAP.md) lists Beta's scope (target 2027 Q3 / Q4) but defines no
"done". This file does. It is a checklist with evidence, not a plan: every
evidence reference below was checked against the tree at the time of writing
(file exists; test or step is named in `.github/workflows/ci.yml`). Re-check
before relying on it; [STATUS.md](STATUS.md) is the detailed record.

Status as of 2026-10-19 (Tier 2 work; its new CI assertions are not yet observed in a CI run): **0 of 8 items fully MET against
their own full roadmap wording; 4 MET as scoped below, 4 PARTIAL, 0 NOT MET.**
The "done" statements here were written by the maintainers of this repo
against what the code does; they are deliberately narrow so that MET means
something checkable. Where a roadmap item reads wider than the statement, the
gap is listed under "Remains".

## What this release claims: "Beta developer preview"

A developer preview of the Beta scope, for people who read the code and the
docs. It claims:

- The eight items below are implemented to the extent each one's "done"
  statement says, and the cited tests pass in CI.
- The MARSHAL plumbing (kernel request, user-space proxy, CITADEL HTTP call,
  decision classification, per-action fail-open/fail-closed policy) exists and
  is exercised in CI **against mock CITADEL endpoints**.
- The kernel, drivers, and mobile boot walk run **under QEMU** (x86_64 and
  aarch64/`virt`).

### Not claimed

This list is mirrored in
[RELEASE_NOTES_BETA_DRAFT.md](RELEASE_NOTES_BETA_DRAFT.md). A release must not
be described as having any of the following.

1. **No live governance.** No code path in this repo reaches a real CITADEL
   `EXECUTE`. CI reaches an `Execute` verdict only from canned mock servers
   (`kernel/tests/support/mock_citadel_server.py`,
   `mock_citadel_server_multi.py`) and from the selective listener
   (`kernel/tests/support/arm_marshal_selective_listener.py`, which returns
   `Execute` unless told to refuse a named action); the mocks answer `EXECUTE`
   to any request. No real CITADEL ever answers in CI. A real
   `EXECUTE` is impossible today: nothing constructs the operator
   `actor_token` or `sig_operator` Gate 1 needs, and the MARSHAL principal on
   mobile is the placeholder `el0:arm-demo` ([ROADMAP.md](ROADMAP.md) open
   question "Operator identity", STATUS.md "MARSHAL gate for mobile").
2. **The MARSHAL gate fails open for three of six mobile actions.** If the proxy is
   unreachable, eSIM enable and MVNO bind/suspend proceed ungoverned (ADR
   [0003](adrs/0003-unreachable-marshal-policy-is-per-action.md)). `data.reset_usage`,
   `esim.delete` and `mvno.reactivate_account` fail closed (ADR
   [0008](adrs/0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md)).
   On x86, `grid_sandbox::spawn_instance`
   also fails open on an unreachable or unconfigured proxy
   ([MARSHAL-ENFORCEMENT-POLICY.md](MARSHAL-ENFORCEMENT-POLICY.md)). A reply
   that was reached but is faulty (malformed or empty body, bad content-length,
   a non-403 HTTP error such as 400 or 500, a 403 that is not a
   `REFUSE`/`HARD_STOP` Decision) is not unreachable: it blocks all six mobile
   actions and x86 `spawn_instance` (ADR
   [0006](adrs/0006-a-reachable-but-faulty-marshal-reply-fails-closed.md)). The
   consequence is a possible availability hazard. CITADEL documents a setting,
   `CITADEL_DRY_RUN_ALLOWED=false`, under which a Kerkese with `dry_run: true`
   (every Runix request) is answered 400; a CITADEL that fails with 5xx also
   blocks every gated action, loudly. The audited CITADEL source does not
   implement that setting, so the 400 case is not an observed behaviour
   ([ADR 0007](adrs/0007-dry-run-true-stays-until-operator-identity.md)). Still
   fail-open: no proxy or device, connect failure, timeout, and a
   kernel-to-proxy `ipc` reply that is empty or incomplete when the wait ends.
   Reply bytes that can never decode (unknown tag, outcome or error kind,
   oversize length, non-UTF-8 message) are a faulty reply and block. The link
   is unauthenticated, so an attacker who controls it can still stall (fail-open)
   or forge a well-formed `Execute`. The proxy is bounded (20 s idle allowance before the
   first request byte, 3 s for the rest of the frame, 2 s write timeout, at most 8 concurrent connections, CITADEL
   connect 1 s / total 3 s), so an idle or slow client cannot stall it, but an
   attacker who can reach its listener (a local process, or the guest through
   QEMU guestfwd) can still hold the 8 slots and reopen them every ~20 s to
   starve legitimate requests, which the kernel reads as unreachable. There is
   no per-peer limit. Fail-open success is logged as "not governed"; `Refuse`,
   `HardStop`, a faulty reply and local failure always block.
3. **Nothing outside tests calls `grid_sandbox::spawn_instance`.** The
   boot-time Grid Sandbox path (`kernel/src/main.rs` Phase B7) authorizes and
   loads `grid-sandbox-host` directly; the MARSHAL-gated multi-instance entry
   point is reached only from `kernel/tests/`.
4. **Boot-time module authorization is a wiring proof, not an enforcing gate.**
   `kernel/src/citadel.rs` builds its allowlist from the bytes it then checks,
   so it cannot reject a real module, and its evidence log is dropped
   (ROADMAP open question; STATUS.md "Beta review findings"). Do not call it
   fail-closed.
5. **Demo signing keys.** Capability and module signing keys are demo keys
   behind the `insecure-demo-keys` feature, which is on by default
   (`kernel/Cargo.toml`, `blk-driver-host/Cargo.toml`). There is no key
   provisioning, rotation, or secure boot chain.
6. **Mobile data policy does not meter or enforce.** Usage numbers are
   asserted by the caller of `SYS_DATA_ACCOUNT`; nothing measures bytes,
   nothing polls the billing period, no code consults a data session before
   network I/O, and the period clock counts ticks from boot, not calendar time.
   The engine's output is advice (`ActionRequest`) that nothing acts on. No
   persistence: accounts, sessions, usage and the WORM chain are lost on
   reboot. (Local `THREAT_MODEL.md` mobile gaps 13, 28, 29; STATUS.md "Data
   policy engine".)
7. **No real carrier, SIM or subscriber data.** Three MVNO accounts (0 to 2) are
   compiled in; eSIM `identity` is an opaque `u64`, not an ICCID/IMSI; there is
   no RSP/profile download, modem, RIL or carrier feed.
8. **Flat capability set on `kernel-arm`.** One `CURRENT_CAPABILITIES` set is
   shared, not per-process (THREAT_MODEL gap 5).
9. **No real HTTPS.** `tls-client` has no consumer and cannot talk to the real
   web: no wall clock, no root store (one CA per connection), RSA
   certificate verification removed ([RFC-TLS-APPROACH.md](RFC-TLS-APPROACH.md)).
   `citadel_proxy` to CITADEL is the only HTTP client and runs on the host.
10. **Filesystem IPC is narrow.** Read of a named file, and overwrite of an
    existing file within a single sector with no resize. Create, delete and
    grow exist inside `blk-driver-host` and are CI-verified there, but are
    deliberately not exposed over IPC. FAT32 only.
11. **QEMU-only verification.** No hardware (x86 or ARM) has been booted.
    Network tests rely on QEMU user-mode networking (`guestfwd`).
12. **Two tests are deliberately not in CI**: `kernel/tests/net_driver_dns.rs`
    (the CI runner gets no DNS answer from 8.8.8.8; see commit `ce9a203`; it runs only in
    the separate `dns-diagnose` workflow, which is not on `main`) and
    `kernel/tests/syscall_cost.rs` (a timing measurement, not a pass/fail
    check). Resolution against a real resolver is therefore not CI-verified.
    `kernel/tests/net_driver_dns_mock.rs` is in CI as its own step (added 2026-10-19, not
    yet observed in a CI run). It sends the guest's query to a host mock through the SLIRP
    gateway, so the resolver path is proven against that mock, not against the internet.
13. **Not a full release process.** The Alpha has a tag (`v0.1.0-alpha`) and a
    notes-only GitHub release with no binary artifacts attached. This Beta adds
    a tag-triggered workflow (`.github/workflows/release.yml`) that builds the
    x86_64 image, the aarch64 kernel ELF and the host ELFs and publishes
    `SHA256SUMS` as a draft release, but nothing is signed: a checksum file is
    not a signature. There is no update channel and no support policy. RC and
    v1.0 scope (desktop shell, WORM boot chain, attestation, secure dialer,
    VoIP, roaming governance) is not started.
14. **MARSHAL verdicts are not authenticated, and only part of the privileged
    surface is gated.** The kernel-to-proxy reply is unsigned JSON/`ipc` over
    plaintext TCP. Every request is `dry_run: true`, hardcoded. Runix's docs call
    this a simulation request, but the audited CITADEL source does not treat it as
    one, so do not rely on it as a simulation ([ADR 0007](adrs/0007-dry-run-true-stays-until-operator-identity.md)).
    An attacker who can reach the proxy listener can still starve the link
    into "unreachable" (bounded, not prevented), which fails open for three of the
    six mobile actions and for x86 `spawn_instance`. Only the six mobile actions below and x86 `spawn_instance` ask
    MARSHAL; every other privileged syscall in `kernel-arm/src/svc.rs` and
    `kernel/src/syscall.rs` is capability-checked only. On mobile, denial auditing
    is quota-limited (ADR 0009): `Refuse`/`HardStop` denials and capability denials
    on the eSIM, MVNO and data syscalls are WORM-audited, but each class keeps only
    its first quota of entries, and capability denials on the RIL and IPC syscalls
    are serial-only.

## Summary

| # | Side | Item | Status |
|---|------|------|--------|
| D1 | Desktop | Grid sandbox isolation | MET (as scoped) |
| D2 | Desktop | User-space network stack | MET (as scoped) |
| D3 | Desktop | Filesystem driver | PARTIAL |
| D4 | Desktop | MARSHAL integration | PARTIAL |
| M1 | Mobile | MVNO stack core | PARTIAL |
| M2 | Mobile | eSIM lifecycle | MET (as scoped) |
| M3 | Mobile | Data policy engine | MET (as scoped) |
| M4 | Mobile | MARSHAL integration | PARTIAL |

"CI step" below means a step name in `.github/workflows/ci.yml`. Tests named
`kernel/tests/*.rs` boot in QEMU. The step named
`cargo test (boots every kernel/tests/*.rs in QEMU)` is a fixed list of
`--test` lines, not a glob; a new test file is not in CI until added there.

---

## D1. Grid sandbox isolation: MET (as scoped)

**Done means:** a WebAssembly module runs only inside a ring-3 process with its
own address space; its linear-memory and table growth are capped by a tier
(T1/T2/T3) chosen by the signed module authorization, not by the module; the
three tiers give different, checked outcomes for the same request; and two
instances of the module can be spawned with separate state.

**Evidence:**
- `kernel/tests/grid_sandbox_wasm.rs` (T2), `grid_sandbox_tier_t1.rs`,
  `grid_sandbox_tier_t3.rs`: same grow request succeeds under T1, fails under
  T2 and T3, result read as a code from the boot-info page. All three are in
  the `cargo test (boots every kernel/tests/*.rs in QEMU)` step.
- `kernel/tests/grid_sandbox_multi_instance.rs`: two `spawn_instance` calls,
  same step.
- `wasm-runtime/tests/tier_isolation.rs` (limiter logic, host-side), run by CI
  step `test` (`cargo test --workspace`).
- `kernel/tests/process_isolation.rs`, `scheduler_address_space.rs`,
  `ring3_cooperative.rs`: per-process address spaces and ring-3 scheduling.
- CI job `boot`, step `boot in QEMU and check for kernel serial output`
  (greps the `grid-sandbox-host ran wasmi in an isolated ring 3 process` line).

**Remains (outside the scoped statement):**
- The tier controls memory and table caps only (STATUS.md, tier
  isolation text); nothing here makes a tier change which syscalls or capabilities a
  module gets.
- The only modules that run are the ones embedded in `grid-sandbox-host`
  (`hello.wat`, `grow_probe.wat`). There is no path to load a third-party
  module, and the tier-3 "untrusted" case is exercised with the same
  first-party binary.
- Cap sizes are arbitrary initial values, not tuned to a workload.

## D2. User-space network stack: MET (as scoped)

**Done means:** a ring-3 driver process, holding only the capabilities it was
granted (no raw port-I/O privilege), brings up virtio-net and an IP stack, and
another ring-3 process can use it through a typed, capability-gated sockets
IPC surface to complete a TCP exchange, with more than one concurrent handle.

**Evidence:**
- `kernel/tests/net_driver_icmp.rs`, `net_driver_dhcp.rs` (in the fixed
  `cargo test` list); `net_driver_tcp.rs`, `net_driver_sockets.rs`,
  `net_driver_sockets_concurrent.rs` (own CI steps `cargo test net_driver_tcp`,
  `cargo test net_driver_sockets`, `cargo test net_driver_sockets_concurrent`,
  using `guestfwd`).
- `kernel/tests/ipc_session.rs`, `ipc_bad_port.rs`, `ioport_range.rs`.
- CI step `test net-driver-host (host-side property tests)`, and the
  property coverage of the RX parsing boundary (STATUS.md). A `cargo-fuzz` target for that
  boundary (`net-driver-host/fuzz`) runs only in the manual or weekly `fuzz` workflow
  (`.github/workflows/fuzz.yml`), not as a PR gate; that workflow has not yet run on GitHub.
- CI job `boot` greps `net-driver-host: ICMP echo reply received`.

**Remains (outside the scoped statement):**
- DNS exists in the driver. `kernel/tests/net_driver_dns.rs` (real egress) is not in CI.
  `kernel/tests/net_driver_dns_mock.rs` covers the resolver path in CI against a host mock
  through the SLIRP gateway (added 2026-10-19, not yet observed in a CI run; its Linux
  assumptions are unverified).
- No UDP socket surface; no interrupt-driven RX/TX; no real wall-clock time.
- No TLS consumer (see Not claimed 9).
- Verified only against QEMU user-mode networking.

## D3. Filesystem driver: PARTIAL

**Done means:** a ring-3 driver serves a real FAT32 volume over virtio-block:
reads files by name, writes to existing files, authorizes every request with a
per-file capability token, refuses revoked tokens, and fails safe if the
device stops answering.

**Evidence:**
- Read, long names, subdirectories, multi-cluster: `kernel/tests/blk_fat32_read.rs`
  (CI step `cargo test blk_fat32_read (real FAT32 image via virtio-blk)`, with
  follow-up steps that check the on-disk result with `mtools`:
  `verify WRITE.TXT was actually overwritten on disk`,
  `verify PARTIAL.TXT was actually resized and overwritten on disk`,
  `verify GROW.TXT/DELETE_M.TXT/CREATED.TXT reflect Phase 7's writes on disk`).
- IPC surface and per-request token: `kernel/tests/blk_fs_ipc.rs`
  (CI step `cargo test blk_fs_ipc (filesystem IPC surface via virtio-blk)`).
- Concurrency: `blk_fs_concurrent.rs`, `blk_fs_concurrent_write.rs`.
- Revocation: `blk_fs_revoked.rs` and `cap_is_revoked.rs` (CI step
  `cargo test blk_fs_revoked (revoked file token refused by blk-driver-host)`).
- Quarantine after a poll timeout: `blk_fs_quarantine.rs` (CI step
  `cargo test blk_fs_quarantine (poll timeout quarantines the device)`).
- Raw device round trip: `blk_driver_rw.rs`.
- CI step `test blk-driver-host (host-side property tests)` (FAT32 parser).

**Remains:**
- Over IPC, a write is an in-place overwrite of an existing file within one
  sector, no resize (`ipc/src/fs.rs`, `FsRequest::Write` doc). Create, delete
  and grow are internal to the driver only. Decided for Beta (D3-b): they stay
  driver-internal. Exposing them needs new request variants, distinct per-operation
  capability resources (today one `file:<name>` token covers a file), quota and disk-fill
  handling, a redone allocator-safety argument, and a MARSHAL-gating decision for
  destructive delete. Revisit before any caller needs them (RC).
- FAT32 only; no other filesystem; no permissions model beyond the tokens.
- The driver has no device reset after quarantine; it stays failed until reboot.
  Decided for Beta (D3-a): quarantine is permanent until the driver restarts, because
  fail-closed is the Beta posture. A device reset mid-write could leave FAT state
  inconsistent, and a reset would loosen a deliberate design. A supervisor that respawns
  the driver is the better recovery model. Revisit with that supervisor, or reset in RC.
- No hardware verification (QEMU virtio-blk only).

## D4. MARSHAL integration (desktop): PARTIAL

**Done means (checkable):** (a) a privileged desktop action asks MARSHAL
before it runs and a `REFUSE`/`HARD_STOP` blocks it; (b) the request path is
the typed `ipc` wire format through a user-space proxy to CITADEL (in CI only
a mock CITADEL is ever reached); (c) the
action is audited to WORM; (d) a real CITADEL decision, obtained with a real
operator identity, can allow an action.

**Status by clause:** (a) mechanism MET, test-only caller, ungoverned in practice
(`grid_sandbox::spawn_instance` fails open on unreachable); (b) MET (to a mock CITADEL only);
(c) PARTIAL; (d) **NOT MET**.

**Evidence:**
- (a) `kernel/tests/grid_sandbox_marshal_shadow.rs` (CI step
  `cargo test grid_sandbox_marshal_shadow (real MARSHAL enforcement - blocks on a reachable Refuse, fail-open when unreachable)`).
  `Refuse`/`HARD_STOP` block, proven in CI against stand-ins and against a mock
  CITADEL that reproduces the real handler's HTTP 403 + Decision; no real
  CITADEL is exercised. The same test's third case, `"shadow-faulty"`
  (case 2b in the file), proves a reached-but-faulty reply blocks the spawn
  with `MarshalEnforcementError::FaultyReply` and records `Faulty` in the WormLog;
  case 2c, `"shadow-malformed"`, does the same for raw reply bytes that are no
  valid response.
- (b) `kernel/tests/marshal_tcp_roundtrip.rs` (CI step
  `cargo test marshal_tcp_roundtrip ...`) and `marshal_proxy_e2e.rs` (CI step
  `cargo test marshal_proxy_e2e (real citadel_proxy + mock CITADEL via guestfwd)`:
  real `citadel_proxy` binary, mock CITADEL HTTP endpoint).
- (c) the shadow test asserts a `WormLog` entry in every case.
  `citadel-integration` unit tests run in step `test`.
- Boot allowlist wiring: `kernel/tests/citadel_demo.rs` and the `boot` job's
  `CITADEL boot authorization OK` line.

**Remains:**
- (d): no operator identity exists, so no real `EXECUTE`; the only `Execute`
  verdicts in CI come from a mock that answers `EXECUTE` unconditionally.
  The proxy attaches only its own Verifier signature
  ([RFC-VERIFIER-IDENTITY.md](RFC-VERIFIER-IDENTITY.md)). Decision on identity
  architecture is open and tracked as RC scope in ROADMAP.
- `spawn_instance` is never called outside tests (Not claimed 3). Decided for Beta
  (D4-a): no production caller ships. A boot-time caller would be ungoverned in practice,
  because no dev or CI boot sets `RUNIX_MARSHAL_PROXY_ADDR`, so the call would pass
  unchecked. A ring-3 syscall caller needs a tier-derivation design first (the tier is
  caller-supplied today, and the allowlist is built from that same tier), and a latency
  measurement against the T1 300 ms budget. Revisit once a deployment exists for the proxy
  and both of those are done.
- Unreachable or unconfigured proxy fails open (Not claimed 2).
- The verdict is not authenticated end to end (unsigned JSON over plaintext
  TCP between kernel and proxy), and every request is `dry_run: true`
  (Not claimed 14).
- The boot-time module gate is a wiring proof (Not claimed 4).
- WORM evidence is an in-memory log: lost on reboot, not a durable chain.

## M1. MVNO stack core: PARTIAL

**Done means:** an account registry enforces its invariants in one place
(bounded accounts and profile bindings, enable requires an `Active` account,
suspend force-disables bound profiles and re-checks, delete frees the
binding); capabilities scope bind, suspend and reactivate separately; network
selection is a pure function with distinguishable refusal reasons; all of it
runs in the kernel's syscall path. The partial point is that it does so for
three compiled-in demo accounts (0 to 2), not for subscribers.

**Evidence:**
- Host tests of `mobile/src/account.rs` and `selection.rs`: CI step `test`
  (`cargo test --workspace`).
- CI job `kernel-arm`, steps `test (host-side unit tests)` and
  `boot in QEMU and check EL3 boot, exception resume, GIC, EL3->EL1 drop`
  (asserts `SYS_MVNO_BIND ... authorized`,
  `SYS_SIM_ENABLE ... DENIED (MVNO AccountNotActive(Suspended))`,
  `... DENIED (MVNO NotBound)`, and `MVNO network selection PASS`).
  The same assertions repeat in step
  `boot in QEMU without secure=on and check the no-EL3 path`.
- Audit lines (ADR 0009), in both of those plain-boot steps: the MVNO gate refusal
  (`SYS_SIM_ENABLE ... MVNO gate refusal audited to WORM (... class rejected ...)`) and
  the MVNO capability denials (`... capability denial audited to WORM (... class
  cap-denial.mvno ...)`). Not yet observed in a CI run of this change.

**Remains:**
- Three compiled-in demo accounts (0 to 2); no persistence; selection runs on a fixed
  candidate list. No modem, RIL or carrier source feeds it; no billing,
  rating or provisioning backend.
- The MARSHAL principal is the placeholder `el0:arm-demo`.
- Decided for Beta (M1-a): no provisioning and no slot reclamation. Account ids are
  sequential and never reused by design, because reusing one would let a stale token
  authorize a new account. No syscall closes an account, so "closed accounts keep their
  slot" is latent, not observed. A provisioned account would be unusable without runtime
  capability-token issuance, which needs key custody (RC). Per-account resources are
  issued only at boot, and the data plan tables cover accounts 0 to 2 only. Revisit with
  persistence and key custody (RC/v1.0).

## M2. eSIM lifecycle: MET (as scoped)

**Done means:** each profile is in exactly one of `Created`, `Disabled`,
`Enabled`, `Deleted`; every transition goes through one validating function
with a per-operation required source state; at most one profile per slot is
`Enabled`; each operation needs its own scoped capability (delete is a
separate resource); and every successful transition is audited at the syscall boundary.

**Evidence:**
- 13 host tests of the state machine, including an exhaustive
  operation-by-source-state matrix (`kernel-arm/src/sim.rs`): CI job
  `kernel-arm`, step `test (host-side unit tests)`.
- QEMU boot walk, step
  `boot in QEMU and check EL3 boot, exception resume, GIC, EL3->EL1 drop`
  (asserts the full Created, Disabled, Enabled, Disabled, Deleted walk, plus
  `SYS_SIM_INSTALL ... FAILED (wrong state for this operation (Enabled))`,
  the same for delete, and capability denial on slot 99).

**Remains (outside the scoped statement):**
- `identity` is an opaque `u64`, not an ICCID/IMSI; no profile download (RSP,
  SM-DP+), no real profile data.
- Deleted containers are never reclaimed; no persistence across reboot.
- Governance of enable rests on item M4 and is fail-open; governance of delete is
  fail-closed when MARSHAL is unreachable (ADR 0008).

## M3. Data policy engine: MET (as scoped)

**Done means:** an account's plan (cap, throttle percentage, roaming flag,
escalation percentage) determines session and usage decisions; a reconciler
reports drift between observed state and the plan; a billing-period model
gates the usage reset; and the reset is capability- and MARSHAL-gated with
its period refusal, success, and local-failure, unreachable and `Refuse`/`HardStop`
denial audited, and its capability denials too (ADR 0009, quota-limited per class).

**Evidence:**
- Pure-logic host tests (`mobile/src/policy.rs`, `reconcile.rs`, `period.rs`):
  CI step `test`; `kernel-arm` lib tests: step `test (host-side unit tests)`.
- QEMU boot walk assertions on `SYS_DATA_ACCOUNT` (throttle and suspend
  advice), `SYS_DATA_RECONCILE` (incident lines), `SYS_DATA_RESET`
  (fail-closed denial when no proxy, period refusal, early-override, cooldown,
  no-period install) in step
  `boot in QEMU and check EL3 boot, exception resume, GIC, EL3->EL1 drop`
  and `boot in QEMU and check a real citadel_proxy EXECUTE admits eSIM enable (Beta item 2.6 follow-up)`
  (the latter asserts the reset against a mock CITADEL).
- Audit lines (ADR 0009): the plain-boot steps assert the data capability-denial
  lines (`... capability denial audited to WORM (... class cap-denial.data ...)`) and
  the reconciler's clean-pass lines. The `MARSHAL Refuse denial audited` lines for the
  data reset are asserted in the `MARSHAL REFUSE` steps, which use the test-only
  selective stand-in listener, not the real `citadel_proxy`. Reconciler incident
  dedupe is covered only by host tests in `kernel-arm/src/audit_chain.rs`. None of
  these lines has yet been observed in a CI run of this change.
- Session cleanup and usage-feed refusals (ADR 0010): the steps
  `boot in QEMU and check EL3 boot, exception resume, GIC, EL3->EL1 drop` and
  `boot in QEMU without secure=on and check the no-EL3 path` assert
  `closed by kernel cleanup after MVNO suspend` (and that the
  `session-without-enabled-profile` incident never appears), and the refusals
  `DENIED (account is Suspended, not Active; returns code 8)` and
  `DENIED (account has no bound profile; returns code 9)`. The step
  `boot in QEMU and check a real citadel_proxy EXECUTE admits eSIM enable` asserts two
  cleanup lines (suspend, operator SIM disable). The secure-boot walk was run locally
  only (a scratch build with the demo token lifetime raised; see THREAT_MODEL gap 3). The
  other steps were not run locally, and none of these lines has yet been observed in a
  CI run of this change.
- Design records: ADRs [0001](adrs/0001-data-syscalls-not-marshal-gated.md)
  to [0005](adrs/0005-no-period-reset-installs-a-period-and-early-resets-have-a-cooldown.md),
  and [0010](adrs/0010-governed-session-cleanup-and-advisory-data-policy.md).

**Remains:**
- Decided, not a gap (M3-c, ADR 0010): no code performs an `ActionRequest`, and the
  engine stays advisory. This is the partial point the statement used to carry. Revisit
  when usage is measured from an authenticated source (THREAT_MODEL gap 13) and the kernel
  has an operator identity (ADR 0007), so that a kernel-initiated suspension has an actor
  MARSHAL's separation-of-duties rules can accept.
- The inputs are asserted, not measured. The usage feed refuses accounts that are not
  Active and accounts with no bound profile (ADR 0010), but the byte count is still
  unauthenticated.
- The governed suspend, delete and operator disable close the sessions they end (ADR
  0010). A future path that ends a session's precondition without calling the cleanup
  would leave a row, and the reconciler reports it only when called.
- No data path: nothing consults a session before network I/O and nothing
  measures bytes. `SYS_DATA_ACCOUNT` is a demo syscall.
- `ActionRequest` (`NotifyOnly`, `Throttle`, `SuspendAccount`) is advice; no
  code performs it. Per-sandbox-tier traffic classes are not built.
- Nothing starts or ends a billing period on a schedule; the clock is the
  ARM generic counter from boot.
- No billing, rating or persistence. The five non-reset data syscalls are
  outside MARSHAL by design (ADR 0001).

## M4. MARSHAL integration (mobile): PARTIAL

**Done means (checkable):** (a) each consequential mobile action asks
MARSHAL through the proxy before it takes effect; (b) `Refuse`/`HardStop`
blocks it and leaves state untouched; (c) the verdict that allowed an action
is recorded (the `Refuse`/`HardStop` denial is also WORM-audited since ADR 0009); (d) unreachable-MARSHAL behavior is an explicit per-action
policy; (e) a real CITADEL `EXECUTE` with a real operator identity admits an
action.

**Status by clause:** (a) MET for six actions; other privileged syscalls are not
MARSHAL-gated (`esim.enable`, `esim.delete`,
`mvno.bind_profile`, `mvno.suspend_account`, `mvno.reactivate_account`,
`data.reset_usage`); (b) MET; (c) PARTIAL (the allowing verdict is recorded on
successes; `Refuse`/`HardStop` denials are WORM-audited since ADR 0009, within the
class quota);
(d) MET as a policy, exercised in CI only against absent routes, never a real
outage; (e) **NOT MET**.

**Evidence:**
- (b): CI steps `boot in QEMU and check MARSHAL REFUSE denies eSIM enable (Beta item 2.6)`
  and `boot in QEMU and check MARSHAL REFUSE denies MVNO suspend (Beta item 3.4)`
  (selective listener refuses named actions; the `Refuse` is canned, no real
  CITADEL answers). Through the real `citadel_proxy`, `Refuse`/`HARD_STOP`
  block, proven in CI against stand-ins and against a mock CITADEL that
  reproduces the real handler's HTTP 403 + Decision; no real CITADEL is
  exercised.
  Denial audit (ADR 0009): the two `MARSHAL REFUSE` steps assert `SVC: MARSHAL Refuse
  denial audited to WORM (...)` against the test-only selective stand-in listener, not
  the real `citadel_proxy`. The real-`citadel_proxy` 403 step asserts `SVC: MARSHAL
  HardStop denial audited to WORM (...)`. None of these lines has yet been observed
  in a CI run of this change.
- (a), (c): CI step `boot in QEMU and check a real citadel_proxy EXECUTE admits eSIM enable (Beta item 2.6 follow-up)`
  (real `citadel_proxy`, mock CITADEL; asserts `MARSHAL verdict: Execute` and
  exactly three data evaluations). This step proves the chain, not live
  governance: the mock answers `EXECUTE` to anything.
- (d): the plain boot step asserts `MARSHAL verdict: Unreachable (fail-open:
  not governed)` for eSIM enable and MVNO bind/suspend, and `DENIED (MARSHAL
  unreachable: fail-closed for this action)` for the reset, the eSIM deletes and the
  MVNO reactivate. Policy in ADR
  [0003](adrs/0003-unreachable-marshal-policy-is-per-action.md), and ADR
  [0008](adrs/0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md)
  for delete and reactivate.
- Faulty replies: CI step `boot in QEMU and check a real citadel_proxy relaying a garbage 200 / HTTP 500 from a mock CITADEL fails closed (faulty reply) for eSIM enable/delete and MVNO suspend`
  (real `citadel_proxy`, mock CITADEL answering a non-JSON 200 for `esim.*` and
  HTTP 500 for `mvno.suspend_account`; asserts `DENIED (MARSHAL faulty reply:
  fail-closed)`, the `Faulty` evaluation lines, six WORM denials with
  `authorized=false`, and that the actions answered `EXECUTE` are still admitted).
  A genuinely unreachable MARSHAL still follows the per-action table, as in the
  plain boot step above.
- Proxy policy, wire and hardening tests (`desktop/src/citadel/policy.rs`,
  `proxy.rs`, `transport.rs`: idle and slow clients, oversized length, the
  connection cap, a never-answering CITADEL yielding `Timeout`): CI step `test`.

**Remains:**
- (e): no operator identity (Not claimed 1); signing key is the demo key.
- Three of six actions fail open when MARSHAL is unreachable: `esim.enable`,
  `mvno.bind_profile`, `mvno.suspend_account` (Not claimed 2). They stay fail-open by
  decision, each with a recorded reason (ADR 0008: enable may be needed to bootstrap
  connectivity, bind is a prerequisite of enable, suspend is the restrictive direction);
  the revisit conditions are in that ADR. `esim.delete` and `mvno.reactivate_account`
  were decided fail-closed in ADR 0008.
- Denial audit is quota-limited (ADR 0009): once a class is full, further
  `Refuse`/`HardStop` blocks are counted, not individually recorded. RIL and IPC
  capability denials are serial-only (STATUS.md, "The bounded mobile WORM chain").
- Link is plaintext TCP and the verdict is unsigned.
- A proxy built before `MarshalError::PolicyRefused` reports its own policy
  rejections as `MarshalError::Other`, which is now a faulty reply and blocks
  (it used to fail open); kernel and proxy must still be deployed together.
- The proxy's bounded concurrency does not stop an attacker who can reach the
  listener from starving it (see Not claimed 2).
- A live CITADEL must carry `rbacMap` entries for these actions; CI cannot
  show whether a given deployment does.

---

## How to re-verify

```
cargo build --workspace && cargo test --workspace      # host crates, mobile cores, abi check
cargo run -p abi-consistency                            # kernel <-> host constant drift
cd kernel && cargo test --target x86_64-unknown-none --test <name>   # one QEMU test
```

The full per-step command set, including the `guestfwd` listeners the network
and MARSHAL tests need, is the `kernel-tests` and `kernel-arm` jobs in
`.github/workflows/ci.yml`. [BUILDING.md](BUILDING.md) explains the toolchain
requirements and the proof lines that cannot pass on a plain local boot.
