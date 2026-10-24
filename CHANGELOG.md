# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
file covers the changes since the published Alpha release, the tag
`v0.1.0-alpha`, up to version `0.1.0-beta.2`. Every entry was derived from the
commit history (`git log v0.1.0-alpha..HEAD`, 105 commits, 2026-10-01 to
2026-10-13); work that already shipped in `v0.1.0-alpha` is not repeated here.
See [docs/STATUS.md](docs/STATUS.md) for what is verified and
[docs/BETA_CRITERIA.md](docs/BETA_CRITERIA.md) for what Beta claims and does
not claim.

## [Unreleased]

### Security

- Fix: `kernel-arm` never set `SCTLR_EL1.nTWE`, so on a core where it resets to 0 an
  EL0 `wfe` (the idle loops at the end of the EL0 payloads and the panic handler of
  `net-driver-host-arm`) trapped to EL1 with EC 0x01 instead of idling. `mmu.rs` now
  sets it, with the MMU bit, through the pure helper `hw_contract::sctlr_with_mmu_and_el0_wfe`
  (a read-modify-write that only ORs bits in). QEMU's cortex-a53 resets `SCTLR_EL1` to
  `0xc50838` (measured by printing it before `install()`), which already has `nTWE` set,
  so the change is a no-op there and is for real silicon, where the reset value is
  UNKNOWN; it is covered by the helper's unit tests only.
- Fix: `net_process::setup` took the boot-info mode and the MARSHAL request bytes
  independently, so a mismatch would have faulted at EL0 on first access to unmapped
  request pages. It now rejects mode 1 without bytes, mode 0 with bytes and unknown modes
  before allocating or mapping anything, through the existing error path.
- Tests: a property test drives the real `post_rx_buffer`/`try_post` refusal in both net
  drivers, in debug and release; removing the refusal is no longer caught only by the
  two cfg-gated unit tests.
- Fix: `net-driver-host-arm` accepted a device-written RX length below the 12-byte
  virtio-net header, and `RxToken::consume` subtracted the header length without
  saturating, so a length under 12 underflowed into a huge slice length
  (undefined behaviour in a release build). The validator now rejects `len < 12`
  and `consume` saturates, the same fix `net-driver-host` received earlier. The
  ARM driver's queue-size handling is a separate fix (F6, below).
- Fix: `net-driver-host` and `net-driver-host-arm` could permanently lose RX buffers.
  `receive()` consumed a used-ring entry before checking its descriptor id and length
  and before checking for a free TX slot, and an early return did not re-post the
  buffer, so a hostile or bad completion, or a burst while TX was full, removed one of
  the eight RX buffers for good. The TX slot is now checked first. A valid descriptor
  id with an invalid length is dropped and its buffer re-posted. An out-of-range
  descriptor id is counted and skipped, with no buffer re-posted. At most 16 used
  entries are examined per call. The policy lives in a pure `rx_policy.rs` module with
  host tests. x86 is covered by the existing QEMU ICMP and DHCP tests, which exercise
  the happy path only. The ARM crate has not been run under QEMU for this change beyond
  a boot. A forged used entry that arrives after its buffer was legitimately re-posted
  can still duplicate an avail entry (`docs/THREAT_MODEL.md`, F1 and F4).
- Fix: `net-driver-host` and `net-driver-host-arm` did not track which RX buffers they
  had posted, so a completion for a buffer the driver still held (a repeat within one
  batch, or while a delivered frame was outstanding) could be delivered a second time,
  and its re-post could write a second avail entry for that buffer. The driver now keeps
  one posted bit per RX buffer, sets it only on the path that writes an avail entry
  (which refuses a second write), and clears it when a used entry is accepted. A
  completion for a buffer it holds is counted and skipped, not delivered or re-posted.
  Re-posts of dropped completions are deferred to the end of the batch, so a repeat
  within one batch is caught. Host tests cover the guard, and four call-sequence tests
  pin the order in which `receive()` takes a TX slot before polling the RX ring. x86 QEMU
  ICMP, DHCP and TCP tests pass. The guard does not catch a forged entry that arrives
  after its buffer was legitimately re-posted; that entry can still duplicate an avail
  entry (`docs/THREAT_MODEL.md`, F4).
- Fix: `net-driver-host-arm` accepted any device-reported `QueueNumMax` except 0 while
  always posting 8 RX and 4 TX descriptors, so a small or non-power-of-two queue could
  break the RX path. The driver now programs the largest power of two no greater than
  `min(QueueNumMax, 256)`, and fails through the existing queue-setup failure
  (result=3) only when that is below the posted descriptor count. This is a protocol
  violation by a non-spec device, not a memory-safety bug. Unlike x86, which rejects an
  invalid size, the ARM driver clamps it, because MMIO v2 lets the driver write
  `QueueNum` itself (`docs/THREAT_MODEL.md`, F6). A device with a small `QueueNumMax`
  has not been tested, since QEMU reports 256.
- Fix: `esim.delete` and `mvno.reactivate_account` failed open when MARSHAL was
  unreachable, so anyone who could drop the link could delete a profile (which is
  irreversible) or restore a suspended account. Both now fail closed, as
  `data.reset_usage` already did: the denial reads `DENIED (MARSHAL unreachable:
  fail-closed for this action)`, leaves state untouched, and is WORM-audited with
  `authorized=false` (ADR 0008). `esim.enable`, `mvno.bind_profile` and
  `mvno.suspend_account` still fail open. In the plain boots (no proxy), both
  deletes and the reactivation are now denied, so the account stays Suspended and
  the profile is never deleted there.
- kernel-arm: the demo Ed25519 trust root (`DEMO_SEED` in `src/capabilities.rs`) is
  gated behind the `insecure-demo-keys` feature, which is on by default, as in
  `kernel/`. A build without the feature stops with a `compile_error!` that names
  the missing key provisioning, instead of silently shipping the demo key. CI runs
  a `--no-default-features` build and checks for that message.
- Fix: the kernel-arm WORM chain had no size bound, and a caller holding a data,
  session or eSIM capability could grow it without limit. `SYS_DATA_RECONCILE` also
  re-recorded the same incident on every call. The chain is still one hash-chained
  append-only log, but each of ten event classes now has a fixed quota of entries (456
  in total, including summary slots). An event past its class's quota is counted and
  coalesced into a summary entry, committed at 1, 4, 16 and so on, at most 8 times per
  class, and the coalescing is printed on serial. `verify` also checks the bound's
  accounting (ADR 0009). A persistent reconciler incident is recorded once, when first
  seen, and a clean reconcile pass is recorded once after a non-clean one and then
  counted. Residual: each class keeps its first quota of events, the quotas are global
  rather than per caller, `applied` can be exhausted (later changes are counted, not
  refused), the serial log is unbounded, and the chain is still volatile and unsigned.
- Fix: denials that were serial-only on mobile are now WORM-audited with
  `authorized=false`, within the same per-class quotas: MARSHAL `Refuse` and `HardStop`
  blocks, capability denials on the six eSIM, three MVNO and six data syscalls, and the
  MVNO enable gate's refusal (ADR 0009). Capability denials on the RIL and IPC
  syscalls, a malformed `SYS_DATA_SESSION_CLOSE` argument, an unknown reset mode and
  the no-period `SYS_DATA_PERIOD` poll remain serial-only.
- Fix: a governed path that ends a data session's precondition no longer leaves the
  session row behind. `SYS_MVNO_SUSPEND`, a successful `SYS_SIM_DELETE` and a successful
  operator `SYS_SIM_DISABLE` close those sessions in the same syscall, after their own
  state change, and audit each row (`closed by kernel cleanup after ...`). Before, only an
  explicit `SYS_DATA_SESSION_CLOSE` removed rows, so stale rows could fill the 16-entry
  session table, and the reconciler could only report them (ADR 0010).
- Fix: `SYS_DATA_ACCOUNT` counted bytes for accounts that were Suspended or Closed, and for
  Active accounts with no bound profile. It now refuses both, with codes `8`
  (`USAGE_NOT_ACTIVE`) and `9` (`USAGE_NO_PROFILE`), before the counter is touched, and
  audits each refusal as `Rejected`. The check is `data_codes::usage_feed_refusal` over
  `mvno::has_bound_profile`, a thin wrapper over the registry's `profiles_of`. The kernel
  now issues `data:usage:1` for demo account 1, the walk's Active account with no bound
  profile (demo data). The byte count is still unauthenticated (ADR 0010).

### Added

- Docs: ADR [0009](docs/adrs/0009-bounded-worm-chain-and-denial-auditing.md) records
  the per-class bound, the coalescing rule, the denial auditing and the residual gaps
  that remain open.
- CI: the kernel-arm boot steps assert the new capability-denial, MVNO gate-refusal
  and clean-pass audit lines. The `Refuse` and `HardStop` audit lines are asserted in
  the MARSHAL steps, which have not yet been observed in a CI run of this change.
- CI: the `host` job runs `cargo fmt --check` and `cargo clippy -D warnings` on
  `grid-sandbox-host`, `net-driver-host`, `blk-driver-host` and `net-driver-host-arm`,
  after adding the `x86_64-unknown-none` and `aarch64-unknown-none` targets. These
  crates are not workspace members, so the root steps never checked them.
  `undocumented_unsafe_blocks` is enforced for all four: `net-driver-host-arm` gained
  the attribute after its 12 undocumented `unsafe` sites were given `// SAFETY:`
  comments. The same change fixes the `x0` operand of the two `svc #0` blocks in
  `net-driver-host-arm`'s `_start`: it was declared `in(..)` although the kernel
  overwrites `x0` with its return value, and is now `inout("x0") .. => _`.

- Docs: ADR [0007](docs/adrs/0007-dry-run-true-stays-until-operator-identity.md)
  keeps `dry_run: true` hardcoded on every MARSHAL request until operator identity
  exists. The audited CITADEL source does not treat dry-run as a simulation, and the
  `CITADEL_DRY_RUN_ALLOWED=false` setting its docs describe is not implemented there.
- Docs: ADR [0008](docs/adrs/0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md)
  records the fail-closed decision for delete and reactivate and the reasons the
  other three gated actions stay fail-open.
- Docs: ADR [0010](docs/adrs/0010-governed-session-cleanup-and-advisory-data-policy.md)
  records the session cleanup and the usage-feed refusals, and that the policy engine
  stays advisory (M3-c), with the conditions for revisiting that.
- CI: `.github/workflows/fuzz.yml` runs six `cargo-fuzz` targets on demand and weekly,
  never on push or pull request. It adds `boot_sector_fuzz` to the `blk-driver-host` fuzz
  crate (`BootSectorInfo::parse`, the `FsInfo` round trip, the reusable directory slot and
  short-name encoding). The workflow has not yet run on GitHub.
- CI: `kernel/tests/net_driver_dns_mock.rs` resolves a hostname through the SLIRP gateway
  (`10.0.2.2`), where a host mock (`kernel/tests/support/mock_dns.py`) answers with
  `192.0.2.53`. `NetBootInfo` gains a `dns_server` field at offset 124 (zero keeps the
  default `8.8.8.8`), inside the existing padding, so the struct stays 128 bytes. The step
  is not yet observed in a CI run, and its Linux assumptions (sudo for port 53, the
  gateway mapping) are unverified.
- CI: the kernel-arm boot steps assert the session cleanup lines and the usage-feed
  refusal codes `8` and `9`. These have not yet been observed in a CI run.

## [0.1.0-beta.2] - 2026-10-13

### Security

- Fix: malformed MARSHAL reply bytes failed open. The kernels decoded the
  kernel-to-proxy `ipc` reply with `MarshalResponse::decode`, whose `None` meant
  both "not enough bytes yet" and "can never be valid" (unknown tag, outcome or
  error kind, oversize length, non-UTF-8 message), so a garbled real `REFUSE`, or
  any malformed bytes, ended as `Unreachable` and admitted eSIM enable/delete,
  MVNO bind/suspend/reactivate and x86 `spawn_instance`. The new
  `MarshalResponse::decode_status` returns `Complete`, `Incomplete` or
  `Malformed`; `Malformed` is now `ShadowMarshalOutcome::Faulty` and blocks on
  both kernels (ADR 0006). A reply that is merely incomplete when the wait
  budget ends (silence or a stall) stays `Unreachable`. Residual: the link is
  unauthenticated, so an attacker who controls it can still stall (fail-open
  for the five actions) or forge a well-formed `Execute`; authenticating the
  link is the real fix.
- Fix: a MARSHAL reply that was reached but is faulty (`MarshalError::BadResponse`
  or `MarshalError::Other`: a malformed or empty body, a bad content-length, a
  non-403 HTTP error such as 400 or 500, a 403 whose body is not a
  `REFUSE`/`HARD_STOP` Decision) was classified `Unreachable` and so failed open
  for eSIM enable/delete, MVNO bind/suspend/reactivate and x86 `spawn_instance`.
  It is now the new outcome `ShadowMarshalOutcome::Faulty` and blocks all six
  mobile actions and `spawn_instance`, regardless of the per-action unreachable
  table (`db0aeb9`, `625e944`, `4e07444`; ADR 0006). The denial reads
  `DENIED (MARSHAL faulty reply: fail-closed)`, is WORM-audited with
  `authorized=false`, and the data reset returns `RESET_DENIED_FAULTY = 11`.
  Genuinely unreachable cases (no proxy, connect failure, timeout, an empty or
  incomplete kernel-to-proxy `ipc` reply) are unchanged. Availability note:
  every Runix request is `dry_run: true`, so a CITADEL that rejects dry-run
  requests answers HTTP 400, and one that fails with 5xx, now blocks every
  gated action loudly instead of silently allowing it.
- Fix: `citadel_proxy` could be stalled by one idle or slow client (it served
  one connection at a time with no read timeout), which the kernel read as
  MARSHAL unavailable. It now has a 20 s idle allowance before the first request byte and a 3 s total deadline for the rest of the frame (a first version with a 1 s total deadline was
  too tight for a slow emulated guest and was relaxed), a 2 s write
  timeout, at most 8 concurrent connections (excess closed immediately), an
  oversized declared length rejected on the 4-byte prefix, and a CITADEL HTTP
  connect timeout of 1 s and total timeout of 3 s, where a timeout is
  `MarshalError::Timeout` (`4a26c08`, `f8322c0`). Residual: an attacker who can
  reach the listener (a local process, or the guest through QEMU guestfwd) can
  still hold the 8 connections open and reopen them every ~20 s to starve
  valid requests; there is no per-peer limit. The fix for that is
  controlling who can reach the listener or authenticating the link.

### Added

- CI: boots a real `citadel_proxy` against a mock CITADEL answering a garbage
  HTTP 200 and an HTTP 500 and asserts the ARM kernel fails closed (faulty
  reply) for eSIM enable/delete and MVNO suspend (`d8d561e`).
- Tests: `grid_sandbox_marshal_shadow` gains a third case, `shadow-faulty`,
  asserting a faulty reply blocks `spawn_instance` and records `Faulty`
  (`4e07444`); host tests pin the faulty and unreachable classification and the
  proxy's idle, slow-client, oversized-length and connection-cap behaviour.
- Docs: ADR [0006](docs/adrs/0006-a-reachable-but-faulty-marshal-reply-fails-closed.md).

## [0.1.0-beta.1] - 2026-10-12

### Security

- Fix: `SYS_IPC_RECV` halted the whole kernel for any ring-3 caller. An
  unchecked `CHANNELS[port]` index ran before the capability check and
  `panic = "abort"` made the out-of-bounds access fatal. All port-indexed
  accesses in `ipc.rs` are now bounds-checked (`98bf422`, test `ipc_bad_port`).
- Fix: a port-I/O capability token covered more than its range. The access
  width was ignored, so a 4-byte access at the last granted port reached up to
  3 ports past it. The whole access must now fit (`a8bd3f3`, test `ioport_range`).
- Fix: `net-driver-host` accepted a device-reported RX length under the virtio
  header size, which could wrap a slice length. It is now rejected and the
  consume path uses saturating arithmetic (`51c606f`).
- Fix: `blk-driver-host` did not check revocation on file tokens. It now asks
  the kernel through the new `SYS_CAP_IS_REVOKED` (16, gated on
  `revocation:query`) and fails closed on any answer other than "not revoked"
  (`482ac57`, `b541ac0`, tests `cap_is_revoked`, `blk_fs_revoked`). A shared
  `blk_driver_extra_capabilities` helper keeps spawners from omitting the
  capability (`a4e6a39`).
- Fix: virtio queue sizes are validated in both drivers (power of two; at least
  the driver's real minimum; at most 256). A bad size now fails the probe
  instead of aborting (`d057c7b`, `51c606f`).
- Fix: `blk-driver-host` quarantines the device after a poll timeout instead of
  reading a stale completion later (`d057c7b`; QEMU regression test `c998f40`).
- Fix: a `citadel_proxy` policy refusal was classified as unreachable and so
  failed open. It now travels as its own `MarshalError::PolicyRefused` and
  blocks, in both `kernel-arm` and the x86 kernel (`0c87c3e`). A proxy built
  before this change still fails open; deploy kernel and proxy together.
- Fix: a real CITADEL answers `REFUSE` and `HARD_STOP` as HTTP 403 with a
  Decision body, and `citadel_proxy` discarded that body, so a real refusal
  was classified unreachable and failed open on both kernels. The transport
  now relays a 403 Decision, so the refusal blocks (CI proves this against a
  mock CITADEL that reproduces the handler's 403 + Decision; no real CITADEL
  is exercised).
- Fix: `kernel-arm` SIM operations shared one legality table, so a
  never-installed profile could be disabled then enabled, and `install` could
  overwrite an Enabled profile. Each operation now has its own required source
  state (`0c87c3e`).
- Fix: on `kernel-arm`, a MARSHAL evaluation that failed locally (for example
  out of memory) fell back to "unreachable" and so proceeded ungoverned. Local
  failures now fail closed, and evaluation address spaces and stacks are
  reclaimed so the heap no longer drains after about 8 evaluations (`0de97f8`).
- Every `unsafe` site in `grid-sandbox-host`, `net-driver-host` and
  `blk-driver-host` carries a `// SAFETY:` comment; each crate warns on
  `clippy::undocumented_unsafe_blocks` (`28e3a91`, `b9ebe03`, `1e4a4b4`).
  Hardening gaps found while doing this are recorded in `docs/STATUS.md`
  (`f8a101a`, `efffb46`).
- `abi-consistency` CI check fails if constants duplicated between the kernel
  and the ring-3 hosts (heap and boot-info addresses, result offsets,
  `BootInfo` layout, syscall numbers) drift (`4b19652`).
- `kernel/src/citadel.rs` states the `insecure-demo-keys` barrier itself
  (`c5bafd6`). Docs now record the boot allowlist as a wiring proof, not an
  enforcing gate (`de59268`).

### Added

- Kernel: `SYS_RANDOM` (RDRAND-backed, capability-gated entropy) and a
  session/handle IPC primitive (`SYS_IPC_SESSION_OPEN/ACCEPT/SEND/RECV/
  SEND_LOCK/SEND_UNLOCK`) with per-caller isolation. `blk-driver-host`,
  `net-driver-host` and the kernel's MARSHAL client were migrated onto it. A
  measured round trip is about 228 times cheaper than the fixed-port transport
  (`4fbb5e2`, tests `sys_random`, `ipc_session`, `syscall_cost`).
- Kernel: `SYS_CAP_IS_REVOKED` (`482ac57`); `capability-manager`
  `signature_fingerprint`, `RevocationList::is_fingerprint_revoked` and an
  O(log n) fingerprint revocation index (`327906b`, `a4e6a39`).
- Kernel: build-time `RUNIX_MARSHAL_PROXY_ADDR` hook so a real boot can point
  `spawn_instance`'s MARSHAL evaluation at a proxy; unset by default
  (`8b7a5a0`).
- `citadel-integration`: depends on `citadel-kerkese-core` 1.0.0; the local
  `KerkeseTransport` duplicate is dropped (`a3cbe2a`).
- `citadel_proxy` recognizes `esim.enable` and `esim.delete` (`e5166a8`) and
  records its own Verifier-identity decision in WORM (`8d0fabd`).
- `tls-client`: pure-Rust TLS 1.3 client crate for `x86_64-unknown-none`
  (`1c49264`; no consumer yet).
- Fuzz target and proptest fallback for the `blk-driver-host` FAT32 directory
  and chain-walk code (`1fe4203`).
- Mobile eSIM profile lifecycle, capability-gated and gated by MARSHAL
  (fail-open when MARSHAL is unreachable; `Refuse`/`HardStop` denials are not
  WORM-audited)
  (`50bf624`, `d93e124`: initiating principal passed through `esim_marshal`).
- Mobile MVNO account model and network selection, wired into `kernel-arm`,
  with the MVNO syscalls routed through MARSHAL (`6d4d8f6`, `fda8a47`,
  `727fc01`).
- Mobile data policy engine and read-only reconciler, wired into `kernel-arm`
  (`1660232`, `aef10bd`); billing-period model and `SYS_DATA_PERIOD` (24)
  (`3da349f`).
- Governed usage reset `SYS_DATA_RESET`: period gate, early-override
  capability, early-reset cooldown, demo-period install on a no-period
  account, and the last WORM entry read back onto the serial log
  (`aaeb5b0`, `f3e89e2`, `6f3d9c5`, `7a7319d`, `96700b5`, `1de4af1`).
- Mobile MARSHAL gate on `kernel-arm`: `esim_marshal` wired to a real
  transport, a per-action unreachable policy (reset is fail-closed; eSIM
  enable/delete and MVNO bind/suspend/reactivate stay fail-open, that is they
  proceed ungoverned when MARSHAL is unreachable), and recorded verdicts in the
  WORM reason and serial line (`319d111`, `727fc01`, `3da349f`). Denials by
  `Refuse`/`HardStop` are not WORM-audited on mobile (serial line only). Each evaluation uses its own source port and closes its socket
  (`0088a4e`).
- `kernel-arm` EL0 process model: ARM ELF64 parser and loader, per-process
  address spaces, MMIO-window capability type, cooperative scheduler and
  general-purpose IPC, and the first real EL0 process (`6cf1a58`, `58b202f`,
  `7806bec`, `33725c0`, `0d99bc1`).
- `kernel-arm` networking: virtio-mmio net device discovery, virtqueue
  bring-up with a real ARP round trip, `smoltcp` confirmed to build for
  `aarch64-unknown-none`, and real outbound TCP at EL0 through
  `net-driver-host-arm` (`447e531`, `1d65b9b`, `4a24f80`, `fa46ef7`).
- `docs/`: `docs/adrs/` (ADRs 0002 to 0005), `docs/BETA_CRITERIA.md`,
  `docs/RELEASE_NOTES_BETA_DRAFT.md` (`6a04eee`, `aaeb5b0`, `3da349f`,
  `0e488dc`, `803ee7c`, `2bc7d50`). Docs also now describe the data policy
  engine, the IPC migration, the MARSHAL identity gap and the driver hardening
  gaps.
- Release tooling: tag-triggered `.github/workflows/release.yml` (draft
  release, `SHA256SUMS`, dry run via `workflow_dispatch`) and `ci.yml` made
  callable (`7daf8c7`).
- CI additions: host unit tests for `kernel-arm` and `net-driver-host-arm`
  (`e4845f9`); QEMU tests `ipc_session` and `sys_random` (`755ba5d`),
  `blk_fs_concurrent_write` (`aa52f29`), `blk_fs_revoked`, `cap_is_revoked`
  (`b541ac0`, `482ac57`), `blk_fs_quarantine` (`c998f40`); assertions for the
  reset period gate, early override, cooldown and no-period install in the five
  ARM boot steps (`9fdefda`, `c7e34d4`); the `abi-consistency` check
  (`4b19652`).

### Changed

- All `blk-driver-host` and `net-driver-host` IPC now goes over sessions; each
  server has one session-accept port instead of separate request and response
  ports (`4fbb5e2`).
- `net-driver-host` sockets IPC server pre-checks `SESSION_ACCEPT` cheaply
  instead of throttling itself (`47a14cc`).
- Version bumped to `0.1.0-beta.1` across the workspace and the standalone
  crates (`f45e0fa`).
- Docs corrected for two stale MARSHAL-identity claims and a re-confirmed
  operator-identity gap; `kernel-arm` build-directory requirement documented;
  proof greps that fail on a plain local boot explained (`b11d739`, `3743409`,
  `ae8565b`, `97f3d68`, `c1b3efb`).
- CI: `net_driver_dns` was added to the QEMU test list (`755ba5d`), a
  throwaway diagnosis workflow was run (`7c4ff71`, merged in `b40844b`), and the
  test was removed again because the runner gets no DNS answer from 8.8.8.8
  (`ce9a203`). DNS is therefore not CI-verified.

### Removed

- RSA certificate verification from `tls-client`, to resolve RUSTSEC-2023-0071
  (`4d3d993`).

### Fixed

- A stale `marshal_proxy_e2e` request fixture (missing `dry_run`) and the
  `grid_sandbox_marshal_shadow` test (`cc66be5`, `47a14cc`).
- A session queue shared by both peers let a caller read back its own bytes
  before the peer did; each session now has two directional queues with
  independent send locks (`4fbb5e2`).
- `kernel-arm` MARSHAL evaluations after the first failed to connect because
  they reused a fixed source port and initial sequence number and never sent a
  FIN (`0088a4e`).
- `kernel-arm` heap exhaustion from unreclaimed evaluation processes
  (`0de97f8`).
- `SYS_DATA_PERIOD`'s "no billing period" refusal was WORM-audited on every
  call, so polling could grow the audit chain; it is serial-only now
  (`3da349f`).
- rustfmt and clippy drift, a clippy MSRV lint, and CI ordering (payload
  binaries such as `net-driver-host-arm` built before the crates that embed
  them) (`5c31c15`, `22bc3b2`, `468a85f`, `6e98f4e`, `200cfd8`, `a67dde2`).

[Unreleased]: https://github.com/opensecstack/runix/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/opensecstack/runix/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/opensecstack/runix/compare/v0.1.0-alpha...v0.1.0-beta.1
