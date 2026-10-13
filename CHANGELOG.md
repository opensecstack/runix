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
