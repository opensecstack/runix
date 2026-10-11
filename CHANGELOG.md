# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No
version numbers or dates are assigned yet. This section covers everything
committed after the `alpha-complete` tag. Each line was derived from the commit
history (`git log alpha-complete..HEAD`); see [docs/STATUS.md](docs/STATUS.md)
for what is verified and [docs/BETA_CRITERIA.md](docs/BETA_CRITERIA.md) for what
Beta claims and does not claim.

## [Unreleased]

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
  the kernel through the new `SYS_CAP_IS_REVOKED` (16) and fails closed on any
  answer other than "not revoked" (`482ac57`, `b541ac0`, test `blk_fs_revoked`).
- Fix: virtio queue sizes are validated (power of two within the driver's real
  minimum and 256) in both drivers; a bad size now fails the probe instead of
  aborting (`d057c7b`, `51c606f`).
- Fix: `blk-driver-host` quarantines the device after a poll timeout instead of
  reading a stale completion later (`d057c7b`; QEMU regression test `c998f40`).
- Fix: concurrent senders on one IPC port could interleave messages (`51c0c4c`).
- Fix: a `citadel_proxy` policy refusal was classified as unreachable and so
  fail-open; it now travels as its own `MarshalError::PolicyRefused` and blocks.
  Also closes an SIM source-state hole where a never-installed profile could be
  disabled then enabled (`0c87c3e`). A proxy built before this change still
  fails open; deploy kernel and proxy together.
- Fix: `SYS_IPC_RECV` is now capability-gated and the shared FS response port
  is retired (`cc51dd5`).
- Fix: syscall wrappers declare RCX/R8-R11 clobbers on `int 0x80` (`c3f911e`).
- Remove RSA certificate verification from `tls-client` to resolve
  RUSTSEC-2023-0071 (`4d3d993`).
- `cargo-deny` supply-chain checks in CI, with `allow-git` empty so a git
  dependency fails closed until reviewed (`a415ff9`, `deny.toml` fixes after).
- Every `unsafe` site in `grid-sandbox-host`, `net-driver-host` and
  `blk-driver-host` carries a `// SAFETY:` comment; each crate warns on
  `clippy::undocumented_unsafe_blocks`.
- `abi-consistency` CI check fails if kernel and ring-3 host duplicated
  constants (210 today) drift (`4b19652`).
- `kernel/src/citadel.rs` states the `insecure-demo-keys` barrier itself
  (`c5bafd6`). Docs now record the boot allowlist as a wiring proof, not an
  enforcing gate (`de59268`).

### Added

- ARM/TrustZone bring-up in new `kernel-arm`: EL3 boot, exception vectors,
  GICv2, EL3 to EL1 Non-secure drop, EL1 MMU, EL0 RIL isolation boundary with
  SVC gate and capability checks, and basic SIM provisioning. A no-EL3 boot path
  is also supported.
- Mobile Beta work in `kernel-arm` and `mobile/`: eSIM profile lifecycle
  (state machine, per-operation capabilities, audit); MVNO account registry and
  network selection; data policy engine, reconciler and billing-period model;
  governed usage reset (`SYS_DATA_RESET`) with period gate, early-override
  capability, cooldown and no-period install (ADRs 0001 to 0005).
- Mobile EL0 process model: ELF64 loader, per-process address spaces,
  cooperative scheduler and IPC, virtio-mmio net discovery, virtqueue bring-up,
  real outbound TCP at EL0 (`net-driver-host-arm`).
- MARSHAL gate for mobile: six governed actions, an EL0 transport process per
  evaluation, per-action unreachable policy (`FailOpen`/`FailClosed`), verdicts
  recorded in WORM text, `citadel_proxy` recognizes `esim.*`, `mvno.*` and
  `data.reset_usage`.
- Desktop network stack in `net-driver-host`: virtio-net, smoltcp, ARP/ICMP,
  TCP, DHCP, concurrent sockets, DNS, and a typed sockets IPC surface.
- Desktop filesystem driver in `blk-driver-host`: virtio-blk, FAT32 read, long
  filenames, subdirectories, partial write, cluster allocation, directory
  growth, create/delete/grow (driver-internal), and a typed filesystem IPC
  surface with per-request capability tokens.
- Grid Sandbox tiers T1/T2/T3 with tier-driven memory and table caps, boot
  verified for all three, plus multi-instance `spawn_instance`.
- `spawn_instance` MARSHAL evaluation, first observe-only, then real
  enforcement (`Refuse`/`HardStop` block; unreachable or unconfigured fails open).
- Kernel to proxy MARSHAL wire contract in `ipc`, a real `HttpKerkeseTransport`
  and `citadel_proxy` binary in `desktop`, a boot-time proxy address hook, and
  an end-to-end QEMU test through a real proxy and a mock CITADEL.
- Kernel syscalls and IPC: RDRAND entropy (`sys_random`), session/handle IPC
  primitive with both drivers migrated onto it, `SYS_CAP_IS_REVOKED`.
- `capability-manager`: signature fingerprints and an O(log n) revocation index.
- `citadel-integration`: boot-time module allowlist (replacing the stub),
  per-instance authorization with a local WORM evidence log, and a dependency on
  `citadel-kerkese-core` 1.0.0.
- `tls-client`: pure-Rust TLS 1.3 client crate for `x86_64-unknown-none`
  (no consumer yet).
- Fuzz harnesses for `capability-manager`, `net-driver-host`, and the
  `blk-driver-host` FAT32 and allocator code, with proptest fallbacks.
- `docs/`: ARCHITECTURE, STATUS, ROADMAP, BUILDING split from the README;
  MARSHAL enforcement policy and Verifier-identity RFCs; TLS and IPC-response
  capability RFCs; `docs/adrs/`; `docs/BETA_CRITERIA.md`.

### Changed

- `citadel-integration` license re-confirmed as Apache-2.0 with a written
  argument (`af789e9`).
- `citadel_proxy` records its own Verifier-identity decision in WORM (`8d0fabd`).
- Project renamed from CitadelOS to Runix in the tree (`0e490a9`).
- CI: `kernel-arm` and `net-driver-host-arm` host unit tests, a QEMU test per
  new driver and MARSHAL path, `net_driver_dns` run then removed again because
  the runner gets no DNS answer.

### Fixed

- Ring 3 stack under-mapping in the `grid_sandbox_wasm` test (`47bd3ef`).
- `kernel-arm` silent boot failure without `secure=on` (`1643323`) and the
  AP[2:1]=0b01 QEMU hang in EL0/EL1 page isolation (`c9ba1c7`).
- `blk-driver-host` poll timeout under TCG without KVM (`cdb789b`).
- `net-driver-host` sockets IPC server exhausting its budget before a client
  connected (`72b0bb2`).
- A stale `marshal_proxy_e2e` request fixture, and a MARSHAL test budget that
  needed a test-only override (`cc66be5`, `47a14cc`).
- Several rustfmt and clippy drift fixes and CI ordering fixes (payload
  binaries built before the crates that embed them).
