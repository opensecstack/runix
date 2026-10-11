# Runix Beta developer preview: release notes

This is a developer preview for people who will read the code, not a product
release. The exit criteria and the evidence for every statement below are in
[BETA_CRITERIA.md](BETA_CRITERIA.md); the full change list is in
[../CHANGELOG.md](../CHANGELOG.md); detailed implementation state is in
[STATUS.md](STATUS.md).

## Known limitations and what this release does NOT claim

Read this first. This list mirrors "Not claimed" in BETA_CRITERIA.md.

- **No live governance.** Nothing here reaches a real CITADEL `EXECUTE`. CI's
  only `Execute` verdicts come from a mock that approves every request. No
  operator identity exists, so a real approval is currently impossible.
- **The MARSHAL gate mostly fails open.** With the proxy unreachable or
  unconfigured, eSIM enable/delete, MVNO bind/suspend/reactivate, and the x86
  `spawn_instance` proceed ungoverned. Only the mobile usage reset fails
  closed.
- **`spawn_instance` is called only from tests.** The boot path loads the
  Grid Sandbox host without going through the MARSHAL-gated entry point.
- **Boot-time module authorization is a wiring proof, not an enforcing gate.**
  It builds its allowlist from the bytes it checks and cannot reject a real
  module.
- **Demo signing keys.** `insecure-demo-keys` is on by default. No key
  provisioning, secure boot chain or WORM boot chain.
- **Mobile data policy is advisory and unmetered.** Usage is asserted by the
  caller, nothing polls the billing period, the clock counts from boot, and
  nothing acts on the engine's advice. Everything in the mobile state (accounts,
  usage, sessions, audit chain) is in memory and lost on reboot.
- **No real carrier or SIM data.** One compiled-in demo account; opaque
  `u64` profile identity; no profile download, modem or RIL feed.
- **Flat capability set on the ARM kernel.**
- **No real HTTPS.** `tls-client` has no consumer, no clock, a single-CA
  verifier and no RSA verification.
- **Narrow filesystem IPC.** Named-file read and single-sector in-place
  overwrite only; FAT32 only.
- **QEMU only.** No hardware has been booted.
- **Not in CI by design:** `net_driver_dns` (runner gets no DNS answer) and
  `syscall_cost` (a measurement). DNS is not CI-verified.
- **Grid Sandbox runs only embedded first-party demo modules.** There is no
  way to load a third-party module, and tiers cap memory and tables only.
- **RC and v1.0 scope is not started** (desktop shell, app framework,
  hardware attestation, secure dialer, VoIP, roaming governance, update
  channel, compliance suites).

## What is in it

This is the implemented state of the tree. The Grid Sandbox, network stack and
filesystem driver were implemented before the `v0.1.0-alpha` tag (first
shipped in it); the changes since that tag are listed in the CHANGELOG.

Desktop (x86_64 microkernel plus ring-3 hosts):

- Grid Sandbox: `wasmi` inside a ring-3 process with its own address space,
  three tiers with different memory/table caps, multiple instances.
- User-space network stack: virtio-net driver with smoltcp (ARP, ICMP, DHCP,
  TCP), a typed sockets IPC surface, concurrent handles.
- Filesystem driver: virtio-blk, FAT32, per-request capability tokens,
  revocation check, quarantine after a device timeout.
- MARSHAL plumbing: kernel client, typed `ipc` wire format, `citadel_proxy`
  user-space proxy making real HTTP calls, per-instance spawn evaluation.

Mobile (aarch64 `kernel-arm`, QEMU `virt`):

- EL3 to EL1 to EL0 boot with GIC, MMU, per-process address spaces and an EL0
  process model.
- eSIM profile lifecycle, MVNO account registry and network selection, data
  policy engine and reconciler, governed usage reset with a billing-period
  gate, all behind scoped capabilities.
- A MARSHAL gate over six actions, with a per-action unreachable policy and
  recorded verdicts.

Security fixes made while preparing this preview are listed under Security in
the CHANGELOG, including an IPC out-of-bounds access that halted the kernel,
a port-I/O width check, a network RX length bug, missing revocation checking
in the filesystem driver, and virtio queue-size validation.

## What works (verified)

"Verified" means a named test passes in CI under QEMU or on the host; see
BETA_CRITERIA.md for the exact test or CI step behind each line. Status of the
eight Beta items: MET as scoped: Grid Sandbox isolation, user-space network
stack, eSIM lifecycle. PARTIAL: filesystem driver, MVNO core, data policy
engine, and MARSHAL integration on both desktop and mobile. None is NOT MET.
"MET as scoped" is defined in that document and is narrower than the
roadmap wording.

## Build and boot

See [BUILDING.md](BUILDING.md). In short, the host crates build with
`cargo build --workspace`; the x86_64 kernel and the aarch64 kernel are
separate packages with their own toolchains; `cargo run -p xtask -- run`
builds and boots the x86_64 image in QEMU. Some proof lines in a boot log
(the two net TCP proofs) need a listener that the CI sets up and cannot pass on a
plain local boot; BUILDING.md lists them.
