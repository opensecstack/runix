# Runix

Runix (formerly "CitadelOS" in early planning) is a capability-secure,
Linux-adjacent operating system for desktop and mobile, built around a Rust
microkernel and a WebAssembly application layer, with
[CITADEL](https://github.com/opensecstack/opensecstack) governance
(MARSHAL, WORM, VIGIL, AUGUR) integrated as infrastructure rather than
bolted on.

We are currently in **Alpha**, pre-1.0, no shipped release. The kernel's
own bring-up is complete — boot, exception handling, paging, a kernel
heap, PIC/PIT interrupts, a cooperative scheduler, a syscall ABI, IPC, a
real ring 0 → ring 3 transition, per-process address spaces, an ELF
loader, and multi-process ring 3 scheduling are all built and verified end
to end in QEMU, with a CI-wired test suite. See
[docs/STATUS.md](docs/STATUS.md) for the detailed, current-truth account of
what's actually implemented (and what broke along the way) — this file is
deliberately just an entry point.

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — layer split (L1-L6,
  desktop vs. mobile), sandbox tiers, workspace layout, and why
  `kernel`/`kernel-arm`/`xtask` aren't root-workspace members.
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — Alpha/Beta/RC/v1.0 phase targets
  and open questions (license, SDK dependency).
- **[docs/STATUS.md](docs/STATUS.md)** — the detailed engineering log: what's
  built, how it was verified, and real bugs hit along the way. Read this
  before assuming something is or isn't implemented.
- **[docs/BUILDING.md](docs/BUILDING.md)** — build/test/boot commands and the
  kernel build-stage checklist.
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — what Runix defends
  against today vs. known gaps; update it when a trust boundary changes.

## Quick start

```
cargo build --workspace                              # everything except kernel/xtask
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

cd kernel && cargo build --target x86_64-unknown-none # kernel alone (needs nightly)
cargo run -p xtask -- run                              # build + boot in QEMU, serial to stdout
```

See [docs/BUILDING.md](docs/BUILDING.md) for the full picture, including the
QEMU-native `cargo test` harness and the Windows MSVC/GNU nightly gotcha.
