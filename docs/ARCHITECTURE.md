# Runix architecture

This describes the layer split, workspace layout, and why certain crates
are (or aren't) members of the root Cargo workspace. For current
implementation status, see [STATUS.md](STATUS.md); for phase targets, see
[ROADMAP.md](ROADMAP.md).

This repo is a single Cargo workspace shared by both the desktop and mobile
editions — they share the same kernel, capability manager, WASM runtime, and
CITADEL integration; only the platform-specific layers (`desktop/`,
`mobile/`) differ.

## Layers

| # | Desktop | Mobile | Crate |
|---|---------|--------|-------|
| L1 | Microkernel | Microkernel + ARM TrustZone | `kernel` |
| L2 | Capability Manager | *(folded into L4 CITADEL Layer)* | `capability-manager` |
| L3 | OS Services | Radio Abstraction / MVNO Stack | `desktop`, `mobile` |
| L4 | Grid Sandbox | CITADEL Layer | `wasm-runtime`, `citadel-integration` |
| L5 | CITADEL Runtime | App Runtime | `citadel-integration`, `wasm-runtime` |
| L6 | Application Layer | User Interface | `desktop`, `mobile` |

## Sandbox tiers

- **T1 Critical** — system daemons, crypto, key management → MARSHAL real-time (<300ms)
- **T2 Trusted** — first-party applications → MARSHAL standard
- **T3 Untrusted** — third-party apps, web content → MARSHAL evidence-gated

We maintain an internal threat model tracking what's actually enforced
today vs. what these tiers still need before they're real — tiering itself
doesn't exist yet in Alpha. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Workspace layout

```
runix/
├── kernel/               standalone (not a workspace member — see below):
│                         microkernel (desktop, x86_64) — boot, IPC, memory,
│                         scheduling
├── kernel-arm/           standalone (not a workspace member — see below):
│                         microkernel ARM/TrustZone boot bring-up (mobile,
│                         aarch64) — EL3 boot, real exception vectors
│                         (catch + resume with full context preserved),
│                         the EL3→EL1 Non-secure drop (the TrustZone
│                         boundary), partial GIC bring-up; see its own doc
│                         comment for full status and the "why a separate
│                         crate from kernel/" decision
├── xtask/                standalone (not a workspace member — see below):
│                         builds kernel's bootable image, runs it in QEMU
├── capability-manager/   shared: capability-token access control (no_std +
│                         alloc — see below; still a normal workspace
│                         member, unlike kernel/xtask)
├── ipc/                  shared: user-space IPC wire types
├── wasm-runtime/         shared: WASM sandbox engine (Grid Sandbox / App Runtime)
├── citadel-integration/  shared: MARSHAL / WORM / VIGIL binding
├── desktop/              desktop-only: shell, grid sandbox, drivers
└── mobile/               mobile-only: RIL, MVNO stack, TrustZone HAL
```

`kernel/`, `kernel-arm/`, and `xtask/` are each their own single-package
workspace, not members of the root `[workspace]`:

- `kernel/` is freestanding (`x86_64-unknown-none`, `no_std`, `panic=abort`)
  — a different target than every host-side crate here, which cargo can't
  mix into one `cargo build --workspace` invocation.
- `kernel-arm/` is freestanding too, but targets `aarch64-unknown-none` — a
  third target triple, distinct from both `kernel/`'s and the root
  workspace's. Unlike `kernel/`, it builds on **stable** (no
  `x86_64`-crate-style nightly-only dependency, no `extern
  "x86-interrupt"` equivalent) — see its own `rust-toolchain.toml`.
- `xtask/` depends on the `bootloader` crate (the image builder), whose
  build script needs a **nightly** cargo — mixing that into the otherwise
  all-stable root workspace breaks it. (`kernel-arm/` needs no equivalent
  image-building step at all — QEMU's `virt` machine loads a `-kernel` ELF
  and jumps straight to its entry point; see `kernel-arm/linker.ld`.)

Everything else (`capability-manager`, `ipc`, `wasm-runtime`,
`citadel-integration`, `desktop`, `mobile`) is a normal host-target member of
the root workspace, on stable — `capability-manager` is `no_std` + `alloc`
internally (so `kernel/` can depend on it directly, as a path dependency,
without needing its own copy), but that's an implementation detail of the
crate itself, not a reason to pull it out of the root workspace the way
`kernel`/`xtask` had to be: it still builds fine for the host target too
(`#[cfg(test)]` opts back into `std` for its own test suite).
