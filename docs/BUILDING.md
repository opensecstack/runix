# Building, testing, and booting Runix

Host-side crates (everything except `kernel/` and `xtask/`):

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The kernel needs **nightly** (see `kernel/rust-toolchain.toml`) — not for
`x86_64-unknown-none` itself (that's a tier-2 target with precompiled
`core`/`alloc`, stable is fine for that), but because exception handlers use
`extern "x86-interrupt"`, which is still unstable
([rust-lang/rust#40180](https://github.com/rust-lang/rust/issues/40180))
despite being the standard way every x86_64 Rust kernel defines them.
`--target x86_64-unknown-none` is explicit everywhere below — deliberately
not a `.cargo/config.toml` default; see the "config leak" note in
[STATUS.md](STATUS.md):

```
cd kernel
cargo build --target x86_64-unknown-none
cargo clippy --target x86_64-unknown-none --bins --lib -- -D warnings
   # --bins --lib, not --all-targets: the *default* libtest harness still
   # can't run on a bare target — `cargo test` (below) is what actually
   # exercises tests/*.rs, via its own non-libtest mechanism.
```

`cargo test` (also from `kernel/`) builds each `kernel/tests/*.rs` as its
own bootable binary, boots it for real in QEMU, and reads pass/fail from the
isa-debug-exit device (`kernel/src/qemu_exit.rs`) — a real exit code, not
grepped serial text. This is what "Test harness — QEMU integration tests"
(kernel build stage 9, below) actually means, and it's why plain
`cargo test --workspace` on the host isn't enough: it can't see
architecture-specific bugs like the GDT/segment-register one in
[STATUS.md](STATUS.md). `--test <name>` is required, one per file under
`tests/` — a bare `cargo test` (or even `cargo test --tests`, despite the
name) also tries to build the *library's own* unit-test harness, which needs
`test`/panic-unwind that doesn't exist on a bare-metal target regardless of
`harness = false` on the integration tests themselves:

```
cargo test --target x86_64-unknown-none --test basic_boot
```

**`grid-sandbox-host` must be built first**: `kernel/src/main.rs` now
`include_bytes!`s its compiled output directly (the CITADEL-gated real
module load, Phase B7 — see `kernel/src/citadel.rs`'s doc comment), so
`kernel/` itself won't compile without it, the same requirement
`kernel/tests/grid_sandbox_wasm.rs` already has:

```
cd grid-sandbox-host
cargo build --target x86_64-unknown-none --release
```

Building a bootable image and running it in QEMU by hand (this needs
nightly too, separately — transitively through the `bootloader` crate's
build script, see `xtask/rust-toolchain.toml`):

```
cd xtask
cargo run -- build   # -> ../target/runix-bios.img
cargo run -- run     # build + boot in QEMU, serial on stdio
```

A legacy BIOS boot through this crate's own multi-stage loader (SeaBIOS ->
stage 2/3/4 -> the kernel ELF, now with `grid-sandbox-host`'s ~2 MB
embedded) can take well over the naive-looking default QEMU timeout on a
slow or nested-virtualization host — give it real time (a minute-plus) in
scripts before concluding a boot has hung, not just crashed silently; see
`.github/workflows/ci.yml`'s `boot` job for the timeout this project
actually uses in CI.

On a Windows dev box with no MSVC Build Tools (`link.exe`) installed, the
host-default nightly resolves to `-msvc` and fails to link. Force GNU
explicitly instead:

```
rustup run nightly-x86_64-pc-windows-gnu cargo run -- build
```

## Kernel build stages (Alpha)

1. Toolchain & target bring-up — `x86_64-unknown-none`, `no_std`/`no_main`,
   `bootloader_api` for the entry point. **Done.**
2. "Hello kernel" — serial (UART/COM1) output so boot is verifiable from the
   host instead of trusting a black QEMU window. **Done** (`kernel/src/serial.rs`).
3. CPU init — GDT with a TSS (dedicated IST stack for double faults), IDT
   with breakpoint/double-fault/page-fault/GPF handlers. **Done**
   (`kernel/src/gdt.rs`, `kernel/src/interrupts.rs`) — verified by
   deliberately triggering a breakpoint exception and confirming execution
   resumes afterward instead of faulting.
4. Memory management — physical frame allocator over the bootloader's memory
   map, an `OffsetPageTable` mapper over the physical-memory mapping the
   bootloader is now configured to provide, and a kernel heap
   (`linked_list_allocator`, `allocator::HEAP_SIZE` — grown from an
   initial 100 KiB once later phases' allocations outgrew it, see
   [STATUS.md](STATUS.md)) backing `alloc::{Vec, Box}`. **Done**
   (`kernel/src/memory.rs`, `kernel/src/allocator.rs`) — verified by actually
   allocating a `Box` and a growing `Vec` at boot and checking their values,
   not just that `init_heap()` returned `Ok`.
5. Interrupts — PIC remapped past the exception vectors (0-31), timer
   (PIT/IRQ0) unmasked and wired to a handler that ticks an atomic counter,
   every other IRQ line left masked (an unmasked line with no handler would
   general-protection-fault the kernel the moment it fired). **Done**
   (`kernel/src/interrupts.rs`, `kernel/src/boot.rs`) — verified by enabling
   interrupts (`sti`) and spin-waiting on the tick counter actually
   advancing, not just on `sti` not faulting.
6. Threading & scheduler — fixed-layout `Context` struct (callee-saved
   registers + return address, matching what `pop`/`ret` expect off a
   thread's stack) built by hand for freshly spawned threads; a naked
   `switch_to` function that saves the caller's registers, swaps `rsp`, and
   restores the target's; a cooperative (not yet timer-preemptive)
   round-robin run queue. **Done** (`kernel/src/scheduler.rs`) — verified by
   spawning three threads that each print 3 tagged messages and yield
   between them, and confirming the output actually interleaves
   (`A0,B0,C0,A1,B1,C1,A2,B2,C2`) instead of running one thread to
   completion before the next starts — proof each thread's context truly
   resumes where it left off, not from scratch.
7. Basic IPC — syscall ABI over `int 0x80` (syscall number in RAX, up to 3
   args in RDI/RSI/RDX, return in RAX), and fixed-count byte channels
   addressed by port id, both callable from kernel code today since there's
   no ring 3 yet to *require* the syscall path — the ABI itself doesn't care
   which ring issues `int 0x80`. **Done** (`kernel/src/syscall.rs`,
   `kernel/src/ipc.rs`) — verified by two threads exchanging three bytes
   over a channel, driven entirely through `SYS_IPC_SEND`/`SYS_IPC_RECV`
   syscalls (not direct `ipc::send`/`recv` calls), and checking the
   receiver got exactly `['X', 'Y', 'Z']`, in order — proof the syscall
   gate, the register remapping, and the channel all compose correctly, not
   just that each works in isolation. (`SYS_IPC_SEND` later became
   capability-gated — see [STATUS.md](STATUS.md) — but that's later work
   layered on top of this stage, not a change to what "basic IPC" itself
   means here.)
8. Ring 3 / user-space transition — a user-accessible stack mapped fresh
   (so `Mapper::map_to`'s flag propagation marks every page-table level
   `USER_ACCESSIBLE` as it creates them), ring 3 access granted to the one
   4 KiB code page a hand-written naked `user_hello` function lives on
   (`allow_user_access` fixes up each *existing* page-table level by hand,
   since those predate the grant and don't get the propagation trick), and
   an `iretq`-based jump that drops CPL from 0 to 3. The syscall gate's DPL
   also had to move from Ring0 to Ring3 (`interrupts.rs`) — left at the
   default, a ring 3 `int 0x80` general-protection-faults before ever
   reaching the handler; the `int` instruction checks CPL against the
   gate's DPL, not just whether a handler exists. **Done**
   (`kernel/src/userspace.rs`) — verified by `user_hello` writing `"USR\n"`
   one byte at a time through `SYS_WRITE`, proving the syscall path accepts
   a genuine CPL 3 caller, not just a kernel-mode one — the same gate that
   was tested from ring 0 in stage 7 now has to work from a strictly lower
   privilege level, which is exactly what the DPL fix above makes possible.
9. Test harness — `cargo test` (from `kernel/`, targeting
   `x86_64-unknown-none`) builds each `kernel/tests/*.rs` as its own
   bootable binary (`harness = false` — no libtest, there's no
   `test`/panic-unwind runtime on bare metal), boots it for real in QEMU via
   the `runner` in `kernel/.cargo/config.toml`, and reads pass/fail from the
   isa-debug-exit device. **Done** (`kernel/src/qemu_exit.rs`,
   `kernel/tests/basic_boot.rs`, `xtask`'s `test-runner` subcommand) — a
   real `cargo test` exit code, not grepped serial text, and it's what
   `.github/workflows/ci.yml`'s `kernel-tests` job runs. (The `boot` job
   alongside it still greps the *full* `main.rs` demo's serial output —
   coarser, but it's the only thing exercising every phase's feature
   together in one run; `basic_boot.rs` is deliberately minimal, and more
   `tests/*.rs` files can grow alongside it as later phases land, rather
   than everything routing through `main.rs`.)

Three real bugs caught along the way, each worth knowing before touching
the relevant code again — full detail in [STATUS.md](STATUS.md):

- **Stale segment registers after loading a new GDT** (`gdt.rs`) — the
  bootloader's leftover SS collided with our TSS descriptor, and the next
  `iretq` general-protection-faulted. Fix: explicitly null SS/DS/ES/FS/GS
  in `gdt::init()`.
- **Stack alignment for freshly spawned threads** (`scheduler.rs`) — a
  thread's initial `rsp` has to land at the same offset (mod 16) a real
  `call` would leave it at, or a stack-spilled SSE register faults later,
  not on the first context switch.
- **`.cargo/config.toml` target leaking across processes** — an ambient
  `[build] target` in `kernel/.cargo/config.toml` broke `xtask`'s nested
  `cargo` invocations (wrong target, then a confusing codegen error rather
  than "wrong target"). Fix: no ambient default: `--target
  x86_64-unknown-none` explicit everywhere instead.
