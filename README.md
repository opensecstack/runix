# Runix

Runix (formerly "CitadelOS" in early planning) is a capability-secure,
Linux-adjacent operating system for desktop and mobile, built around a Rust
microkernel and a WebAssembly application layer, with
[CITADEL](https://github.com/opensecstack/opensecstack) governance
(MARSHAL, WORM, VIGIL, AUGUR) integrated as infrastructure rather than
bolted on.

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
doesn't exist yet in Alpha.

## Workspace layout

```
runix/
├── kernel/               standalone (not a workspace member — see below):
│                         microkernel — boot, IPC, memory, scheduling
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

`kernel/` and `xtask/` are each their own single-package workspace, not
members of the root `[workspace]`:

- `kernel/` is freestanding (`x86_64-unknown-none`, `no_std`, `panic=abort`)
  — a different target than every host-side crate here, which cargo can't
  mix into one `cargo build --workspace` invocation.
- `xtask/` depends on the `bootloader` crate (the image builder), whose
  build script needs a **nightly** cargo — mixing that into the otherwise
  all-stable root workspace breaks it.

Everything else (`capability-manager`, `ipc`, `wasm-runtime`,
`citadel-integration`, `desktop`, `mobile`) is a normal host-target member of
the root workspace, on stable — `capability-manager` is `no_std` + `alloc`
internally (so `kernel/` can depend on it directly, as a path dependency,
without needing its own copy), but that's an implementation detail of the
crate itself, not a reason to pull it out of the root workspace the way
`kernel`/`xtask` had to be: it still builds fine for the host target too
(`#[cfg(test)]` opts back into `std` for its own test suite).

## Roadmap

| Phase | Target | Desktop | Mobile |
|-------|--------|---------|--------|
| Alpha | 2027 Q1 / Q2 | Microkernel boot, capability manager, basic IPC, WASM runtime, CITADEL stub | Same + ARM TrustZone boot, RIL isolation, basic SIM provisioning |
| Beta  | 2027 Q3 / Q4 | Grid sandbox isolation, user-space network stack, filesystem driver, MARSHAL integration | MVNO stack core, eSIM lifecycle, data policy engine, MARSHAL integration |
| RC    | 2028 Q1 / Q2 | Desktop shell, app framework, WORM boot chain, hardware attestation | Secure dialer, VoIP trunk, roaming governance, VIGIL health monitoring |
| v1.0  | 2028 Q3 / Q4 | NIS2/GDPR suite, secure update channel, full MARSHAL governance, EU CRA alignment | Full MVNO operations, NIS2 suite, network slicing, EU regulatory alignment |

We are currently in **Alpha**. The kernel's own bring-up — all 9 "Kernel
build stages" below — is **complete**: boot, serial output, exception
handling, paging, a working kernel heap, PIC/PIT timer interrupts,
cooperative round-robin context switching, a syscall ABI (`int 0x80`), byte
channels between threads, a real ring 0 → ring 3 transition, and a QEMU-native
`cargo test` harness are all working, verified end to end in QEMU (the
`main.rs` demo boots through every phase, exercises capability-gated IPC —
see `capability-manager` below — and lands in ring 3, which prints `USR`
back through the syscall gate as its last act).

Of Alpha's five roadmap items, four are done: microkernel boot, basic IPC,
WASM runtime engine bring-up, and — as of the capability-gate work below —
the capability manager. **`wasm-runtime`** now has a real engine
(`wasmi`) that loads and executes WASM bytecode, calls exported functions,
and — as of the host-function import work — lets WASM code call back into
the runtime. `wasmi` over `wasmtime` on purpose: no `std` feature enabled,
since `wasmtime` needs a host OS (mmap, threads, signal handlers for its
JIT) and this crate is meant to eventually run hosted by the kernel itself,
not the dev host — see `wasm-runtime/src/lib.rs`. Verified two ways, both
checking real data round-trips rather than "no error was returned":
`WasmRuntime::call_i32x2_to_i32` loads a module and calls a fixed-signature
exported function, checked by compiling a tiny `add(a, b) -> a + b` module
from WAT at test time and asserting real arithmetic results
(`wasm-runtime/tests/call_add.rs`); `WasmRuntime::call_and_capture_output`
instantiates a module that *imports* `host.print(byte: i32)` and calls it
twice, checked by asserting the runtime's host-side buffer received exactly
those bytes, in order (`wasm-runtime/tests/host_import.rs`) — the direction
that eventually becomes the real syscall bridge into `citadel-integration`,
once that's more than a stub. Memory isolation is verified too, not just
assumed from "`wasmi` is a compliant interpreter": an out-of-bounds store
traps cleanly instead of touching anything outside the module's declared
memory, a `memory.grow` past a module's own declared maximum correctly
fails (returns `-1`, per spec — it doesn't trap) rather than silently
growing past it, and an in-bounds store/load round-trips exactly the value
written — the last one matters because a bounds check that (wrongly)
rejected *everything* would make the OOB test pass for the wrong reason
(`wasm-runtime/tests/memory_isolation.rs`). No sandbox tiers or MARSHAL
channel permits yet; those land with Beta's grid sandbox work.

**Architecture decision: `wasm-runtime` stays host-side through Alpha, not
kernel-hosted.** There are two ways it could eventually run under Runix:

1. *Interpreter linked into the kernel itself (ring 0).* Simpler, but
   breaks the isolation the layer split (L1 Microkernel vs. L4 Grid
   Sandbox, see "Layers" above) exists for — a bug in `wasmi` would be a
   ring 0 vulnerability, not a sandbox escape.
2. *Interpreter as its own ring 3 process*, loaded by the kernel, talking
   to it only through the syscall gate (`int 0x80`) — what "Grid Sandbox"
   actually means: WASM code gets bytecode-level bounds checking *and*
   hardware-enforced ring 3 isolation, so an interpreter bug still can't
   reach kernel memory.

Option 2 is the real target, and the kernel infrastructure it needed —
an ELF/module loader, per-process address spaces, and multi-process
scheduling with real ring 3 cooperation — is now built (see the
process-isolation and multi-process-scheduling sections above). That
infrastructure being ready doesn't mean `wasm-runtime` itself was ready to
run on it, though — until now it wasn't even `no_std`.

**`wasm-runtime` is now `no_std` + `alloc`** — the concrete first step of
actually moving onto that infrastructure, not the whole move. Two changes:

- The crate gained `#![cfg_attr(not(test), no_std)]` + `extern crate alloc;`
  (same split `capability-manager`/`citadel-integration` already use —
  `#[cfg(test)]` opts back into `std` for the existing host-side test
  suite, which is untouched and still passes).
- `RuntimeError` stopped using `#[derive(thiserror::Error)]`. Confirmed by
  actually trying to build this crate for `x86_64-unknown-none` (not by
  reading `thiserror`'s docs): `thiserror` 1.x hard-requires
  `std::error::Error` and fails inside its own code, not this crate's —
  the same reason `capability-manager` and `citadel-integration` both
  hand-roll a `Display` impl instead of using it. Replaced with a manual
  `impl fmt::Display for RuntimeError`, matching that existing convention
  rather than being a one-off exception.

Confirmed by actually building for the real target, not just adding the
attribute and hoping: `cargo build --target x86_64-unknown-none` from
`wasm-runtime/` compiles clean, including the full `wasmi` dependency
tree — `wasmi`'s own "no `std` feature enabled" claim (see above) held up
under an actual bare-metal build, not just the default-features-off
Cargo.toml setting. Full existing test suite (7 tests across `call_add.rs`/
`host_import.rs`/`memory_isolation.rs`) still passes on the host, and
`clippy` is clean on both targets.

**Still not what "Grid Sandbox" means end to end.** This crate compiling
for the bare-metal target is necessary, not sufficient — it's still a
*library*, not something that runs. Actually hosting it in ring 3 needs it
(or a thin binary wrapping it) built as its own freestanding ELF, loaded
through `elf::Elf64` and `scheduler::spawn_ring3_process` the same way
`ring3_cooperative.rs`'s hand-written processes are today — that wiring
doesn't exist yet. This is the next concrete step, not a claim already
made.

**`capability-manager`** is no longer a stub either: `CapabilityToken`
issuance and verification are real (Ed25519 over a canonical, pipe-joined
string — CITADEL's own signing convention, not JSON-signing's
cross-implementation footguns — see `capability-manager/src/lib.rs`), and
`no_std` + `alloc` so it can be verified from `kernel/` itself, not just on
the host. `SYS_IPC_SEND` is capability-gated now
(`kernel/src/syscall.rs`/`kernel/src/capabilities.rs`): each scheduler
thread carries an `Option<CapabilityToken>`
(`scheduler::spawn_with_capability`), and a send only reaches the channel
if that thread's token verifies against a `port:<n>` resource string at the
current tick count. Verified with two senders on the same port — one
holding a valid token, one holding none — checking that the channel
received *only* the authorized byte: `SYS_IPC_SEND` returned `0` for the
authorized sender and `u64::MAX` (the same "denied" signal any other
syscall failure uses — a hostile caller can't distinguish "no capability"
from "wrong resource" from "expired") for the other, and the port held
exactly one byte, not two. The trust root is a hardcoded demo Ed25519
keypair (`capabilities::demo_signing_key`) the kernel both issues and
verifies against — real key provisioning (loaded from firmware/a future
WORM boot chain, never baked into the binary) is later work; this exists to
prove the wiring, not to be a real trust anchor. Token lifetimes are
expressed in PIT ticks since boot, not wall-clock time, for the same
reason `interrupts::ticks()` stood in for "now" back in Phase 4 — there's
no RTC driver yet.

Revocation is the last piece: `RevocationList` (`capability-manager`) tracks
revoked tokens by signature — a token's signature already uniquely
identifies its exact signed content, so no separate token-ID field was
needed. Deliberately *not* part of `CapabilityToken::verify` itself:
revocation is administrative state (who's tracking it, synced from where),
not cryptography, and forcing every verifier to carry a list — even an
always-empty one — would be the wrong default for the common case.
`kernel/src/capabilities.rs` wraps a kernel-global instance
(`revoke`/`is_revoked`), and `syscall::dispatch`'s `SYS_IPC_SEND` check
consults both: `!is_revoked(&token) && check(&token, resource, now).is_ok()`.
Verified with a token that's valid on every count `verify()` itself checks
(right signature, not expired, right resource) but was explicitly revoked
right after being issued: `SYS_IPC_SEND` still returned `u64::MAX` and the
port received nothing — proof the gate actually consults revocation status,
not just signature/expiry/resource. `revoke` is kernel-internal, not a
syscall — "let the token holder revoke their own token" isn't a meaningful
operation; they'd just stop using it.

With this, Alpha's capability-manager work is done: issuance, verification,
syscall-gate enforcement, and revocation, all end-to-end in QEMU.

**`citadel-integration`** is no longer a stub either, though it's not what
the original "CITADEL stub" roadmap line implied. Rather than a live
MARSHAL round-trip at boot (see the crate's own module docs for exactly
why that doesn't fit — Kerkese requires Separation of Duties between two
human principals, which a kernel boot has neither the identities nor the
network stack to satisfy yet), it implements **boot-time module
authorization via a build-time-signed allowlist**: `ModuleManifestEntry`
(Ed25519 over a canonical string, same convention as
`capability-manager`'s tokens) and `BootAllowlist`, which verifies a
module's SHA-256 against a signed manifest entry before anything would
load it — fail-closed, no fail-open mode. Five unit tests cover the real
cases: authorizes a matching module, rejects an unlisted one, rejects
tampered bytes, rejects a wrong signing key, and rejects a validly-signed
entry reused for the wrong module ID.

**Not yet wired into `kernel/`**, though: nothing in the boot path calls
`authorize_module_load` — `kernel/Cargo.toml` doesn't even depend on this
crate yet. Real, tested, and correct in isolation; inert until something
in `main.rs`'s boot sequence actually calls it before loading a module.
Real *runtime* MARSHAL/WORM/VIGIL integration (once Runix has running
user-space processes to gate, not just boot-time module loads) remains
Beta/RC work, blocked on the same external SDK gap as before — see "Open
questions" below.

Two real bugs surfaced integrating `capability-manager` into `kernel/`,
both worth knowing before touching crypto-heavy code here again:

- **Stack overflow, not a crypto bug.** The very first `CapabilityToken::issue()`
  call general-protection-faulted with RSP pointing *into the kernel
  heap* (`0x4444_4444_xxxx`, our `HEAP_START`) — the boot thread's stack
  had already been blown through and had started corrupting adjacent
  memory before the fault even landed. Unoptimized (`dev`-profile) elliptic-curve
  arithmetic in `curve25519-dalek`/`sha2` is stack-hungry enough to
  overflow the bootloader's 80 KiB default boot stack on its own. Fixed
  two ways at once: `kernel/Cargo.toml` now opts `curve25519-dalek`,
  `sha2`, and `ed25519-dalek` into full optimization even in `dev` profile
  (normal inlining/register allocation shrinks the stack usage — a
  standard practice for crypto deps in embedded/kernel Rust), and
  `main.rs`'s `BOOTLOADER_CONFIG.kernel_stack_size` is bumped to 512 KiB as
  a safety margin on top, not a substitute for the real fix.
- **Then a plain out-of-memory.** With the stack fixed, the very next run
  hit `memory allocation of 16384 bytes failed` — the 100 KiB heap from
  Phase 3 was sized for that phase's own smoke test, and never grew to
  account for `main.rs`'s demo now spawning 7 scheduler threads at 16 KiB
  of stack each (112 KiB alone) plus capability token allocations on top.
  `allocator::HEAP_SIZE` is now 1 MiB — headroom for the current demo plus
  room to grow, not a principled sizing.
- Also worth a general note for `curve25519-dalek` specifically: it
  auto-selects a "simd" backend whenever the compiler is nightly —
  always true here — regardless of whether the target's codegen actually
  supports it. On `x86_64-unknown-none` that's an LLVM ICE ("Do not know
  how to split the result of this operator"), not a normal compile error.
  `kernel/.cargo/config.toml` forces the portable `serial` backend via
  `rustflags`, scoped to the `x86_64-unknown-none` target only (same
  "don't let it leak into xtask's nested build" reasoning as the earlier
  `.cargo/config.toml` fix below).

**Guard pages for thread stacks.** The stack-overflow bug above was fixed
by making the *boot* stack bigger, but every scheduler thread spawned
after boot (`scheduler::spawn`) was still using a plain `Box<[u8]>` from
the kernel heap as its stack — no guard page, no isolation from whatever
heap allocation happened to land next to it. A thread that overflowed its
stack wouldn't fault at all; it would silently walk into and corrupt
adjacent heap data, exactly the kind of bug that's cheap to cause and
expensive to diagnose (it was, in fact, how the bug above first
presented). Fixed by giving every thread its own individually-mapped
stack with a real unmapped guard page underneath it:

- `memory.rs` grew a global `MAPPER_AND_FRAME_ALLOCATOR` slot
  (`install`/`with_mapper_and_frame_allocator`) so any module — not just
  `main.rs` — can map or unmap pages after boot. `scheduler.rs` needed
  this to map each new thread's stack; `main.rs` was refactored to install
  once at boot and route its own heap-init and userspace-mapping calls
  through the same slot rather than keeping a second, redundant path.
- `scheduler.rs`'s `Thread::new()` now carves out a
  `GUARD_PAGE_SIZE`-then-`STACK_SIZE` region per thread starting at
  `STACK_REGION_START` (`0x6666_6666_0000`, stepping by
  `STACK_REGION_STRIDE` per thread), maps only the stack pages
  (`PRESENT | WRITABLE`), and deliberately leaves the guard page
  unmapped. A stack overflow now walks straight into a page with no
  mapping at all instead of into live heap memory.
- The failure mode this produces is **not** a clean page fault, which is
  worth knowing before "why didn't my page-fault handler print anything"
  comes up again: at the moment of overflow, RSP is already at or past
  the guard page boundary, so the CPU can't push the page-fault's own
  interrupt frame onto the current stack — pushing that frame faults too,
  escalating to a double fault. This is already handled correctly by the
  IST-based double-fault handler from Phase 2 (it runs on its own
  dedicated stack, set up in `gdt.rs`), so no new fault-handling code was
  needed — just the guard page itself, plus recognizing in
  `kernel/tests/guard_page.rs` that a double fault here is success, not
  failure.
- `kernel/tests/guard_page.rs` is the regression test: it spawns a thread
  that recurses until its stack is exhausted on purpose, and asserts the
  resulting panic message contains `DOUBLE FAULT` at an address inside the
  new `0x6666_6666_0000` stack region (observed:
  `stack_pointer: 0x666666660ff0`) — a silent-corruption regression would
  instead either hang or panic somewhere unrelated, and this test would
  catch either. Wired into CI's `kernel-tests` job alongside `basic_boot`.

**Real frame/stack reclamation.** Every thread's stack (guard-paged, above)
was mapped on spawn but never unmapped — fine for a demo that boots a
handful of threads and stops, but `BootInfoFrameAllocator` was a pure bump
allocator with no way to give a frame back, and no thread ever actually
*exited* (every demo thread loops forever), so the two gaps hid each other.
The moment anything long-running exists (the network stack that's next, for
instance — see the roadmap below), this becomes a real, fast leak: any code
path that repeatedly spawns and finishes short-lived work exhausts physical
memory with no way to recover. Fixed on both ends:

- `memory.rs`'s `BootInfoFrameAllocator` grew a `freed: Vec<PhysFrame>`
  free-list and a `FrameDeallocator` impl — `allocate_frame` now checks the
  free-list (LIFO) before bumping further into unused memory. Not a real
  buddy/slab allocator, just "reuse what's been handed back" — enough to
  stop the leak without pretending to be more sophisticated than the rest
  of this kernel's memory management currently is.
- `scheduler.rs` gained `exit_current_thread()`: a thread that's done calls
  this instead of looping forever. It can't unmap its own stack — it's
  still running on it — so the exiting thread is queued as a *zombie*
  instead, and `yield_now()` reaps any pending zombies (unmap + deallocate
  their frames) at the top of every call, which by construction always runs
  on some *other* thread's stack. `Thread`'s `guard_page_base` field
  (previously `#[allow(dead_code)]`, kept only for "future teardown") is
  what makes reaping possible — it's how a zombie's exact stack page range
  gets reconstructed.
- `kernel/tests/thread_reclaim.rs` is the regression test, and it's
  deliberately not another single-boot-log grep: it spawns and exits 20,000
  short-lived threads in a loop (16 KiB/thread × 20,000 ≈ 312 MiB, well past
  the 128 MiB QEMU is given here) and asserts the run completes rather than
  `allocate_frame` panicking partway through from exhaustion. A leak
  regression fails loudly and specifically, not "eventually something felt
  slow." Wired into CI's `kernel-tests` job.

**Scheduler watchdog: detection, not preemption.** The cooperative scheduler
has always had one structural weakness: a thread that never calls
`yield_now()` blocks every other thread forever, with no way for anything
else in the kernel to even notice, let alone recover. That gap was
tolerable while the only threads that existed were ones we wrote ourselves,
each looping and yielding forever by hand — it stops being tolerable the
moment less-trusted code (a driver, eventually a WASM-sandboxed app) can
get scheduled. Real preemption (timer-interrupt-driven forced context
switches) is a bigger feature than this needed to be — it still isn't
built — but *detecting* a stuck thread instead of hanging silently forever
was small enough to do now, and is exactly the same trade guard pages made
for stack overflows: turn a silent failure into a loud, immediate one.

- `interrupts.rs` gained a lock-free watchdog: `record_yield()` (called
  from `scheduler::yield_now()`/`exit_current_thread()` on every call)
  stamps the current PIT tick count into an atomic; `timer_interrupt_handler`
  checks, on every tick, whether more than `WATCHDOG_THRESHOLD_TICKS` (20 —
  a little over a second at the default ~18.2 Hz PIT rate) have passed
  since the last recorded yield, and panics if so. Deliberately lock-free —
  this runs from inside the timer ISR, which can fire while some other
  thread already holds `scheduler::SCHEDULER`'s lock mid-`yield_now()`;
  taking that same lock here would deadlock the CPU against itself.
- `scheduler::init()` arms it; `main.rs` explicitly disarms it right before
  the ring 3 handoff, with a comment explaining why: `user_hello` spins
  forever by design (see `userspace.rs`) and doesn't call `yield_now()` at
  all, so an armed watchdog would eventually mistake that intended
  behavior for a real hang.
- Two regression tests, not one, because this needed proof in both
  directions: `kernel/tests/watchdog.rs` spawns a thread that spins without
  ever yielding and asserts the kernel panics with the watchdog's message
  rather than hanging; `kernel/tests/thread_reclaim.rs`'s existing
  20,000-iteration cooperative loop doubles as proof the watchdog does
  *not* false-positive under heavy, legitimate `yield_now()` traffic. Both
  wired into CI's `kernel-tests` job.

**Compile-time barrier on the demo signing key.** `kernel/src/capabilities.rs`'s
hardcoded Ed25519 seed (`DEMO_SEED`) exists purely to prove the
`capability-manager` <-> syscall-gate wiring end to end — there's no real key
provisioning yet (no firmware or WORM boot-chain binding to load a real key
from), so it was, until now, one accidental refactor away from silently
becoming a real trust anchor in a build meant to ship. Fixed with a Cargo
feature rather than a runtime check, since the goal is catching this at
*compile* time, before a binary with the demo key baked in can even exist:
`kernel/Cargo.toml` gates the whole module behind `insecure-demo-keys`,
on by default (there's nothing to fall back to yet), and
`capabilities.rs` opens with a `compile_error!` under
`#[cfg(not(feature = "insecure-demo-keys"))]` naming exactly what's
missing. `cargo build --no-default-features` now fails loudly instead of
building successfully with a demo key inside; a future release recipe that
wires in real key provisioning is expected to disable the default feature
and satisfy that `compile_error!` for real, not silence it.

**Per-process address spaces — the shared prerequisite `wasm-runtime`
rehosting and the network stack's ring 3 driver were both blocked on.**
Both of those already had a documented "ring 3 from day one" decision (see
`wasm-runtime`'s architecture note above and the network-stack note below)
— but both were stalled on the exact same missing piece: today there is
**one page table for the entire system**. Every ring 3 thing that exists
(`userspace::user_hello`) runs in the same address space as the kernel and
every other thread, distinguished only by which pages happen to be flagged
`USER_ACCESSIBLE` — a second untrusted process would be able to *address*
the first one's memory even if today's flags happen to deny touching it.
This was flagged explicitly in the threat model's "no per-process address
space" gap, and rather than let both `wasm-runtime` and the network driver
each independently work around it (or silently reinvent the same fix
twice), it made more sense to build the real primitive once:

- `kernel/src/process.rs`'s `AddressSpace` owns a *private* top-level page
  table (PML4), built by copying — not linking — every entry from
  whichever table is currently active. Copying, not deep-copying: the
  kernel-space sub-tables end up physically shared across every address
  space on purpose (kernel code/heap/interrupt handling must stay
  reachable identically everywhere, and there's no benefit to duplicating
  4 KiB leaves of a mapping that's supposed to be the same in every
  process), while a specific slot a caller then touches via
  `map_private_page` gets detached first (its P4 entry cleared) so the
  fresh mapping built there is privately owned by that one address space,
  never touching what any other table's copy of that same slot still
  points at.
- `AddressSpace::activate`/`process::restore` do the actual `Cr3` switch —
  the real, hardware-enforced boundary, not just "we allocated a different
  struct." `activate` returns the *pair* `(PhysFrame, Cr3Flags)` it read
  before switching, not just the frame — restoring a frame with whatever
  flags happen to be active *at restore time* would be silently wrong the
  moment this kernel ever sets a non-default `Cr3Flags` (PCID), even
  though it doesn't today.
- `kernel/tests/process_isolation.rs` is the proof, and it's a real `Cr3`
  switch, not a simulated one: builds two address spaces, maps the exact
  same virtual address privately in each with different content (`0xAA`
  vs. `0xBB`), then actually switches into each in turn and reads back
  through that fixed VA from ring 0. If the "detach before mapping" logic
  above ever regressed and both processes ended up sharing that slot,
  this test would observe the same byte both times, or the wrong one —
  instead it observes exactly `A=0xaa B=0xbb`, proving the same address
  genuinely resolves to different physical memory depending on which
  table is loaded. Deliberately entirely ring 0 — proving the address-space
  primitive itself doesn't need ring 3 execution, a scheduler integration,
  or an ELF loader, none of which exist yet (see `process.rs`'s module
  doc comment for exactly what's still missing before anything can
  actually *run* inside one of these). Wired into CI's `kernel-tests` job.
- One real bug caught immediately by actually running this in QEMU rather
  than just compiling it: the first version's test VA
  (`0x_BBBB_BBBB_0000`) was non-canonical — bit 47 set while bits 63-48
  were clear, which the `x86_64` crate correctly rejects
  (`VirtAddr::new` panics: "virtual address must be sign extended in bits
  48 to 64"). Every *working* hand-picked address already in this kernel
  (`0x4444...`, `0x5555...`, `0x6666...`) happens to avoid this because
  their leading nibble's top bit is 0 — `B`'s top bit isn't. Fixed by
  picking `0x_7777_7777_0000` instead, matching the existing pattern
  instead of extending it into an unsafe range.

This does **not** yet mean `wasm-runtime` or the network driver can move
into ring 3 — an ELF/module loader and multi-process scheduling (switching
`Cr3` alongside the stack pointer on context switch, and giving a ring 3
thread its own kernel-entry stack so it can `SYS_YIELD` back
cooperatively) are still unbuilt. This is the foundation both of those
now build on, not the rehosting itself.

**ELF/module loader — the smaller, self-contained half of "something can
actually run in one of these address spaces."** Deliberately built before
multi-process scheduling, not after: it needs no scheduler, GDT/TSS, or
syscall-dispatch changes at all, and gave the harder piece (Cr3-switching
context switches, per-thread kernel-entry stacks, real `SYS_YIELD`) a
concrete, real payload to schedule once it exists, instead of designing it
against nothing.

- `kernel/src/elf.rs`'s `Elf64` parses just enough of the ELF64 format —
  `e_ident`/`e_entry`/`e_phoff`/`PT_LOAD` program headers — to map a
  binary's loadable segments; deliberately not a general ELF library (no
  section headers, no relocations, no dynamic linking) until something
  real needs more than this.
- `load_segments` generalizes `AddressSpace::map_private_page` (which used
  to hardcode `PRESENT | WRITABLE` for every page) to take real flags,
  translated from each segment's actual `PF_R`/`PF_W`/`PF_X` bits — a
  read+exec segment is mapped non-writable, a read+write segment is mapped
  non-executable. Real W^X, replacing a default that would have made
  every loaded segment writable *and* executable at once, the exact
  combination W^X exists to forbid.
- BSS (the `p_memsz`-beyond-`p_filesz` tail) is explicitly zero-filled,
  not left as whatever a freshly allocated physical frame happened to
  contain — skipping that would leak stale physical memory content
  (potentially another process's former data, given frames get reused —
  see the memory-reclamation fix above) into a newly loaded process.
- One real, latent bug in `AddressSpace` itself, caught by this being the
  first caller to map more than one page per address space: the original
  `map_private_page` unconditionally cleared its target's top-level (P4)
  table entry on *every* call, to detach it from whatever the space was
  seeded from. Fine for exactly one page per space (all
  `process_isolation.rs` ever needed) — wrong the moment a second page
  lands in the *same* P4 slot, which one P4 slot spanning 512 GiB makes
  near-certain for any real multi-segment binary: the second call's clear
  would have silently erased the first call's mapping. Fixed by tracking
  which P4 slots a given `AddressSpace` has already detached
  (`detached_p4_slots: BTreeSet<u16>`) and only clearing a slot the first
  time it's touched.
- `AddressSpace::translate` (built directly on the `x86_64` crate's own
  `Translate` trait, not custom table-walking) lets a caller check what's
  actually mapped where without activating the address space first —
  added specifically so `kernel/tests/elf_loader.rs` could verify real
  W^X permissions landed correctly, not just that content did.
- `kernel/tests/elf_loader.rs` hand-assembles a minimal, valid two-segment
  ELF64 image as a `Vec<u8>` at runtime (there's no filesystem yet to load
  a real one from) — one read+exec segment, one read+write segment with a
  BSS tail — and verifies all three properties above: correct content
  (checked by an actual `Cr3` switch and read-back, same rigor as
  `process_isolation.rs`), correct W^X permissions per segment (via
  `translate`), and a zero BSS byte. All three passed on the first real
  QEMU run once the P4-slot-reuse fix above was in. Wired into CI's
  `kernel-tests` job.

Still not execution: this loader maps a binary's segments and hands back
its entry point, nothing calls into it in ring 3 yet — that's what
multi-process scheduling is for.

**Multi-process scheduling — first slice: `Cr3` now follows the schedule.**
Deliberately split into two pieces, in dependency order — this half first
because it needed neither a scheduler stack per ring 3 thread nor a real
`SYS_YIELD`, and gave the eventual harder half something concrete to
switch between once it exists:

- `scheduler::Thread` can now optionally own a `process::AddressSpace`
  (`scheduler::spawn_with_address_space`). `yield_now` switches `Cr3` to
  the incoming thread's address space right before resuming it — or back
  to the kernel's own table (`memory::kernel_p4_frame`, captured once by
  `memory::install`) when resuming a thread that doesn't have one — and
  skips the write entirely when the target is already what's loaded, so
  the common case (switching between two plain kernel threads, which is
  most of what `thread_reclaim.rs`'s 20,000-iteration loop does) doesn't
  pay for a TLB flush it doesn't need.
- One real, subtle bug, found by actually running two address-space-owning
  threads through the scheduler rather than just building the mechanism:
  `AddressSpace::new()` copies the *currently active* table's P4 entries
  at the moment it's called — copying is by pointer for a slot that
  already has a P3 sub-table to point at, but a slot that's still empty at
  copy time just copies "not present," full stop. Building an address
  space *before* any thread had ever been spawned meant the thread-stack
  region's P4 slot was still empty at copy time — so when
  `spawn_with_address_space` then mapped that very thread's own stack
  (populating that slot in the *live* kernel table, after the copy already
  happened), the copy never saw it. The thread's own stack was invisible
  the instant its `Cr3` loaded: an immediate double fault trying to run on
  its own, suddenly-unmapped stack. Fixed at the root, not documented
  around: `scheduler::init()` now unconditionally reserves the
  thread-stack region's P4 slot (one permanent, otherwise-unused page)
  before anything else, so `AddressSpace::new()` is safe to call any time
  afterward — a real invariant instead of a call-order rule callers have
  to remember.
- `kernel/tests/scheduler_address_space.rs` is the regression test, and it
  goes further than a single manual `Cr3` switch: two threads, each owning
  its own address space, both mapping the *same* virtual address privately
  with a different marker byte, running five interleaved round trips
  through the real scheduler. Each thread writes its marker, yields
  (handing control to the *other* thread, running under its *own* `Cr3`,
  which writes its own different marker to the same VA), and on resuming
  re-reads that VA to confirm its own value survived — if the scheduler's
  `Cr3` tracking were wrong in either direction, one thread would observe
  the other's marker instead of its own. Hit the exact double fault above
  on the first real run; passed cleanly (`A=0xa5`/`B=0x5a`, five rounds
  each) once the P4-slot reservation was in. Wired into CI's
  `kernel-tests` job.

Still ring 0 only: `entry` for a `spawn_with_address_space` thread runs in
the kernel's own privilege level today, just under a private `Cr3` — real
ring 3 execution inside one of these still needs a per-thread kernel-entry
stack and a real `SYS_YIELD`, the harder half of multi-process scheduling
and the natural next slice.

**Multi-process scheduling — second slice: real ring 3 processes
genuinely cooperating.** Closes the gap the first slice left open: a
thread's `entry` can now actually call `userspace::enter_usermode` and
have its ring 3 code cooperate with the scheduler via a real `SYS_YIELD`,
not just run under a private `Cr3` from ring 0.

- The TSS's RSP0 (`gdt.rs`) — where the CPU lands on any ring 3 -> ring 0
  trap — used to be one shared stack for the whole system, fine with
  exactly one ring 3 thing ever running (`userspace::user_hello`, which
  deliberately never yields, precisely to avoid this gap). `gdt::TSS`
  became a `static mut` (previously an immutable `lazy_static!`) so
  `gdt::set_kernel_stack` can rewrite RSP0 at runtime; `scheduler.rs`'s new
  `spawn_ring3_process` gives each ring 3-capable thread its *own*
  dedicated, guard-paged kernel-entry stack (a new region,
  `KERNEL_ENTRY_STACK_REGION_START`, separate from each thread's ordinary
  cooperative-switch stack), and `yield_now` calls `set_kernel_stack`
  alongside its existing `Cr3` switch, right before resuming a thread that
  has one. Without a stack of its own, a second ring 3 thread trapping in
  while the first was suspended mid-syscall would corrupt the first's
  saved context — the exact failure mode a per-thread stack exists to
  prevent.
- No `SYS_YIELD` *implementation* changes were needed — `syscall::dispatch`
  already just called `scheduler::yield_now()` unconditionally; the gap
  was purely that every ring 3 trap shared one RSP0, making a second
  concurrent ring 3-capable thread unsafe. Once each thread has its own,
  the existing dispatch code is already correct for ring 3 callers too.
- `AddressSpace` gained `map_existing_frame` (`process.rs`) — maps an
  *already-compiled* kernel code page (a hand-written naked ring 3 entry
  point's own `.text`, found via the new `memory::translate_kernel_addr`)
  at a private VA, instead of copying its bytes into a freshly allocated
  page like `map_private_page` does. Needed because two independent
  processes each need their own code mapped read+exec (real W^X, same
  discipline as the ELF loader) without either one being able to write to
  it.
- `kernel/tests/ring3_cooperative.rs` is the proof: two real ring 3
  processes, each its own `AddressSpace` with its own private code+stack,
  each running a hand-written naked function that does `SYS_WRITE` then
  `SYS_YIELD` three times, then yields forever. A broken per-thread stack
  would show up here as a fault, corrupted registers, or a hang well
  within the bounded round trips this test runs. It didn't — the serial
  output interleaves perfectly: `ABABAB`.
- One real bug, caught by writing this test rather than just the
  mechanism: the first version used RCX as a loop counter across the
  `int 0x80` boundary without saving it. `int 0x80` isn't a normal call
  with a register-preservation ABI — `syscall::entry`'s own register
  remapping (`mov rcx, rdx`, part of turning `int 0x80` convention
  registers into the `dispatch` function's SysV argument registers)
  clobbers RCX on every trip through it, on top of whatever `dispatch`
  itself uses as a normal `extern "C" fn`. The counter never reliably hit
  zero — nothing faulted (proving the underlying per-thread-stack
  mechanism genuinely was sound), but the serial output was a much longer,
  uncontrolled run of `A`s and `B`s instead of the intended three each.
  Fixed by `push rcx` / `pop rcx` around each syscall pair, using the ring
  3 stack `build_process` already mapped but the original version never
  actually needed until this.

`userspace::user_hello` itself is untouched — it still runs by hand,
outside the scheduler, on the single default RSP0. The next natural step
is routing an ELF-loaded binary (not a hand-written naked function) through
this same `spawn_ring3_process` path — at which point `wasm-runtime` or the
network driver can actually start using it.

**Network stack — started, ring 3-first by design.** Beta's roadmap item
is "user-space network stack" (see the Roadmap table above) — the
architecture decision made before writing any of it was to build the whole
stack (virtio-net driver, TCP/IP via `smoltcp`, sockets) as a real ring 3
process from day one, not as in-kernel code that gets moved out later. The
same reasoning as `wasm-runtime`'s ring 0 vs. ring 3 decision above applies
even more directly here: a network stack parses bytes an external,
untrusted party controls, and a parsing bug in ring 0 is a kernel
vulnerability, not a sandboxed one. Nothing about "get it working first,
isolate it later" changes that risk while it's true — building ring
3-first from the start means the isolation boundary is never something to
retrofit under pressure once a real bug shows up.

That said, discovering *what hardware exists* needs raw port I/O, which
only ring 0 can do — so the first slice of this work is deliberately
kernel-side and deliberately narrow:

- `kernel/src/pci.rs` walks PCI config space (legacy mechanism #1, ports
  `0xCF8`/`0xCFC` — ECAM/MCFG is faster but needs ACPI table parsing this
  kernel doesn't do yet, so it's out of scope until something actually
  needs config space past the first 256 bytes) and returns every populated
  `(bus, device, function)` slot's vendor/device/class IDs. This is
  intentionally *not* where the "fuzz untrusted parsing" rigor below
  applies — every byte read here comes from QEMU/firmware, not from the
  network, so there's no attacker-controlled input to fuzz yet.
- `xtask`'s `run_qemu` now always gives every boot and every test a real
  `-device virtio-net-pci` (explicit `-netdev user,id=net0` backend, not
  relying on QEMU's default NIC — the default is an e1000, and "whatever
  QEMU defaults to" isn't something to test against) — so PCI enumeration
  has real hardware to find instead of only being exercisable once an
  actual driver exists to want it.
- `kernel/tests/pci_scan.rs` is the regression test: boots, scans, and
  asserts the virtio-net device (vendor `0x1AF4`, device `0x1000`) is
  actually found among the results, not just that `pci::scan()` returns
  without a hardware fault. Caught a real bug immediately: the first
  version of this test never initialized the heap (unlike `basic_boot.rs`,
  which doesn't need one), and `pci::scan()` collects into a `Vec` —
  `memory allocation of 40 bytes failed` on the very first run, fixed by
  giving the test the same heap-init sequence every other allocating test
  already uses. Wired into CI's `kernel-tests` job.

**The testing-rigor commitment for what comes next.** Everything verified
in this kernel so far — including every fix documented above — has been a
hand-written scenario booted in QEMU and checked against an expected
outcome. That's been enough because nothing here has parsed a single byte
that came from outside the machine; PCI config space, like everything
before it, is trusted input. The virtio-net driver and the TCP/IP stack on
top of it change that completely — Ethernet/IP/TCP headers are the first
attacker-controlled bytes this kernel will ever touch, arriving directly
into the same class of code (parsing fixed-layout binary structures,
turning length fields into buffer bounds) that has caused a large fraction
of every real-world kernel network stack's CVEs. `capability-manager`'s
`hex::decode` over a signature field is exactly this kind of parsing too,
and hasn't been fuzzed yet either — tracked as a "testing rigor" gap in our
internal threat model. Fuzzing the packet-parsing code (and property-testing
the parts of the driver/stack with real invariants, like the scheduler
interaction once one exists) starts alongside the first parser that
touches network bytes, not after — this section will be updated with the
actual harness once that code exists, not left as an aspiration.

## Building

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
not a `.cargo/config.toml` default; see the "config leak" note further down:

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
architecture-specific bugs like the GDT/segment-register one further down
this README. `--test <name>` is required, one per file under `tests/` — a
bare `cargo test` (or even `cargo test --tests`, despite the name) also
tries to build the *library's own* unit-test harness, which needs
`test`/panic-unwind that doesn't exist on a bare-metal target regardless of
`harness = false` on the integration tests themselves:

```
cargo test --target x86_64-unknown-none --test basic_boot
```

Building a bootable image and running it in QEMU by hand (this needs
nightly too, separately — transitively through the `bootloader` crate's
build script, see `xtask/rust-toolchain.toml`):

```
cd xtask
cargo run -- build   # -> ../target/runix-bios.img
cargo run -- run     # build + boot in QEMU, serial on stdio
```

On a Windows dev box with no MSVC Build Tools (`link.exe`) installed, the
host-default nightly resolves to `-msvc` and fails to link. Force GNU
explicitly instead:

```
rustup run nightly-x86_64-pc-windows-gnu cargo run -- build
```

### Kernel build stages (Alpha)

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
   initial 100 KiB once later phases' allocations outgrew it, see the
   capability-manager integration notes above) backing `alloc::{Vec, Box}`.
   **Done**
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
   capability-gated — see the `capability-manager` integration notes
   above — but that's B4/B5 work layered on top of this stage, not a
   change to what "basic IPC" itself means here.)
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

A real bug caught along the way, worth knowing before touching `gdt.rs`
again: after loading a new GDT, the CPU's other segment registers
(SS/DS/ES/FS/GS) still hold whatever the bootloader left in them — stale
indices into a table that no longer exists. Here the bootloader's leftover
SS happened to land on our TSS descriptor's low half, which isn't a valid
data segment, so the very next `iretq` (returning from the test breakpoint
exception) general-protection-faulted trying to reload it. Fix: explicitly
null out SS/DS/ES/FS/GS in `gdt::init()` instead of relying on the
bootloader's leftovers not colliding with whatever *our* table happens to
put in the same slot.

Another one, in `scheduler.rs` this time: a freshly spawned thread's initial
stack layout has to leave `rsp` sitting at the same offset (mod 16) that a
real `call` instruction would — the SysV ABI expects `rsp ≡ 8 (mod 16)` at
function entry, since `call` pushes an 8-byte return address onto a
previously 16-aligned stack. `switch_to`'s `ret` fakes that same entry state
for a thread that was never actually `call`ed, so getting the arithmetic
wrong doesn't fail on the first context switch — it silently misaligns any
stack-spilled SSE register in the entry function, faulting only once such a
spill actually happens. `Thread::new`'s `entry_rsp` computation has the
derivation in a comment; don't change the stack-top math without re-deriving
it.

A third, this time in the build setup rather than the kernel's own code:
Cargo discovers `.cargo/config.toml` by walking up from the *current working
directory*, not from `--manifest-path`. `kernel/.cargo/config.toml` used to
set `[build] target = "x86_64-unknown-none"` as an ambient default (nice
DX — plain `cargo build` from `kernel/` just worked) — but that default also
leaked into the `runner`'s own `cargo run --manifest-path ../xtask/Cargo.toml`
subprocess, since its CWD stayed inside `kernel/`. That forced `xtask` (a
host-side tool that depends on `serde` via `bootloader`) to try compiling
for a bare-metal target and fail with `can't find crate for std`. Fix:
`kernel/.cargo/config.toml` has no `[build] target` anymore — pass
`--target x86_64-unknown-none` explicitly on every kernel command instead
(see "Building" above). A `.cargo/config.toml` default is convenient right
up until something inside the same directory tree needs a *different*
target — then it's an invisible cross-process footgun.

That fix immediately caused a follow-on bug, worth flagging since it's easy
to reintroduce: `xtask`'s own `build_kernel()` function invokes
`cargo build` in `kernel/` to produce the binary it wraps into a boot
image — and it was *also* relying on the now-removed ambient default,
silently building a host binary instead of the bare-metal one. The failure
mode was confusing rather than obvious: not "wrong target," but a codegen
error (`offset is not a multiple of 16`) from compiling `userspace.rs`'s
naked `.balign 4096` assembly for the wrong target entirely. Fixed by
passing `--target x86_64-unknown-none` explicitly in `build_kernel()` too.
Moral: an ambient config default rarely has exactly one reader — grep for
every place that relied on it before removing it, not just the one you
were fixing.

## Open questions

- **License**: workspace default stays Apache-2.0 through Alpha and Beta.
  **Decision: still deferred, but the deferral's own reasoning is now
  stale and worth re-checking soon.** The original reasoning was "there's
  no real governance logic in `citadel-integration` yet, so there's
  nothing whose license would meaningfully differ" — no longer true: the
  crate now has real, tested logic (`ModuleManifestEntry`/`BootAllowlist`,
  boot-time module authorization — see above). It's arguably still
  Apache-2.0-appropriate (boot-time signature verification isn't the
  MARSHAL/WORM *governance* logic the AGPL question was originally about),
  but that argument hasn't actually been made yet, just assumed by
  inertia. Revisit explicitly — either re-confirm Apache-2.0 with real
  reasoning or switch — rather than letting "deferred until real logic
  exists" silently stay deferred now that real logic exists. Full
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
