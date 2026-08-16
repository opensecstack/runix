# Runix status (Alpha)

This is the detailed, narrative engineering log of what's actually built,
verified, and (importantly) what broke along the way — as opposed to
[ROADMAP.md](ROADMAP.md)'s target dates/scope, or [BUILDING.md](BUILDING.md)'s
build-stage checklist. Read this before assuming something is or isn't
implemented; the roadmap describes targets, not current state.

We are currently in **Alpha**. The kernel's own bring-up — all 9 "Kernel
build stages" (see [BUILDING.md](BUILDING.md)) — is **complete**: boot, serial
output, exception handling, paging, a working kernel heap, PIC/PIT timer
interrupts, cooperative round-robin context switching, a syscall ABI
(`int 0x80`), byte channels between threads, a real ring 0 → ring 3
transition, and a QEMU-native `cargo test` harness are all working, verified
end to end in QEMU (the `main.rs` demo boots through every phase, exercises
capability-gated IPC — see `capability-manager` below — and lands in ring 3,
which prints `USR` back through the syscall gate as its last act).

All five of Alpha's roadmap items are done: microkernel boot, basic IPC,
WASM runtime (engine bring-up *and* ring 3 hosting — see the
`grid-sandbox-host` section below), the capability manager (as of the
capability-gate work below), and CITADEL boot-time module authorization
wired into `kernel/`'s own boot sequence (see the `citadel-integration`
section below). **`wasm-runtime`** now has a real engine
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
   Sandbox, see [ARCHITECTURE.md](ARCHITECTURE.md)) exists for — a bug in
   `wasmi` would be a ring 0 vulnerability, not a sandbox escape.
2. *Interpreter as its own ring 3 process*, loaded by the kernel, talking
   to it only through the syscall gate (`int 0x80`) — what "Grid Sandbox"
   actually means: WASM code gets bytecode-level bounds checking *and*
   hardware-enforced ring 3 isolation, so an interpreter bug still can't
   reach kernel memory.

Option 2 is the real target, and the kernel infrastructure it needed —
an ELF/module loader, per-process address spaces, and multi-process
scheduling with real ring 3 cooperation — is now built (see the
process-isolation and multi-process-scheduling sections below). That
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

**Now actually what "Grid Sandbox" means end to end, not just a
bare-metal-compiling library.** `grid-sandbox-host` (a separate
freestanding crate, own `[workspace]`, same pattern as
`kernel`/`xtask`) is a real, `rustc`-compiled binary hosting the
`wasmi` engine, built as its own ELF and loaded through `elf::Elf64`
into its own `process::AddressSpace`, then run as a genuine ring 3
process via `scheduler::spawn_ring3_process` — not a hand-written naked
function like `ring3_cooperative.rs`'s processes. Verified end to end
by `kernel/tests/grid_sandbox_wasm.rs`: `grid-sandbox-host` executes a
real embedded WASM module (`hello.wat`) via two `host.print` calls that
cross back out through the syscall gate to the kernel's `SYS_WRITE`
handler, reaching the host and printing `"Hi"` — proof the whole chain
worked (host allocator init on a kernel-mapped private heap, `wasmi`
engine/module/store construction, host-function import wiring, guest
bytecode execution, and the syscall gate back out) inside a genuinely
hardware-isolated ring 3 process, not simulated. Wired into CI
(`.github/workflows/ci.yml` builds `grid-sandbox-host` first, since
`grid_sandbox_wasm.rs`'s `include_bytes!` needs its compiled output
already on disk, then runs the test) — not a manual-only step. Two real
bugs found getting here, both worth knowing before touching this path
again: `map_private_page` maps one 4 KiB page per call, but the ring 3
entry stack (`PAYLOAD_STACK_SIZE`, 4 pages) was only mapped once,
leaving the actual stack pointer 3 pages past what was mapped and
page-faulting on first use — fixed by looping over the full page range,
same pattern the heap mapping already used; and a fresh heap page isn't
guaranteed zeroed by the allocator, only its own free-list header is,
so newly mapped heap pages are now explicitly zeroed. No sandbox tiers
or MARSHAL channel permits yet — this proves the mechanism, not the
full Beta-scope Grid Sandbox policy layer.

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
reason `interrupts::ticks()` stood in for "now" back in build stage 5 —
there's no RTC driver yet.

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

**Now wired into `kernel/`, and gating a real module load** — not just
tested in isolation, and not just a demo call on throwaway bytes.
`kernel/Cargo.toml` depends on `citadel-integration`, and
`kernel/src/citadel.rs` (a demo trust root, same pattern as
`capabilities.rs`'s demo capability-token root) calls
`BootAllowlist::authorize_module_load` from `main.rs`'s boot sequence in
two phases. Phase B6: an allowlist entry signed for a demo module's exact
bytes is accepted, and the same check against tampered bytes is correctly
refused — verified end to end in QEMU by `kernel/tests/citadel_demo.rs`,
wired into CI alongside the rest of the `kernel-tests` suite. Phase B7:
the *same* check, this time against `grid-sandbox-host`'s real compiled
bytes, actually gating whether `main.rs` goes on to parse, load, and run
it as a ring 3 process (via `elf::Elf64` -> `process::AddressSpace` ->
`scheduler::spawn_ring3_process` — the same mechanism the
`grid-sandbox-host` section above proved works, now reached from the real
boot path instead of only a test) — fail-closed, an unauthorized module
is never touched. Verified in QEMU: the real boot log shows
`grid-sandbox-host authorized by CITADEL allowlist`, then the binary
loading and running to completion (its `wasmi`-hosted WASM module prints
`"Hi"`, round-tripping through the syscall gate, exactly as
`grid_sandbox_wasm.rs` already proved), before the boot thread continues
on to `user_hello`. Real *runtime* MARSHAL/WORM/VIGIL integration (once Runix has running
user-space processes to gate, not just boot-time module loads) remains
Beta/RC work, blocked on the same external SDK gap as before — see
[ROADMAP.md § Open questions](ROADMAP.md#open-questions).

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
  build stage 4 was sized for that stage's own smoke test, and never grew
  to account for `main.rs`'s demo now spawning 7 scheduler threads at
  16 KiB of stack each (112 KiB alone) plus capability token allocations
  on top. `allocator::HEAP_SIZE` is now 1 MiB — headroom for the current
  demo plus room to grow, not a principled sizing.
- Also worth a general note for `curve25519-dalek` specifically: it
  auto-selects a "simd" backend whenever the compiler is nightly —
  always true here — regardless of whether the target's codegen actually
  supports it. On `x86_64-unknown-none` that's an LLVM ICE ("Do not know
  how to split the result of this operator"), not a normal compile error.
  `kernel/.cargo/config.toml` forces the portable `serial` backend via
  `rustflags`, scoped to the `x86_64-unknown-none` target only (same
  "don't let it leak into xtask's nested build" reasoning as the
  `.cargo/config.toml` fix in [BUILDING.md](BUILDING.md)).

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
  IST-based double-fault handler from build stage 3 (it runs on its own
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
The moment anything long-running exists (the network stack that's next, see
below), this becomes a real, fast leak: any code path that repeatedly
spawns and finishes short-lived work exhausts physical memory with no way
to recover. Fixed on both ends:

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
is "user-space network stack" (see [ROADMAP.md](ROADMAP.md)) — the
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

## Mobile L1: ARM/TrustZone boot bring-up (`kernel-arm/`)

Started from nothing to a real, QEMU-verified boot path in one push, in a
separate freestanding crate from `kernel/` (which is deeply `x86_64`-specific
— see `kernel-arm/src/main.rs`'s doc comment for why). Verified with
`qemu-system-aarch64 -M virt,secure=on,gic-version=2 -cpu cortex-a53`:

- Boots to **EL3** (Secure Monitor — the exception level TrustZone
  Secure-world firmware runs at), confirmed via `CurrentEL`, not assumed
  from `secure=on` alone.
- A real `VBAR_EL3` exception vector table (`vectors.rs`) catches a
  deliberately-triggered synchronous exception and resumes execution with
  the interrupted code's *full* register context preserved — a first
  version only saved/restored `x0` and silently corrupted the rest, the
  same class of bug as the `int 0x80` register-clobber issue below.
- GIC (Generic Interrupt Controller) bring-up is fully proven: a Software
  Generated Interrupt is delivered through the IRQ vector, acknowledged
  and EOI'd. Getting here took two real fixes — see the GIC entry below.
- The actual TrustZone boundary: drops from EL3 to EL1 Non-secure via
  `eret` (`nonsecure.rs`), confirmed by EL1 code reading `CurrentEL` after
  landing.
- EL1's own MMU is up (`mmu.rs`): two 1 GiB identity-mapped blocks (Device
  for the GIC/UART, Normal non-cacheable for RAM), verified with `AT
  S1E1R` actually asking the hardware to translate an address and
  confirming the result matches — not just that `SCTLR_EL1.M`'s write
  didn't crash. Getting a working MMU up took two more real fixes — see
  below.
- The actual RIL isolation boundary (`el0.rs`/`svc.rs`/
  `capabilities.rs`/`ril_channel.rs`): a real EL1 -> EL0 drop, an `SVC`
  syscall gate (dispatched through `el1_vectors.rs`'s vector-8 handling —
  the ARM analogue of `int 0x80`), and per-operation resource-access
  checks gated by a real `capability-manager` token — the *same* crate
  the x86_64 kernel uses for `SYS_IPC_SEND`, reused rather than
  reimplemented. Proven end to end: an EL0 demo (`el0_demo`) issues an
  unconditional `SYS_WRITE` (proves the `SVC` gate works), `SYS_RIL_ACCESS`
  for a channel it holds a capability for (authorized) and one it doesn't
  (denied), then `SYS_RIL_SEND`/`SYS_RIL_RECV` round-tripping a real byte
  (`0x41`, `'A'`) through the authorized channel's single-slot mailbox and
  getting denied on the unauthorized one — proving the capability check
  gates actual per-operation I/O, re-checked on every call, not just a
  one-time access decision. **Not** real EL0/EL1 memory isolation yet —
  `mmu.rs`'s Normal block stays EL1-only (`AP[2:1]=0b00`); the correct
  `0b01` bit was tried and reverted after a real, reproducible QEMU hang —
  see the bug entry below. The enforced boundary today is the capability
  check at the `SVC` gate, matching `kernel/src/capabilities.rs`'s role on
  the x86_64 side, not an MMU permission boundary (which doesn't exist at
  this granularity yet regardless).
- **Basic SIM provisioning** (`sim.rs`) — closing out Alpha mobile's last
  unstarted roadmap item. A minimal per-slot profile state machine
  (`Uninitialized -> Provisioned -> Activated`), gated by the *same*
  capability check the RIL syscalls use: this slice generalized the demo
  capability store (`ril_capability.rs`, now `capabilities.rs`) from a
  single RIL-only slot to a small set of tokens covering any resource
  kind, specifically so SIM slots and RIL channels could be authorized
  independently for the one EL0 context. Proven end to end: `el0_demo`
  walks slot 0 through `SYS_SIM_STATUS` (`Uninitialized`) ->
  `SYS_SIM_PROVISION` (`Provisioned`) -> `SYS_SIM_ACTIVATE` (`Activated`),
  confirming each transition with another `SYS_SIM_STATUS`, then gets
  denied on `SYS_SIM_PROVISION`/`SYS_SIM_STATUS` for an unauthorized
  slot — proving the capability boundary is uniform across resource
  kinds, not something special-cased for RIL. Deliberately not a real
  SIM/eSIM implementation: no APDU protocol, and `provision`'s "identity"
  is one opaque `u64` (the `SVC` ABI only carries plain register
  arguments — a real ICCID/IMSI needs ~15-20 digits, more than fits in
  one), not real ICCID/IMSI digit strings. A fixed-size-buffer syscall ABI
  is real follow-up work, not something to fake by packing digits into a
  register.

Not yet started: the real RIL/SIM *protocol* work itself (talking to
actual radio/SIM hardware, not just proving the isolation boundary and
provisioning state machine they'll run under) — per `mobile/src/lib.rs`'s
doc comment, that starts once the shared kernel boots on target hardware;
everything above is still QEMU-only.

Non-secure boot (`-M virt` without `secure=on`, which resets straight to
EL1 instead of EL3) now works too — previously produced no UART output at
all, root-caused and fixed; see the bug entry below.

## Real bugs worth knowing before touching the relevant code again

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
(see [BUILDING.md](BUILDING.md)). A `.cargo/config.toml` default is
convenient right up until something inside the same directory tree needs a
*different* target — then it's an invisible cross-process footgun.

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

Two more, in `kernel-arm/` this time. First: an AArch64 exception vector
stub only saved/restored `x0` (the register it clobbers to carry the
vector index into the handler) before resuming a caught exception via
`eret` — silently corrupting whatever else the interrupted code had live
in `x1`-`x18`/`x29`/`x30`, since `unsafe { asm!("brk #0") }` has no
operands or clobber list, so the compiler assumes a bare trap instruction
touches nothing. Same class of bug (and fix — save/restore the full
caller-saved register set, not just the one register the handler itself
happens to touch) as `kernel/src/syscall.rs`'s undeclared `RCX`/`R8`-`R11`
clobber across `int 0x80` on the x86_64 side. Second, harder to find: a
Software Generated Interrupt would sit correctly pending at the GIC
distributor (`GICD_ISPENDR0` read back `0x1`) and even show as the
highest-priority pending interrupt at the CPU interface (`GICC_HPPIR`),
with `PSTATE.I`/`F` both confirmed clear — every register that looked
relevant said "this should fire" — and still never trap into EL3. GDB
attached to QEMU (`qemu-system-aarch64 ... -S -s`, then `gdb -x
script.py`) is what found it: `SCR_EL3.IRQ`/`SCR_EL3.FIQ` (bits 1/2),
which control physical interrupt *routing* to EL3 and are a separate
concern entirely from both the GIC's own state and `PSTATE` masking. Left
at 0 (their reset value), physical IRQ/FIQ simply never route to EL3 at
all, no matter how correct everything else is. See `kernel-arm/src/gic.rs`
for the full list of GIC configurations ruled out before finding this.

Two more, bringing up `kernel-arm/`'s EL1 MMU (`mmu.rs`). First: EL1 had no
exception vector table at all when the first `mmu::install()` attempt ran
— `VBAR_EL1` defaults to `0` at reset, so the wrong page-table entry didn't
produce a diagnosable fault, it silently jumped the CPU to whatever raw
bytes sit at physical address `0x200` (the zero-based "current EL, SPx,
Synchronous" vector offset). The only way to see *that* a fault had even
happened was attaching GDB and noticing `$pc` had moved there — nothing
printed, nothing else visibly changed. Fixed by building EL1's own vector
table (`el1_vectors.rs`, install it *before* touching the MMU) — the same
lesson as `kernel/`'s own boot sequence learned early (see its own vector
table's history), just re-learned on a second architecture. Second, found
immediately after that fix made the fault actually diagnosable:
`CPACR_EL1.FPEN` (bits [21:20]) traps FP/SIMD access by default, and nothing
here ever touches a `v`/`q` register on purpose, yet a plain
`serial_println!` call with no format arguments faulted with
`ESR_EL1.EC=0x7` ("FP/SIMD access trapped") while other, structurally
identical calls didn't — the compiler's own memcpy-lowering choice for
that particular string's length used NEON registers, not anything this
code asked for. Fixed by setting `CPACR_EL1.FPEN=0b11` as the very first
thing `el1_entry` does, before any other EL1 code (including the first
print) runs, rather than debugging this class of trap fault-by-fault as
different string lengths happen to trigger it.

Two more, bringing up `kernel-arm/`'s RIL isolation boundary (`el0.rs`/
`svc.rs`/`ril_capability.rs`). First, a genuine compile error rather than a
silent one: `el0::drop_to_el0`'s `asm!` block used `adrp`/`add` against a
scratch `x0` register to compute the EL0 stack pointer, declared as
`out("x0") _` alongside `options(noreturn)` — but `noreturn` forbids
declaring *any* asm output, since the compiler assumes control never
returns to observe one. Fixed by computing the stack address in ordinary
Rust *before* the `asm!` block and passing the final value in as a normal
`in(reg)` operand, removing the need for an in-block scratch register
entirely. Second, a real QEMU behavior, not a logic bug in the page table:
setting `mmu.rs`'s Normal block to `AP[2:1]=0b01` (the architecturally
correct bit for granting EL0 data access, needed once `el0.rs` existed)
reproducibly hung QEMU (`cortex-a53`, `virt`) at `mmu::install`'s
`SCTLR_EL1.M` write/`isb` — entirely on the EL1 side, before any EL0 code
had run. That doesn't fit the architecture (`AP[1]` is defined to gate
EL0's own access, not EL1's), and adding a `tlbi vmalle1` before enabling
translation (a real correctness fix, kept regardless) made no difference —
ruled out as the cause without being root-caused further. Reverted the bit
rather than block on it: it isn't the enforced isolation boundary (that's
the capability check at the `SVC` gate), and `el0_demo` never performs an
EL0 data access, so nothing today actually depends on it. Revisit once EL0
code needs direct memory access instead of only `SVC`. Third, in
`ril_capability.rs`: the demo capability's expiry window was a fixed
`1_000_000`-tick constant, sized without checking `CNTFRQ_EL0` first — on
this platform's actual generic-timer frequency that's under a millisecond
of real time, comfortably exceeded by heap init plus a handful of UART
prints between issuance and the first check, so every demo token "expired"
before `el0_demo` ever got to use it (`SYS_RIL_ACCESS channel 0 DENIED
(capability token expired)`, for a token issued moments earlier). Fixed by
sizing the window off `CNTFRQ_EL0` directly (`svc::frequency_hz()`) instead
of a magic tick count.

One more, closing out the "no UART output without `secure=on`" known gap
from earlier: `-M virt` without `secure=on` resets straight to EL1 (no
EL3 exists at all in that config), but `rust_start` ran the EL3-only boot
phase unconditionally regardless of which EL it actually landed at.
`vectors::install()`'s `VBAR_EL3` write is UNDEFINED when executed from
EL1, and — same failure signature as the MMU bug above, now hit a third
time — with `VBAR_EL1` not installed yet either, that trap silently
jumped to whatever raw bytes sit at physical address `0x200`, producing
no output at all. Root-caused with a GDB `stepi` from `_start` (same
technique as the GIC fix), which showed `$pc` landing at `0x200` after
only a handful of instructions; confirmed by adding a raw-asm UART
write-probe directly in `_start` (zero Rust codegen, to rule out an
`FP`/`SIMD`-trap theory first) — worth noting the probe itself had a bug
on the first attempt (`movz x2, #0x9000, lsl #16` computes `0x9000_0000`,
not UART0's real `0x0900_0000` — an extra hex digit shifted the whole
address by 16x), which produced a real store-permission fault to
unmapped memory and briefly looked like confirmation of the wrong theory
before the immediate was corrected. Fixed by having `rust_start` check
`CurrentEL` and, when no EL3 is present, call a new
`nonsecure::el1_entry_no_el3` directly instead of running the EL3-only
phase — factored out of the existing `el1_entry` so both paths share the
same EL1 setup (MMU, heap, capability issuance, EL0 drop) but print an
honest, distinct account of *how* EL1 was reached (the EL3-drop path
still says "dropped from EL3, `SCR_EL3.NS=1`"; the no-EL3 path no longer
claims a security-state switch that never happened).

A follow-up investigation into the `AP[2:1]=0b01` QEMU hang above, not a
resolution: rather than re-deriving the same "hangs, not root-caused"
result, this pass swept all four `AP[2:1]` encodings on the same table
entry to narrow down *which* bit actually triggers it. `0b00` (today's
value) works, `0b01` (`AP[2]`=0, EL1 rw / EL0 rw — what's actually
wanted) hangs immediately at `SCTLR_EL1.M`/`isb`, and `0b10`/`0b11`
(`AP[2]`=1, EL1 read-only either way) both instead get *past* that point
— "MMU enabled" prints — and hang one step later, exactly where the next
code needs to write to this block's own stack, which is the expected
consequence of making EL1's data read-only, not an anomaly. That
localizes the real issue precisely: `AP[2]=0` (EL1 keeps full
read/write, architecturally unaffected by `AP[1]` per the spec) combined
with `AP[1]=1` (EL0 access newly granted) hangs immediately, while every
`AP[2]=1` encoding gets further. Also ruled out this pass: `nG` (bit 11)
set alongside `0b01<<6` — identical immediate hang. Checked for a
matching known QEMU issue (none found, QEMU 10.1.5, `cortex-a53` and
`max` both reproduce it identically — not CPU-model-specific either).
Reverted again, same reasoning as before (not the enforced isolation
boundary, nothing today depends on it) — see `mmu.rs`'s doc comment on
`normal_block_descriptor` for the full, precise account, worth reading
before attempting a third pass at this.
