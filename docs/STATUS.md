# Runix status (Alpha)

This is the detailed, narrative engineering log of what's actually built,
verified, and (importantly) what broke along the way — as opposed to
[ROADMAP.md](ROADMAP.md)'s target dates/scope, or [BUILDING.md](BUILDING.md)'s
build-stage checklist. Read this before assuming something is or isn't
implemented; the roadmap describes targets, not current state. Decisions
that cross crate or trust boundaries are recorded separately, with their
alternatives and revisit triggers, in the
[architecture decision records](adrs/README.md).

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
(`wasm-runtime/tests/memory_isolation.rs`). Sandbox tiers now exist — see
"Grid sandbox isolation tiers" below for what "MARSHAL channel permits"
concretely means today and what it still doesn't.

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
so newly mapped heap pages are now explicitly zeroed. At the time this
proved the mechanism, there were no sandbox tiers or MARSHAL channel
permits yet — the next section is that policy layer's starting slice.

**Grid sandbox isolation tiers (T1/T2/T3) — a signed permit, and a real
host-imposed enforcement mechanism, not just a label.** Until now the only
isolation distinction anywhere in this codebase was ring 0 vs. ring 3 —
every module `grid-sandbox-host` might ever run got identical treatment.
CLAUDE.md already defines the tier vocabulary (T1 Critical → MARSHAL
real-time <300ms, T2 Trusted → MARSHAL standard, T3 Untrusted → MARSHAL
evidence-gated); this closes the gap between that policy statement and any
code enforcing it, without needing the still-open `opensecstack/sdk/rust`
blocker (see ROADMAP.md) — that blocks a *live* MARSHAL Gate evaluation
client, which `citadel-integration`'s own doc comment already explains
isn't reachable from boot-time kernel code anyway (no network stack
reachable that early, no Separation-of-Duties principal). What Beta could
start immediately instead: a signed tier assignment (the "permit") flowing
from CITADEL's existing boot-time allowlist into a real, host-enforced
resource-limit difference inside the WASM engine (the "isolation").

The permit: `citadel-integration::ModuleManifestEntry` gained a
`tier: SandboxTier` field, folded into the same signed canonical string
that already authenticates `module_id`/`sha256_hex` (bumped to `v2`:
`v2|module_id|sha256_hex|tier`) — a validly-signed entry authenticates its
tier the same way it already authenticated the module's identity and
content hash, with no separate check needed. Verified the way every prior
tamper-resistance property in this codebase is verified: a test
(`rejects_tampered_tier`) signs an entry as `T2Trusted`, mutates the
in-memory `tier` field to `T1Critical` *without re-signing*, and confirms
`authorize_module_load` now returns `InvalidSignature` — the same
"tampered field, not just tampered bytes" property `rejects_tampered_bytes`
already proved for module content, now proved for the tier assignment too.
`BootAllowlist::authorize_module_load` returns `Result<SandboxTier, ...>`
instead of `Result<(), ...>` — the tier is the actual value a successful
authorization now hands back, not a discarded unit.

The isolation: confirmed by reading `wasmi` 0.32.3's own source
(`limits.rs`, `store.rs`) that `StoreLimits`/`StoreLimitsBuilder` +
`Store::limiter(...)` let a host cap a module's linear-memory/table growth
**regardless of what the module itself declares** — a real, new ceiling,
not the weaker property `memory_isolation.rs`'s existing tests already
proved (that a module's *own declared* maximum is honored, which a hostile
module could simply declare much larger, or not declare at all).
`wasm-runtime` gained `SandboxLimits` (three constructors —
`t1_critical()`: 8 MiB memory / 4096 table elements, `t2_trusted()`: 4 MiB
/ 2048 (also `WasmRuntime::new()`'s default, so every existing call site
and test keeps compiling unchanged), `t3_untrusted()`: 512 KiB / 256 —
arbitrary initial defaults, not tuned against any real workload) and
`WasmRuntime::new_with_limits(...)`, which installs the limits via
`Store::limiter` before instantiating. Deliberately kept tier-agnostic:
this crate only knows "what are my limits", not "what tier am I" — CITADEL
vocabulary stays out of `wasm-runtime` entirely. Verified by
`wasm-runtime/tests/tier_isolation.rs`: the *same* module, declaring **no**
memory maximum of its own, is allowed to grow to 100 pages under
`t1_critical()`'s limit but capped (returns `-1`, per `memory.grow`'s spec —
it doesn't trap) under `t3_untrusted()`'s, proving the enforcement is
actually tier-driven and not an artifact of the module or the engine.

The wiring end to end: `kernel/src/main.rs`'s Phase B7 authorizes
`grid-sandbox-host` as `T2Trusted` (CLAUDE.md: "first-party apps" — exactly
what the embedded `hello.wat` demo is) and writes the resulting tier into
one new fixed boot-info page (`GridBootInfo { tier: u8 }` at
`GRID_INFO_VA`, `0x_2222_4444_0000` — same "no shared type, just an agreed
ABI" convention `NetBootInfo` already established for the net-driver-host
boundary, deliberately not a shared Rust type since `grid-sandbox-host` has
zero `citadel-integration` dependency and adding one for a 3-value tag
isn't worth the coupling). `grid-sandbox-host/src/main.rs` reads that byte
at `_start`, maps it to a `SandboxLimits` (falling back to the *tightest*
tier, T3, on any unrecognized byte — fail-closed, matching
`authorize_module_load`'s own stance on an unrecognized module, not
fail-open to the most generous tier), and calls
`WasmRuntime::new_with_limits(limits)` in place of the old `WasmRuntime::new()`.
`kernel/tests/grid_sandbox_wasm.rs` (the existing QEMU boot test) needed
the same `GridBootInfo` page mapped and written to keep working at all —
confirmed it still passes, producing the same `"Hi"` output as before,
proving T2's limits are generous enough not to regress the one real
workload that exists today.

**Boot-verified for all three tiers, not just T2 — the gap
`tier_isolation.rs` alone couldn't close.** That test proves the *limiter
logic* is tier-differentiated, but runs on the host, backed by however
much memory the dev/CI machine happens to have — it can't prove a real
ring-3 `grid-sandbox-host` process, with its own tiny private heap, can
actually satisfy a permitted growth request, only that the limiter object
says yes in the abstract. Two new kernel tests
(`kernel/tests/grid_sandbox_tier_t1.rs`/`_t3.rs`) boot the same real
`grid-sandbox-host` binary at `T1Critical`/`T3Untrusted` instead of the
real boot path's `T2Trusted`, and a new embedded probe module
(`grid-sandbox-host/src/grow_probe.wat`, compiled by `build.rs` alongside
the existing `hello.wat`) requests growing its own linear memory by 69
pages (→ 70 total, ~4.375 MiB) — a size chosen so all three tiers give a
genuinely different, meaningful outcome: allowed under `t1_critical()`'s
128-page/8 MiB cap, rejected under `t2_trusted()`'s 64-page and
`t3_untrusted()`'s 8-page caps. The result (grow succeeded / failed /
errored) is written back into the same `GridBootInfo` page at a second,
new offset (`GRID_GROW_RESULT_OFFSET`, matching `NET_RESULT_OFFSET`'s own
convention — `0` means "not yet run", never mistaken for a real outcome),
so all three tests assert a real result *code*, not grepped serial text.
Confirmed: `grid_sandbox_tier_t1` shows the grow succeeding,
`grid_sandbox_tier_t3` and the updated `grid_sandbox_wasm` (T2) both show
it failing — the same real memory.grow request, three real ring-3 boots,
three tier-correct outcomes.

This surfaced a real, load-bearing constraint that had to be designed
around, not just tested past: `grid-sandbox-host`'s original 256 KiB heap
backs *everything* in that process — the `wasmi` engine, module, store,
**and** any real linear-memory growth a module actually performs. A
limiter permitting T1's ~4.375 MiB growth request means nothing if the
process's own allocator can't back that many real bytes — that's a
different failure (real allocator exhaustion) than the tier mechanism
being wrong, and would have made the T1 boot test meaningless (or
flaky/crash-prone) if left unaddressed. `HEAP_SIZE` (both
`grid-sandbox-host/src/main.rs` and `kernel/src/main.rs`'s
`GRID_SANDBOX_HEAP_SIZE`, which must match it) was bumped to 8 MiB
specifically to make that real allocation succeed, with slack for
`wasmi`'s own overhead — not tuned any further than that, same "arbitrary
initial default, not tuned against a real workload" honesty as
`SandboxLimits`' own numbers.

What this doesn't claim: no live MARSHAL Gate evaluation exists (still
SDK-blocked — see the `citadel-integration`/MARSHAL narrative below for
what's actually changed there); T3's "evidence-gated" tier is approximated
purely by resource strictness, not real VIGIL evidence collection (VIGIL
itself doesn't exist yet — though a real, local WORM log now does, see
below); and `grid-sandbox-host` still has no capability-manager token the
way `net-driver-host` does for port I/O — its only syscalls today
(`SYS_YIELD`/`SYS_WRITE`) don't need kernel-mediated tier-gating, since
enforcement happens inside the WASM engine itself, in-process. Revisit
that last point if/when `grid-sandbox-host` gains a syscall that plausibly
needs tier-gating (e.g. an IPC channel to a T1 service).

**No longer true: "still exactly one `grid-sandbox-host` instance, spawned
once at boot."** `kernel::grid_sandbox::spawn_instance(instance_id, tier,
now, key)` is real multi-instance spawning, factored out of the original
single-spawn boot path so it's callable N times — each call gets its own
`AddressSpace`, its own *physically distinct* heap/stack/`GridBootInfo`
frames (not just distinct virtual addresses reusing the same physical
backing, which would have been a much cheaper, much less meaningful
claim), and its own capability token scoped to that specific instance.
Authorization moved with it: `citadel::demo_authorize_instance` checks a
new `InstanceAllowlist`/`InstanceManifestEntry` (additive alongside the
original `BootAllowlist` — existing single-instance boot call sites are
untouched) so a second instance is authorized on its own signed manifest
entry, not by silently inheriting the first instance's grant. That
distinction matters for a concrete reason: once more than one instance
can exist, one module-wide grant would have been ambient authority for
every instance that module ever spawns — a real design point this commit
addressed rather than deferred. Verified by `kernel/tests/
grid_sandbox_multi_instance.rs`: two concurrent instances at *different*
tiers, proving independent tier enforcement, genuinely distinct physical
memory despite identical virtual addresses, and that neither instance's
token authorizes the other's resources.

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
on to `user_hello`. Real *runtime* MARSHAL Gate integration (once Runix has running
user-space processes to gate, not just boot-time module loads) remains
blocked on the same external SDK gap as before — see
[ROADMAP.md § Open questions](ROADMAP.md#open-questions). What follows is
everything that's actually changed on that front since — real movement,
none of it yet a live Gate call.

**A real local WORM evidence log — not the live MARSHAL binding, a
narrower and honestly-scoped first piece of it.** `WormLog`/`WormEntry`
(`citadel-integration/src/lib.rs`) is an append-only, hash-chained log —
each entry's hash covers the previous entry's hash, so removing or
editing a past entry breaks every hash after it, the same tamper-evidence
property a real WORM log needs — recording every authorization decision
(allow/deny, module or instance id, tier) as a side effect of both the
original `BootAllowlist::authorize_module_load` and the new instance-level
authorization below. Its own doc comment is explicit about the boundary:
*local evidence collection only* — no signing, no network round-trip, no
Gate semantics. It does not move the live-Gate blocker; it gives the
eventual live Gate call something real to submit as evidence once that
call exists.

**Toward the actual blocker: a transport shape, a wire contract, and a
first working implementation — in that order, each still one step short
of a real Gate call.** Three commits move this forward, reconciled
against `opensecstack/opensecstack`'s own drafted RFC-0005 rather than a
guessed shape:

1. `KerkeseTransport` trait + `TransportError` enum
   (`citadel-integration/src/lib.rs`) — field-for-field matched against
   the real `citadel-kerkese-core::transport::TransportError` shape, with
   doc-comment-only markers at the three places a real Gate-evaluation
   call would plausibly go (`kernel/src/syscall.rs`'s `SYS_IPC_SEND`/
   `SYS_PORT_IN`/`SYS_PORT_OUT`, `grid_sandbox::spawn_instance`,
   `citadel::demo_authorize`/`demo_authorize_instance`). No
   implementation, not even a mock — a trait shape only.
2. A kernel↔proxy wire contract (`ipc::marshal`'s `MarshalRequest`/
   `MarshalResponse`) carried over a real TCP connection through the
   sockets IPC surface (`ipc::sockets`, `net-driver-host`'s
   `run_socket_ipc_server`) — `kernel::marshal_client` opens a socket,
   connects it to a configurable remote IP/port, sends the encoded
   request, and decodes the response with `MarshalResponse::decode`'s
   already-resumable/streaming-safe parser. (An earlier version of this
   module rode Runix's own internal port-channel IPC on fixed ports
   13/14 instead — that only works between ring-3 processes the kernel
   itself loaded inside the same boot image, and can't reach a real,
   separate proxy process; reworked to use a real socket once that
   limitation was identified.) `MarshalOutcome`
   (`Execute`/`Refuse`/`HardStop`) mirrors `citadel-kerkese-core`'s own
   `Outcome` enum. Verified by `kernel/tests/marshal_tcp_roundtrip.rs`
   against a *test-only* Python listener (`tests/support/
   marshal_proof_listener.py`) reached over a real TCP connection via
   QEMU `guestfwd` — not a MARSHAL proxy or any stand-in for one, it
   always answers `Refuse`, chosen deliberately so that if this test
   scaffolding were ever mistaken for real governance and left in a real
   path, it would fail closed, not open.
3. **A real, working HTTP `KerkeseTransport`** — `desktop::citadel::
   transport::HttpKerkeseTransport`, the first genuinely external-facing
   piece of this whole chain. `desktop/`'s `Cargo.toml` takes
   `citadel-kerkese-core` as a real dependency, pinned to an exact
   upstream commit (never a floating branch — `deny.toml`'s `allow-git`
   now allow-lists exactly that one pinned source, matching the pinning
   policy `ROADMAP.md`'s Open Questions section already committed to).
   The transport bridges the trait's synchronous `submit` to async HTTP
   over `reqwest` via a dedicated Tokio runtime, reads its target endpoint
   from `RUNIX_CITADEL_URL` (never hardcoded), and fails closed with
   `TransportError::Unreachable` *before any network I/O* if
   unconfigured. Genuinely tested, not a stub: four tests against a
   hand-rolled `std::net::TcpListener` mock server covering success,
   not-configured, a non-2xx response, and connection-refused.

`desktop/` still has no call site that invokes `HttpKerkeseTransport`
during an actual module load, and there is still no live CITADEL
deployment reachable in any dev/CI/QEMU scenario — the external blocker
(a real MARSHAL proxy to talk to) remains open. But `kernel::marshal_client`
*does* now have a real caller in an actual authorization path: see
"Grid sandbox: from shadow-mode to real MARSHAL enforcement" immediately
below.

**Grid sandbox: from shadow-mode to real MARSHAL enforcement.**
`kernel::grid_sandbox::spawn_instance` (`kernel/src/grid_sandbox.rs`)
first grew a shadow-mode-only MARSHAL evaluation on every spawn (calls
`marshal_client::evaluate`, records the outcome as a
`runix_citadel_integration::ShadowMarshalOutcome` in a dedicated
`WormLog`, never acts on it — proved by `kernel/tests/
grid_sandbox_marshal_shadow.rs` against a real listener
(`tests/support/grid_sandbox_marshal_shadow_listener.py`) over a real
TCP connection through `net-driver-host`). That has now been turned into
**real enforcement**, per the approved policy in
[MARSHAL-ENFORCEMENT-POLICY.md](MARSHAL-ENFORCEMENT-POLICY.md) (Option B:
fail-open when there's nothing to honor, fail-closed only on a reachable
refusal):

- `shadow_marshal_evaluate` (name kept for continuity with
  `SHADOW_MARSHAL_LOG`/existing tests) now returns the
  `ShadowMarshalOutcome` it computes, in addition to recording it in
  `WormLog` exactly as before — observability is unchanged, only now
  something also acts on the result.
- A new `enforce_marshal_decision` gate: `Unreachable` (which
  `shadow_marshal_evaluate` already produces for both "no proxy
  configured" and "configured but couldn't be reached" — see that
  function's own `match`) and `Execute` both return `Ok(())`;
  `Refuse`/`HardStop` return `Err(MarshalEnforcementError::Blocked(outcome))`.
- `spawn_instance`'s return type changed from `Result<SpawnedInstance,
  CitadelError>` to `Result<SpawnedInstance, SpawnInstanceError>`, a new
  enum with `Authorization(CitadelError)` (boot-time allowlist failures,
  unchanged) and `MarshalEnforcement(MarshalEnforcementError)` (the new
  runtime gate) as two distinct variants — deliberately not folded into
  `CitadelError` itself, since that enum is a closed set of boot-time
  allowlist failures and this is meant to be the first of several future
  runtime enforcement gates (see `MarshalEnforcementError`'s own doc
  comment in `grid_sandbox.rs` for the full reasoning). The enforcement
  gate runs, and can return `Err`, strictly before any ELF parsing,
  `AddressSpace` setup, or capability-token issuance — a blocked spawn is
  never started and then killed, nothing gets spawned at all.
- Verified with a real QEMU boot against all three in-scope paths (Path 4,
  execution under a real deployment's `Execute`, is out of scope until Beta
  per the policy doc): Path 1 (fail-open, unconfigured) —
  `grid_sandbox_multi_instance.rs` passes unchanged, confirming no
  regression to the existing no-proxy-configured default. Paths 2
  (fail-open, configured but unreachable) and 3 (fail-closed, configured
  and reachable `REFUSE`) were both folded into an updated
  `grid_sandbox_marshal_shadow.rs`: a `"shadow-unreachable"` instance
  spawns successfully against an address with no `guestfwd` mapping at
  all (`Unreachable` recorded, spawn allowed), and a `"shadow-refused"`
  instance spawn against the real listener (always answers `REFUSE`)
  returns `Err(SpawnInstanceError::MarshalEnforcement(MarshalEnforcementError::Blocked(ShadowMarshalOutcome::Refuse)))`
  with `Refuse` recorded in the `WormLog` — genuinely blocked, not
  spawned-then-killed by construction (the gate runs, and can return
  `Err`, before any ELF parsing/`AddressSpace`/token work in
  `spawn_instance`'s source). **Platform note**: native Windows QEMU's
  Slirp backend can't run the `guestfwd=...-cmd:...` helper process at all
  (`Slirp: fork_exec: Failed to execute helper program` — confirmed against
  both this test and the pre-existing `marshal_tcp_roundtrip.rs`, so it's a
  Windows-QEMU/harness gap, not a regression from this change), so Paths 2
  and 3's networked cases were run and confirmed passing under this
  project's Fedora WSL environment instead (`PASS` observed, including the
  real listener's log showing it received the request and answered
  `Refuse`, and the kernel's own log showing the `shadow-refused` spawn
  genuinely blocked) — plain `cargo test --target x86_64-unknown-none` from
  a Windows shell only exercises Path 1's no-network case for real.
- Path 3 remains untestable against a *real* MARSHAL deployment (only a
  mock listener) until the rbacMap-coverage and Separation-of-Duties
  questions the policy doc's "Real blocking dependency" section describes
  are resolved — unchanged from that doc's own caveat.

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

**Real, timer-interrupt-driven preemption — not just cooperative yielding.** A thread that never calls
`yield_now()` no longer blocks every other thread forever; the PIT timer forces
a reschedule on every tick regardless of what's currently running. This replaced
an earlier cooperative-only design (`switch_to`, callee-saved registers, resumed
via plain `ret`) that was correct for voluntary yields at function-call
boundaries but fundamentally can't extend to preemption: an interrupt can land
at *any* instruction with arbitrary live registers a `ret`-based resume would
silently corrupt.

The mechanism: voluntary `yield_now()` and involuntary timer preemption trap
into ring 0 through a real interrupt (hardware for the timer, `int
RESCHEDULE_VECTOR` for a yield) and share one unified save/resume path.
`reschedule_entry` (a naked stub) captures all GPRs; the CPU captures RFLAGS/
CS/SS/RSP/RIP as a hardware `TrapFrame`. Resuming *any* thread later is always
the same `iretq`, whether it was suspended by preemption or cooperative yield —
a thread suspended by one can be resumed by the other with no format dispatch.

An earlier design considered keeping two formats (`Cooperative`/`Preempted`) to
avoid touching the full GPR set on voluntary yields (a callee-saved-only
optimization). It was rejected for a real correctness hazard: RFLAGS.IF handling
across a resume triggered by the *other* mechanism than what suspended a thread
— in particular, resuming a voluntarily-yielded thread that was saved with `IF=1`
via an interrupt handler that itself ran with `IF=0` — creates a state machine
hazard at the resume boundary. The unified frame handles this correctly by
letting the hardware's `iretq` restore the exact IF state that was live when the
thread was originally saved, regardless of how the save was triggered.

`kernel/tests/watchdog.rs` proves preemption end-to-end: spawns a thread that
spins forever without ever calling `yield_now()`, and a cooperating counter
thread. The counter still makes progress despite the spinning thread never
yielding — direct proof the preemption mechanism reschedules other threads
regardless of one thread's lack of cooperation. The test runs until the counter
reaches a target (20 iterations), proving genuine progress, not accidental lucky
scheduling. No explicit preemption-only regression test exists beyond this (a
thread spinning without yield_now is exactly the real-world case `watchdog.rs`
covers).

**Scheduler watchdog: now a backstop against mechanism failure.** Back when only
cooperative yielding existed, a stuck thread meant starvation. Now the watchdog's
role changed: it detects if the *reschedule mechanism itself* is broken, not if
a thread forgets to yield. `interrupts.rs` calls `record_yield()` on every
`reschedule` call, whether triggered by a timer tick or a voluntary `int
RESCHEDULE_VECTOR`, and the timer ISR panics if no reschedule has succeeded in
over `WATCHDOG_THRESHOLD_TICKS` (20 — ~1 second) — failure of the preemption
mechanism itself, not an uncooperative thread. The watchdog stays armed through
the ring 3 handoff now; `user_hello` spins forever by design but gets
preempted anyway, so `reschedule` succeeds on every tick and the watchdog never
triggers.

- `interrupts.rs` has the lock-free watchdog implementation: `record_yield()`
  (called from `scheduler::yield_now()`/`exit_current_thread()` on every call,
  and also from `reschedule` itself on every tick) stamps the current PIT tick
  count into an atomic; `timer_interrupt_handler` checks, on every tick, whether
  more than `WATCHDOG_THRESHOLD_TICKS` ticks have passed since the last recorded
  reschedule success, and panics if so. Deliberately lock-free — this runs from
  inside the timer ISR with `RFLAGS.IF=0`, so taking a lock would risk deadlock
  against code holding it mid-reschedule.
- `scheduler::init()` arms it via `interrupts::arm_watchdog()`; stays armed
  permanently after that. Safe to leave on across any ring 3 handoff,
  cooperative or not — the preemption mechanism itself keeps ticking.
- Regression test: `kernel/tests/watchdog.rs` proves recovery (the cooperative
  thread makes real progress despite the rogue thread's refusal to yield),
  coupled with proof that no unexpected panic occurs (the watchdog shouldn't
  trigger once preemption keeps `reschedule` alive). `kernel/tests/
  thread_reclaim.rs`'s 20,000-iteration loop doubles as proof the watchdog does
  *not* false-positive under heavy `yield_now()` traffic. Both wired into CI's
  `kernel-tests` job.

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

**Network stack, Phase 1: the legacy virtio-net virtqueue mechanism proven
end to end.** `net-driver-host` (a new standalone freestanding crate, same
shape as `grid-sandbox-host`) drives virtio-net entirely from ring 3: it
never gets raw port I/O privilege itself, only two new capability-gated
syscalls (`SYS_PORT_IN`/`SYS_PORT_OUT`, `kernel/src/syscall.rs`) scoped by a
single range-based capability (`capabilities::ioport_range_resource`,
covering the device's whole BAR0 register block — chosen over a
per-register-purpose scheme since it needs no new capability-manager
mechanism, matching the granularity `port_resource` already uses for IPC).
`kernel/src/pci.rs` grew BAR0 reading (`read_bar0_io_port`) to find that
range in the first place — legacy virtio-net's control interface is
I/O-space, not MMIO, so no MMIO-mapping infrastructure was needed. Polling
the used ring (no interrupts) sidesteps this kernel's total lack of MSI-X/
IOAPIC support — spec-valid and the same technique DPDK's own poll-mode
virtio driver uses in production. Verified end to end, not just compiling:
`net-driver-host` probes the device (real QEMU MAC,
`52:54:00:12:34:56`), transmits one hand-built ARP request, and receives a
genuine reply from QEMU/SLIRP via the RX virtqueue — checked byte-for-byte
(Ethertype `0x0806`, ARP opcode `2`), a real round-trip through the host,
not "no error was returned." `kernel/tests/net_driver_arp.rs` is the
regression test, and its pass/fail is a real result code, not "didn't
crash": `net-driver-host` writes a PASS/FAIL byte into the shared
`NetBootInfo` page after its own bounded poll loop, since a silent "no
reply, poll bound exceeded" failure wouldn't fault and needs to be
distinguishable from success. Wired into CI's `kernel-tests` and `boot`
jobs (both build `net-driver-host` first, same `include_bytes!` ordering
requirement `grid-sandbox-host` already has).

Three real bugs found getting here, each worth knowing before touching this
class of code again:

- **Physical frame contiguity, silently assumed and silently wrong.**
  Legacy virtio's `QueueAddress` register carries *one* physical address;
  the device computes the avail/used rings' addresses as fixed byte offsets
  from it, so a queue's 3 pages (descriptor table, avail ring, used ring)
  must land on physically *contiguous* frames, not just contiguous virtual
  addresses. A first version just called `AddressSpace::map_private_page`
  three times in a row and trusted `BootInfoFrameAllocator`'s bump
  allocation to hand out consecutive frames — it doesn't, reliably:
  `map_private_page`'s own `map_to` call can itself consume *extra* frames
  for intermediate P1/P2/P3 page-table levels the first mapping in a fresh
  region needs, interleaved with the leaf-frame allocations that actually
  mattered (observed for real: frame 1 landed 2 frames past frame 0, not 1).
  Fixed by allocating every leaf frame *first*, as one tight batch with
  nothing else running in between (`map_zeroed_contiguous_region`, in both
  `kernel/src/main.rs` and `kernel/tests/net_driver_arp.rs`), then mapping
  each pre-allocated frame explicitly via `AddressSpace::map_existing_frame`
  — whatever table frames *that* needs get allocated strictly *after* this
  function's own leaf frames, never in between them. Kept the assertion
  that contiguity actually held as a safety net, not a substitute for the
  real fix.
- **A P4-slot address collision, from picking an address without checking
  existing fixed regions.** Every `net-driver-host`-related virtual address
  originally used a `0x_3333_...` prefix — including `NET_INFO_VA`, which
  turned out to be *exactly* `scheduler.rs`'s own
  `KERNEL_ENTRY_STACK_REGION_START`. A P4 slot spans 512 GiB, so every
  other `0x_3333_...` address (differing only in bits far below that span)
  landed in the *same* slot too. Mapping `NET_INFO_VA` detached that P4
  slot in `net-driver-host`'s own `AddressSpace` (see `map_frame`'s "detach
  on first touch" doc comment in `process.rs`) — invisibly breaking that
  same process's own kernel-entry stack, mapped into that same shared slot
  moments earlier by `alloc_kernel_entry_stack`. The process double-faulted
  the instant it first trapped into ring 0, with a stack pointer that
  looked nonsensical until the P4-slot math was actually done by hand.
  Fixed by moving every `net-driver-host` address to a `0x_1111_...`
  prefix, the one leading nibble not already claimed by an existing fixed
  region (`0x2`/`0x3`/`0x4`/`0x5`/`0x6`/`0x7` are all taken — see
  `GRID_SANDBOX_*`, `KERNEL_ENTRY_STACK_REGION_START`, the kernel heap,
  `STACK_REGION_START`, and the process-isolation test region).
- **The RCX/R8-R11 register-clobber class of bug, this time on RDI/RSI/
  RDX.** `int 0x80`'s round trip has bitten this exact ABI twice before
  (RCX, then R8-R11 defensively) — this time a plain `in(reg) x` operand on
  RDI/RSI/RDX in `net-driver-host/src/syscall.rs`'s copy of the syscall
  wrapper. `in` only tells the compiler what a register holds *going in*;
  it doesn't mark the register clobbered afterward, so the compiler
  remained free to assume a cached value survived to a *later* call.
  Confirmed for real: two back-to-back `port_out` calls in
  `VirtioNet::probe`, both passing the literal `1` for `width`, had the
  second one observed with `width=0` at the kernel's own dispatch —
  `entry`'s remapping shim (`mov rcx, rdx; mov rdx, rsi; mov rsi, rdi; mov
  rdi, rax`) unconditionally overwrites RDI/RSI/RDX on every trip through
  `int 0x80`, and the compiler had no way to know not to cache a shared
  literal across that boundary. Fixed with `inout(reg) x => _` instead of
  `in(reg) x` for all three registers — applied to all three copies of this
  wrapper in the codebase (`kernel/src/syscall.rs`, `grid-sandbox-host`,
  `net-driver-host`) defensively, even where it hadn't yet been observed to
  bite, matching this codebase's existing rule for this ABI: any `int 0x80`
  call site needs the full clobber declaration, not just the registers a
  given caller happens to have hit so far.

Also worth remembering: an ELF that isn't `-C relocation-model=static`
compiles fine and boots, but ring 3-faults on an instruction fetch from
`0x0` almost immediately — `net-driver-host` initially lacked its own
`.cargo/config.toml` (unlike `grid-sandbox-host`, which already has one for
exactly this reason), so it built as a default position-independent (`ET_DYN`)
executable. `kernel/src/elf.rs`'s loader does zero relocation processing,
so a PIE binary's data-section function pointers (`format_args!`'s
`Display::fmt` vtable entries, needed even for an `assert!`/`panic!`
message that never actually fires) are never relocated, left as whatever
raw placeholder the linker wrote for a dynamic loader that doesn't exist
here — calling through one jumps to address 0. Fixed by giving
`net-driver-host` the identical `.cargo/config.toml` `grid-sandbox-host`
already has.

**Network stack, Phase 2a: `smoltcp` brought up on the proven transport,
verified with a real ICMP echo.** `net-driver-host/src/smoltcp_device.rs`
implements `smoltcp::phy::Device` as a thin adapter over `virtio.rs`'s
`Virtqueue`/`VirtioNet` — deliberately its own module, not folded into
`virtio.rs`, which stays pure hand-rolled register/virtqueue mechanics
with zero smoltcp awareness. `RunixNetDevice` owns 8 RX + 4 TX buffers
(grown from Phase 1's 4 RX + 1 TX — smoltcp needs more than one in-flight
TX buffer at once, e.g. an ARP reply interleaved with the packet it's
routing, unlike Phase 1's one hand-built frame at a time) and a small
fixed-size in-use array for TX slot bookkeeping — no new dependency
(`heapless`, `Vec`) needed for that, just a linear scan over
`[bool; TX_BUFFER_COUNT]`. `RxToken`/`TxToken` map directly onto
`Virtqueue::post`/`poll_used`, reusing `validate_rx_completion` verbatim
for RX (still treating device-controlled `(desc_id, len)` as untrusted).
Timekeeping is a simple monotonic loop-iteration counter
(`Instant::from_millis(iteration)`), not a real clock — smoltcp only needs
monotonically non-decreasing values for its RTT/backoff heuristics, not
wall-clock accuracy, so this needed no new kernel syscall.

**Supersedes, not supplements, Phase 1's hand-built ARP flow** —
`kernel/tests/net_driver_arp.rs` is retired, replaced by
`kernel/tests/net_driver_icmp.rs`. `net-driver-host/src/main.rs` no longer
sends a hand-built ARP request directly; smoltcp's own neighbor-discovery
cache performs the equivalent ARP resolution automatically as a
prerequisite to routing the ICMP echo, exercising the *same* virtqueue
mechanism Phase 1 proved by hand, plus real IPv4/ICMP checksums Phase 1
never touched — a strictly stronger proof, not a different or weaker one.

Verified end to end on the first real attempt, not just compiling:
`net-driver-host` brings up an `Interface` with a static IP (`10.0.2.15/24`,
matching SLIRP's own fixed DHCP-lease default — no DHCP negotiated),
sends one ICMP Echo Request to SLIRP's gateway (`10.0.2.2`), and checks
the reply byte-for-byte (`ident`, `seq_no`, and the exact payload
`b"RUNIX-ICMP-PROOF"`) — the same "real round-trip, exact bytes checked"
discipline `is_arp_reply` already established. `NetBootInfo`'s buffer-count
fields grew accordingly (`rx_buffer_phys: [u64; 8]`, `tx_buffer_phys`
from a single `u64` to `[u64; 4]`) across all three copies
(`net-driver-host/src/main.rs`, `kernel/src/main.rs`,
`kernel/tests/net_driver_icmp.rs`) in one atomic change — a breaking
layout change to a struct with no shared-crate enforcement of its own, so
all three had to move together or silently desync.

**Network stack, Phase 2b: a real TCP client, closing out the original
"virtio-net driver + smoltcp TCP/IP" backlog item.** SLIRP has no built-in
TCP listener at all — connecting to the gateway would prove nothing — so
this needed two new pieces of test infrastructure: `xtask/src/main.rs`'s
previously fully-hardcoded `-netdev user,id=net0` is now overridable via
one env var (`RUNIX_NETDEV_ARG`, read once in `run_qemu`; every other
caller leaves it unset and gets the unchanged default), and a real host-
side listener (`kernel/tests/support/tcp_proof_listener.py`, plain
dependency-free Python — `ubuntu-latest` already has it, no new CI install
step) that QEMU's `guestfwd` bridges a guest-initiated connection to via
`nc`. `net-driver-host` connects to `10.0.2.100:9000` (a `guestfwd`-only
synthetic address — QEMU rejects reusing the gateway's own `10.0.2.2` for
this outright: "Conflicting/invalid host:port in guest forwarding rule"),
sends a fixed payload, and checks the exact reply — independently verified
on *both* ends (the guest checks the exact reply bytes; the Python
listener separately asserts it received the exact request bytes), not
just one side's self-report. `NetBootInfo` grew one more field,
`attempt_tcp: u8` — `0` on every path without a `guestfwd` route or
listener (the real boot sequence, `net_driver_icmp.rs`), so a TCP connect
to an address nothing answers doesn't sit in SYN-SENT for a full poll
bound on every ICMP-only run.

Two more real bugs found getting this working — both only surfaced once
an actual second protocol ran after the first, something Phase 2a alone
never exercised:

- **Non-monotonic time silently stalled the whole TCP state machine.**
  Both proof phases run in the same `_start`, each with its own bounded
  `for` loop computing `Instant::from_millis(iteration)` from `iteration =
  0`. `smoltcp::Interface` remembers the last `Instant` it was polled with
  internally (retransmit/backoff timers are computed relative to it) — so
  starting the TCP phase's loop at `0` handed it a timestamp *earlier*
  than what it had already seen during the ICMP phase moments before.
  Confirmed via packet capture, not guessed: with the reset-to-zero
  counter, the guest never sent so much as an ARP request for the TCP
  remote, let alone a SYN — smoltcp's internal state simply never
  progressed. Fixed by threading one shared, always-increasing iteration
  counter across both phases (the ICMP loop's final iteration + 1 seeds
  the TCP loop's own counter).
- **A real resource leak: an unconsumed `TxToken` silently leaked its TX
  slot forever.** `Device::receive()` must return a paired `(RxToken,
  TxToken)` per smoltcp's own contract (in case the inbound packet needs
  an immediate reply, e.g. an ARP request) — but *most* inbound packets
  (a plain ARP *reply*, an ICMP reply with nothing further to send) need
  no reply at all, and smoltcp simply drops the unused `TxToken` without
  ever calling `consume()` on it. The first version of `RunixNetDevice`
  marked a TX slot "in use" the moment `receive()`/`transmit()` handed out
  a token — meaning every inbound packet that *didn't* need a reply leaked
  one of only `TX_BUFFER_COUNT` (4) slots, permanently, since nothing ever
  posted or reaped it. Packet capture showed the exact resulting symptom:
  the guest re-sent an ARP request for the TCP remote three times, each
  one correctly answered by SLIRP, but the connection never progressed to
  an actual SYN — after ~4 total inbound packets across both phases
  (2 during ICMP, 2 during the TCP phase's own ARP resolution), every TX
  slot was already leaked, so `receive()` could never again find a free
  slot to pair with, silently blocking all further RX indefinitely. Fixed
  by moving the "mark this slot in use" step out of `receive()`/
  `transmit()` entirely and into `TxToken::consume()` itself, right where
  the slot is actually posted to the device — a token that's dropped
  unused now correctly leaves its slot untouched instead of leaking it.

Verification for this phase relied on this session's WSL (Fedora) rather
than only the Windows dev box, since the actual mechanism under test
(QEMU spawning a host process via `guestfwd`'s `-cmd:`) is Linux-shell-
specific and can't be rehearsed identically on Windows — packet capture
(`-object filter-dump`) inside WSL is what actually diagnosed both bugs
above, rather than guessing from symptoms alone.

Also still deferred at the time: DHCP, multiple concurrent sockets, and a
sockets API/IPC surface for other ring 3 processes to use this stack — all
three since closed (see below) — plus UDP, TX/RX interrupts, MSI-X/IOAPIC,
real wall-clock timestamps, TCP performance tuning, and fuzzing the
ICMP/ARP-resolution/TCP parsing path (required per the testing-rigor
commitment below, scoped as a fast-follow now that these parsers actually
exist — the property-testing work already done for
`is_arp_reply`/`validate_rx_completion` is the template to extend).

**Sockets IPC surface, then DHCP + concurrent sockets on top of it.** A
typed request/response wire format (`ipc/src/sockets.rs`'s
`SocketRequest`/`SocketResponse`, same one-byte-per-IPC-syscall encoding
`blk-driver-host`'s filesystem IPC surface established) lets other ring 3
processes drive `net-driver-host`'s TCP stack over capability-gated IPC
(`net-driver-host/src/main.rs`'s `run_socket_ipc_server`,
`kernel/tests/net_driver_sockets.rs`) instead of only the driver's own
hardcoded proof. That surface then grew two of this section's own
originally-deferred gaps: `SocketRequest::Open` allocates one of a small,
fixed number of handles (`MAX_SOCKETS`) up front, so `Connect`/`Send`/
`Recv`/`Close` all name which handle they apply to and two independently
opened connections run concurrently without clobbering each other's state
(`kernel/tests/net_driver_sockets_concurrent.rs`, proven with two
overlapping connections through a single `guestfwd` route rather than
two — see that test's own doc comment for why); and `net-driver-host`
acquires its own address via a real `smoltcp::socket::dhcpv4` handshake
against QEMU/SLIRP's built-in DHCP server (always present on `-netdev
user`, whether or not anything asks it for a lease) on the real boot path
(`NetBootInfo::use_dhcp`, `kernel/tests/net_driver_dhcp.rs`) rather than
the fixed `LOCAL_IP` `net_driver_icmp.rs`/`net_driver_tcp.rs`/
`net_driver_sockets.rs` still deliberately use, so as not to disturb those
tests' own static-address assumptions. One more real, if narrow, bug
found getting DHCP's added dependency weight to build for
`x86_64-unknown-none`: a `curve25519-dalek` LLVM codegen crash, the same
class of SIMD-backend bug `kernel/.cargo/config.toml` already works
around for `kernel/` itself — just missing from `net-driver-host/
.cargo/config.toml`, which hadn't needed it until this dependency arrived.

**The testing-rigor commitment, no longer just a commitment for later.**
Everything verified in this kernel up to Phase 1 above was a hand-written
scenario booted in QEMU and checked against one expected outcome — enough
while nothing here parsed a single byte from outside the machine. That
stopped being true the moment `net-driver-host`'s `is_arp_reply` and
`validate_rx_completion` (both `net-driver-host/src/lib.rs`) started
inspecting bytes the emulated virtio-net *device* controls. Rather than
defer property-testing until the real thing (arbitrary attacker bytes over
an actual network) exists, both functions were split out of `main.rs`
specifically so they could be property-tested on the host today —
`#![cfg_attr(not(test), no_std)]`, the same split `capability-manager`
already uses, so `cargo test --lib` runs real `proptest`-generated cases
(256 per property by default) without needing the bare-metal target at
all. Two properties actually mattered enough to write down, not just
"doesn't crash": `is_arp_reply` must never panic regardless of buffer
length or content, and `validate_rx_completion` must never hand back a
buffer index at or past `buffer_count` or a length past the real
4096-byte buffer size — the second property caught a real bug (see
below), not a hypothetical one.

**A real out-of-bounds-read bug, caught by writing the property test, not
by code review.** The original RX poll loop in `main.rs` took `(desc_id,
len)` straight from the device's used-ring entry and used them directly:
`len` as a slice length, `desc_id` as a buffer index, with zero validation
of either. Both fields come from the same "device" this driver's threat
model already treats as untrusted (see docs/THREAT_MODEL.md) — a
misbehaving or malicious device could report a `len` past the actual
4096-byte buffer (an out-of-bounds slice, read directly into
`is_arp_reply`) or a `desc_id` outside the four buffers this driver
actually posted (an out-of-bounds array index into `rx_buffer_phys`, or a
computed address far outside the intended RX buffer region entirely).
Fixed by `validate_rx_completion`, called before either field is used for
anything: a completion that fails validation is dropped outright (logged,
not repaired or guessed at), not silently trusted.

`capability-manager`'s `hex::decode` over the signature field — flagged
unfuzzed here for a while — now has its own property-test coverage too
(`capability-manager/src/lib.rs`'s `tests::properties` module): arbitrary
signature strings, arbitrary resource strings, and a well-formed-but-wrong
signature (valid hex, right length, not the real one) must all either be
correctly rejected or, at minimum, never panic `verify()` — a reachable
panic in signature-checking code would be a denial-of-service on the
capability gate itself, in a `panic = "abort"` kernel (see CLAUDE.md's
"unsafe Rust" rule) where that means killing the process outright.

Both property-test suites run in CI without new infrastructure: `host`
job's existing `cargo test --workspace` already picks up
`capability-manager`'s (a normal workspace member), and a new `cargo test
--lib` step covers `net-driver-host` (`--lib` only, not a bare `cargo
test` — that crate's `#![no_std] #![no_main]` bin target has its own
`panic_handler`, which collides with `std`'s the moment cargo tries to
build a host test harness for it too). At the time this paragraph was
written, no `cargo-fuzz`/libFuzzer harness existed yet — property-testing
via `proptest` was the concrete instantiation of this commitment, not a
placeholder for one. That gap is now closed; see the "Real
`cargo-fuzz`/libFuzzer harnesses" section further down this document for
what exists today.

**Phase 2's smoltcp boundary — fuzzing the driver-stack interface, not the
stack internals.** Phase 2a (smoltcp `Device`/`Interface` bring-up + ICMP
echo) and Phase 2b (real TCP client via QEMU guestfwd) are now complete
and CI-verified. The Ethernet/IP/TCP header parsing itself is handled by
smoltcp (an independently-maintained third-party crate) — not by Runix
code — which means forking and fuzzing smoltcp's internals is out of scope.
What is newly covered: `net-driver-host/src/lib.rs` now has a `smoltcp_fuzz`
property-test module (using `proptest`, the same harness as Phase 1) that
feeds arbitrary/malformed byte sequences (0..1500 bytes, 1..8 frames per
case) directly into a mock `smoltcp::phy::Device` wired into a real
`smoltcp::iface::Interface`, configured identically to the actual bring-up
in `main.rs` (static IP 10.0.2.15/24, default route 10.0.2.2, one ICMP
socket, one TCP socket). The property is: `iface.poll()` never panics
across many random "arbitrary bytes just arrived on the wire" inputs, and
each property case runs across multiple poll iterations per input so
partial TCP connection state (handshake in flight, data buffered in-flight,
etc.) gets exercised, not just a cold single poll of empty state.
Verified in WSL Fedora (this machine's Windows MSVC linker is currently
unavailable — Visual Studio's build tools aren't installed, unrelated to
this change): `cargo test --lib` passes 10/10, including
`smoltcp_fuzz::smoltcp_never_panics_on_arbitrary_frames` at proptest's
default 256 cases — no panic found on first run. Unlike
`validate_rx_completion`'s property test in Phase 1, this one didn't turn
up a live bug; that's a legitimate, expected outcome for a property test
(it exists for regression protection going forward, not a guaranteed find
every time it's written) and not a sign the test is too weak to be worth
keeping. This tests the boundary Runix owns — the raw-bytes-to-smoltcp interface — which
is narrower than "TCP parsing robustness" (that's smoltcp's own concern)
but still load-bearing: a panic in this interface would crash the ring 3
driver process, not corrupt it gracefully.

**Network stack, entropy Phase 1: `SYS_RANDOM`, RDRAND-only — the real
blocker `docs/RFC-TLS-APPROACH.md` named before any TLS code could be
written.** That RFC's original design called for `SYS_RANDOM` backed by a
kernel-resident virtio-rng driver mixed with RDRAND. What shipped instead,
and why: every other virtio device in this codebase
(`net-driver-host`, `blk-driver-host`) is deliberately ring-3 and
capability-isolated over port I/O; a kernel-resident virtio-rng driver
would have been the first virtio surface actually living in the kernel,
growing the TCB for a marginal entropy-quality gain over RDRAND alone
(present in QEMU/KVM and real hardware). See the RFC's own "Phase 1
decision" note for the full argument.

What's real: `kernel/src/entropy.rs` reads RDRAND directly
(`core::arch::x86_64::_rdrand64_step`, wrapped in a `#[target_feature]`
function called only after a cached CPUID leaf-1 ECX-bit-30 check confirms
the running CPU actually has it), retrying up to 10 times per Intel's own
guidance before giving up. `SYS_RANDOM` (`kernel/src/syscall.rs`) is gated
on a new `"random"` capability (`capabilities::random_resource`) — the
same check-then-act, fail-closed shape `SYS_PORT_IN`/`SYS_PORT_OUT` already
use, denial and "RDRAND absent/exhausted" deliberately collapsing to the
same `u64::MAX` sentinel rather than a distinguishable error, and never
falling back to a weaker source (a `SYS_TICKS`-derived counter, say) when
real entropy isn't available. `net-driver-host` is granted the `random`
capability as a second, *extra* token alongside its existing ioport-range
one (`spawn_ring3_process_with_capabilities`, `kernel/src/main.rs`) and
uses it to seed smoltcp's `Config.random_seed` — closing the
deterministic-TCP-ISN/ephemeral-port gap the RFC flagged as a side effect
of the same entropy hole, independent of TLS itself.

Verified in QEMU: `kernel/tests/sys_random.rs` spawns one thread holding a
`random` token and one with no capability at all, asserting the
unauthorized thread is always denied and branching on
`entropy::available()` for the authorized thread's expected outcome — two
genuinely-differing RDRAND values when present, or the same fail-closed
`u64::MAX` when absent. xtask's QEMU invocation carries no explicit `-cpu`
flag, so it runs under the default `qemu64` CPU model, which does **not**
advertise RDRAND — meaning CI actually exercises the fail-closed branch,
not the happy path. That's a real, documented gap rather than a silently
green test proving nothing: this hasn't yet been verified against a CPU
model that actually has RDRAND (e.g. `-cpu host` with hardware
virtualization, or `-cpu qemu64,+rdrand` under TCG) in this environment.
Also verified: `cargo build --workspace`, `cargo clippy --workspace
--all-targets -- -D warnings`, and a full `xtask run` boot showing no
regression in the existing boot sequence through net-driver-host's
DHCP/ICMP round trip.

What this does **not** close: it's a single hardware entropy source with
no virtio-rng mix-in (see `docs/THREAT_MODEL.md`'s matching "Known gaps"
entry for the trust-boundary tradeoff this leaves open), and
`capability-manager`'s demo Ed25519 keypair (`kernel/src/capabilities.rs`'s
hardcoded `DEMO_SEED`) still does not draw on `SYS_RANDOM` — real key
provisioning off that fixture is a separate, higher-stakes change. The TLS
crate/option decision itself (`docs/RFC-TLS-APPROACH.md`'s "Options"
section), trust anchors, and certificate validity checking remain entirely
unimplemented — this phase only unblocked the prerequisite the RFC named,
not TLS itself.

**Network stack, entropy Phase 2: the TLS crate choice — verified for
real, not researched.** `docs/RFC-TLS-APPROACH.md`'s recommendation
(Option A, `embedded-tls`) rested on two `[UNVERIFIED]` claims its
drafting session couldn't check (no network access at the time): whether
`embedded-tls`'s cert verification is production-usable, and whether any
`rustls` `CryptoProvider` builds for `x86_64-unknown-none`. Both settled
by actually building the dependency for the real target, not just reading
about it: `rustls` is confirmed unreachable (every `CryptoProvider` is
disqualified — `ring` concretely, via its `getrandom` dependency hard-
failing to build for this target at all, not an LLVM issue with a known
workaround). `embedded-tls` is confirmed viable via its `rustpki` feature
path (`embedded_tls::pki::CertVerifier` — real X.509 chain verification
against RustCrypto's own signature crates), **not** its `webpki` feature
(which routes through `ring` the same way `rustls` would and is equally
disqualified) — built clean for `x86_64-unknown-none` with
`ed25519`/`p384`/`rsa` all enabled (the three signature families
real-world CA roots actually use), after three LLVM-codegen-ICE
workarounds (`sha2`, `aes`, `curve25519-dalek` — each already a known
class of issue on this target, just newly hit in three more crates).

New `tls-client/` crate (`runix-tls-client`), a root-workspace member,
`no_std` + `alloc`, builds clean on both the host target and
`x86_64-unknown-none`. What exists today: the `embedded-tls` dependency
itself (verified, wired, with its exact feature set and LLVM-ICE
workarounds documented in `tls-client/Cargo.toml`/`.cargo/config.toml`),
and two traits (`Transport`, a caller-supplied byte pipe; `Entropy`, a
caller-supplied `SYS_RANDOM`-backed randomness source, taken as a
parameter rather than read directly — ambient RDRAND access from ring 3
is exactly what `docs/RFC-TLS-APPROACH.md`'s Recommendation section 4
already named as the wrong shortcut). What doesn't exist yet, on purpose:
the actual handshake/connection API, a `TlsClock` implementation (this
system has no wall-clock time), trust-anchor provisioning, and any real
consumer process. Verified: `cargo build --workspace` /
`clippy --workspace --all-targets -- -D warnings`, and the crate's own
`--target x86_64-unknown-none` build/clippy, all clean.

**Network stack, entropy Phase 3: a real TLS 1.3 handshake — proven
against a live server, not just against `embedded-tls`'s types.**
`tls-client::TlsConnection` now wraps `embedded_tls::blocking`'s
connection type over this crate's own `Transport`/`Yield` traits (bridged
via `src/io.rs`, since `embedded_io::Read`'s blocking contract — wait for
≥1 byte, `Ok(0)` means EOF — is a genuinely different shape than this
codebase's universal non-blocking `Ok(0)`-means-"try again" IPC
convention) and `Entropy` to `rand_core::CryptoRngCore` (`src/rng.rs`,
panicking on exhaustion rather than silently degrading — a deliberate
fail-closed choice named in that module's own doc comment, not an
oversight). Certificate verification goes through `rustpki`'s real
`CertVerifier`, never the crate's default `NoVerify`.

Verified against `example.com:443` over a real `TcpStream`
(`tests/live_handshake.rs`, `#[ignore]`d — hits the live internet and a
rotation-prone CA chain, run deliberately with `cargo test -- --ignored`,
never on ordinary CI runs): a genuine TLS 1.3 handshake completed, the
real, live 4-certificate chain (`example.com` -> `Cloudflare TLS Issuing
ECC CA 3` -> `SSL.com TLS Transit ECC CA R2` -> `SSL.com TLS ECC Root CA
2022`) was verified against "AAA Certificate Services" (confirmed via
`openssl verify -partial_chain` to be the cert that actually signs the
fourth entry — getting this wrong on the first attempt, by trusting the
fourth cert's own subject instead of its real issuer, produced a real,
instructive `DecodeError` worth knowing about, not a bug in `embedded-tls`
or this crate), and a real HTTP response was decrypted and read back.

What's still genuinely unbuilt, unaffected by this phase: a `TlsClock`
with a real wall-clock source (`embedded_tls::blocking::NoClock` is used
today — certificate expiry checking is explicitly skipped, not silently,
since no wall-clock source exists anywhere in this system yet), real
trust-anchor *provisioning* (a caller must already have CA DER bytes from
somewhere; `CertVerifier` only ever checks one CA per connection, not a
root store), a kernel-side heap-grant mechanism, and — the actual blocker
now — any real consumer process, since nothing in Runix needs TLS yet.
`docs/RFC-TLS-APPROACH.md`'s "Open questions" section also gained two
resolved answers this session: RDRAND under QEMU/TCG returns genuine
host-OS-sourced entropy by default (confirmed from QEMU's own source, not
assumed), and — measured for real in the very next phase below, not left
as an estimate — a realistic TLS 1.3 handshake's syscall cost under this
codebase's one-byte-per-syscall IPC model.
Verified: `cargo build --workspace` / `clippy --workspace --all-targets --
-D warnings`, and the crate's own `--target x86_64-unknown-none`
build/clippy, all clean.

**Network stack, entropy Phase 4: the first-TLS-consumer question
answered (defer), and the handshake-cost estimate replaced with a real
measurement — which changes the plan.** Two pieces:

Surveyed every current network-facing code path in Runix for a plausible
first `tls-client` consumer. Finding: nothing existing needs one.
`kernel/src/marshal_client.rs` already reaches a trusted, co-located
helper (`citadel_proxy`) that terminates TLS host-side — adequate, and
wrong to touch anyway (kernel-internal, T1-path, would grow the TCB).
`net-driver-host`'s DNS resolver reaches an arbitrary remote in plaintext,
but the real fix is extracting a resolver process, not calling DNS "the
consumer." Mobile's eSIM/RSP provisioning is the one candidate that
genuinely cannot use a trusted-local-helper, but no aarch64 net stack
exists yet to attach it to. Recommendation for if/when a real consumer is
wanted: a small new ring-3 host process, structurally like
`grid-sandbox-host` — proves "library not driver" in ring 3 for real and
needs no new kernel surface beyond the heap-grant question already open.
Deferring is the honest answer for now; every remaining desktop Beta item
needs no arbitrary remote endpoint.

**The handshake-cost question, measured for real** —
`kernel/tests/syscall_cost.rs`, RDTSC-calibrated timing (an `int 0x80`
loop turned out not to reliably advance `interrupts::ticks()` when run on
the bare boot thread — a real, reproducible QEMU/TCG artifact, not a bug
in the measurement's logic; fixed by running the benchmark on a properly
spawned thread, matching every other kernel test's pattern, and documented
in that test's own doc comment as a finding in its own right). Result: the
fixed-port `SYS_IPC_SEND`/`SYS_IPC_RECV` path (Ed25519 verification on
every call) costs **~12,000-30,000μs per syscall** — 300-3,000x worse than
this RFC's own prior "pessimistic" 100μs guess. A realistic handshake
(3,000-6,000 syscalls) costs **35-180 *seconds*** over this path, not
milliseconds. The same benchmark measured the session primitive
(`kernel/src/ipc.rs`'s `SESSIONS` table, built earlier this session) for
direct comparison: **~51μs/syscall, ~228x cheaper** — a 1,500-byte
handshake at that rate costs ~153ms (within the 300ms T1 budget), a
3,000-byte one ~306ms (right at the edge).

**This is the most consequential finding of the TLS work so far**: it
turns "migrate the transport onto the session primitive" from good
architecture into a hard prerequisite — the fixed-port model isn't
somewhat slow for this purpose, it's roughly two orders of magnitude too
slow, regardless of any other optimization applied on top of it. Verified:
`cargo build --target x86_64-unknown-none` / `clippy --target
x86_64-unknown-none --bins --lib -- -D warnings` for the kernel, full
`cargo build --workspace` / `clippy --workspace --all-targets -- -D
warnings` clean.

**Filesystem driver, Phase 1: the legacy virtio-blk transport, proven with
a real sector round trip — no filesystem format yet.** Beta backlog item
4, previously unstarted. Sequenced the same way the network stack was:
prove the *transport* with a real hardware round trip, ring 3-first,
before any filesystem format (FAT32 or otherwise) parses a single byte on
top of it — keeps a transport bug and a parser bug from ever being
confused with each other, the same reasoning that kept `net-driver-host`'s
Phase 1/2a/2b bugs each isolated to one layer.

`blk-driver-host` (a new freestanding crate, own `[workspace]`, same
pattern as `net-driver-host`/`grid-sandbox-host`) reuses
`net-driver-host/src/virtio.rs`'s virtqueue mechanics verbatim in spirit —
same legacy virtio-pci descriptor/avail/used ring layout, same
`QUEUE_ALIGN`/one-page-per-part fixed layout — but as its own copy, not a
shared dependency (this codebase's established convention: each ring-3
binary is independently compiled and linked). The one genuinely new piece:
**descriptor chaining**. Virtio-net's RX/TX buffers are always exactly one
descriptor each; virtio-blk's request format needs three linked
descriptors (a 16-byte header, a 512-byte data buffer, a device-written
status byte) submitted as a single chain via `next`/`VIRTQ_DESC_F_NEXT` —
`Virtqueue::post_chain` writes each descriptor with `next` pointing at the
following one and publishes only the head to the avail ring, same
fence-then-publish discipline `post` already used for one descriptor.

`kernel/src/pci.rs` gained `find_virtio_blk` (device ID `0x1001`, mirroring
`find_virtio_net`'s `0x1000`). Wired into the real boot path as **Phase
B9**, right after Phase B8 (net-driver-host): CITADEL-authorizes
`blk-driver-host` at `T1Critical` (a system driver, same tier
net-driver-host got), issues an `ioport_range_resource`-scoped capability
token at the same `0x20`-byte granularity net's token uses, and spawns it
as a capability-gated ring 3 process with no raw port I/O privilege of its
own — identical isolation shape to every prior driver here.

**A new fixed VA family, chosen carefully, not just incrementally.**
`blk-driver-host`'s private regions (heap, queue, request buffer, the
`BlkBootInfo` boot-info page — same "no shared type, just an agreed ABI"
convention `NetBootInfo`/`GridBootInfo` established) needed their own P4
slot, distinct from every existing one. Grepping every `0x_XXXX_XXXX_0000`
constant across `kernel/src` and `kernel/tests` showed nibbles 1
(net-driver-host), 2 (grid-sandbox-host), 3 (the kernel's own
`KERNEL_ENTRY_STACK_REGION_START` — the exact collision that caused a real,
previously-documented double fault), 4/5/6 (kernel heap/stack/etc.), and 7
(test-only regions) were *all* already taken. Rather than gamble on P4
slot 0 being empty in a process's private table (`AddressSpace::new()`
clones every top-level entry from whatever table was active at creation
time — slot 0 could plausibly carry something worth keeping reachable),
`0x_0999_...` was picked instead: comfortably clear of every existing
family's slot (P4 index is determined by a 16-bit group's top 9 bits, so
anything differing by 128 or more from `0x1111`/`0x2222`/etc. lands in a
genuinely different slot) without needing to reason about slot 0's
contents at all. Verified the way the two prior real P4-slot bugs in this
codebase were both actually caught — by booting it for real, not by the
arithmetic alone: `kernel/tests/blk_driver_rw.rs` passed on the first real
attempt, no double fault at ring 3 entry.

**The proof itself: write sector 0, read it back, check the exact bytes —
and it worked, no bugs found this time.** `blk-driver-host` writes a fixed
33-byte pattern (padded to a full 512-byte sector) to sector 0
(`VIRTIO_BLK_T_OUT`), polls to completion and checks the status byte,
*zeros its own data buffer* (so a passing read can't be a false positive
from leftover memory), then reads sector 0 back (`VIRTIO_BLK_T_IN`) and
checks both the status byte and exact byte equality against the original
pattern. Confirmed in QEMU: `capacity=2048 sectors`, `write completed=1
status=0`, `read completed=1 status=0 bytes_match=1` — a real write, a
real read, from a real (if QEMU-emulated) block device, through a
capability-gated ring 3 process. Unlike every prior phase in this
session's network-stack work, this one didn't turn up a real bug on the
first attempt — a legitimate outcome, not a sign the verification was
shallow (the VA-family collision risk above was the one place a real bug
plausibly could have hidden, and boot-testing ruled it out directly).

What this doesn't claim: no filesystem format is parsed anywhere yet (no
FAT32, no directory structure, nothing beyond raw sector I/O) — that's
Phase 2, explicitly out of scope here. This slice's disk content is
self-written by this same driver in the same boot, not yet
attacker-controlled the way network bytes are; `docs/THREAT_MODEL.md`
flags this as a named revisit trigger (once Phase 2 actually parses a
filesystem format, disk bytes become untrusted input needing the same
fuzzing/property-testing rigor already applied to `net-driver-host`'s
parsers), not a closed question. Only sector 0 is ever touched, and only
sequentially (one request in flight at a time — `post_chain` always
reuses descriptor indices `0..3`, safe only because the previous chain's
completion is always consumed before the next is posted).

**Filesystem driver, Phase 2: read-only FAT32, locate one file, read its
exact contents — the testing-rigor commitment applied from day one, not
retrofitted.** Closes the revisit trigger Phase 1's own writeup named:
disk bytes now genuinely are parsed as untrusted input, and the parser
(`blk-driver-host/src/lib.rs`, new) landed with `proptest` coverage in the
same commit, the same discipline `net-driver-host`'s parsers established
for network bytes. Scope, matching the size of every prior phase: 8.3
short names only (an LFN entry is recognized and skipped, never
misread — no long-name reconstruction), no subdirectories (only the root
directory is ever walked), read-only (no writes anywhere), no syscall/IPC
surface exposing this to other processes yet.

`BootSectorInfo::parse`, `parse_short_dir_entry`, and `fat_entry_at` are
pure functions — no device I/O, so `cargo test --lib` runs real
`proptest`-generated cases on the host, same split `net-driver-host`'s own
lib/bin division already established. Every arithmetic step that touches
an on-disk field uses checked operations, never a bare `+`/`*`: a hostile
or corrupt `fat_size_32` making `reserved_sector_count + num_fats *
fat_size_32` wrap is exactly the class of bug `validate_rx_completion`
was written to catch for virtio-net's device-reported fields, now applied
here — `fat_entry_at` in particular is bounds-checked against whatever FAT
sector bytes it's actually given, returning `None` rather than indexing
past the buffer for an out-of-range cluster number (a cluster number that
reached it came from a directory entry or a previous FAT entry, both
on-disk, both exactly as untrusted as a network header field). 18
property + unit tests, all passing: never-panics properties for all three
parsing functions against arbitrary bytes, plus hand-built fixtures for
the signature check, zero-`sectors_per_cluster`/zero-`num_fats` rejection,
the FAT-region-overflow rejection, and the LFN/deleted/end-of-directory
skip logic.

**A real bug, found by testing the actual interaction, not either half in
isolation.** The first end-to-end attempt against a real FAT32 image
failed with "boot sector did not parse as FAT32" — even though the
fixture image was genuinely valid (confirmed independently with `mtools`'
own `mdir`/`mtype` before trusting the kernel test's result). Cause:
Phase 1's own sector round-trip proof unconditionally writes a test
pattern to sector 0 before Phase 2 ever runs — harmless on the zero-filled
scratch image `blk_driver_rw.rs` uses, but sector 0 *is* the FAT32 boot
sector on a real volume, so Phase 1 was silently destroying the exact
sector Phase 2 was about to parse, in the same boot. Fixed by making the
two proofs mutually exclusive per boot (`attempt_fat32` selects one or the
other, never both) — `blk_driver_rw.rs` already proves Phase 1
independently on its own scratch image, so there was nothing to gain from
re-running it against an image it would only corrupt. The kind of bug this
session's "verify the real interaction, not just each piece" discipline
exists to catch: neither the parser's own property tests nor Phase 1's own
already-passing test would ever have surfaced this on their own.

**The fixture is a real FAT32 image, not a hand-rolled byte array.**
`kernel/tests/support/make_fat32_image.sh` builds one with actual tooling
(`mkfs.fat -F 32`, `mtools`' `mcopy` — writes into a FAT image directly,
no mount/loop-device/root privilege needed, matching every other
CI-runnable fixture in this codebase), containing one root-directory file,
`HELLO.TXT`, with a fixed known content string shared verbatim between
the fixture script and `blk-driver-host`'s own expected-bytes constant (one
definition, not independently duplicated on each side, to avoid a silent
drift the tests would never catch). `xtask` gained a `RUNIX_BLK_IMG`
override for its virtio-blk `-drive`, same override-point shape
`RUNIX_NETDEV_ARG` already established for `-netdev`. Confirmed end to
end in QEMU: `capacity=131072 sectors`, `FAT32 file_size=68 bytes_read=68
contents_match=1` — the real boot sector parsed, the real root directory
walked, the real file located and its exact 68 bytes read back over the
same virtio-blk transport Phase 1 proved.

What this doesn't claim (at the time Phase 2 landed): no writes anywhere;
no long filenames; no subdirectory traversal; no syscall or IPC surface
yet exposing any of this to another process. Phase 3, below, closes three
of those.

**Filesystem driver, Phase 3: a real IPC surface, capability-scoped both
ways, plus the two coverage gaps Phase 2 left open.** Before this, nothing
outside `blk-driver-host` itself could ask it for a file — Phase 2 was a
self-contained proof, not a service. Closed here: the syscall/IPC surface,
capability-manager scoping (falls out of the same design, not bolted on),
subdirectory traversal, and multi-cluster/larger-file coverage. Deferred,
named rather than silently dropped: long filenames (real VFAT LFN
reconstruction is a meaningfully-sized parser addition on its own) and
write support (a different risk class entirely — a bug there can corrupt
a real filesystem, not just fail a read; needs its own dedicated design
pass).

Reading `kernel/src/syscall.rs`/`kernel/src/ipc.rs`/`kernel/src/scheduler.rs`
directly (not assuming) surfaced the actual starting point: no multi-byte
or process-to-process IPC mechanism exists in this kernel at all —
`SYS_IPC_SEND`/`SYS_IPC_RECV` move one byte at a time through one of 16
fixed 32-byte queues, and the `runix-ipc` workspace crate (`Envelope`) is
genuinely dead code, zero consumers anywhere. The filesystem service is
built entirely on that existing generic mechanism — no new syscalls. Two
fixed ports (`8` request, `9` response, distinct from Phase B4/B5's
transient boot-time demo ports `0`-`2`): a requester sends one trigger
byte to port 8, authorized by a capability scoped to `port_resource(8)`
(the *existing* `port:<n>` convention, unchanged); `blk-driver-host`
replies on port 9 with a 2-byte little-endian length header followed by
that many content bytes.

**One real architectural constraint this surfaced**: `scheduler::Thread`
held exactly one `Option<CapabilityToken>`. Serving requests means
`blk-driver-host` needs a *second* capability — its existing virtio-blk
io-port token, plus a new one authorizing it to send on the reply port.
Rather than turn every existing single-capability call site into a `Vec`
everywhere, `Thread` gained an additive `extra_capabilities: Vec<CapabilityToken>`
field (empty by default) alongside the untouched `capability` field, and
a new `spawn_ring3_process_with_capabilities` alongside the existing
single-capability function — every other call site in `net-driver-host`/
`grid-sandbox-host`/every existing kernel test keeps compiling and
behaving identically, confirmed by re-running the *entire* existing test
suite, not just the new tests, since this touches shared scheduler/syscall
code every capability-gated test depends on.

Verified in `kernel/tests/blk_fs_ipc.rs` with both directions of the gate,
not just the happy path: a thread holding no capability at all is denied
(`u64::MAX`) when it tries to send the request trigger — mirroring
`kernel/src/main.rs`'s own Phase B4 `thread_sender_unauthorized` demo —
and confirmed nothing leaks to the response port from a denied send
either. A second thread, holding a capability scoped to exactly port 8,
gets the exact 68 bytes of `HELLO.TXT` back over real, capability-gated
IPC between two independently-scheduled contexts. Worked on the first
real boot attempt.

**Subdirectories and multi-cluster files, closed together as an extension
of Phase 2's own proof** (not a new phase — they're the same "locate and
read a file" capability, just exercised more thoroughly): `find_entry_in_directory`
already took any starting cluster, so a `SUBDIR/NESTED.TXT` fixture entry
proves it actually works one level deep, not just at the root. Separately,
`HELLO.TXT`'s 68 bytes fit inside the fixture's single 512-byte cluster
(confirmed by actually inspecting the formatted image's own BPB, not
assumed) — meaning `next_cluster_in_chain`/`is_end_of_chain` had never
been exercised past one cluster. A new `BIG.TXT`, exactly 3000 bytes of a
deterministic pattern generated identically by the fixture script and the
driver's own expectation (one formula, not two copies to drift apart),
spans several clusters and is read back and checked byte-for-byte.
Confirmed: `nested_bytes_read=59 contents_match=1`,
`big_file_bytes_read=3000 contents_match=1` — no bugs found in either,
unlike several earlier phases this session, a legitimate outcome given how
directly this code was already exercised getting Phase 2 working.

**Filesystem driver, Phase 4: long filenames, verified against real
on-disk bytes, not just the spec text.** The last two gaps left after
Phase 3, each with its own dedicated slice as promised. Before writing any
parser code, the actual VFAT LFN layout was confirmed by dumping and
hand-decoding the raw 32-byte directory entries a real `mkfs.fat`/`mcopy`
run produced for `long-filename-test.txt` — not assumed from the spec
alone. That surfaced the exact, easy-to-get-backwards ordering: LFN
entries are stored in *descending* sequence order (the entry covering the
*end* of the name comes first in the directory), so reconstructing the
name means concatenating fragments in the *reverse* of scan order.
`blk-driver-host/src/lib.rs` gained `LfnFragment::parse` and
`short_name_checksum` (the standard algorithm every real FAT32
implementation uses to bind an LFN run to its short entry) — both pure,
property-tested (6 new tests, 24 total), and `short_name_checksum`'s own
unit test asserts against `0xd0`, the checksum actually read back from
that same real fixture's `LONG-F~1.TXT` entry, not an assumed-correct
value. `find_entry_by_long_name` (`main.rs`) walks a directory the same
way `find_entry_in_directory` does, but accumulates LFN fragments and
only trusts a complete run whose checksum matches the short entry that
follows — an incomplete or orphaned run is never silently accepted.
ASCII-only matching is this slice's explicit, named limit (real LFN names
can hold any UTF-16; this driver only ever needs to find names it already
knows the ASCII spelling of). Confirmed: `long_name_bytes_read=62
contents_match=1`, worked on the first real attempt — a direct result of
verifying the byte layout against reality before writing the reconstruction
logic, not after.

**Filesystem driver, Phase 5: a first real write — small on purpose.**
The last of the six original gaps, and the one flagged from the start as
"a different risk class" needing its own dedicated pass. This slice is
that pass's *first* increment, not its completion: it overwrites
`WRITE.TXT`'s content, but only because that fixture file is exactly one
512-byte sector on one cluster — meaning zero free-cluster allocation,
zero FAT chain modification, zero directory-entry size-field update, and
zero partial-sector read-modify-write were needed. Each of those remains
explicitly deferred (see `docs/THREAT_MODEL.md`), not silently assumed
solved by this slice. Mechanically, nothing new was needed at the
transport level — `BlkDevice::write_sector` has existed and been proven
since Phase 1; what's new is locating *which* sector to write via the
FAT32 parser instead of a hardcoded sector 0. Verified two independent
ways: `blk-driver-host` itself writes a fixed pattern
(`write_pattern_byte`, `b'Z' - (i % 26)`) and reads it back via a *fresh*
`read_sector` call (a genuine round trip through the device emulation, not
a cached buffer), and CI separately runs `mtype` against the actual
backing image file afterward to confirm the new content really landed on
disk — not just trusting the driver under test to grade its own work, the
same instinct that made this fixture real `mkfs.fat` output rather than a
hand-rolled byte array from the start. Confirmed:
`write completed=1 status=0 read_back_matches=1`, `mtype` independently
showing `ZYXWV...` — worked on the first real attempt.

With Phase 5, all six gaps identified after Phase 2 have at least a first
real increment — four closed in earlier phases (syscall/IPC surface,
capability scoping, subdirectories, multi-cluster coverage), two given
their first slice here (long filenames, a first real write). What remains
deliberately open, named rather than implied-done: growing/shrinking
files, creating/deleting entries, free-cluster allocation and tracking,
partial-sector read-modify-write, and a real syscall/IPC surface for
*writes* (Phase 3's IPC surface is read-only) — Phase 6, below, closes two
of these (partial-sector RMW, a first size update); the rest stay open.

**Filesystem driver, Phase 6: case-insensitive long-name matching, and a
real partial write + resize — still no allocation.** Two more named
deferrals get their own scoped slice, each still avoiding the
free-cluster-allocation risk the write-support revisit trigger
specifically calls out. **Still not attempted, unchanged**: free-cluster
allocation/tracking, FAT chain extension or truncation (true
growth/shrink across cluster boundaries), create/delete of directory
entries — tightly coupled, highest-corruption-risk items that get their
own dedicated planning pass, not a rushed bundle here.

*Part A — case folding.* Real FAT/VFAT lookups are case-insensitive (LFN
preserves *display* case; matching isn't case-sensitive) — Phase 4's
`long_name_matches` did a strict comparison, so searching for
`LONG-FILENAME-TEST.TXT` would have failed to find the real, lowercase
`long-filename-test.txt`. `ascii_case_insensitive_eq` folds `'A'..='Z'`
and `'a'..='z'` together on both sides — ASCII-only, named as this
function's own limit; a general Unicode-aware fold (accented characters,
locale-specific rules) is a separate, still-open non-goal. Verified
against the *same* real fixture file Phase 4 already validated, searched
with an all-uppercase target — no new fixture needed. Confirmed:
`case_insensitive_long_name_match=1`.

*Part B — partial-sector write + file-size update.* `PARTIAL.TXT` starts
at exactly 512 bytes of a lowercase-letter pattern (deliberately visually
distinct from every other fixture pattern, so a bug reading the wrong
file's sector is easy to spot). This phase overwrites only the *first*
300 bytes with a new pattern — genuine read-modify-write, not a
full-sector clobber — and shrinks the directory entry's `file_size` to
300, then confirms both through the *ordinary, unmodified read path*
(`find_entry_in_directory` + `read_file_contents`), not just an isolated
field mutated in isolation. `find_entry_with_location` (new, additive —
`find_entry_in_directory` itself is untouched) returns where the short
entry lives so its `file_size` field can be patched directly.
Independently confirmed via `mdir`/`mtype` in CI, not just the driver's
own self-report: file size shows `300`, not `512`, and content starts
`01234...`. A second, low-level check (bypassing `file_size` entirely)
confirms bytes `300..512` of the sector still hold the *original*
pattern — the exact check a naive full-sector-overwrite bug would fail
even though the first check alone could still pass by coincidence.

Confirmed: `size_write_ok=1 size_visible=1 contents_match=1
tail_preserved=1`. A real finding while wiring this up, worth remembering
as a class but not a logic bug: the kernel test's own outer poll bound
(`kernel/tests/blk_fat32_read.rs`, 100 iterations) had never been revised
as Phases 3-6 each added more sequential virtio requests to one boot's
combined proof — by Phase 6 the total legitimately needed more real
scheduling turns than 100 iterations allowed, so the test reported "never
finished" even though nothing was actually wrong. Bumped to 2000 (still
bounded, not infinite) — the same "the poll bound needs to grow as the
work it's waiting for grows" adjustment the `boot` job's own QEMU timeout
already needed once, for the same underlying reason.

**Filesystem driver, Phase 7: free-cluster allocation, chain growth,
delete, and create — the three highest-corruption-risk items named after
Phase 6 all get a first real, narrowly-scoped slice.** Tied together in
one coherent narrative rather than three disconnected pokes: grow an
existing file into a newly allocated cluster, delete a file (freeing its
cluster and directory slot), then create a brand-new file that reuses
exactly that freed slot and cluster.

Ground truth was confirmed by reading the real fixture's actual FAT bytes
before writing any code, not assumed from spec: clusters 2-14 are the
existing fixture files, clusters 15+ read as `0x00000000` (free), and the
volume's two FAT copies (`num_fats=2`) start out byte-identical — meaning
a correct writer has to update *both*, not just the first, or leave a
real, silent inconsistency behind.

*Shared primitives.* `write_fat_entry` patches one cluster's entry via
real read-modify-write (preserving the top 4 reserved bits, same
discipline as Phase 6's directory-entry patch) in **every** FAT copy, not
just the one this driver's own reads consult. `allocate_free_cluster`
scans the FAT sector-by-sector from cluster 2 upward for the first entry
that reads `0`, bounded the same defensive way every chain walk in this
module is.

*Part A — chain growth.* `GROW.TXT` starts at exactly one full cluster
(512 bytes, no existing slack) on purpose, isolating "link a genuinely new
cluster" from Phase 6's already-proven "fill a partial final cluster."
`run_grow_proof` walks to the file's current last cluster (generic, not
assuming single-cluster), allocates a new one, writes 200 new bytes into
it, links it in — the new cluster's own EOC marker is written *before*
the old last cluster is repointed at it, so a crash between the two
writes leaves either an unlinked orphan cluster or an already-extended
chain, never a chain pointing at a half-initialized cluster — then
patches `file_size` to 712. Verified through the ordinary,
unmodified read path: reading the full 712 bytes back requires walking
across the freshly-created link, exercising exactly the code this slice
exists to prove.

*Part B — delete.* `run_delete_proof` walks `DELETE_M.TXT`'s chain,
zeroing every cluster's FAT entry via `write_fat_entry`, then marks its
directory entry's first byte `0xE5` (the standard deleted marker).
Verified two ways: `find_entry_in_directory` no longer finds it (proving
`0xE5` is honored by the *write* side, not just the already-proven
parsing side), and `allocate_free_cluster` immediately afterward returns
exactly the cluster just freed — not just "some free cluster exists
somewhere," but proof this specific cluster is genuinely reusable.

*Part C — create.* `run_create_proof` scans the root directory for a
`0xE5`-marked slot (the one part B just freed — this phase's create only
ever reuses an *already-deleted* slot; if none exists it fails closed
rather than growing the directory into a new cluster, which stays
explicitly out of scope), allocates a cluster, writes content into it,
marks it EOC, and writes a complete new short entry (`CREATED.TXT`) into
the reused slot.

Confirmed: `chain growth proof OK (Phase 7a PASS)`, `delete proof OK
(Phase 7b PASS)`, `create proof OK (Phase 7c PASS)` — all three passed on
the first genuinely correct attempt. Independently confirmed via
`mdir`/`mtype` in CI against the real backing image, not just the
driver's own self-report: `GROW.TXT` shows 712 bytes ending in the
expected digit cycle, `DELETE_M.TXT` no longer appears in the directory
listing at all, `CREATED.TXT` exists with the exact expected content.
Directly inspecting the image's own FAT bytes afterward also confirmed
both FAT copies stayed byte-identical through every write this phase
made, and that `CREATED.TXT` really did land on the exact cluster
`DELETE_M.TXT` had just given up.

Two real, non-logic bugs found by actually booting this, both fixed
before any of the above is meaningful:

- **A genuine ring-3 stack overflow**, first misdiagnosed as needing more
  investigation before the actual cause was clear: `run_grow_proof`/
  `run_create_proof` each add another `[u8; 4096]`-sized local buffer to
  the same sequential call chain Phase 6's own proof already used most of
  the existing 16 KiB ring-3 stack on. The page fault
  (`CAUSED_BY_WRITE | USER_MODE`, faulting a few dozen bytes past the live
  stack pointer, in `find_entry_in_directory`'s own prologue) reproduced
  identically across three separate rebuilds — including one full `cargo
  clean` — before the real cause surfaced: `kernel/tests/blk_fat32_read.rs`
  defines its **own independent copy** of `BLK_STACK_SIZE` (it doesn't
  share `kernel/src/main.rs`'s), so bumping the latter alone had zero
  effect on the test that actually exercises this path. Fixed by bumping
  the test file's own constant from `4096 * 4` to `4096 * 8`, plus a
  matching bump in `kernel/src/main.rs` for the real boot path, which will
  need it too once the real syscall surface (Phase 3's still-open gap)
  ever calls these code paths directly.
- **A self-inflicted false regression, not a code bug**: an ad hoc
  regression run pointed `RUNIX_BLK_IMG` at the real FAT32 fixture for
  *every* kernel test, including `blk_driver_rw` — whose Phase 1 proof
  intentionally overwrites sector 0 (the boot sector on a real FAT32
  volume), the exact hazard `run_fat32_proof`'s own doc comment already
  names. Corrupted the fixture's boot sector (signature bytes read back
  as `0x00 0x00` instead of `0x55 0xAA`), which then made the *next* test
  in the run report a spurious "boot sector did not parse" failure.
  Fixed by rebuilding the fixture and re-scoping which tests get
  `RUNIX_BLK_IMG` — not a driver bug, but a reminder that this fixture is
  shared, mutable state across a test run, same as every other
  write-adjacent phase's fixture-handling care already assumes.

**Still not attempted immediately after Phase 7**: growing the *directory*
itself, allocating or linking more than one cluster in a single
grow/create call, and the FSInfo sector's free-cluster-count/next-free
hint going stale — all three closed by Phase 9, below. Concurrency around
IPC sends is closed by the section after that; the allocation path itself
remains single-writer internally (nothing in this driver spawns concurrent
allocations against itself), which is a narrower, still-accurate claim
than "no concurrency/locking exists anywhere," which was too broad.

**Filesystem driver, Phase 8: a first write-capable, multi-request IPC
surface — Phase 3's syscall/IPC gap finally gets a real increment.**
Until now the IPC surface was exactly what Phase 3 left it: one hardcoded
read-only lookup, served **at most once** per boot, then the driver idled
forever. `docs/THREAT_MODEL.md`'s own revisit trigger for this named the
next step explicitly — "an arbitrary path sent at request time instead of
one fixed target name, or more than one file/process served at once" —
while separately noting that a real multi-file surface needs a
path-scoped capability convention that doesn't exist yet
(`capabilities::check` is exact-string match only, no wildcards). This
phase closes the two things that don't require inventing that convention
yet, and deliberately leaves the rest open.

`run_fs_ipc_server` is rewritten from "find file → wait for one trigger →
reply → idle forever" into a real loop serving **both** the existing
read path (`HELLO.TXT`, unchanged, backward-compatible) and a **new
write path** against `WRITE.TXT` over a second, independently
capability-gated port (`FS_WRITE_REQUEST_PORT = 10`) — one port per file,
reusing the *existing* `capabilities::port_resource` convention exactly
as `SYS_IPC_SEND` already enforces it, not a new resource-string kind.
Write wire format: a 2-byte little-endian length (must be exactly 512,
`WRITE.TXT`'s whole one-sector capacity — anything else is rejected, not
truncated or padded) then that many payload bytes; reply is a single
status byte on the existing shared response port. A real finding while
designing this, corrected before any code was written: `blk-driver-host`
itself needs **no new capability** for the write port — it only ever
*receives* on ports 8/10 (unauthenticated, same as every receive in this
codebase) and *sends* on port 9 (already covered by its existing reply
token); the new capability is granted to the *client* thread allowed to
send a write request, the exact same shape the read path's
`request_token` already has.

Verified via a real QEMU boot of an extended `kernel/tests/blk_fs_ipc.rs`,
all in one boot, proving the server loop genuinely serves more than one
request for the first time: unauthorized read denied (existing,
unchanged), authorized read OK (existing, unchanged), unauthorized write
denied (new — same capability gate, now covering the write path too),
authorized write OK (new). Independently confirmed via `mtype` in CI
against the real disk image afterward, not just the round trip through
this still-young protocol: `WRITE.TXT` shows the IPC write's own
`zyxwv...` pattern (deliberately distinct from Phase 5's direct-write
`ZYXWV...` pattern, so the two are never confused), landed *after* Phase
5/6's own checks already ran against the same file earlier in the same
CI run. Passed on the first genuinely correct attempt, no debugging
detours this time.

**Still not attempted immediately after Phase 8**: arbitrary/dynamic
filenames in the request, per-caller dynamic authorization, and
create/delete/grow over IPC. The first two are closed by Phase 10, below;
create/delete/grow stay internal-only, deliberately — Phase 7's riskier
primitives are not yet exposed to a caller that only proved it can name a
file, not that it should be trusted with allocation/deallocation.

**Filesystem driver, Phase 9: directory growth and multi-cluster
allocation in one call — the two structural gaps Phase 7 named as its own
next planning pass.** Both closed together because they share the same
root cause: Phase 7's `find_deleted_slot` only ever recognized an
`0xE5`-marked entry as reusable, and its allocation calls only ever
reserved one cluster. A directory that was full but had *never* had a
deletion — or a grow/create that needed more than one new cluster — both
failed closed, correctly but not usefully.

`find_deleted_slot` is replaced by `find_reusable_slot`, which recognizes
**both** an `0xE5` deleted entry *and* the `0x00` end-of-directory
sentinel — the latter case allocates and links a fresh directory cluster
(zeroed, so it still ends in its own `0x00` sentinel), extending the
directory chain the same way a file's chain gets extended, then reuses
the first slot in the new cluster. `allocate_cluster_chain` replaces
Phase 7's single-cluster `allocate_free_cluster` call sites with a real
two-pass allocator: reserve N free clusters first (failing the whole
operation closed if fewer than N exist, before touching any FAT entry),
then link them into a chain — no half-linked chain is ever left behind on
a failure partway through.

Verified via a new `run_multi_cluster_grow_proof` (extends `MULTI.TXT` by
700 bytes, spanning two brand-new clusters allocated and linked in a
*single* call — deliberately distinct from Phase 7's `GROW.TXT`, which
only ever needed one) and a new `run_directory_growth_proof`. The
directory-growth fixture is deliberately adversarial, not incidental:
`make_fat32_image.sh` now packs the root directory's first cluster to
**exactly** 16 live entries (its full 512-byte capacity, 32 bytes each) —
`HELLO.TXT`, `BIG.TXT`, `SUBDIR`, the long-filename entry, `WRITE.TXT`,
`PARTIAL.TXT`, `GROW.TXT`, `DELETE_M.TXT`, `MULTI.TXT`, plus five
one-line `FILL01.TXT`–`FILL05.TXT` filler files — so that by the time the
directory-growth proof runs, Phase 7's own delete+create (net zero
occupancy change) has left this cluster still genuinely full, forcing a
real second cluster to be allocated rather than incidentally finding room
left over from an earlier phase. Independently confirmed in CI: a real
finding while wiring the check up — `mdir`'s space-padded 8.3 field
format broke a naive `grep`/size check for `GROW.TXT` once `GROWDIR.TXT`
also existed (a substring collision in the parsing, not a driver bug),
fixed by tightening the match.

**Filesystem driver, Phase 10: dynamic filenames over IPC, per-caller
authorization, and a live FSInfo hint — the two gaps Phase 8 named as its
own next trigger, plus one from even earlier.** `ipc/src/fs.rs` replaces
Phase 8's "one port names one fixed file" protocol with a real typed
message: `FsRequest::Read { name, token }` / `Write { name, data, token }`
— an arbitrary filename *and* a real `CapabilityToken` embedded in every
single request, not just a capability to reach the port at all.
`blk-driver-host` calls `verify_file_token` on every request, checking the
embedded token against the *specific named file* before touching disk —
a second, per-request authorization layer sitting on top of (not instead
of) the kernel's existing port-level `SYS_IPC_SEND` gate. This is the
actual point of per-request authorization the port-level gate alone can't
give: a caller can hold a perfectly valid capability for the port itself
and still be denied for the file it names in a given request.

Verified via `kernel/tests/blk_fs_ipc.rs`, extended past Phase 8's two
cases into four: **two different files** (`HELLO.TXT`, `BIG.TXT`) served
successfully over the *same* read port in one boot (Phase 8 could only
ever serve the one file its port was wired to); a caller holding a
genuinely valid port-level capability but a file-scoped token minted for
a *different* file gets `FsError::Unauthorized`, not the file's contents
— proven for both the read and the write path. Also closes the FSInfo
sector's stale-hint gap named back in Phase 7: `allocate_cluster_chain`
and the delete path now keep the FSInfo sector's free-cluster count in
sync with every allocation and every free, so a real OS reading this
volume afterward no longer sees a hint that lied about how much space Phase
7–10's own writes actually consumed.

**Filesystem driver: closing a concurrency hazard that lived in the IPC
layer itself, not in this driver's own logic — the last item on Phase
7's original list.** A real `FsRequest` (Phase 10's embedded
`CapabilityToken` alone encodes past 1 KB) exceeds the IPC channel's
32-byte `CHANNEL_CAPACITY`, so a sender's `SYS_IPC_SEND` loop has to block
mid-message — which was exactly the scheduler's opportunity to interleave
a second concurrent sender's bytes into the first message, producing a
"franken-message" that still *decodes* as well-formed, just wrong. This
was a real, previously-latent bug in `kernel/src/ipc.rs`'s send path, not
something Phase 10's own logic introduced — it only became reachable once
a message got large enough to need more than one blocking round.

Fixed with a per-port advisory send lock: `kernel::ipc::begin_send`/
`end_send`, exposed as two new capability-gated syscalls
(`SYS_IPC_SEND_LOCK`/`SYS_IPC_SEND_UNLOCK`, checked through the same
`authorized_for_port` gate `SYS_IPC_SEND` itself uses) — now the mandatory
calling convention for any multi-byte send, documented directly in
`kernel::ipc`'s own doc comment. Verified by a new
`kernel/tests/blk_fs_concurrent.rs`: two client threads send real,
different `FsRequest`s to the same port at the same time, and both get
back their own exact, uncorrupted content — the test that would have
failed, non-deterministically, before this fix.

**Filesystem driver: the concurrent-*allocator* half of that same gap —
investigated, and closed as safe *by construction* with a real QEMU proof
rather than an assertion.** The send-lock fix above closed concurrent
*senders*; this document then named concurrent *allocators* ("allocating
in response to concurrent callers racing each other") as still open. It
was never actually established whether that was a live bug or a gap the
architecture already forecloses — `allocate_cluster_chain`'s own doc
comment asserted "no concurrency exists in this driver to race against"
without anything backing it. Traced end to end, it is foreclosed, for two
*independent* reasons:

1. **Allocation is not reachable over IPC at all today.** `_start`'s
   `serve_fs_requests` branch (which enters `run_fs_ipc_server`) and its
   `attempt_fat32` branch (which runs `run_grow_proof` /
   `run_multi_cluster_grow_proof` / `run_create_proof` /
   `run_directory_growth_proof` / `run_fsinfo_hint_proof` — every single
   `allocate_cluster_chain`/`allocate_free_cluster` call site in the
   driver) are mutually exclusive. `handle_write_ipc_request` writes
   exactly one already-allocated sector and rejects anything else, so no
   client request can reach the allocator even once, let alone twice
   concurrently.
2. **This process has exactly one thread of execution.** It is spawned
   once via `scheduler::spawn_ring3_process_with_capabilities` (one
   `Thread`); it spawns nothing, runs no async executor, and handles no
   interrupts of its own. `run_fs_ipc_server` calls its handler inline and
   cannot begin decoding request N+1 until request N has fully returned —
   the read port and write port are polled in sequence in the same loop
   body, never overlapped. The scheduler *is* timer-preemptive (not
   cooperative-only — `kernel/src/scheduler.rs`, and this driver does
   yield mid-allocation, since every `dev.write_sector` spins through
   `poll_for_completion`'s `yield_now`), but preemption suspends and later
   resumes this *same* context; it never creates a second one. No other
   process holds the virtio-blk io-port capability needed to touch the FAT
   at all.

The serialization half of that argument is now proven in QEMU, not just
reasoned about: `kernel/tests/blk_fs_concurrent_write.rs` spawns two
client threads back-to-back (no yield between the spawns) that both send
a full `FsRequest::Write` to the *same* `FS_WRITE_REQUEST_PORT` for two
different files, with byte patterns drawn from disjoint value ranges
(`b'A'..=b'G'` vs `b'a'..=b'k'`) so a single stray byte from the wrong
writer is detectable at every offset. Both writes report `Ok`, and both
files read back holding exactly their own writer's pattern — confirmed
independently against the raw image afterwards (each pattern occurs
exactly once, in its own sector, with no sector mixing the two ranges),
the same "don't let the thing under test grade itself" discipline every
other write-path phase here uses. `allocate_cluster_chain`'s doc comment
now carries this conclusion instead of the bare assertion.

What this does **not** prove, stated plainly: nothing here makes
`allocate_cluster_chain` itself re-entrancy-safe. Its two-pass
reserve-then-link sequence yields to the scheduler between (and inside)
its FAT writes, so a *second* concurrent caller would observe a
half-reserved chain. That is safe today only because reason 2 above
holds. If this driver ever gains real internal concurrency — per-client
scheduled tasks instead of one sequential loop, a second thread, or an
async executor — or if an allocating operation is ever exposed over IPC,
this argument must be redone and the allocator given an actual mutual-
exclusion guard.

**Still not attempted, filesystem driver, current state**: any *internal*
concurrency in this driver (a second thread, an async executor, or
per-client scheduled tasks rather than one sequential request loop) —
which is exactly what today's allocation-safety argument rests on, see the
section immediately above.

**Real `cargo-fuzz`/libFuzzer harnesses — closing the gap this document
named above ("No `cargo-fuzz`/libFuzzer harness exists yet").**
`docs/THREAT_MODEL.md` commits to fuzzing landing "alongside the first
network parser"; until now that commitment was only met by `proptest`
(randomized property tests, not corpus-driven coverage-guided fuzzing).
Two standalone `cargo fuzz init`-shaped crates now exist, same
"declare its own empty `[workspace]` so cargo doesn't walk it into the
parent" convention `net-driver-host`/`blk-driver-host` already use for
their own standalone-ness, plus a `channel = "nightly"` toolchain file
(`cargo-fuzz` needs nightly for its sanitizer/instrumentation flags,
unlike either target crate's own toolchain):

- `capability-manager/fuzz/` (`capability-manager-fuzz`, target
  `verify_fuzz`): feeds arbitrary bytes at the actual public entry point,
  `CapabilityToken::verify()`, split into a `now` timestamp, a `resource`
  string, and a `signature` string set directly onto a token issued with a
  fixed deterministic keypair — covering `hex::decode(&self.signature)`,
  the exact call this document already named as the fuzzing-rigor gap when
  it was still only proptested.
- `net-driver-host/fuzz/` (`net-driver-host-fuzz`, target
  `smoltcp_fuzz`): duplicates the existing `#[cfg(test)] mod smoltcp_fuzz`
  harness from `net-driver-host/src/lib.rs` (`FuzzDevice` /
  `build_iface_and_sockets`, credited in the fuzz target's own doc
  comment) rather than exposing it from the library — same boundary the
  proptest module already exercises (arbitrary bytes into a real
  `smoltcp::iface::Interface::poll`, split on `0xff` into up to 8 frames
  polled across several timestamps each, so multi-poll state like a
  half-open TCP handshake gets exercised, not just a cold single frame).

Both verified in WSL Fedora (this machine's own constraint — libFuzzer/ASan
need nightly + a real C++ toolchain, poor fit for Windows/MSVC; `cargo-fuzz`
and a C++ compiler were installed there for this): `cargo +nightly fuzz
build` succeeds for both crates, and `cargo +nightly fuzz run <target> --
-max_total_time=20` ran each for its full 20 seconds with no crash,
timeout, or sanitizer report — `verify_fuzz` completed 107,242 runs,
`smoltcp_fuzz` ran until its time budget was interrupted at over 474,000
runs; both are legitimate "harness builds and runs clean" results, not
evidence of exhaustive coverage. No CI wiring yet: `cargo-fuzz` needs
nightly and, in CI, likely ASan support whose availability on
`ubuntu-latest` runners hasn't been confirmed, and a fuzz run is exactly
the kind of open-ended, potentially-flaky job that shouldn't gate every
merge — so for now this stays a documented local-run workflow (`cd
capability-manager/fuzz && cargo +nightly fuzz run verify_fuzz`, similarly
for `net-driver-host/fuzz`'s `smoltcp_fuzz`), revisited if/when a
`workflow_dispatch`-triggered smoke job is worth the added CI surface.

**`blk-driver-host`'s allocator — the fuzz-coverage half of the same
"concurrent allocators" gap named above, closed separately.** The
allocator's real entry points (`allocate_cluster_chain`/
`allocate_free_cluster`) do live virtio-blk I/O with no fake-able device
abstraction, so rather than leave the gap unaddressed, the sector-scan
decision logic was extracted into a new pure function,
`first_free_cluster_in_fat_sector` (`blk-driver-host/src/lib.rs`) —
behavior unchanged, `allocate_free_cluster` now calls it per sector read
off the real device, covered by 3 new unit tests plus a `proptest`
property asserting the actual invariant a caller depends on (any returned
cluster is `>= 2` and its own FAT entry genuinely reads back as free, not
just "didn't panic"). `blk-driver-host/fuzz/` (`blk-driver-host-fuzz`) adds
two targets on the same convention as `capability-manager/fuzz`/
`net-driver-host/fuzz`: `chain_link_values_fuzz` (2,130,212 runs in 20s, no
crash) and `first_free_cluster_fuzz` (580 runs in 20s — dramatically fewer,
because a fuzzer-controlled `entries_per_sector` can drive its scan loop
into billions of iterations; a real latent algorithmic-DoS shape, harmless
today only because every real caller derives that value from a
`BootSectorInfo` capped at 1024, flagged here rather than fixed since
tightening it was out of this task's scope). Both verified in WSL Fedora,
same constraint as the two fuzz crates above.

**Explicitly still NOT fuzzed**: `blk-driver-host`'s FAT32 *parser itself*
(`boot_sector_parse`, directory-entry parsing, LFN fragment reassembly,
short-name checksums) still has only the `proptest` coverage described in
this document's Filesystem-driver Phase 2 section above — the fuzz targets
above cover the allocator, not the parser. Also unfuzzed:
`net-driver-host`'s virtio-net completion validation
(`validate_rx_completion`, covered by its own `proptest` suite only) and
anything in `kernel/` itself (no parser there takes fully untrusted input
today). None of this is a regression — it's the same "proptest first,
`cargo-fuzz` where the corpus-driven, coverage-guided difference actually
matters" prioritization this document has used throughout — but it means
"fuzzing exists in this repo" should not be read as "the FAT32 parser is
fuzzed."

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
  one-time access decision.
- **Real EL0/EL1 memory isolation, page-granular, not just the SVC-gate
  capability check.** `mmu.rs` now builds a real three-level translation
  table for the Normal region: mostly 2 MiB blocks (EL1-only, same as
  before), except the one 2 MiB slice containing this crate's own image,
  which descends further to 4 KiB pages. Only two things in that slice are
  marked `AP[2:1]=0b01` (EL0-accessible): `el0_demo`'s code page and
  `EL0_STACK`'s pages. Everything else — in particular
  `el1_exception_vectors` — stays `AP[2:1]=0b00`. `el0_demo` now proves
  *data* access genuinely works, not just execute: a real `strb`/`ldrb`
  push-and-read-back onto its own stack, echoed via `SYS_WRITE` (`0x42`,
  `'B'`, printed right after the `SYS_WRITE` gate proof). This closes the
  gap an earlier attempt (see the bug entry below) left open — that
  attempt set `AP[1]=1` on the *entire* 1 GiB block and hung QEMU
  reproducibly; the real root cause (found via `-d int,guest_errors`
  tracing) was that EL1 could no longer fetch its own exception vector
  table once `AP[1]=1` was set anywhere in the block it lived in — a
  genuine QEMU/TCG bug, since `AP` bits are architecturally defined to
  gate data access, not instruction fetch. The fix isn't a workaround for
  that bug, it's the architecturally correct design regardless: real
  isolation needs page-granular permissions, not "the whole block or
  nothing," and confining `AP[1]=1` to a small, dedicated page range never
  triggers the QEMU issue in the first place. See `mmu.rs`'s doc comment
  on `Level3Table` for the full account.
- **Basic SIM provisioning** (`sim.rs`, Alpha form) — the first minimal
  per-slot state machine (`Uninitialized -> Provisioned -> Activated`, behind
  `SYS_SIM_PROVISION`/`SYS_SIM_ACTIVATE`), gated by the same capability check
  the RIL syscalls use. It proved the SIM capability boundary is uniform
  across resource kinds rather than special-cased for RIL. **Superseded in
  Beta** by the eSIM lifecycle below: those two syscalls no longer exist
  (`svc.rs` now dispatches `SYS_SIM_CREATE`..`SYS_SIM_STATUS`, numbers 5–10),
  and the identity limit it recorded (one opaque `u64`, not an ICCID/IMSI)
  still applies.

Not yet started: the real RIL/SIM *protocol* (APDU and eUICC command sets,
talking to actual radio and SIM hardware, not just the isolation boundary
and state machines they run under). Per `mobile/src/lib.rs`'s doc comment,
that starts once the shared kernel boots on target hardware. Everything in
this section, Beta included, is still QEMU-only.

Non-secure boot (`-M virt` without `secure=on`, which resets straight to
EL1 instead of EL3) now works too — previously produced no UART output at
all, root-caused and fixed; see the bug entry below.

## Mobile Beta: eSIM lifecycle, MVNO accounts, the MARSHAL gate, and the EL0 process model

Beta items 1–4 (eSIM lifecycle, the MARSHAL gate, the MVNO account core, the
data policy engine) are built under `kernel-arm/`, with the pure policy cores in
`mobile/`, and the QEMU boot walk asserts them in CI. Item 4 covers account
entitlements only. It decides and it reconciles, but it has no data path, no
real metering and no persistence, and it never acts on its own (see the data
section). The MARSHAL gate's transport is an EL0 process, so the EL0 process
model those items run on is described last. The trust consequences of everything below are in
[THREAT_MODEL.md](THREAT_MODEL.md)'s mobile block; this section is what was
built and what it does not do.

### eSIM lifecycle (`kernel-arm/src/sim.rs`, `svc.rs`)

Each profile is in one of four states: `Created`, `Disabled`, `Enabled`,
`Deleted`. There are four slots (`SLOT_COUNT`), each holding up to four
profile containers (`MAX_PROFILES_PER_SLOT`). Every profile state change goes
through one function, `SimSlot::transition`, which validates the whole
transition before mutating anything. The legal transitions are
`Created -> Disabled` (install), `Disabled -> Enabled` (which demotes whatever
was `Enabled` in the same slot, under the same lock), `Enabled -> Disabled`,
and `Disabled -> Deleted`. Two invariants follow from that table: at most one
profile per slot is `Enabled`, and `Enabled -> Deleted` is a `WrongState`
error that carries the from-state, so a caller learns to disable first.
`Deleted` is terminal. Deleted containers are never reclaimed, so a slot can
fill with them, but profile IDs stay stable for the boot.

Capabilities are scoped per operation and checked on every call. Create
checks `sim:{slot}`. Install, enable, disable and status check
`sim:{slot}:{profile}`. Delete checks `sim:delete:{slot}:{profile}`, a
separate resource, so general profile access does not confer the authority to
destroy a profile.

Enable and delete are the consequential pair: enable silently demotes the
slot's active subscription, and delete is irreversible. Both pass the MARSHAL
gate (below) before the state change, and enable also passes the MVNO gate
first. Disable is not MARSHAL-gated because it is the recoverable direction,
but it is audited.

Audit happens at the syscall boundary (`svc.rs`'s `audit_transition`), not in
`sim.rs`, because only the boundary knows the requesting context. It records
the *intended* from/to, derived from the operation attempted, together with
`authorized` and the error. It does not read `profile_state` before and after:
`sim.rs` releases its lock between calls, so a before/after pair could straddle
another context's transition and record a change that never happened.

Gaps, specific to this section:

- **Fixed (2026-10-10):** `sim::disable` used to accept a `Created` profile,
  because one legality table keyed only on the target state served both
  `install` and `disable`. A never-installed profile could be disabled and then
  enabled, reaching `Enabled` with `identity` still `None`. The symmetric hole
  was real too: `install` over an `Enabled` profile silently demoted it and
  overwrote its identity. Every operation now carries its own required source
  state (`Install` from `Created`, `Enable` and `Delete` from `Disabled`,
  `Disable` from `Enabled`) and `SimSlot::transition` stays the single
  enforcement point for the slot-wide invariants. The state machine is in the
  lib target and has 13 host tests, including an exhaustive operation by
  source-state matrix; the boot walk also proves the install-over-`Enabled`
  rejection.
- `identity` is one opaque `u64`, not an ICCID or IMSI. The register-only
  `SVC` ABI cannot carry the 15–20 digits a real identifier needs.

### MVNO account layer (`mobile/`, `kernel-arm/src/mvno.rs`)

The policy is split from the kernel. `mobile/` (`runix-mobile`) is `core` and
`alloc` only, with no I/O and no clock. Its `account.rs` `AccountRegistry`
enforces every invariant in one `apply(Change, lifecycles)` function that
validates fully before mutating. The registry is bounded (`MAX_ACCOUNTS` 16,
`MAX_PROFILES_PER_ACCOUNT` 4). It never stores eSIM lifecycle state; it reads
that through a `ProfileLifecycles` view, and an unknown lifecycle fails
closed. A closed account keeps its bindings and never frees its slot.

`mobile/src/selection.rs`'s `select_network` is pure. Every refusal is its own
`RefusalReason` (eight variants), so "account suspended", "no allowed
candidate" and "roaming not permitted" are distinguishable to a caller. Inputs
over `MAX_CANDIDATES` (32) or `MAX_ALLOWED_NETWORKS` (64) are refused, not
truncated, and ranking does not depend on modem order.

`kernel-arm/src/mvno.rs` is the only enforcement point. It holds one registry
behind a spin lock, with lock order registry then sim, never the reverse.
Three syscalls manage accounts:

- `SYS_MVNO_BIND` (16) needs both `mvno:account:{id}` and the profile's
  `sim:{slot}:{profile}`, so account access alone cannot claim a profile.
- `SYS_MVNO_SUSPEND` (17) needs `mvno:suspend:{id}`. Suspend is scoped apart
  from general account access because it cuts service.
- `SYS_MVNO_REACTIVATE` (18) needs `mvno:account:{id}`.

Enable is fail-closed on the MVNO side. A profile that is not bound to an
Active account is denied before any MARSHAL round trip. Suspend is a two-step
handshake: the registry flips the account to `Suspended` and returns the
`force_disable` list, then `svc.rs` applies `sim::disable` to each entry,
audits each one, and re-checks "no `Enabled` profile under a non-Active
account" against live sim state. Delete releases the profile's binding so the
account's capacity frees.

Simplifications, all deliberate at this stage:

- In-memory only. Accounts, bindings, sim state, data usage and sessions, and
  the WORM chain are lost on reboot.
- The one account is compiled in (`open_demo_account`, `AccountRegistry::demo`).
  It is demo data, not a subscriber base.
- The MARSHAL principal is the placeholder `el0:arm-demo`, not a token subject
  (see the MARSHAL section and the THREAT_MODEL gaps).
- Selection is proven on a fixed candidate list at boot, against a local
  registry (`mvno_proof.rs`). No modem, RIL or carrier source feeds it.

### MARSHAL gate for mobile (`marshal_action.rs`, `marshal_transport.rs`, `esim_marshal.rs`)

One gate covers six action types: `esim.enable`, `esim.delete`,
`mvno.bind_profile`, `mvno.suspend_account`, `mvno.reactivate_account` and
`data.reset_usage`. Of the data syscalls, only the governed usage-period reset
is inside it. The other four are outside by design (see the data policy engine
section, which also explains why).
`marshal_action.rs`'s `MarshalAction` builds each Kerkese envelope. The eSIM
envelope is byte-identical to the format it had before the gate was
generalized, and a host test pins that. `esim_marshal::evaluate` wraps
`marshal_transport::evaluate`, and `esim_marshal::enforce` is the shared
enforcement. There is no separate MVNO path. The registry lock is never held
across an evaluation, because an evaluation can drive a nested EL0 excursion.

The transport runs each evaluation in a fresh `net-driver-host-arm` EL0
process, with its own address space and its own TCP source port. The process
sends the encoded `runix-ipc` `MarshalRequest` to the configured proxy and
copies the reply back via `SYS_MARSHAL_PROOF_DONE` (15). The kernel decodes
the reply with `MarshalResponse::decode`. Every request sets `"dry_run": true`,
which is hardcoded in `kerkese_json`, and `citadel_proxy` forwards that flag
upstream. The principal is `el0:arm-demo`, role `operator`.

How the result is classified (`marshal_transport.rs`, `esim_marshal::enforce`):

| Result | Covers | Policy |
|---|---|---|
| `Remote(Unreachable)` | No proxy configured (no process spawned), no device, connect failure, no report within 64 boot-thread yields, empty or undecodable reply, **and every `MarshalResponse::Error` kind except `PolicyRefused`** | Fail-open: the operation proceeds |
| `Remote(Refuse)` / `Remote(HardStop)` | A decoded CITADEL decision, **or** `MarshalError::PolicyRefused` from `citadel_proxy`'s own policy layer | Blocked, registry and sim untouched, **not WORM-audited** |
| `LocalFailure(SetupFailed / SpawnFailed / ExcursionFaulted)` | The kernel could not run the evaluation: out of memory, thread spawn, EL0 fault | Fail-closed, `DENIED (MARSHAL local failure: ...)`, WORM-audited with `authorized=false` |

The fail-open row has a consequence that has to be stated plainly. While the
MARSHAL proxy is unreachable, every consequential mobile operation (eSIM enable
and delete, MVNO bind, suspend and reactivate) proceeds without governance.
Any failure of the link (proxy down, connection refused, no answer within the
budget) turns the gate off for that operation. A proxy policy rejection is
NOT fail-open any more: it used to be (`citadel_proxy` returned its own
`POLICY_REFUSE` as `MarshalError::Other` and the kernel mapped every `Error`
to the unreachable class, so an explicit "no" was treated as an outage). It
now travels as its own wire variant, `MarshalError::PolicyRefused` (response
tag 1, error-kind byte 4, same bounded string encoding as the other kinds),
which both kernels classify as a refusal (`marshal_action::classify_response`
on ARM, `grid_sandbox::shadow_marshal_evaluate` on x86). The kernel and the
proxy must be deployed together: a proxy built before this change still sends
`Other("POLICY_REFUSE...")`, which stays fail-open. A kernel envelope that
fails to parse at all is still `BadResponse` and so still fail-open.

The desktop side (`desktop/src/citadel/{policy,proxy}.rs`) recognizes
`esim.enable`, `esim.delete`, the three `mvno.*` actions and `data.reset_usage`.
Each action family has its own field rules: eSIM actions require `slot` and
`profile`, MVNO actions require `account`, `data.reset_usage` requires `account`
alone, and each family rejects the others' fields (for the reset, `slot`,
`profile`, `module_id` and `instance_id` are refused). The proxy attaches its
own Verifier identity (`sig_verifier`) and records its own WORM verification
entry, attributed to module `esim`, `mvno` or `data` (the reset's instance is
`account-N`). CITADEL's server-side `rbacMap` carries entries for the eSIM and
MVNO actions (`esim.*` merged from `opensecstack` `b575903`; `mvno.*` via
opensecstack PR #83). As of 2026-10-11 the `data.reset_usage` entry is a local,
unpushed change in an opensecstack checkout and is not merged upstream. This
repository cannot show that checkout's state, so the claim is as reported. Until
the entry is merged, a live CITADEL is expected to hard-REFUSE the action at
Gate 2, and the kernel would print `DENIED (MARSHAL Refuse)` and leave the
counter alone. CI's mock CITADEL answers EXECUTE for any request, so CI cannot
show this.

Not closed:

- The proxy cannot construct `actor_token` or `sig_operator`. It attaches only
  its own Verifier signature, so a live Gate 1/2 decision for a real operator
  is not reachable from this code.
- The signing key is the demo key.
- CI's mock CITADEL (`mock_citadel_server_multi.py`) answers EXECUTE for any
  request. The CI steps prove the kernel, proxy, policy and wire chain. They do
  not prove a live Gate 2 pass.
- The verdict is not authenticated end to end. `MarshalResponse::Decision`
  carries an outcome and an opaque JSON body with no signature, and the link
  is plaintext TCP. See THREAT_MODEL.md.

### Data policy engine (`mobile/src/policy.rs`, `reconcile.rs`; `kernel-arm/src/data.rs`, `data_state.rs`, `data_codes.rs`, `svc.rs`)

What was built is the account-entitlement layer. An account's plan is a
`DataEntitlement`: an optional byte cap (`None` is unlimited), a throttle
percentage, a roaming-data flag, and an escalation percentage. The engine
decides session and usage questions against that plan. The reconciler compares
observed live state with the same plan and reports drift. Both are pure code in
`mobile/` (`runix-mobile`): no I/O, no clock, no stored state.

Not built, and nothing above implies it:

- **Per-sandbox-tier traffic classes (T1/T2/T3).** Policy is per account. No
  sandbox tier affects a decision.
- **A data path or real metering.** Usage is whatever the holder of
  `data:usage:{id}` reports through `SYS_DATA_ACCOUNT`, a demo syscall. Nothing
  measures bytes, and no code path consults a data session before network I/O.
- **Billing or rating.**
- **Persistence.** Counters and sessions are in memory and are lost on reboot.
- **A billing-period clock.** The engine has no notion of time, and nothing
  starts a period on a schedule. `SYS_DATA_RESET` starts one, but only when a
  caller issues it, so a billing-period boundary needs a caller. Whether a
  period has really ended is the caller's claim, not something the kernel
  checks.

**The engine only requests, and nothing in this block acts on its own.** This
is the governing invariant. The rest follows from it.

- `ActionRequest` (`NotifyOnly`, `Throttle`, `SuspendAccount`) is advice.
  `evaluate_usage` returns it, and nothing performs it.
- The data syscalls never suspend, disable, close, or change account or profile
  state in response to a request. `SYS_DATA_ACCOUNT` changes a usage counter.
  `SYS_DATA_SESSION_OPEN` and `SYS_DATA_SESSION_CLOSE` change the session table.
  `SYS_DATA_RECONCILE` writes only the usage table's `last_used` bookkeeping.
  `SYS_DATA_RESET` zeroes a usage counter and clears `last_used`. It runs only
  when a caller issues it, behind its own capability and the MARSHAL gate, and
  never as a response to an `ActionRequest`.
- The demo's suspension is carried out by the caller. The boot walk issues
  `SYS_MVNO_SUSPEND(0)`, which needs `mvno:suspend:0` and passes the MARSHAL gate
  (`mvno.suspend_account`) before the registry changes. The walk issues it
  unconditionally and does not branch on the code `SYS_DATA_ACCOUNT` returned.
- The reconciler is read-only in its types. `reconcile` takes an immutable
  `&Observed` and returns `Incident`s, each a kind, a subject and two facts. It
  holds no handle to live state.

The reason is that a usage counter, or a reconciler, that suspended an account
on its own would be an ungoverned writer. It would bypass the MARSHAL gate and
the WORM chain, which is the parallel authorization path this project forbids.
Correcting drift is a separate governed act, and it goes through the same gates
as any other suspension.

**The engine (`mobile/src/policy.rs`)**

- **Pure and replayable.** `evaluate_session` and `evaluate_usage` are functions
  of their arguments. `PolicyDecisionRecord::decide` captures inputs and outputs,
  and `replays()` recomputes from the recorded request and compares. That catches
  a record edited after the fact. It does not catch a record forged in full,
  because anyone can recompute a consistent one. The kernel does not store the
  struct. It writes a one-line text form (`describe_session_record`) that carries
  every input, so an auditor can rebuild the record. Nothing in the kernel parses
  those entries back or calls `replays()`.
- **Validated entitlements.** `DataEntitlement` has private fields and one
  constructor, `DataEntitlement::new`. It rejects a throttle above 100, an
  escalation below 100, and an escalation above `MAX_ESCALATE_PERCENT` (10,000).
  An incoherent plan cannot be built, so it cannot be evaluated. The upper bound
  catches a raw byte count typed into a percent field. The compiled-in demo plans
  are const literals in the same module, and a test proves they validate.
- **Exact arithmetic.** Each band test is `used * 100 >= cap * percent` in
  `u128`. There are no floats and no rounding, and "at the threshold" counts as
  reaching it (`>=`). Usage is added with a saturating add, so a wrapped counter
  cannot reopen a capped account.
- **Session root cause first.** A session decision checks account standing
  (`Suspended`, then `Closed`), then profile lifecycle (anything but `Enabled`),
  then network class (roaming without `roaming_data_allowed`), then usage. The
  first failing check is the one reported. A suspended account's denial reads as
  suspension, not as over cap.

Usage bands, strongest first (`evaluate_usage`), with cap `C`, usage `U`, throttle
`T` and escalation `E`:

| Band | Condition | Request | Session |
|---|---|---|---|
| `Anomalous` | `U*100 >= C*E` | `SuspendAccount` | denied `CapExceeded` |
| `CapReached` | `U >= C` | `NotifyOnly` | denied `CapExceeded` |
| `Throttled` | `U*100 >= C*T` | `Throttle` | allowed, throttled |
| `Normal` | otherwise | none | allowed |

Because `E >= 100`, `Anomalous` implies the cap is also reached. The suspension
request is additional to the denial. Only `Anomalous` requests suspension, so a
plain cap-reached session is denied without one. At `E = 100` the `CapReached`
band cannot be reached.

Special plans:

- **Unlimited (`cap = None`)** is always `Normal` and never escalates, at any
  usage, including `u64::MAX`. The kernel's demo table has no unlimited plan, so
  this is covered by host tests only.
- **Zero allowance (`cap = Some(0)`)** is a valid plan. Every session is denied
  `CapExceeded`, even at zero usage. The band is `CapReached` with a `NotifyOnly`
  request, never `Anomalous`. An account that cannot use data is not asked to be
  suspended for that.

**The reconciler (`mobile/src/reconcile.rs`)**

- The caller builds an `Observed` snapshot from copies of live state. The
  snapshot carries the policy-intended values (caps, escalation percentages,
  roaming permission), so the reconciler compares state with the plan without
  importing any other module's types.
- **Bounded.** 64 accounts, 256 profiles, 256 sessions. A snapshot over a bound
  produces one `snapshot-too-large` incident and nothing else, because
  truncating would silently skip records.
- **Duplicates are excluded.** Records sharing a key are reported and left out of
  every other check, since which copy counts would depend on input order. Output
  is sorted by kind, subject and facts, so it does not depend on the order the
  caller listed records in.
- **`usage-regression` cannot fire through any syscall today.** The counter only
  goes up, except that `SYS_DATA_RESET` sets it to zero, and the reset clears
  `last_used` in the same critical section, so a legitimate period reset is not
  reported as tampering (see `data_state.rs`). `last_used` records only what the
  reconciler saw. The check remains a tripwire for any other path that lowers the
  counter.
- **The checks**, by group. Snapshot: `snapshot-too-large`. Binding and profile:
  `duplicate-account`, `duplicate-profile`, `enabled-profile-under-inactive-account`,
  `enabled-profile-unbound`, `profile-owner-unknown`, `multiple-enabled-in-slot`.
  Usage: `usage-regression`, `usage-over-cap-not-restricted` (active account, usage
  at or over cap, an open session), `anomalous-usage-no-escalation` (active account,
  usage at or past the escalation threshold). Sessions:
  `session-without-enabled-profile`, `session-account-mismatch`,
  `roaming-session-not-permitted`.

**Kernel glue.** `data.rs` owns the one `DATA` lock around `DataState`
(`data_state.rs`): a usage table and a session table, each bounded at 16
(`MAX_DATA_ACCOUNTS`, `MAX_DATA_SESSIONS`). A full table refuses and never evicts.
`DATA` is a leaf lock. No method calls out while holding it, and the syscall
handlers copy what they need before they audit. `data_codes.rs` holds the return
codes, the argument packing, the enum adapters, the demo plan table and the WORM
description strings, all host-tested.

**Syscalls.** `svc.rs`'s dispatch arms 19–23 (`SYS_DATA_*`), with `el0.rs` keeping
its own copies of the numbers, as the other mobile syscalls do.

| No. | Syscall | Arguments (x1, x2, x3) | Capability | Returns |
|---|---|---|---|---|
| 19 | `SYS_DATA_ACCOUNT` | account, bytes | `data:usage:{account}` | `0` none, `1` notify, `2` throttle, `3` suspend requested (advice); `4`–`7` refused |
| 20 | `SYS_DATA_SESSION_OPEN` | account, slot, profile \| roaming<<8 | `data:session:{account}` | `0` allow, `1` allow throttled; `2`–`6` engine denial; `7`–`13` refused |
| 21 | `SYS_DATA_SESSION_CLOSE` | account, slot, profile | `data:session:{account}` | `0` closed, `1` denied, `2` not open, `3` bad argument |
| 22 | `SYS_DATA_RECONCILE` | none | `data:reconcile` | incident count; `u64::MAX` if denied |
| 23 | `SYS_DATA_RESET` | account | `data:reset:{account}` + MARSHAL (`data.reset_usage`) | `0` counter reset; `1` no capability; `2` MARSHAL `Refuse`/`HardStop`; `3` MARSHAL local failure; `4` no entitlement; `5` no such account |

The refusal codes are named. For `SYS_DATA_ACCOUNT`: `4` no capability, `5` no
entitlement for the account, `6` no such account, `7` usage table full (bytes not
counted). For `SYS_DATA_SESSION_OPEN`: `7` no capability, `8` no entitlement, `9`
no such account, `10` profile not bound to this account, `11` unknown profile, `12`
malformed argument, `13` allowed by policy but the session table is full, so
nothing was recorded. The reset's codes are `RESET_OK`, `RESET_DENIED_CAPABILITY`,
`RESET_DENIED_MARSHAL`, `RESET_DENIED_LOCAL_FAILURE`, `RESET_NO_ENTITLEMENT` and
`RESET_NO_SUCH_ACCOUNT` in `data_codes.rs`. Its one argument is in x1, and x2 and
x3 are ignored.

**The packed third argument.** `SYS_DATA_SESSION_OPEN` takes the profile id in bits
0–7 and the roaming flag in bit 8. Bits 9–63 must be zero, or the call returns
`12`. The ABI passes three argument registers, and a session open needs four
values. The profile id is a `u8`, so its register has spare bits to carry the
flag, which avoids a second ABI widening for one bit. Rejecting reserved bits
means a caller that meant a wider id or a future flag is refused, not served the
wrong profile. `SYS_DATA_SESSION_CLOSE` takes a plain profile id. A roaming bit
there is a bad-argument error, because a caller that sets it is confused about
which call it is making.

**Check order inside each call.**

- *Session open:* capability; packed argument; entitlement; account exists;
  ownership (the profile must be bound to this account); lifecycle; engine. The
  ownership check comes before the lifecycle read, so the state of another
  account's profile is not revealed through a different code. The decision and the
  insert happen in one critical section under the `DATA` lock.
- *Usage feed:* capability; entitlement; account exists; saturating add; engine;
  WORM entries. The feed does not consult account standing or profile binding.
- *Close:* capability; plain profile argument; the open row is removed if present.
- *Reconcile:* capability; snapshot from copies; `reconcile`; WORM entries for each
  incident; `mark_observed`; incident count.
- *Reset:* capability (`data:reset:{account}`); entitlement; account exists;
  MARSHAL evaluate and enforce (`data.reset_usage`), with no lock held; only then
  the counter reset and the `last_used` clear, in one critical section; WORM entry
  with the before and after counter. The entitlement and account checks run before
  the gate, so a reset that cannot happen costs no network round trip.

**Separate capability scopes.** `data:usage:{id}` is separate from
`data:session:{id}` because the feed is privileged. Counting bytes into an account
can push it over its cap, which denies it service, and over the escalation
threshold, which makes the engine request suspension. Holding the right to open
and close sessions does not imply the right to meter. `data:reconcile` is not
account-scoped, because the reconciler reads every account in one pass and writes
only evidence and its own bookkeeping. `data:reset:{id}` is a third account-scoped
resource, separate from both. The reset lifts a cap, so neither the right to meter
nor the right to open sessions implies it.

**Not MARSHAL-gated, and why (four of the five).** None of the feed, open, close
or reconcile changes governance-consequential state. The feed moves a counter,
open and close change the session table, and the reconciler reads. The
consequential act a request can lead to, suspension, stays on `SYS_MVNO_SUSPEND`,
which is gated. The fifth, the usage reset, does lift a cap, so it is gated; see
the next subsection. The code comments also record why a gate on the other four
would be wrong: the reclamation work and the walk's evaluation budget are built
around the gated set. The CI boot assertions, in both boots, fail if a log line
contains `MARSHAL evaluation for data` unless that line names `data.reset_usage`,
and they require exactly one such line. That is a tripwire on the log. The
structural guarantee is that `MarshalAction` has one data variant, `DataResetUsage`,
so adding another data action would mean changing the enum. The walk performs
eight evaluations per boot: seven from the eSIM and MVNO calls and one from the
reset.

**The governed usage-period reset (`SYS_DATA_RESET`, syscall 23).** It starts a new
usage period for one account by zeroing its counter. It is the one data syscall
the MARSHAL gate covers. It is gated because it lifts a cap: whoever can run it can
restore service the plan had withheld, the same kind of act as
`SYS_MVNO_REACTIVATE`. The decision is recorded in
[adrs/0002-usage-reset-is-marshal-gated.md](adrs/0002-usage-reset-is-marshal-gated.md),
which follows [adrs/0001-data-syscalls-not-marshal-gated.md](adrs/0001-data-syscalls-not-marshal-gated.md)
and names a reset as the revisit trigger for leaving the four ungated.

What it does, in order (`svc.rs`'s `data_reset`):

1. Capability `data:reset:{account}`, re-checked on every call. A denial prints to
   the serial log only.
2. Entitlement, then account existence (a lookup in the registry that fails only for
   an unknown account). Both run before the gate, so a reset that cannot happen costs
   no network round trip. Each refusal is WORM-audited with `authorized=false`.
3. MARSHAL evaluation of `data.reset_usage`, with the Kerkese action
   `{"type":"data.reset_usage","account":A}`. `Execute` and `Unreachable` proceed,
   which is the fail-open policy every gated action shares. `Refuse` and `HardStop`
   deny, and nothing is audited for them, as for the other gated syscalls. A local
   evaluation failure denies and is WORM-audited.
4. Only then the data lock. The counter goes to the pure `reset_usage()` (zero),
   and the reconciler's `last_used` for the account is cleared in the same critical
   section. The reconciler therefore reads the reset as a new period and does not
   report a `usage-regression`. No lock is held across step 3.
5. A WORM entry with the before and after counter, then the serial line.

It does not close sessions, change standing, or touch profiles. It does not check
whether the account is Suspended or Closed. A reset on a suspended account lifts the
cap, but session open still reports `Suspended` first, so service is not restored
until `SYS_MVNO_REACTIVATE`. A reset of an account that has no usage row succeeds and
creates no row; its WORM entry reads `used 0 -> used 0`. The reset does not check the
counter before zeroing it, so it zeroes an account under its cap as readily as one
over it. Its WORM entry does record the counter's value before the reset.

Its return codes are in the table above. In the boot walk the reset is evaluated
as `data.reset_usage` with the no-proxy verdict `Unreachable`. The
desktop `citadel_proxy` recognizes the action, so a proxy-backed boot reads
`Execute` and a boot whose proxy refuses it reads `Refuse`. The reset is therefore
asserted in all five QEMU boot steps, and each step also checks the outcome its
configuration produces.

**Audit trail.** Data entries go to the same chain as the eSIM and MVNO transitions
(`ESIM_WORM_LOG`). Calls past the capability check normally append at least one
entry. The exceptions are listed at the end of this subsection.

- `data:usage:{id}`, feed: `used N -> used M`, `authorized=true`. Refusals (no
  entitlement, no such account, table full) are `authorized=false`, with
  `Metered -> Metered`.
- `data:usage:{id}`, advisory request: `band X -> REQUEST <action> (advisory;
  nothing was performed by this syscall)`, `authorized=true`. One is written for
  every escalation, including `NotifyOnly` and `Throttle`, not only suspension.
  `authorized=true` here means the feed was authorized and advice was issued. It
  does not mean any state changed.
- `data:session:{id}`, decision: an allowed open is `Closed -> Open` (or
  `Open (throttled)`), `authorized=true`. An engine denial or a kernel-side refusal
  is `Closed -> Open` with `authorized=false`, and the cause is in the reason. An
  allowed open that the full table could not record is `authorized=false`, and its
  reason says so.
- `data:session:{id}`, close: `Open -> Closed (by caller via SYS_DATA_SESSION_CLOSE)`,
  `authorized=true`. Closing a session that is not open is `Closed -> Closed`,
  `authorized=false`.
- `data:reconcile:<subject>`, incident: `expected <fact> -> observed <fact>`,
  `authorized=false`, with a reason beginning `RECONCILER EVIDENCE (observed drift,
  not a denial; nothing was corrected)`. **This `authorized=false` is not a
  denial.** A reader tells the two apart by the `data:reconcile:` subject prefix and
  that reason.

- `data:reset:{id}`, applied: `used B -> used A`, `authorized=true`, with the reason
  `usage period reset (new period); reconciler memory cleared; no session, standing
  or profile changed`. The entry does not record the MARSHAL verdict. `Execute` and
  `Unreachable` produce the same entry.
- `data:reset:{id}`, refused for no entitlement or no such account:
  `usage period in force -> usage period in force`, `authorized=false`.
- `data:reset:{id}`, MARSHAL local failure: `usage period in force -> new usage
  period (counter reset)`, `authorized=false`, with the local-failure reason.

Not audited, serial line only: capability denials on all five data syscalls, a
malformed argument to `SYS_DATA_SESSION_CLOSE`, a reconcile pass with zero
incidents, and a reset that MARSHAL `Refuse`s or `HardStop`s, as for the other
gated syscalls.

**What the boot walk proves.** The walk in `el0.rs` runs between the first `ENABLE`
(profile 0 is bound to account 0 and `Enabled`) and the existing `SUSPEND(0)`. That
is the first point where a session can be allowed in the walk. The second is after
the reset, at steps 12 to 16. In order:

1. `SESSION_OPEN(0, 0, 0)`: allowed (`0`), usage 0.
2. `SESSION_OPEN(0, 0, roaming)`: denied `RoamingDataNotAllowed` (`5`). The home
   session is left open.
3. `ACCOUNT(0, 900)`: 900 of 1000 bytes, so `Throttle` is requested (`2`).
4. `SESSION_OPEN(0, 0, 0)`: `AllowThrottled` (`1`). The live row is refreshed, not
   duplicated.
5. `ACCOUNT(0, 700)`: 1600 bytes, 160% of cap, so `SuspendAccount` is requested
   (`3`). The account is still Active and the session still open.
6. `SESSION_OPEN(0, 0, 0)`: denied `CapExceeded` (`6`). The open session is not
   closed.
7. `RECONCILE`: two incidents, `usage-over-cap-not-restricted` (expected
   `Suspended`, observed `1600/1000`) and `anomalous-usage-no-escalation` (expected
   `150%`, observed `1600/1000`).
8. `SUSPEND(0)`, the existing MARSHAL-gated suspension. Profile 0 is force-disabled.
9. `RECONCILE`: one incident, `session-without-enabled-profile` (expected
   `Enabled`, observed `Disabled`). The usage incidents are gone. Suspension does
   not close sessions.
10. `SESSION_CLOSE(0, 0, 0)`: closed by the caller (`0`, audited).
11. `RECONCILE`: zero incidents.

The second phase runs after the walk's second `ENABLE`, which re-enables profile 0.
Account 0 is Active again, usage is still 1600 of 1000 bytes, and no session is open.

12. `SESSION_OPEN(0, 0, 0)`: denied `CapExceeded` (`6`). The cap is still in force.
13. `SYS_DATA_RESET(0)`: capability `data:reset:0`, then MARSHAL `data.reset_usage`
    (the eighth evaluation of the boot, `Unreachable` here), then usage 1600 -> 0 with
    the reconciler's memory cleared. This is the only reset in the walk. It closes no
    session.
14. `SESSION_OPEN(0, 0, 0)`: allowed (`0`), `used=0`. Service is restored.
15. `RECONCILE`: zero incidents. The reset cleared `last_used`, so 1600 -> 0 is not
    reported as a regression.
16. `SESSION_CLOSE(0, 0, 0)`: closed by the caller (`0`, audited).

Denial proofs: `SESSION_OPEN(0, 0, 1)` on profile 1, which is installed but never
bound, is refused with `10`. `SESSION_OPEN(99, ...)`, `ACCOUNT(99, ...)` and
`SYS_DATA_RESET(99)` are refused by the capability check, before any state is read
or MARSHAL is consulted.

Documented choices:

- **A clean pass needs either a suspended account or a reset.** After `REACTIVATE`
  the account is Active again at 160% of cap. `anomalous-usage-no-escalation` fires
  for an Active account whether or not a session is open, and the reconciler would
  correctly raise it again. The first clean pass is therefore the one at step 11,
  while the account is suspended. The one at step 15 is clean because the reset
  zeroed the usage.
- **Real demo numbers.** Account 0 is the only entry in the kernel's plan table:
  cap 1000 bytes, throttle at 80% (800), escalation at 150% (1500), roaming not
  allowed. The walk feeds 900 and then 700. Nothing else in the boot exercises a
  second account's plan.

**Tests.** 71 host tests cover the data layer: 19 in `policy.rs` and 21 in
`reconcile.rs` (`mobile/`), 15 in `data_state.rs` and 16 in `data_codes.rs` (the
`kernel-arm` lib target). They cover the band boundaries at `u64::MAX`, the
replay property, the deny-reason precedence, the table bounds, idempotent opens,
and the encodings of every return code. The reset's gate decision is among them:
`Refuse`, `HardStop` and local failures block, and `Execute` and `Unreachable` pass.
The reset's counter change and `last_used` clear are tested in `data_state.rs`. The
kernel-side refusal codes (`7`–`13`) are pinned as values and checked for
distinctness. The boot walk exercises only some of them. The reset's capability
scope is tested in `capabilities.rs`, and `data.reset_usage`'s JSON and label in
`marshal_action.rs`.

**Gaps, specific to this section.** The over-cap-until-reboot limitation is closed by
the governed reset above. What the reset adds, and what remains, is listed here and
in THREAT_MODEL.md's mobile gaps (25 to 27).

- Usage is caller-asserted. Nothing measures it, so whoever holds `data:usage`
  decides the numbers. The reset does not read the counter, so the numbers do not
  decide whether a reset happens.
- The reset is a privileged lever. A holder of `data:reset:{id}` who gets an
  `Execute` or `Unreachable` verdict can restore service. `Unreachable` passes, so a
  proxy that is down or cut off lets a reset through with no verdict. The reset's
  WORM entry does not record which verdict it got.
- There is no period clock. Nothing schedules a reset, and nothing limits how often
  one can be issued. A reset on a suspended account lifts the cap without restoring
  service.
- Policy only requests. A caller that ignores a suspension request leaves the
  account Active, and an already-open session stays open.
- Sessions are a kernel table that no traffic path reads. A denial is a
  bookkeeping fact until a data path exists.
- Sessions survive suspension and deletion. Only `SYS_DATA_SESSION_CLOSE` removes
  them.
- Calls past the capability check append WORM entries, and nothing bounds the log.
  The reconciler re-records the same incidents on every call while drift persists.
- The reconciler runs only when called, and a clean pass leaves no WORM entry.
- The snapshot and the session-open decision read live state under separate locks.
  That is consistent with one EL0 context and IRQs masked during the SVC handler,
  and not otherwise.
- The usage feed does not check standing or binding, so a suspended account keeps
  accruing counted usage.
- Demo plans and the single account are compiled in. There is no provisioning path.

### EL0 process model (`elf.rs`, `loader.rs`, `process.rs`, `scheduler.rs`, `el0_exec.rs`, `net_process.rs`)

Built and QEMU-verified:

- **ELF64 parser** (`elf.rs`): accepts `ET_EXEC` and `EM_AARCH64` only, and
  checks every `PT_LOAD` range against the image length before anything is
  copied from it.
- **Loader with W^X** (`loader.rs`): maps segments into an address space. A
  segment that is both writable and executable is rejected
  (`SegmentWritableAndExecutable`). That is stricter than the x86_64 loader,
  which maps such a segment. A 64 KiB unmapped guard gap sits between the
  segments and the 16 KiB EL0 stack. Nothing has yet faulted into that gap, so
  it is a layout property that has not been tested.
- **Per-process address spaces** (`process.rs`): each process has a private
  level-1 table, seeded from the kernel's. Private pages live in the window
  `0x8000_0000`–`0xBFFF_FFFF` (level-1 index 2), which never shares
  translation structures with code EL1 must keep fetching. There is no
  `TTBR0`/`TTBR1` split: the kernel stays identity-mapped under `TTBR0_EL1`,
  because a split means relinking the kernel high, which is more change than
  the mobile work needed. There are no ASIDs. Every switch is a full
  `tlbi vmalle1`, because the mappings are Global. `AddressSpace::destroy()` is
  the reclamation path (see the bug entry below).
- **Cooperative scheduler** (`scheduler.rs`): round robin. A switch saves the
  AAPCS64 callee-saved set, including `d8`–`d15` (the low halves of
  `v8`–`v15`), 160 bytes in all. Threads may own an address space, and
  `TTBR0_EL1` is written only when it changes. Exited threads are reaped.
- **One-shot EL0 entry** (`el0_exec.rs`): an EL1 frame `eret`s to EL0 and
  resumes when the EL0 code issues its done syscall (`SYS_EL0_PROOF_DONE` 13,
  `SYS_NET_PROOF_DONE` 14, `SYS_MARSHAL_PROOF_DONE` 15). At most one excursion
  is in flight at a time, and EL0 can finish but cannot yield.
- **`net-driver-host-arm`**: a separate compiled ELF, embedded at build time,
  containing a ported virtio-mmio/virtio-net driver and `smoltcp`. Its one
  kernel-mediated authority is the MMIO window for its own virtio slot, checked
  by `check_mmio_window` (containment, computed with `checked_add`). It does
  real outbound TCP, both for the `10.0.2.100:9000` proof round trip and for
  MARSHAL requests. Its poll loops are bounded by iteration counts
  (2,000,000 for the connect-and-exchange loops, 200,000 for the graceful
  close), not by time.
- **Channels** (`ipc_channel.rs`): four single-byte mailboxes in their own
  `ipc:{n}` space, re-checked on every call (`SYS_IPC_SEND` 11,
  `SYS_IPC_RECV` 12).

Not present, stated so none of it is assumed:

- **Timer-driven preemption.** The generic timer is read for the current time,
  but never raises an interrupt that reschedules. EL0 code runs until it
  issues a syscall, and the kernel cannot interrupt it.
- **Guard pages under EL1 thread stacks.** Those stacks are 8 KiB heap blocks.
- **A per-thread EL1 entry stack and a general `SYS_YIELD`.** Until these
  exist, EL0 can finish but cannot yield, and only one excursion runs at a time.
- **A typed IPC layer for the channels.** They carry raw bytes. The MARSHAL
  path does use the typed `runix-ipc` wire format.
- **A per-process capability model.** One global capability set serves the
  single EL0 context, which is why the MARSHAL principal is a placeholder.
- **A real secure world.** EL3 here is this crate's own boot code
  (`vectors.rs`, `nonsecure.rs`), not TF-A firmware, so no secure-world code
  runs or is isolated from the kernel.
- **Persistent storage, the real RIL/SIM/eUICC protocol, and real hardware.**
  Everything runs under QEMU (`virt`, `cortex-a53`).

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
ruled out as the cause without being root-caused further at the time.
Reverted the bit rather than block on it, with two later follow-up
investigations that did eventually root-cause and fix it — see further
below, after the other bugs found in between. Third, in
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

A follow-up investigation into the `AP[2:1]=0b01` QEMU hang above, not
yet a resolution: rather than re-deriving the same "hangs, not
root-caused" result, this pass swept all four `AP[2:1]` encodings on the
same table entry to narrow down *which* bit actually triggers it. `0b00`
(then-current value) works, `0b01` (`AP[2]`=0, EL1 rw / EL0 rw — what's
actually wanted) hangs immediately at `SCTLR_EL1.M`/`isb`, and
`0b10`/`0b11` (`AP[2]`=1, EL1 read-only either way) both instead get
*past* that point — "MMU enabled" prints — and hang one step later,
exactly where the next code needs to write to this block's own stack,
which is the expected consequence of making EL1's data read-only, not an
anomaly. That localized the real issue precisely: `AP[2]=0` (EL1 keeps
full read/write, architecturally unaffected by `AP[1]` per the spec)
combined with `AP[1]=1` (EL0 access newly granted) hangs immediately,
while every `AP[2]=1` encoding gets further. Also ruled out this pass:
`nG` (bit 11) set alongside `0b01<<6` — identical immediate hang. Checked
for a matching known QEMU issue (none found, QEMU 10.1.5, `cortex-a53`
and `max` both reproduce it identically — not CPU-model-specific
either). Reverted again pending the actual root cause.

**Third pass: root-caused and fixed for real.** `-d int,guest_errors`
tracing (QEMU's own exception log, independent of whether this crate's
handler ever runs) showed the "hang" was never a soft lockup — it's a
real, repeating `Taking exception 3 [Prefetch Abort]`, `ESR
0x21/0x8600000d` (`EC=0x21` Instruction Abort from-EL1-to-EL1,
`IFSC=0b001101` Permission fault level 1), `FAR`/`ELR` both pinned at the
*exact address of `el1_exception_vectors`' own vector-4 entry*. EL1's
exception vector table, living in the same 1 GiB block, could no longer
be *fetched* once `AP[1]=1` was set anywhere in that block — even though
`AP` bits are architecturally defined to gate data access, not
instruction fetch (`UXN`/`PXN` govern that, and neither was set). A
genuine QEMU/TCG emulation bug, not a logic error in this crate's
descriptors.

The fix isn't a workaround for the QEMU bug — it's to stop triggering it,
by never putting `AP[1]=1` on a region that also contains code EL1 needs
to keep fetching. `mmu.rs` now builds a real three-level translation
table: the Normal region stays mostly 2 MiB blocks (`AP[2:1]=0b00`,
identical to before), except the one 2 MiB slice containing this crate's
own image, which descends to 4 KiB pages. Only `el0_demo`'s code page
and `EL0_STACK`'s pages (computed from their real linked addresses, not
hardcoded offsets) get `AP[2:1]=0b01`; `el1_exception_vectors` and
everything else stays `AP[2:1]=0b00`. This sidesteps the QEMU bug
entirely and *is* the architecturally correct design anyway — real
isolation needs page-granular permissions, not "the whole block or
nothing."

One real bug surfaced building the fix, worth remembering as its own
lesson: the first attempt still hung, identically, even with the fix in
place — because `el0_demo`'s `.balign 4096` only aligns its own *start*,
not its whole page. The linker packed `el1_exception_vectors` right
after it in the same 4 KiB page (confirmed via `nm`: `el0_demo` at
`0x40081000`, `el1_exception_vectors` at `0x40081800`, both inside
`[0x40081000, 0x40082000)`), so marking "el0_demo's page" EL0-accessible
silently marked the vector table too, retriggering the exact same fault
at a smaller scale. Fixed by padding `el0_demo`'s `naked_asm!` with a
*trailing* `.balign 4096`, forcing whatever the linker places next onto
a fresh page instead of packing it into el0_demo's unused tail space.
After that fix, confirmed with a real EL0 *data* access, not just "no
crash": `el0_demo` now pushes a byte onto its own stack and reads it
back via genuine `strb`/`ldrb` through `SP_EL0`, echoed via `SYS_WRITE`
(`'B'`, `0x42`) — a real read/write round-trip through the page-granular
mapping, verified in QEMU for both the `secure=on` and no-`secure`
boot paths. See `mmu.rs`'s doc comment on `Level3Table` for the complete
account.

- **A resource leak that silently turned MARSHAL off (`kernel-arm`).** Every
  MARSHAL evaluation process leaked its address space (~332 KiB) and its
  thread stack. The 4 MiB EL1 heap drained after roughly eight evaluations.
  The next evaluation's setup failed with out-of-memory, and that failure was
  mapped to `Unreachable`, which is fail-open. From then on MARSHAL was off for
  the rest of the boot, and the only trace was an ordinary `Unreachable` line.
  Two fixes, both needed:
  1. **Real reclamation.** `AddressSpace::destroy()` (`process.rs`) frees only
     memory the space owns. `reclaim.rs`'s `plan_frees` validates every extent
     before any free (4 KiB alignment, non-empty, inside the heap, no
     overlaps, so a double free is refused). `destroy` refuses the live
     `TTBR0_EL1` space and never frees an MMIO window, and it flushes the TLB
     before any frame is freed. The virtio device is reset first, so it cannot
     DMA into memory the heap has since reused. Exited threads are reaped by
     `scheduler::reap_exited`. `reclaim_proof.rs` runs 24 evaluations and checks
     that every thread was reaped and that heap use stays within a 16 KiB
     budget. The measured drift was zero.
  2. **A policy split.** A local failure of the evaluation machinery (setup or
     out-of-memory, spawn, EL0 fault) now fails closed and is WORM-audited.
     Only an unreachable remote stays fail-open. The reason: a buggy or hostile
     EL0 caller can exhaust resources just by repeating governed syscalls, so
     treating a local failure as fail-open would let it bypass MARSHAL.

  Residual leaks, tracked and not yet closed: the boot proofs' own one-off
  threads and address spaces (about 332 KiB, once per boot), and an evaluation
  that times out or faults before its process exits.

- **Source-port reuse: only the first MARSHAL evaluation per boot reached the
  listener (`kernel-arm`).** Every evaluation process connected from the same
  source port, 49152. The EL0 driver never sets smoltcp's random seed, so the
  initial sequence number did not vary between processes, and no process sent a
  FIN. Behind SLIRP's `guestfwd`, the second and later connections were
  therefore indistinguishable from the first, and the listener only ever saw
  one. Fix: each evaluation gets its own source port, 49153 through 65152,
  wrapping (`marshal_action.rs`'s `marshal_local_port`, pinned by
  `marshal_local_ports_are_distinct_in_range_and_wrap_safely`), and the process
  closes its connection gracefully within a bounded poll budget. This failure
  appeared only with several evaluations in one boot, so single-evaluation
  proofs did not catch it. It needed a real multi-evaluation run to show.

## MARSHAL Verifier identity: the `citadel_proxy` becomes a real second principal

`docs/RFC-VERIFIER-IDENTITY.md` (Option A, repo-owner-approved) fixes the
specific defect that made `kernel/src/grid_sandbox.rs`'s shadow-mode MARSHAL
evaluation provably trip CITADEL Gate 3's `NDS_SAME_IDENTITY` hard-stop
regardless of deployment config: the kernel used to build a Kerkese-shaped
envelope asserting `"actor":"kernel","verifier":"kernel"` — one identity
playing both Separation-of-Duties roles, plus bare strings where CITADEL's
real `KerkeseActor`/`KerkeseVerifier` Go types expect objects.

**What changed, and where:**

- `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate` — **one string
  literal changed**, nothing else in that function or file: the kernel now
  asserts `actor` as a real `{"user_id":"kernel:grid_sandbox","role":"operator"}`
  object and never asserts a `verifier` at all. (This landed alongside a
  separate, parallel task turning shadow-mode evaluation into real
  enforcement — the two changes touch the same function for unrelated
  reasons; this section covers only the envelope-shape/identity change.)
- `desktop/src/citadel/identity.rs` (new): the proxy's own Ed25519 demo
  keypair (`proxy_signing_key`/`proxy_verifying_key`, a fixed seed distinct
  from both of `kernel/`'s demo trust roots — same "prove the wiring works,
  not a real trust anchor" honesty `kernel/src/capabilities.rs`'s own demo
  key already documents), real `KerkeseActor`/`KerkeseVerifier`/`KerkeseSoD`/
  `KerkeseAction`/`KerkeseEvidence`/`Kerkese` structs matching
  `citadel/internal/marshal/types.go` field-for-field, a `canonical_payload`
  function that reproduces `citadel/internal/marshal/sig.go`'s
  `CanonicalPayload` byte-for-byte (verified by a fixture test against the
  same date `citadel/internal/marshal/marshal_test.go`'s `baseKerkese` uses),
  and `sign_verifier_payload` — a real Ed25519 signature over that payload,
  not a placeholder.
- `desktop/src/citadel/policy.rs` (new): the proxy's own local policy check,
  run *before* it ever attaches its Verifier identity. Real, scoped
  honestly: it recognizes only action types CITADEL's own `rbacMap` lists
  for `grid_sandbox.spawn_instance`, validates `module_id`/`instance_id`/
  `actor.user_id` are well-formed, requires `dry_run` to be present rather
  than defaulted, and refuses outright if the kernel's request already
  carries a `verifier` (a regression guard, not just a shape check). What it
  is **not**: a re-verification of `InstanceManifestEntry`'s signature —
  that data is kernel-owned, in-memory state (`kernel::citadel::demo_authorize_instance`
  builds a throwaway, self-signed, self-verified allowlist per call, see
  that function's own doc comment) with no persisted, independently-checkable
  form this process can reach without an `ipc::marshal::MarshalRequest`
  wire-contract extension — out of this change's scope, flagged here rather
  than faked.
- `desktop/src/citadel/proxy.rs` — rewritten from a pure byte-forwarder
  (its old module doc comment's own description) into a real
  parse → policy-check → enrich → forward pipeline: `build_response` now
  parses the kernel's minimal envelope, calls `policy::check`, and only on
  success builds the enriched `Kerkese` (fresh UUID `execution_id` — the
  kernel's own `instance_id` isn't UUID-shaped, so it's carried instead in
  `evidence.extra.kernel_execution_id` — a real UTC timestamp, and a real
  `sig_verifier`) before ever calling `HttpKerkeseTransport::submit`. A
  policy refusal returns `MarshalError::Other` and never touches the
  transport at all.

**Verified, specifically, that this fixes the SoD defect** — not just that
the code compiles: `desktop/src/citadel/proxy.rs`'s
`enriches_envelope_with_a_distinct_signed_verifier_identity_before_forwarding`
test captures the *actual bytes this proxy POSTs*, decodes them as a real
`Kerkese`, and asserts `sod.operator_user_id != sod.verifier_user_id`
(`"kernel:grid_sandbox"` vs. `"citadel_proxy:verifier"`), that `actor.role`
(`"operator"`, CITADEL's `roleGroupMap` → `"privileged"`) and `verifier.role`
(`"auditor"` → `"oversight"`) land in different groups (Gate 3's second,
independent same-*group* check), and that `sig_verifier` is a real signature
verifying under the proxy's own key over `canonical_payload` of exactly that
envelope. A second test, `policy_refusal_never_forwards_to_citadel`, proves
a policy-refused request never reaches the transport at all (the mock
CITADEL endpoint panics if it receives a connection it shouldn't).

**What's still scoped down — flagged, not faked:**

- **Signature registration against a live CITADEL deployment.** `sig_verifier`
  is computed correctly and verifies under the proxy's own key, but nothing
  registers `proxy_verifying_key()` with a real `Store::GetSigningKey`
  lookup, and CITADEL's `EnforceSignatures` defaults to `false` anyway (see
  `Engine::EnforceSignatures`'s own doc comment) — so today this is *evidence
  a real Verifier co-signed the request*, not something any live deployment
  actually checks. Real key provisioning is its own ADR per the RFC's open
  questions section, and needs infrastructure (CITADEL-side key registration,
  sinauth-backed `VerifierToken`) outside this repo.
- **The SoD-fix claim was verified by construction/inspection, not by
  running the real Go `gate3NDS` code against this envelope.** This session
  did not modify the sibling `opensecstack/opensecstack` working directory
  (out of caution about write access/scope to another project) — the proof
  is the Rust-side test above plus direct comparison against
  `citadel/internal/marshal/marshal.go`'s real `gate3NDS`/`roleGroupMap`
  source (read, not executed, as part of this change) and
  `marshal_test.go`'s `TestGate3_HardStop_SameIdentity`/`TestGate3_HardStop_SameGroup`
  fixtures, which show exactly what a real Gate 3 run keys its checks on.
  Running the actual Go engine against this envelope (or adding an
  equivalent Go-side test) is real, valuable follow-up work this change
  did not do.
- **No new `ipc::marshal::MarshalRequest` field for kernel-asserted evidence**
  (e.g. an `InstanceManifestEntry` the proxy could independently re-verify)
  — the RFC's "What changes" section names this as a plausible next step;
  it's an `ipc` wire-contract change and was out of this change's scope.
- **`citadel-integration::WormLog` does not yet record the proxy's own
  verification decision as a separate evidence entry** (the RFC's "two
  principals, two log entries" goal) — `desktop/` has no WORM-writing path
  today; this is follow-up work, not attempted here.

Verified: `cargo build --workspace`, `cargo test -p runix-desktop` (19/19
passing, including the two tests above), `cargo clippy -p runix-desktop
--all-targets -- -D warnings` (clean), and a standalone
`cargo build --target x86_64-unknown-none` from `kernel/` under
`nightly-x86_64-pc-windows-gnu` (per `docs/BUILDING.md`'s Windows toolchain
note) confirming the one-line `grid_sandbox.rs` change still compiles
against the kernel's real target.

## `SYS_IPC_RECV` capability gate — Option A (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`) implemented

The finding: any process that could issue `SYS_IPC_RECV` at all could drain
*any* port's queue, including a response port a completely different,
legitimately-authorized client was waiting on — `blk-driver-host`'s shared
`FS_RESPONSE_PORT` was the concrete leak (a per-file `CapabilityToken`
gated *asking* to read a file, but not *receiving* the answer). Fixed per
the repo-owner-approved Option A: `SYS_IPC_RECV` now calls the same
`authorized_for_port` gate `SYS_IPC_SEND`/`SYS_IPC_SEND_LOCK`/
`SYS_IPC_SEND_UNLOCK` already had, and the filesystem surface's single
shared response port is retired — each client's `FsRequest` now carries
its own response port plus a second `CapabilityToken` scoped to it
(`ipc/src/fs.rs`), verified by `blk-driver-host` before it ever answers on
that port. Port `9` (formerly `BLK_FS_RESPONSE_PORT`) is now free;
`kernel/src/main.rs` carries a documented allocation map of all 16 ports
so the next service doesn't pick a colliding number by hand.

**A real, measured performance regression was found and fixed while
verifying this, not just a theoretical concern.** `SYS_IPC_RECV`'s
universal calling convention across this entire codebase (`blk-driver-host`,
`net-driver-host`, `marshal_client`, every kernel test that receives) is a
tight busy-poll loop — yield-and-retry, up to hundreds of thousands of
iterations, while waiting for a response. Before this change, an empty
poll was a cheap lock-and-check (`ipc::try_recv`'s `pop_front` on an empty
queue). With the naive fix (check `authorized_for_port` — a real Ed25519
signature verification — on *every* poll, empty or not), a single
`net_driver_sockets.rs` run went from finishing in seconds to still not
finishing after 10+ minutes under QEMU/TCG, indistinguishable from a hang
until directly instrumented and confirmed to be genuinely (if extremely
slowly) progressing. Root cause confirmed by iteration-count debug logging,
not guessed. Fixed with `ipc::is_empty` (`kernel/src/ipc.rs`): a cheap peek
before the expensive check — `SYS_IPC_RECV` now costs what it always did
on an empty port (the overwhelming majority of polls in this calling
pattern) and only pays for real signature verification once there is an
actual byte to reveal. The one honest tradeoff this introduces: an empty
port and an unauthorized-but-nonempty port are no longer *timing*-
indistinguishable to the caller (both still return the same `u64::MAX`, so
the *outcome* is unchanged) — accepted for now, consistent with this
project's threat model already treating other timing side channels as out
of scope (see `docs/THREAT_MODEL.md`).

**Every real `SYS_IPC_RECV` call site in the tree was audited and fixed**,
per the RFC's own top-named risk (an unauthorized receive is silently
indistinguishable from an empty port, so a caller missing a token doesn't
error, it just never sees data): `blk-driver-host` (both request ports),
`net-driver-host` (`SOCK_REQUEST_PORT`, needed in every test file that
spawns it with `serve_sockets: 1` — `net_driver_sockets.rs`,
`net_driver_sockets_concurrent.rs`, `marshal_tcp_roundtrip.rs`,
`marshal_proxy_e2e.rs`, `grid_sandbox_marshal_shadow.rs`), and every client
thread that calls `marshal_client::evaluate`/receives sockets responses
directly (same five files above, each needed a self-granted
`SOCK_RESPONSE_PORT` receive token via the new
`scheduler::grant_current_extra_capability` — a thread that never went
through a `spawn*` call carrying the token it needs grants it to itself at
its own start, deliberately not exposed as a syscall, kernel-internal
plumbing only).

Verified in QEMU, every affected test, real pass/fail:
`blk_fs_ipc.rs`/`blk_fs_concurrent.rs`/`blk_fs_concurrent_write.rs` (native
Windows), `net_driver_sockets.rs`/`net_driver_sockets_concurrent.rs`/
`marshal_tcp_roundtrip.rs`/`grid_sandbox_marshal_shadow.rs`/
`marshal_proxy_e2e.rs` (this project's Fedora WSL environment — native
Windows QEMU's Slirp still can't run `guestfwd` helpers on this machine,
same pre-existing limitation earlier MARSHAL work already worked around).
`marshal_proxy_e2e.rs` in particular re-proves the real `citadel_proxy`
binary's full chain (mock CITADEL endpoint -> real HTTP -> real proxy ->
real TCP -> sockets IPC) still works correctly under the new recv gate.
`cargo build --workspace` and the kernel's own
`cargo build --target x86_64-unknown-none` / `cargo clippy --target
x86_64-unknown-none --bins --lib -- -D warnings` all clean.

**What Option A does not close, named explicitly per the RFC**: this
supports roughly eight capability-separated clients system-wide (the
free port slots), all known at build time — `net-driver-host`'s sockets
surface got the receive-side gate "for free" but not per-handle owner
attribution (`ipc/src/sockets.rs`'s existing caller-attribution caveat
still applies). Option C (a real session/handle primitive keyed on a new
thread identity) remains the named long-term destination, not attempted
here.

## Option C: the session/handle IPC primitive — kernel side built and proven, consumers not migrated

Follow-up to the section above. `docs/RFC-IPC-RESPONSE-CAPABILITY.md`
recommended building this in two independent steps — `ThreadId` first,
then the session table — and that's what happened, in one pass:

- **`ThreadId`** (`kernel/src/scheduler.rs`): a monotonic, never-reused
  `u64` assigned in `Thread::new` (and `Thread::placeholder` — the boot
  thread is a real session participant too, several kernel tests already
  drive IPC directly from it via `grant_current_extra_capability`).
  `scheduler::current_thread_id()` exposes it the same way
  `current_capability` already exposes the running thread's token.
- **The session table** (`kernel/src/ipc.rs`): additive alongside the
  existing fixed `[Mutex<Channel>; PORT_COUNT]` array, which is completely
  untouched — `SESSIONS: Mutex<BTreeMap<SessionId, Session>>` plus
  `PENDING_BY_PORT` (a FIFO of opened-but-not-yet-accepted sessions, keyed
  by the fixed `server_port` whose capability convention gates them).
  Bounded (`MAX_LIVE_SESSIONS = 64` global, `MAX_SESSIONS_PER_OWNER = 8`)
  so a hostile client can't exhaust kernel heap by open-looping.
  `SessionId`s are never reused, same reasoning `capabilities.rs`'s tokens
  already have for not being guessable/replayable.
- **Six syscalls** (`kernel/src/syscall.rs`, numbers 10-15):
  `SYS_IPC_SESSION_OPEN`/`_ACCEPT`/`_SEND`/`_RECV`/`_SEND_LOCK`/
  `_SEND_UNLOCK`. The RFC's own prose named three; building it surfaced a
  real gap the prose didn't resolve — nothing told a server a new session
  existed to receive from unless it already knew the `SessionId`, so
  `SESSION_ACCEPT` (a real listen/accept step, not just send/recv) had to
  exist. The send-lock pair mirrors `SYS_IPC_SEND_LOCK`/`_UNLOCK` exactly,
  scoped to one session instead of one fixed port — the RFC's own "Cost,
  honestly" section already named this as needed, just didn't count it in
  the headline "three syscalls."
- **A design decision the RFC's prose left ambiguous, resolved and
  documented**: `Session.server` is `Option<ThreadId>`, bound lazily by
  whichever thread's `SESSION_ACCEPT` first claims a pending session — not
  pinned at `OPEN` time, since the kernel has no way to know in advance
  who (if anyone) will ever accept it.
- **Teardown on exit**: `scheduler::reap_zombies` now calls
  `ipc::reap_sessions_for(thread.id)` for every reaped zombie — removes
  every session that thread owned or served, and purges any of its
  still-pending opens. This resolves the RFC's own flagged lock-ordering
  concern directly: `reap_zombies` already holds `SCHEDULER`'s lock and
  already has the zombie's `id` in hand, so session-table cleanup never
  needs to re-acquire `SCHEDULER` — `SCHEDULER` → `SESSIONS`/
  `PENDING_BY_PORT` is the only lock order that occurs anywhere in the
  kernel; every other caller (the session syscalls) only touches
  `SCHEDULER` via `current_thread_id()`, which fully releases it before
  returning.

**Verified in QEMU** (`kernel/tests/ipc_session.rs`, three phases in one
boot): capability denial (a thread with no `port:<n>` token is denied both
`SESSION_OPEN` and `SESSION_ACCEPT`); real isolation (two client threads
open independent sessions against one server thread on the same port,
each sends its own 4-byte pattern, and each gets back *only* its own bytes
echoed — the actual property this primitive exists to prove, not argued
about); and real teardown (a session's owner exits mid-session — sequenced
via an explicit flag handshake, not a fixed yield count, so the timing is
deterministic despite this scheduler's real timer preemption — and the
still-alive server thread's `SESSION_SEND` to that exact session id
transitions from succeeding to `u64::MAX` once the exit is reaped).
Re-ran the entire existing kernel test suite afterward (not just the new
file) since this touches `scheduler.rs`/`ipc.rs`, both load-bearing for
nearly everything: `basic_boot`, `guard_page`, `thread_reclaim`,
`watchdog`, `process_isolation`, `elf_loader`, `scheduler_address_space`,
`ring3_cooperative`, every `grid_sandbox_*` test, `citadel_demo`,
`pci_scan`, every `net_driver_*`/`blk_*` test, `marshal_tcp_roundtrip`,
`grid_sandbox_marshal_shadow`, and `sys_random` all still pass unchanged.
(`net_driver_sockets`/`net_driver_sockets_concurrent`/`net_driver_tcp`/
`marshal_proxy_e2e` fail the same pre-existing way they always do on native
Windows — no `guestfwd` support in this machine's Slirp — confirmed by
diffing against a run with no session-primitive changes at all, not a new
regression.) Full `cargo build --workspace` /
`clippy --workspace --all-targets -- -D warnings`, the kernel's own
`--target x86_64-unknown-none` build/clippy, and a full `xtask run` boot
(identical serial output through Phase 7's ring 3 transition) all clean.

**What this explicitly does not do**: migrate any consumer onto the new
primitive. `blk-driver-host`'s fs IPC server (`ipc/src/fs.rs`'s wire
format), `net-driver-host`'s sockets surface (`ipc/src/sockets.rs`), and
`kernel/src/marshal_client.rs` — a *third* fixed-sockets-port consumer
found while scoping this work, previously undocumented anywhere as such —
all still use the fixed-port model completely unchanged, same additive
discipline `extra_capabilities` and the Option A recv-side gate already
followed. Each migration is separate, later work; they're independently
parallelizable against each other once attempted, but starting any of them
without this primitive already proven first would have been exactly the
"partially-applied cross-crate change" this project's own CLAUDE.md warns
against.

## Option C consumers migrated: blk-driver-host and net-driver-host off the fixed-port transport

Follow-up to the section above. The syscall-cost benchmark it references
(`kernel/tests/syscall_cost.rs`, see "Network stack, entropy Phase 4") is
what actually forced this, not the ceiling/attribution gaps named as
Option A's limits: a real TLS-scale exchange (1500-3000 bytes, thousands of
syscalls) over the fixed-port transport (~11,633us/syscall round trip)
exceeds the 300ms T1 real-time budget by 100x+; the session primitive
(~51us/syscall, ~228x cheaper) fits comfortably. `blk-driver-host`'s
filesystem IPC, `net-driver-host`'s sockets IPC, and `kernel::marshal_client`
(the only client of the latter) all now ride sessions exclusively.

- **`blk-driver-host`**: `FS_REQUEST_PORT`(8)/`FS_WRITE_REQUEST_PORT`(10)
  collapsed into one `FS_SERVER_PORT`(8) — reads and writes both flow as
  `FsRequest` variants over whatever session a client opened, since the
  enum tag itself already distinguishes them. `ipc/src/fs.rs`'s
  `response_port`/`response_token` fields (Option A's own workaround for a
  shared response port with no per-caller identity) were retired as
  redundant — a session id is already a kernel-authenticated reply channel,
  verified by participant identity rather than a caller-supplied token.
  Verified: `blk_fs_ipc`, `blk_fs_concurrent`, `blk_fs_concurrent_write`,
  `blk_driver_rw`, `blk_fat32_read` all pass on fresh QEMU images; workspace
  build and `cargo test -p runix-ipc` (29 tests) clean.
- **`net-driver-host`**: `SOCK_REQUEST_PORT`(11)/`SOCK_RESPONSE_PORT`(12)
  collapsed into one `SOCKETS_SERVER_PORT`(11). `kernel::marshal_client`'s
  `evaluate()` now opens exactly one session per call (mapping naturally to
  one socket-open-through-close lifecycle) instead of racing on a shared
  port pair — closing `ipc/src/sockets.rs`'s long-standing "can't attribute
  a handle to its caller" gap as a side effect, not just the performance
  problem this migration set out to fix. Verified: `net_driver_sockets`,
  `net_driver_sockets_concurrent`, `marshal_tcp_roundtrip`,
  `marshal_proxy_e2e` all pass on fresh QEMU images (via WSL Fedora, which
  has the `nc`/`guestfwd` support native Windows Slirp lacks).

**A real isolation bug in the session primitive itself was found and fixed
during this migration — not a driver bug, a kernel bug.** `Session` was one
shared `VecDeque<u8>` for both directions; `session_try_recv` checked only
that the caller was *a* participant (owner or server), never that a queued
byte was written by the *other* one. A client that sent a request and
immediately polled `RECV` for the reply — the obvious, correct-looking way
to write a client (see `kernel::marshal_client::evaluate`'s own shape) —
could race the server's `ACCEPT`+`RECV` and dequeue its own just-sent bytes
back out, silently destroying its own request before the real server ever
saw it. Root-caused via a temporary `serial_println!` in
`session_try_recv` showing a client's own `RECV` firing with a non-empty
queue *before* the session had even been accepted (`server: None`) —
unambiguous proof of a self-read, not a timing coincidence.
`kernel/tests/ipc_session.rs`'s own isolation proof never caught this: it's
an echo test (client sends "AAAA", expects "AAAA" back), and a client
reading back its own bytes instead of a real server echo produces the
identical passing assertion — the test was blind to this failure mode by
construction, not merely unlucky not to hit it.

Fixed by splitting `Session` into two directional queues
(`owner_to_server`/`server_to_owner`) with independent send-locks
(`kernel/src/ipc.rs`), routed by a new `Role` (`Owner`/`Server`) resolved
once per call via `role_of` — an owner's `SEND` always lands in
`owner_to_server`, a server's always in `server_to_owner`, and each side's
`RECV` only ever reads the *other* lane. This makes the bug structurally
impossible rather than dependent on caller-side timing discipline.
`kernel/tests/ipc_session.rs` still passes unchanged, now proving a real
echo rather than accidentally passing for the wrong reason.

**A second, related bug — a real latency floor, not a correctness bug —
was found and fixed while getting `grid_sandbox_marshal_shadow.rs` to pass
against the migrated transport.** `SYS_IPC_SESSION_ACCEPT`'s capability
check (`authorized_for_port`, a real Ed25519 verification) had no cheap
"nothing pending" pre-check the way `SYS_IPC_RECV`'s `ipc::is_empty`
already does — calling it on every iteration of `net-driver-host`'s
up-to-500,000,000-iteration server loop paid that full verification cost
every time, which is what originally forced a workaround throttling
`SESSION_ACCEPT` polling to once every 10,000 iterations. That throttle
was itself a real cost: a hard ~10,000-iteration floor on how fast *any*
client's session ever got accepted, regardless of how fast the rest of the
system was — incompatible with `kernel/src/grid_sandbox.rs`'s
`SHADOW_MARSHAL_MAX_ITERS`'s <300ms T1 real-time budget for MARSHAL shadow
evaluation. Fixed properly, not worked around again: `ipc::session_pending`
(checked in `SYS_IPC_SESSION_ACCEPT`'s dispatch arm, before
`authorized_for_port` runs) gives servers the same cheap pre-check
`SYS_IPC_RECV` already has, so `net-driver-host` polls `ACCEPT` every
iteration again with no throttle at all.

## MARSHAL test fixes: a stale fixture, and a budget that needed a test-only override, not a loosened production constant

Two tests broken by this session's transport migration, for two unrelated
reasons:

- **`marshal_proxy_e2e.rs`**: its `FAKE_KERKESE_JSON` fixture predated
  `docs/RFC-VERIFIER-IDENTITY.md`'s Option A, which made `citadel_proxy`
  actually parse and policy-check the kernel's minimal envelope instead of
  forwarding it opaquely. The old fixture (just `kerkese_version` plus an
  unrecognized `"TEST_ACTION"` type) got refused by `citadel_proxy`'s own
  `policy::check` before ever reaching the mock CITADEL endpoint — surfacing
  as a `BadResponse("missing field \`dry_run\`")` instead of the expected
  Decision. Fixed by replacing it with the same real minimal-envelope shape
  `desktop/src/citadel/proxy.rs`'s own test fixture
  (`minimal_envelope_json`) and `grid_sandbox.rs`'s `shadow_marshal_evaluate`
  actually send. Verified passing end to end against the real `citadel_proxy`
  binary and `mock_citadel_server.py`.
- **`grid_sandbox_marshal_shadow.rs`**: its "shadow-refused" case needs a
  full session-open-through-close round trip against a real listener to
  complete — the same real-round-trip budget `marshal_tcp_roundtrip.rs`/
  `marshal_proxy_e2e.rs` needed raised from 200,000 to 2,000,000 iterations
  earlier in this same migration — but `grid_sandbox.rs`'s own
  `SHADOW_MARSHAL_MAX_ITERS` is a genuine **production** fail-fast budget
  (2,000 iterations) for a hard T1 real-time spawn path, not a test knob,
  and isn't simply raised to match: doing that would loosen a documented
  <300ms safety constant for a reason that has nothing to do with
  production (QEMU/`nc` test-environment overhead, not real proxy latency).
  Fixed by adding `grid_sandbox::set_shadow_marshal_max_iters_override`
  (same "exists mainly for tests, but nothing stops a real deployment from
  using it" posture as `set_shadow_marshal_proxy`) so this one test case can
  ask for a larger budget explicitly, leaving every other caller — every
  other test, and any real deployment — at the tight default. Verified: all
  three cases (`shadow-unconfigured`/fail-open, a genuinely reachable
  `Refuse`/fail-closed against a real listener, `shadow-unreachable`/
  fail-open) pass; `net_driver_sockets`/`net_driver_sockets_concurrent`/
  `marshal_tcp_roundtrip` all still pass with the `ACCEPT` throttle removed.

## MARSHAL boot-time proxy wiring: closing the one remaining gap in spawn_instance's real enforcement

`grid_sandbox::spawn_instance`'s enforcement (fail-open on `Unreachable`,
fail-closed on a reachable `Refuse`/`HardStop`) was already real and proven
by the test above — but nothing in `kernel_main`'s actual boot sequence
ever called `set_shadow_marshal_proxy`, only test files did. So in any real
boot, `SHADOW_MARSHAL_PROXY` stayed `None` forever and every real spawn
silently fail-opened: not because the enforcement logic was fake, but
because nothing in boot ever pointed it at anything.

Closed with a build-time hook, `RUNIX_MARSHAL_PROXY_ADDR` (`ip:port`), read
via `option_env!` the same way `xtask` already threads `RUNIX_NETDEV_ARG`
through to QEMU — unset by default, so boot behavior is byte-for-byte
identical to before this change. Verified both ways: booting without the
var produces no MARSHAL log line at all; booting with
`RUNIX_MARSHAL_PROXY_ADDR=10.0.2.100:9104` set logs "MARSHAL shadow proxy
configured at [10, 0, 2, 100]:9104 from RUNIX_MARSHAL_PROXY_ADDR", and
`grid_sandbox_marshal_shadow.rs` still passes.

**Two gaps remain, deliberately out of scope for this change**: no live
MARSHAL deployment exists anywhere to point `RUNIX_MARSHAL_PROXY_ADDR` at
(see `docs/ROADMAP.md`'s open questions); and nothing outside test code
(`kernel/tests/grid_sandbox_marshal_shadow.rs`, `kernel/tests/
grid_sandbox_multi_instance.rs`) ever actually calls `spawn_instance` —
this kernel's own boot loads `grid-sandbox-host` through the separate
CITADEL boot-allowlist path (`citadel::demo_authorize`), not through
`spawn_instance`, which exists for spawning app *instances* inside an
already-running `grid-sandbox-host`. A real trigger for that (a launcher, a
shell, some other runtime-driven request) doesn't exist yet. The boot-time
proxy configuration is now genuinely complete; it isn't yet load-bearing in
practice, for two independent reasons that were already open before this
change and aren't closed by it.

## Rust MARSHAL SDK dependency resolved upstream: `citadel-kerkese-core` 1.0.0

`opensecstack/sdk/rust` cut `citadel-kerkese-core` as v1.0.0 — a `no_std` +
`alloc` core for building, signing, and submitting CITADEL MARSHAL Kerkese
requests, built specifically for hosts like this kernel that can't pull in
Tokio/reqwest, verified against the Go reference implementation
(`citadel/internal/marshal/{types,sig}.go`) with a known-answer test. This
closes [opensecstack/opensecstack#34](https://github.com/opensecstack/opensecstack/issues/34),
the external blocker `docs/ROADMAP.md`'s open questions previously
described as unresolved — see that doc for the full account.

`citadel-integration` already depends on it: its own locally-duplicated
`KerkeseTransport` trait and `TransportError` enum (which existed only as a
documented "shape to code against later") were deleted and replaced with
`pub use citadel_kerkese_core::{KerkeseTransport, TransportError}` — same
trait shape, same error variants, verified identical before swapping.
**Purely mechanical, not a capability unlock**: nothing calls
`KerkeseTransport` anywhere in `citadel-integration` or `kernel/` — there
was no implementation before, there's no implementation now. Boot-time
module authorization is completely unaffected (still offline Ed25519
verification, no network round-trip). This removed the reason a
kernel-direct MARSHAL client used to be blocked; it didn't advance
kernel-direct over `citadel_proxy` (the implementation that actually exists
and works today) as this system's real transport — see
`docs/ROADMAP.md`'s open questions for that still-fully-open architectural
decision.

## A live CITADEL/MARSHAL deployment exists and is reachable — but a real round trip needs identity work that doesn't exist yet

As of 2026-10-02, a real CITADEL deployment is reachable over the network
(Cloudflare tunnels fronting CITADEL and sinauth), independently verified,
not just reported: `GET /api/v1/health` on both returns `200` with a real
body (`{"status":"ok","db":"ok",...}` for CITADEL); `POST
/api/v1/marshal/evaluate` with an empty body returns a real, structured
`REFUSE`/`HARD_STOP` `Decision` (not a transport-level error) — Gate 1
(AuthN) `WARN`s on missing credentials rather than failing closed (this
deployment doesn't have `EnforceIdentity`/`EnforceSignatures` set), Gate 2
(AuthZ) `FAIL`s on an empty role, Gate 3 (NDS) `HARD_STOP`s on
same-identity-by-default. This closes the "no live MARSHAL deployment
exists anywhere" half of every open item that previously named it
(`docs/ROADMAP.md`, `docs/THREAT_MODEL.md`'s MARSHAL/WORM trigger,
`docs/MARSHAL-ENFORCEMENT-POLICY.md`) — there is now something real to
point `RUNIX_MARSHAL_PROXY_ADDR`/`RUNIX_CITADEL_URL` at.

**What this does not close, and why it's a bigger gap than it looks**:
getting a real `EXECUTE` (or even a real, non-warn-mode `REFUSE`) requires
operator-side identity credentials that nothing in this codebase has ever
constructed. `HttpKerkeseTransport` (`desktop/src/citadel/transport.rs`)
adds zero credentials of its own — confirmed by its own doc comment,
"forward the carried `kerkese_json` to `HttpKerkeseTransport` verbatim" —
it's a pure bytes-in/bytes-out HTTP POST. `citadel_proxy`
(`desktop/src/citadel/proxy.rs`) only ever attaches `sig_verifier` (its own
proxy identity, signing as the Verifier principal per
`docs/RFC-VERIFIER-IDENTITY.md`'s Option A) — nothing anywhere constructs
an `actor_token` (a sinauth-issued bearer JWT for the *operator* identity)
or a `sig_operator` (an Ed25519 signature registered via `POST
/api/v1/keys/register` for that same operator). Both are required inputs
Gate 1 checks; today's envelope simply never carries them.

**Deliberately not provisioned yet, on purpose, not an oversight**: seeding
two sinauth accounts (operator + verifier) and registering an Ed25519 key
for the operator is roughly 20 minutes of infrastructure work — but it
would sit unused until `citadel_proxy` (or whatever ends up holding this
responsibility) is taught to actually carry operator-side credentials, and
*that* is a real identity-architecture decision, not a stub to bolt on:
where does an operator's bearer token come from at request time (does the
kernel hand it to the proxy somehow? does the proxy hold a service-account
identity and impersonate the real operator?), and where does an operator's
private signing key live (almost certainly never inside the kernel itself —
so where, and how does the proxy get access to sign with it on the
operator's behalf without becoming a single point of total compromise for
every operator identity it can sign as?). Provisioning accounts before that
design question is answered would front-run the decision, not advance it.
This is RC-scope work (real identity integration), not Beta-scope
(transport/enforcement plumbing, which — see the sections above — is done
and correct). The precise, honest state of this gap, worth repeating
exactly: **live, reachable, evaluating correctly — refusing for the right
reasons — but nothing in this codebase can yet construct a request that
should be allowed to succeed.**
