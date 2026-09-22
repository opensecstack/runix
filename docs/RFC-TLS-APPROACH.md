# RFC: TLS for the user-space network stack

**Status**: proposal for repo owner review. No code written yet. This is the
gate before any TLS implementation work on Beta's "user-space network stack"
roadmap item.

> **Research caveat, stated up front**: the drafting session had no network
> access. Every claim below about *this repo* was verified by reading the
> code and is cited by file and line. Every claim about *external crates*
> (`embedded-tls`, `rustls`, `mbedtls`) is from prior knowledge, is marked
> **[UNVERIFIED]**, and must be confirmed against crates.io/docs.rs before
> this RFC is accepted. Version numbers in particular should be treated as
> approximate until checked.

## Context

`net-driver-host/` is a freestanding ring-3 process (`#![no_std]`,
`#![no_main]`, `alloc` via `linked_list_allocator`, `panic = "abort"`)
running `smoltcp` 0.14 with `default-features = false` over a legacy
virtio-net driver. ICMP, a TCP client, DHCP, and a typed sockets IPC surface
(`runix_ipc::sockets`) all work today. DNS is landing in parallel.

TLS is the next roadmap item, and unlike DNS/DHCP it is not a bounded
addition. Four constraints make it a design decision rather than a
dependency choice:

1. **No host OS at all.** No `mmap`, no threads, no signal handlers, no
   `libc`. This rules out anything in the `wasmtime` category — the same
   constraint `wasm-runtime/src/lib.rs` already documents for choosing
   `wasmi` ("`wasmtime` needs a host OS (mmap, threads, signal handlers for
   its JIT)"). That precedent is directly on point and should govern here.
2. **No entropy source exists.** The kernel's syscall table
   (`kernel/src/syscall.rs:18-54`) is `SYS_YIELD`, `SYS_WRITE`,
   `SYS_IPC_SEND`, `SYS_IPC_RECV`, `SYS_PORT_IN`, `SYS_PORT_OUT`,
   `SYS_TICKS`, `SYS_IPC_SEND_LOCK`, `SYS_IPC_SEND_UNLOCK` — there is no RNG
   syscall. `rand_core`/`getrandom` appear in this workspace only as
   **dev-dependencies** (`capability-manager/Cargo.toml:29-30`, used by
   host-side tests at `capability-manager/src/lib.rs:169`); no freestanding
   target has ever linked them. `kernel/src/capabilities.rs:33` is explicit
   that the demo keypair is hardcoded precisely so it is "reproducible
   across boots instead of needing an entropy" source. This is not a small
   gap: TLS without a real CSPRNG is worse than no TLS, because it produces
   the appearance of confidentiality without the substance.
3. **No certificate store.** There is a filesystem (`blk-driver-host`,
   `runix_ipc::fs`), but no CA bundle, no notion of system trust anchors,
   and no wall-clock time source for `notBefore`/`notAfter` validation —
   `SYS_TICKS` is a boot-relative tick count, not a date.
4. **Tight memory.** `net-driver-host`'s heap is 256 KiB total
   (`main.rs:69-70`, `HEAP_START`/`HEAP_SIZE`), sized for "smoltcp's
   footprint for one interface and one ICMP socket." A TLS 1.3 record can
   carry 16 KiB of plaintext, so a conforming implementation needs receive
   and transmit record buffers in that ballpark **per session** — a
   double-digit percentage of the whole heap for one connection.

One existing detail is worth naming because TLS work touches it: `main.rs:218`
constructs the interface as `Config::new(EthernetAddress(mac).into())` and
never sets `random_seed`, so smoltcp's TCP initial-sequence-number and
ephemeral-port randomization run off the default seed and are deterministic
across boots. That is a pre-existing, non-TLS weakness with the same root
cause (no entropy), and whatever fixes entropy for TLS should fix it too.

One thing is better than expected: **the RustCrypto stack already builds for
`x86_64-unknown-none` in this exact process.** `net-driver-host/Cargo.lock`
contains `ed25519-dalek` 2.2.0, `curve25519-dalek` 4.1.3, `sha2` 0.10.9,
`subtle`, and `zeroize`, pulled in through `runix-ipc` →
`runix-capability-manager`. So "pure-Rust crypto primitives in a freestanding
ring-3 binary" is already proven here, not speculative. With one scar:
`capability-manager/Cargo.toml:20-26` forces `sha2`'s `force-soft` feature
because the default build "hits an LLVM codegen ICE ('Do not know how to
split the result of this operator') on x86_64-unknown-none." Any TLS stack
that pulls `sha2` inherits that requirement, and sibling crates (`aes-gcm`,
`chacha20poly1305`, `p256`) may have their own equivalents that nobody here
has tested yet.

## The prior question: where does TLS terminate?

Before choosing a crate, decide whether `net-driver-host` should hold TLS
state at all. It should not.

`net-driver-host` is the one process holding a capability token scoped to
the virtio-net device's BAR0 port-I/O range (`main.rs:29-33`). It is the
closest thing this system has to a T1-tier component on the network path.
Putting TLS inside it would mean:

- An X.509 parser — historically one of the most productive bug classes in
  all of security — running in the process that owns device registers.
- Every other process's session keys living in one shared address space, so
  a single memory-safety bug in the driver compromises every TLS session on
  the system simultaneously, with no per-caller separation. The sockets IPC
  surface already can't tell callers apart: `ipc/src/sockets.rs:30-37` says
  outright that the wire format "alone can't distinguish *which caller*
  opened a given handle when multiple processes share the same fixed
  request/response ports." A shared TLS terminator would inherit exactly
  that ambiguity for key material.
- No way to give a T3 caller a weaker trust-anchor set than a T1 caller,
  because policy would live in one process serving both.

The alternative is TLS as a **library, linked into whichever ring-3 process
needs it**, speaking to `net-driver-host` over the existing
`SocketRequest::{Open,Connect,Send,Recv,Close}` surface as an opaque byte
pipe. The driver never sees plaintext, never holds a key, and never parses a
certificate. Session keys live in the process that owns the session, at that
process's own tier. This also satisfies CLAUDE.md's shared-crate rule: a
`tls-client` crate is usable from desktop and mobile and from the
MARSHAL/CITADEL proxy chain, rather than being a capability of one x86-only
driver binary.

All options below therefore assume **library, not driver**. The remaining
question is which library.

## Options

### Option A: `embedded-tls` as a shared `no_std` client crate

**Design**: new workspace-adjacent crate (`tls-client/`, `no_std` + `alloc`,
same `#![cfg_attr(not(test), no_std)]` split `capability-manager`,
`citadel-integration`, and `wasm-runtime` all use) wrapping `embedded-tls`
in TLS 1.3 client mode. The crate takes a byte-pipe abstraction the caller
implements over `runix_ipc::sockets`, a caller-supplied RNG handle, and an
explicit trust-anchor set. Trust anchors are **compiled in and
build-time-signed**, mirroring `citadel-integration`'s
`BootAllowlist`/`ModuleManifestEntry` pattern rather than inventing a
runtime cert store.

**[UNVERIFIED] properties to confirm**: `embedded-tls` (drogue-iot) is
`no_std`-native, TLS 1.3 **client only** (no server, no TLS 1.2), generic
over blocking and async I/O traits, requires the caller to pass an RNG
implementing `rand_core`'s `CryptoRng`-style trait, and exposes a pluggable
verifier with a permissive default that must be explicitly replaced.
Approximate version 0.17.x. Its cipher suite support is narrow
(AES-128-GCM-SHA256 territory), and its record buffers are caller-provided
and sized around the 16 KiB record maximum. **Every sentence in this
paragraph needs checking before acceptance**, especially: (a) whether
certificate-chain verification is production-usable or still effectively
opt-out-by-default, (b) exact buffer sizing requirements, (c) which crypto
backend it pulls and whether that backend builds clean on
`x86_64-unknown-none` or needs `force-soft`-style workarounds like `sha2`
did.

**Cost**: TLS 1.3 client only — no server, and no fallback if a peer speaks
only 1.2. Certificate verification quality is the open risk; if it is weak,
this crate buys encryption without authentication, which against an active
attacker is close to buying nothing. Memory: the caller process needs a
heap sized for record buffers, so any process using it needs its `*BootInfo`
heap grant re-sized (a kernel-side change, since ring-3 processes here
cannot map their own memory — `main.rs:34-42`). Smaller ecosystem and
smaller audit history than rustls.

### Option B: `rustls` in `no_std` mode with a pure-Rust crypto provider

**Design**: same library-not-driver shape, built on `rustls` 0.23.x with
`default-features = false` and a `no_std`-compatible `CryptoProvider`.

**[UNVERIFIED] properties to confirm**: `rustls` 0.23 does advertise
`no_std` + `alloc` support, requiring the caller to supply a time provider
and a crypto provider, with `rustls-pki-types` supporting `no_std`. The
decisive question is the provider: `aws-lc-rs` needs CMake and a C
toolchain and is almost certainly disqualified for `x86_64-unknown-none`;
`ring` compiles C and assembly through a per-target support list that I do
not believe includes `x86_64-unknown-none`; the pure-Rust `rustls-rustcrypto`
provider exists but I believe is explicitly not released as
production-ready. **If no provider builds for this target, Option B is not
an option at all**, and confirming that is the single highest-value piece
of verification this RFC needs.

One fact that *is* verified locally and favors this option if a provider
exists: `rustls-pki-types` 1.15.1 is already in the root `Cargo.lock`, so
some host-side crate already depends on it — the types are not foreign to
this tree.

**Cost**: much heavier dependency graph than Option A, on a target where a
single crate (`sha2`) already required a hand-found workaround for an LLVM
codegen ICE; expect to rediscover that problem several more times. Needs a
time provider that this system cannot supply honestly (`SYS_TICKS` is
boot-relative), so certificate expiry checking would be either stubbed or
wrong. In exchange: by far the best-audited TLS implementation in Rust,
server support, and TLS 1.2 compatibility.

### Option C: defer in-guest TLS; terminate at the existing host-side proxy for Beta

**Design**: write no TLS in Runix this cycle. Ring-3 processes keep
speaking plaintext TCP through `net-driver-host`, and the existing
`desktop/src/bin/citadel_proxy.rs` — which runs hosted, on a real OS, with
`std` — terminates TLS on Runix's behalf when it forwards to CITADEL. Spend
the cycle on the actual prerequisites instead: a capability-gated entropy
syscall, a trust-anchor provisioning story, and a heap-grant mechanism that
can afford record buffers.

**Cost**: this is only honest while the peer on the other side of the
plaintext hop is a local, trusted process. It does not generalize — the
moment a Runix process wants to reach an arbitrary HTTPS endpoint, or the
moment `citadel_proxy` stops being co-located, the model is simply "no
transport security," and describing it otherwise would be self-deception.
It also risks calcifying: a plaintext-to-a-helper pattern is exactly the
kind of Alpha shortcut that becomes load-bearing once mobile's stack is
built on top of it. If chosen, it needs an explicit expiry condition
written down, not just an intention to revisit.

### Rejected without a full option: `mbedtls` bindings

Rejected on the same grounds `wasm-runtime` rejected `wasmtime`, plus build
tooling. The Fortanix `mbedtls` crate can be built `no_std` with
caller-supplied entropy callbacks **[UNVERIFIED]**, but it compiles C
sources via a `cc`/build-script path and expects libc-shaped shims. That
means introducing a C cross-toolchain into a build that is currently pure
Rust and is developed Windows-native (per the project's dev-environment
notes), for every CI run and every `xtask` invocation. The licensing is
fine (mbedtls is Apache-2.0-available), but "a C toolchain now gates the
network stack build" is a structural cost far larger than the TLS feature
itself. Not worth a full option slot.

## Recommendation

**Option A (`embedded-tls`, as a shared library terminating in the caller
process), sequenced behind an entropy prerequisite — with Option C as the
explicit fallback if verification shows `embedded-tls`'s certificate
verification is not production-usable.**

Reasoning:

1. **The library-not-driver split is the actual architectural decision, and
   it is the same decision under every option.** It keeps X.509 parsing and
   session keys out of the one process holding a device-register
   capability, and it gives per-caller, per-tier key separation that a
   shared terminator provably cannot (`ipc/src/sockets.rs:30-37` already
   documents that the sockets surface cannot attribute a handle to a
   caller). Adopt this part regardless of which crate wins.
2. **Option A is the only candidate whose no-host-OS support is its design
   center rather than a supported configuration.** That is precisely the
   reasoning `wasm-runtime/src/lib.rs` used for `wasmi` over `wasmtime`, and
   following an established in-repo precedent beats re-deriving the
   tradeoff from scratch.
3. **Option B may not even be reachable**, and its blocker is not fixable
   from this repo — it depends on whether any `rustls` `CryptoProvider`
   builds for `x86_64-unknown-none`. That should be verified, but it should
   not be planned around.
4. **Entropy must land first, and it must be capability-gated.** The
   tempting shortcut is `RDRAND` directly in the ring-3 process: it is an
   unprivileged instruction, so it would work with no kernel change at all.
   That is exactly what makes it wrong here — it is ambient authority by
   construction, invisible to the capability system, unattributable in
   WORM, and untestable under a deterministic QEMU harness. The right shape
   is a new `SYS_RANDOM` gated by a `capability-manager` token, backed by a
   kernel virtio-rng driver, with `RDRAND` available as a mix-in inside the
   kernel rather than as a user-space bypass. This also fixes smoltcp's
   deterministic `random_seed` (`main.rs:218`) as a side effect, and it is
   a strictly smaller, better-bounded piece of work than TLS itself — a
   good thing to build and prove alone first.
5. **It has a falsifiable next step.** Before writing any TLS code: add
   `embedded-tls` to `net-driver-host`'s dependency graph (or a scratch
   crate on the same target), build for `x86_64-unknown-none`, and see what
   breaks. Given `sha2` already needed `force-soft` on this target, a clean
   build is a real, non-obvious result, and a failed build is a cheap early
   answer.

If verification shows `embedded-tls` cannot authenticate a peer to a
standard a reviewer would accept, do **not** ship it with a permissive
verifier and a TODO — fall back to Option C with a written expiry
condition. Encryption without authentication on a governance path is worse
than an acknowledged plaintext hop, because it invites everything
downstream to be designed as if the channel were secure.

## What changes under Option A (prose only — no code written yet)

- A new `tls-client` crate joins the shared tier alongside
  `capability-manager`, `ipc`, `wasm-runtime`, and `citadel-integration`:
  `no_std` + `alloc`, Apache-2.0, `#![cfg_attr(not(test), no_std)]` so its
  own test suite can opt back into `std`. It is deliberately ignorant of
  tiers, CITADEL, and MARSHAL — the same decoupling `wasm-runtime` documents
  for itself. Being shared rather than desktop- or mobile-local is the
  point: mobile's stack must not grow its own copy.
- `net-driver-host` gains **nothing**. Its Cargo.toml does not change, its
  heap does not change, and it never sees plaintext or key material. This
  is the load-bearing half of the proposal.
- The kernel gains a `SYS_RANDOM` syscall gated by a `capability-manager`
  token, backed by a virtio-rng device driver. It needs its own capability
  kind, its own allocation at spawn time in `kernel/src/main.rs`'s loader
  path, and a decision about behavior when virtio-rng is absent — which
  must be a hard failure for any caller that asked for it, never a silent
  fallback to a counter or a fixed seed. `smoltcp`'s `Config.random_seed` in
  `net-driver-host` should be fed from the same source once it exists,
  closing the deterministic-ISN gap independently of TLS.
- Trust anchors are compiled in and build-time-signed, reusing
  `citadel-integration`'s existing allowlist-and-manifest pattern rather
  than inventing a runtime cert store. A runtime store over `runix_ipc::fs`
  is a later, separate decision, and it would need its own integrity story
  before it could be trusted more than a baked-in set.
- Certificate validity-period checking is explicitly, visibly out of scope
  until a real wall-clock source exists. It should be an obvious, named
  unimplemented behavior — not silently skipped inside a verifier.
- Any process linking `tls-client` needs a larger heap grant than
  `net-driver-host`'s current 256 KiB, provisioned by the kernel at spawn
  time, since ring-3 processes here cannot map their own memory.
- `docs/THREAT_MODEL.md` needs a new trust-boundary entry when the entropy
  syscall lands (a new capability kind, a new kernel-mediated resource, and
  the demo-key/no-entropy gap partially closing), per its own "Revisit
  triggers" discipline.
- `docs/STATUS.md`'s network-stack section gains a TLS subsection stating
  plainly what is and is not authenticated.

## Open questions

- **Does `embedded-tls` verify certificate chains to a standard a reviewer
  would accept today?** This is the single question the recommendation
  hinges on, and it could not be answered without network access. If the
  answer is no, the recommendation flips to Option C.
- **Does any `rustls` `CryptoProvider` build for `x86_64-unknown-none`?** If
  `rustls-rustcrypto` has matured into something releasable, Option B's
  audit-maturity advantage may outweigh Option A's simplicity, and this RFC
  should be reopened rather than quietly followed.
- **Do `aes-gcm` / `chacha20poly1305` / `p256` need `force-soft`-equivalent
  workarounds on this target,** the way `sha2` did? A cheap build
  experiment answers this and materially affects the effort estimate for
  both A and B.
- **What is the entropy quality story in QEMU specifically?** virtio-rng in
  a QEMU guest sources from the host, which is fine; whether `RDRAND` is
  meaningfully implemented under TCG (as opposed to KVM passthrough) I
  could not verify, and it matters for whether the kernel-side mix-in is
  real entropy or theater.
- **Who owns the trust-anchor set, and is it governance-relevant?** If the
  anchors that authenticate a MARSHAL connection are themselves
  CITADEL-provisioned, that deepens `citadel-integration`'s coupling to
  CITADEL internals — which is exactly the kind of change the licensing
  question in `docs/ROADMAP.md § Open questions` names as a revisit
  trigger. Keeping trust anchors in `tls-client` (generic,
  CITADEL-ignorant) rather than in `citadel-integration` avoids the
  question; putting them in `citadel-integration` raises it.
- **Is a TLS *server* ever needed?** Option A forecloses it. Nothing in the
  current architecture wants one, but if mobile's provisioning flows or a
  future device-pairing feature do, that is an Option-B-shaped requirement
  discovered late.
- **Does the one-byte-per-syscall IPC transport (`ipc/src/sockets.rs:10-20`)
  make a TLS handshake unacceptably slow?** A handshake is several
  kilobytes of round-tripped data, each byte a syscall, against T1's
  <300ms MARSHAL constraint. This may be the thing that forces a
  bulk-transfer IPC path before TLS is usable on a T1 path at all — worth
  measuring early, because it is a `kernel`-side change with its own design
  questions.

## References

- `net-driver-host/src/main.rs` — freestanding ring-3 shape, `HEAP_SIZE`
  (:69-70), capability-gated port I/O (:29-42), `Config::new` without
  `random_seed` (:218)
- `net-driver-host/Cargo.toml` — `smoltcp` 0.14 feature set, `no_std`
  dependency discipline
- `net-driver-host/Cargo.lock` — `ed25519-dalek` 2.2.0 / `curve25519-dalek`
  4.1.3 / `sha2` 0.10.9 already building for this target
- `capability-manager/Cargo.toml:20-26` — the `sha2` `force-soft` LLVM
  codegen ICE workaround
- `ipc/src/sockets.rs` — the byte-pipe surface TLS would run over;
  caller-attribution caveat (:30-37)
- `wasm-runtime/src/lib.rs` — the `wasmi`-over-`wasmtime` precedent this RFC
  follows
- `citadel-integration/src/lib.rs` — the build-time-signed-allowlist pattern
  trust anchors should mirror
- `kernel/src/syscall.rs:18-54` — the syscall table `SYS_RANDOM` would
  extend
- `kernel/src/capabilities.rs:33` — demo keypair hardcoded specifically to
  avoid needing entropy
- `docs/THREAT_MODEL.md` — demo signing key gap; "Revisit triggers"
- `docs/ROADMAP.md § Open questions` — licensing trigger relevant to where
  trust anchors live
