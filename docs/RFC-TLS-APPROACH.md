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

> **Phase 1 decision (implemented, 2026-09-26)**: this RFC's entropy design
> (point 4 of "Context" below, and the `SYS_RANDOM` line under "What changes
> under Option A") called for `SYS_RANDOM` backed by a kernel-resident
> virtio-rng driver mixed with RDRAND. That's not what shipped first. Every
> other virtio device in this repo (`net-driver-host`, `blk-driver-host`) is
> deliberately ring-3 and capability-isolated over port I/O — a
> kernel-resident virtio-rng driver would have been the first virtio surface
> actually living in the kernel, growing the TCB for a marginal
> entropy-quality gain over RDRAND alone (present in QEMU/KVM and real
> hardware). Phase 1 ships **RDRAND-only `SYS_RANDOM`** instead
> (`kernel/src/entropy.rs`, `kernel/src/syscall.rs`'s `SYS_RANDOM`,
> `kernel/src/capabilities.rs::random_resource`), gated on a `"random"`
> capability, failing closed (returns the same `u64::MAX` denial sentinel)
> when RDRAND is absent or exhausted rather than falling back to anything
> weaker. `net-driver-host` now seeds smoltcp's `Config.random_seed` from it
> (`net-driver-host/src/main.rs`), closing the deterministic-ISN gap this
> RFC named as a side benefit, independent of TLS. Everything else in this
> document — the TLS crate/option decision itself, trust anchors, cert
> validity checking — is unaffected and still not implemented. Virtio-rng
> as a second entropy source remains an explicit, separately-scoped
> follow-up; see `docs/THREAT_MODEL.md`'s entry on the single-source
> RDRAND trust tradeoff this leaves open.

> **Phase 2 in progress (2026-09-27)**: verifying this RFC's two
> `[UNVERIFIED]` crate-choice claims (embedded-tls's real cert-verification
> quality; whether any `rustls` `CryptoProvider` builds for
> `x86_64-unknown-none`) with actual network access, which the drafting
> session didn't have. In parallel, the crate-agnostic scaffolding — the
> "library, not driver" split itself, which the Recommendation section
> already established is correct regardless of which crate wins — has
> started: `tls-client/` (`runix-tls-client`), a new root-workspace member,
> `no_std` + `alloc`, builds clean on both the host target and the real
> `x86_64-unknown-none` target. It currently defines only two traits —
> `Transport` (a caller-supplied byte pipe) and `Entropy` (a caller-supplied
> `SYS_RANDOM`-backed randomness source, taken as a parameter rather than
> read directly, for the ambient-authority reason this RFC's own
> Recommendation section 4 already gives) — and deliberately wraps no TLS
> implementation yet. That part is genuinely staged behind the
> verification above, not started early: which library owns the handshake/
> record layer, what its buffer-sizing and RNG-trait requirements actually
> are, and the resulting heap-grant sizing for whatever ring-3 process
> first links this crate all depend on its answer.

> **Phase 3 (2026-09-27): a real TLS 1.3 handshake works.** Phase 2's
> verification came back positive (`embedded-tls` via `rustpki`, `rustls`
> confirmed unreachable), so the handshake/connection API was built:
> `tls-client::TlsConnection`, bridging this crate's `Transport`/`Yield`
> traits to `embedded_tls::blocking`'s `Read`/`Write` requirements
> (`src/io.rs`) and `Entropy` to `rand_core::CryptoRngCore`, panicking on
> exhaustion rather than degrading (`src/rng.rs`) — a deliberate fail-closed
> choice, not an oversight; see that module's own doc comment. Real
> certificate verification via `rustpki`'s `CertVerifier`, never the
> crate's default `NoVerify`.
>
> **Proven against a live server, not just against `embedded-tls`'s type
> signatures**: `tests/live_handshake.rs` (`#[ignore]`d, run deliberately
> with `--ignored`, not on every CI run — see that file's own doc comment
> for why) connects to `example.com:443` over a real `TcpStream`, completes
> a genuine TLS 1.3 handshake, verifies the real, live 4-certificate chain
> (`example.com` -> `Cloudflare TLS Issuing ECC CA 3` ->
> `SSL.com TLS Transit ECC CA R2` -> `SSL.com TLS ECC Root CA 2022`) against
> "AAA Certificate Services" (the actual root that fourth cert is
> cross-signed by, confirmed via `openssl verify -partial_chain`), and
> decrypts a real HTTP response. Getting the trust anchor right took one
> real, instructive failure first: trusting the fourth cert directly by its
> own subject (rather than its actual issuer) made `CertVerifier` try to
> verify that cert's signature against its own public key, which fails —
> a mistake in how the test was first written, not in `embedded-tls` or
> this crate's own code, but worth naming since it's exactly the kind of
> "which cert is actually the trust anchor" confusion a real consumer could
> also make.
>
> **Still not done, unaffected by this phase**: `TlsClock`
> (`embedded_tls::blocking::NoClock` is used — certificate expiry checking
> is explicitly skipped, not silently, since no wall-clock source exists),
> real trust-anchor provisioning (a caller must already have CA DER bytes;
> `CertVerifier` only checks one CA per connection, not a root store — a
> real multi-root store needs either multiple connection attempts or an
> upstream change), the heap-grant mechanism, and — the thing all of this
> is actually blocked on now — a real consumer process, since nothing in
> Runix needs TLS yet.
>
> **Open questions resolved by research** (this RFC's own "Open questions"
> section, updated in place): RDRAND under QEMU/TCG returns genuine
> host-OS-sourced entropy by default (confirmed from QEMU's own
> `util/guest-random.c` — a deterministic mode exists but only activates
> under `-icount`/`-seed`, which this project's `xtask`/CI never pass); a
> realistic TLS 1.3 handshake with an ECDSA/Ed25519 server certificate runs
> roughly 1,500-3,000 bytes round-trip, meaning 3,000-6,000+ syscalls under
> this codebase's one-byte-per-syscall IPC transport — likely to exceed
> T1's 300ms MARSHAL budget under QEMU/TCG specifically (no per-syscall
> timing figure exists in this repo yet to confirm the exact margin; this
> needs an actual measurement before a T1-tier consumer could rely on it).

> **Phase 4 (2026-09-28): the first-consumer question, and the real
> handshake-cost measurement.** Two threads of work, both closing out this
> RFC's remaining action items:
>
> **Who should be the first real consumer of `tls-client`?** Surveyed every
> current network-facing code path in Runix (not just roadmap docs).
> Finding: **nothing existing needs it yet**. The kernel's own MARSHAL
> evaluation (`kernel/src/marshal_client.rs`) reaches `citadel_proxy`, a
> co-located trusted helper that already terminates TLS host-side (Option
> C's plaintext-hop pattern, already in effect and adequate) — and it's
> kernel-internal code, so linking a TLS stack there would be the wrong
> direction regardless (T1-path, grows the TCB). `net-driver-host`'s DNS
> resolver reaches an arbitrary remote (`8.8.8.8`) in plaintext, but a real
> fix lives in extracting a resolver into its own process, not naming DNS
> "the first consumer" of this crate. Mobile's eSIM/RSP provisioning is the
> one candidate that genuinely cannot use a trusted-local-helper (an SM-DP+
> is a real third party) — but no aarch64 net driver, sockets surface, or
> MVNO code exists yet to attach it to. **Recommendation if/when a first
> consumer is wanted**: a small new ring-3 host process (structurally like
> `grid-sandbox-host`), not an addition to an existing privileged process —
> proves "library not driver" in ring 3 for real, needs no new kernel
> surface beyond the already-open heap-grant question, and is the only way
> to *measure* real IPC-transport cost (see below) rather than guess it.
> **Until then, deferring is the honest, defensible answer** — every
> desktop Beta item left (grid sandbox isolation, filesystem driver,
> MARSHAL integration) needs no arbitrary remote endpoint.
>
> **The handshake-cost open question, measured for real**
> (`kernel/tests/syscall_cost.rs`): the fixed-port IPC model's
> capability-gated syscalls cost **~12,000-30,000μs each** (Ed25519
> verification on every call) — 3,000-6,000 syscalls per handshake means
> **35-180 *seconds***, not milliseconds. The session primitive built
> earlier this session (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`'s Option C)
> measured **~51μs/syscall — ~228x cheaper** — putting a 1,500-byte
> handshake at ~153ms (within budget) and a 3,000-byte one at ~306ms (right
> at the edge). **This turns "migrate onto the session primitive" from a
> good idea into a hard prerequisite for any T1-path TLS use** — the old
> transport isn't slower, it's roughly two orders of magnitude too slow to
> ever work here, independent of anything else optimized. See this RFC's
> own "Open questions" section for the full numbers and methodology
> (including a real QEMU/TCG timer-delivery artifact hit and worked around
> while measuring this).

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

### Option A: `embedded-tls` as a shared `no_std` client crate — **verified, this is what's built**

**Design**: new workspace-adjacent crate (`tls-client/`, `no_std` + `alloc`,
same `#![cfg_attr(not(test), no_std)]` split `capability-manager`,
`citadel-integration`, and `wasm-runtime` all use) wrapping `embedded-tls`
in TLS 1.3 client mode. The crate takes a byte-pipe abstraction the caller
implements over `runix_ipc::sockets`, a caller-supplied RNG handle, and an
explicit trust-anchor set. Trust anchors are **compiled in and
build-time-signed**, mirroring `citadel-integration`'s
`BootAllowlist`/`ModuleManifestEntry` pattern rather than inventing a
runtime cert store.

**Verified for real (2026-09-27), not [UNVERIFIED] any longer** — every
claim in this paragraph confirmed by actually building the crate, cited by
what was found:

- `embedded-tls` moved from `drogue-iot` to `embassy-rs` (still
  maintained, just relocated) — latest is 0.19.0, with a certificate-chain
  robustness PR merged days before this verification pass.
- It **does** default to no certificate verification (`NoVerify`) — the
  RFC's original worry was correct. But a real, non-default verifier
  exists: `embedded_tls::pki::CertVerifier`, real X.509 chain verification
  against RustCrypto's own signature crates (not a stub), gated behind the
  crate's `rustpki` feature (+ `ed25519`/`p384`/`rsa` for which signature
  algorithms to support) — **not** its `webpki` feature, which routes
  through `ring` and is rejected (see Option B below; the same blocker
  applies here under a different feature flag).
- Built clean for the real `x86_64-unknown-none` target with
  `--no-default-features --features rustpki,ed25519,p384,rsa` — all three
  major CA-root signature families (Ed25519, ECDSA P-384, RSA) — zero
  `ring`/`aws-lc-rs`/`getrandom` anywhere in the resulting dependency tree
  (confirmed by inspecting the actual `cargo add` dependency list, not
  assumed). Needed three LLVM-codegen-ICE workarounds along the way
  (`sha2`, `aes`, `curve25519-dalek` — each crate's own `*_force_soft`/
  backend cfg flag, now in `tls-client/.cargo/config.toml`), the same class
  of issue `capability-manager`'s existing `sha2` workaround already
  documents for this target, just hit three more times across different
  crates.
- **Update (2026-10-03): the `rsa` feature was dropped after this
  verification pass.** `rsa` 0.9.10 carries RUSTSEC-2023-0071 (the "Marvin
  Attack," an unpatched RSA private-key timing side-channel), and
  `embedded-tls`'s own use of it is verify-only — a public-key operation
  the advisory doesn't actually touch — but `cargo-deny`'s check can't see
  that distinction, and accepting the advisory via an ignore-list entry
  would misrepresent a real vulnerability as benign. `tls-client` has no
  real callers yet, so dropping RSA-signed certificate-chain verification
  costs nothing today; see `tls-client/Cargo.toml`'s dependency comment
  for the full reasoning and the revisit conditions. Current feature set
  is `rustpki,ed25519,p384` — two of the three families this bullet
  originally verified, not three.
- TLS 1.3 client only, confirmed (a server-support PR exists upstream but
  its merge status was unconfirmed — treat as not landed).
- Cipher suites/buffer sizing: not yet independently re-verified past what
  actually building the crate confirms (it compiles, links, and exposes
  the expected `pki`/`config` modules) — the RFC's original "AES-128-GCM
  territory, ~16 KiB record buffers" estimate stands unless a later pass
  finds otherwise.

**Cost**: TLS 1.3 client only — no server, and no fallback if a peer speaks
only 1.2. Certificate verification is real (see above) but narrower in
scope than a browser-grade verifier — algorithm coverage, not general
X.509 extension handling, was what got checked; a deeper audit before
trusting this for anything beyond Beta-scope work is still warranted.
Memory: the caller process needs a heap sized for record buffers, so any
process using it needs its `*BootInfo` heap grant re-sized (a kernel-side
change, since ring-3 processes here cannot map their own memory —
`main.rs:34-42`) — not yet done, no consumer process exists yet to size it
for. Smaller ecosystem and audit history than rustls.

### Option B: `rustls` in `no_std` mode with a pure-Rust crypto provider — **rejected, confirmed unreachable**

**Design**: same library-not-driver shape, built on `rustls` 0.23.x with
`default-features = false` and a `no_std`-compatible `CryptoProvider`.

**Verified for real (2026-09-27): no `CryptoProvider` builds for this
target, full stop.** `rustls` 0.23 does genuinely support `no_std` +
`alloc` (confirmed), but every provider option fails:

- `aws-lc-rs`: confirmed no `no_std` support — needs CMake/a C toolchain,
  as the RFC originally suspected.
- `ring`: confirmed disqualified directly, not by analogy — adding
  `embedded-tls`'s `webpki` feature (which routes cert verification
  through `ring`) to this exact crate and building it for
  `x86_64-unknown-none` fails immediately on `ring`'s `getrandom`
  dependency: `error: target is not supported` (`getrandom` has no
  implementation path for a freestanding target with no OS entropy
  source at all — this is a hard disqualification, not an LLVM-ICE class
  of problem with a known workaround).
- `rustls-rustcrypto`: pure Rust, but confirmed still pre-production —
  only release is `0.0.2-alpha`, depends on a `rustls-webpki` version with
  unpatched CVEs, and has roughly 70% cipher-suite coverage. `no_std`
  support is a stated future goal, not current reality. One small hobby OS
  project has an in-progress PR attempting a bare-metal pure-RustCrypto
  provider across several targets — by its own author's admission, "no
  handshake has ever completed" yet. Real signal that others hit this
  exact wall, not evidence of a working solution.

One fact that *is* verified locally and favors this option if a provider
exists: `rustls-pki-types` 1.15.1 is already in the root `Cargo.lock`, so
some host-side crate already depends on it — the types are not foreign to
this tree. Doesn't change the outcome: no provider, no option.

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

**Confirmed, 2026-09-27: Option A (`embedded-tls`, `rustpki` feature path,
as a shared library terminating in the caller process). Option C is no
longer needed as a fallback — the verification this section originally
called for came back positive, not negative.**

Reasoning (mostly historical at this point — kept for the record, since it
was right):

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
3. **Option B may not even be reachable** — confirmed true. See Option B's
   own section above for exactly why (`ring`'s `getrandom` dependency,
   directly, not by analogy).
4. **Entropy must land first, and it must be capability-gated.** Done —
   see the "Phase 1 decision" note at the top of this document for
   `SYS_RANDOM`'s actual shape (RDRAND-only, not virtio-rng — a smaller,
   deliberate deviation from what this point originally called for, argued
   there).
5. **It has a falsifiable next step.** Done, for real, not just planned:
   `tls-client/`'s dependency was added and built for
   `x86_64-unknown-none`. It did break, more than once (`sha2`, then `aes`,
   then `curve25519-dalek` — three separate LLVM-codegen ICEs, not the one
   this point anticipated), and every one had a known-shape fix. The
   `webpki`/`ring` path was also tried and confirmed to fail outright
   (`getrandom`, not an ICE) — which is what settled Option A on
   `rustpki` specifically rather than leaving that choice implicit.

**On the "do not ship a permissive verifier" condition this section
originally set**: it doesn't apply — `embedded-tls`'s default *is*
permissive (`NoVerify`, confirmed), but a real, non-default verifier
(`rustpki`'s `CertVerifier`) is what's actually depended on. Anyone adding
a consumer of `tls-client` later must not construct `embedded-tls`'s
config with the default verifier left in place — that would silently
reintroduce exactly the failure mode this RFC warned against. Worth a
lint/review-checklist item once a real consumer exists, not just prose
here.

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

- ~~**Does `embedded-tls` verify certificate chains to a standard a reviewer
  would accept today?**~~ — **resolved, yes**: `rustpki`'s `CertVerifier`
  does real chain verification against RustCrypto signature crates. See
  Option A's section above.
- ~~**Does any `rustls` `CryptoProvider` build for `x86_64-unknown-none`?**~~
  — **resolved, no**: confirmed directly (`ring`'s `getrandom` fails to
  build for this target at all), not just researched. `rustls-rustcrypto`
  specifically checked and confirmed still pre-production
  (`0.0.2-alpha`, unpatched-CVE `rustls-webpki` dependency, `no_std` a
  stated future goal not current reality) — if that changes later, this
  RFC should be reopened, but nothing suggests it's close.
- ~~**Do `aes-gcm` / `chacha20poly1305` / `p256` need `force-soft`-equivalent
  workarounds on this target,** the way `sha2` did?~~ — **resolved,
  partially**: `aes` (pulled in for AES-GCM) needed one
  (`aes_force_soft`), and so did `curve25519-dalek` (pulled in
  transitively, `curve25519_dalek_backend="serial"` — the same fix
  `kernel/.cargo/config.toml` already uses). `p256`/`p384`/`rsa` built
  clean with no additional flags needed. `chacha20poly1305` isn't in this
  dependency tree at all under the `rustpki` feature set — not checked.
- ~~**What is the entropy quality story in QEMU specifically?**~~ —
  **resolved**: confirmed from QEMU's own `util/guest-random.c` that
  `RDRAND`/`RDSEED` under TCG (software emulation, not KVM) route to
  `qemu_guest_getrandom()`, which by default takes the real,
  non-deterministic branch (the host OS's own CSPRNG) — genuine entropy,
  not a weak/seeded PRNG. A deterministic mode exists (for QEMU's own
  record/replay regression tooling) but only activates under `-icount`/
  `-seed`, which this project's `xtask`/CI invocations never pass. The
  remaining caveat is orthogonal to algorithm quality: a compromised
  hypervisor could in principle return attacker-chosen bytes instead of
  calling the real RNG (a trust-in-the-emulator concern, already covered
  by `kernel/src/entropy.rs`'s and `docs/THREAT_MODEL.md`'s existing
  single-source-trust caveat). Practically moot today regardless — CI's
  default `qemu64` CPU model doesn't expose RDRAND as a feature at all, so
  `kernel/tests/sys_random.rs` already proves the fail-closed path, not
  the real-entropy path.
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
- ~~**Does the one-byte-per-syscall IPC transport (`ipc/src/sockets.rs:10-20`)
  make a TLS handshake unacceptably slow?**~~ — **resolved, measured for
  real (2026-09-28, `kernel/tests/syscall_cost.rs`), and the answer is far
  worse than the prior estimate**: in this exact environment (QEMU/TCG,
  native Windows, no `-cpu`/`-icount` flags), `SYS_IPC_SEND`/`SYS_IPC_RECV`
  (the fixed-port model, full Ed25519 `authorized_for_port` verification on
  *every* call) measured **~12,000-30,000μs (12-30ms) per syscall** across
  two runs — roughly **300-3,000x** the RFC's own prior "pessimistic"
  100μs/syscall guess, not a rounding difference. A realistic 1,500-byte
  handshake (3,000 syscalls) over this path costs **~35-90 *seconds***, a
  3,000-byte handshake **~70-180 seconds** — both catastrophically over the
  300ms T1 budget, not "over budget" in the mild sense the estimate implied.
  RDTSC-based timing was needed to get this number at all: an `int 0x80`
  loop doesn't advance `interrupts::ticks()` visibly when run on the bare
  boot thread (a real, reproducible QEMU/TCG artifact — see that test's own
  doc comment — fixed by running the benchmark on a properly spawned
  thread instead, matching every other kernel test's own pattern).
  **The same benchmark measured the "Option C" session primitive
  (`kernel/src/ipc.rs`'s `SESSIONS` table, built this session — see
  `docs/RFC-IPC-RESPONSE-CAPABILITY.md`) for direct comparison**:
  `SYS_IPC_SESSION_SEND`/`RECV` (authorizes once at
  `SESSION_OPEN`/`ACCEPT`, an O(1) `ThreadId` compare on every call after)
  measured **~51μs/syscall — roughly 228x cheaper**. At that rate, a
  1,500-byte handshake costs **~153ms (fits within the 300ms budget)**; a
  3,000-byte handshake **~306ms (just over — close enough that record-size
  choices or a small further optimization would decide it)**. **This makes
  migrating TLS's transport onto the session primitive a hard prerequisite
  for T1-path usability, not an architectural nicety** — the fixed-port
  model is not merely slower, it is roughly two orders of magnitude too
  slow to ever fit this budget, regardless of any other optimization.

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
