//! Runix TLS client library — `no_std` + `alloc`, like `capability-manager`/
//! `citadel-integration`/`wasm-runtime` (`#![cfg_attr(not(test), no_std)]`,
//! `#[cfg(test)]` opts back into `std` for this crate's own test suite).
//! Meant to be linked into whichever ring-3 process needs TLS, never into
//! `net-driver-host` itself — see `docs/RFC-TLS-APPROACH.md`'s "library,
//! not driver" decision (its Context section, "The alternative is TLS as a
//! **library**...") for the full argument: X.509 parsing and session keys
//! must never live in the one process holding a device-register
//! capability, and per-caller/per-tier key separation is otherwise
//! impossible (`ipc/src/sockets.rs`'s own doc comment already documents
//! that the sockets surface can't attribute a handle to a caller). This
//! crate is deliberately ignorant of drivers, tiers, CITADEL, and MARSHAL
//! — the same decoupling `wasm-runtime`'s own doc comment describes for
//! itself — it only knows how to speak TLS over a byte pipe a caller
//! supplies.
//!
//! **Status: a real TLS 1.3 handshake works, proven against a live server,
//! not just against `embedded-tls`'s type signatures.** The RFC's
//! recommendation (Option A, `embedded-tls`) rested on two `[UNVERIFIED]`
//! claims its drafting session couldn't check (no network access at the
//! time): whether `embedded-tls`'s certificate verification is actually
//! production-usable, and whether any `rustls` `CryptoProvider` builds for
//! `x86_64-unknown-none` at all. Both resolved for real — see
//! `docs/RFC-TLS-APPROACH.md`'s "Phase 2"/"Phase 3" notes for the full
//! account:
//!
//! - `rustls`: no. Every viable `CryptoProvider` (`ring`, `aws-lc-rs`) is
//!   disqualified for this target — confirmed concretely for `ring` (its
//!   `getrandom` dependency hard-fails to build for `x86_64-unknown-none`
//!   at all), matching the RFC's own prior research for `aws-lc-rs` (needs
//!   CMake/a C toolchain).
//! - `embedded-tls`: yes, via its **`rustpki`** feature path
//!   (`embedded_tls::pki::CertVerifier`), not `webpki` (equally
//!   disqualified — it pulls `ring` the same way `rustls` would). Real
//!   X.509 chain verification against RustCrypto's own signature crates,
//!   with `ed25519`/`p384` covering two of the three signature algorithm
//!   families real-world CA roots use (the third, RSA, is deliberately not
//!   enabled — see `Cargo.toml`'s dependency comment on RUSTSEC-2023-0071)
//!   — builds clean for
//!   `x86_64-unknown-none` (see `.cargo/config.toml` for the three
//!   LLVM-codegen-ICE workarounds that took), and — the real proof —
//!   [`TlsConnection`] genuinely completed a TLS 1.3 handshake against
//!   `example.com` over a real `TcpStream`, verified its real, live
//!   4-certificate chain against a real root CA, and decrypted a real HTTP
//!   response (`tests/live_handshake.rs`, `#[ignore]`d — hits the live
//!   internet and a rotation-prone CA chain, run deliberately with
//!   `cargo test -- --ignored`, not on every CI run).
//!
//! What's still genuinely unbuilt, separately scoped: a `TlsClock`
//! implementation with a real wall-clock source (today [`connection::NoClock`]
//! is used, meaning certificate validity-period checking is explicitly
//! skipped, not silently — this system has no wall-clock time at all yet;
//! see `kernel/src/capabilities.rs`'s own token-expiry doc comment for the
//! same gap), real trust-anchor *provisioning* (compiled-in and
//! build-time-signed, per the RFC's "What changes under Option A" section
//! — today a caller must already have CA DER bytes from somewhere, and
//! `CertVerifier` only ever checks against **one** CA per connection, not a
//! root store), a kernel-side heap-grant mechanism sized for whatever real
//! process eventually links this crate, and that real consumer process
//! itself (nothing in Runix needs TLS yet).
//!
//! # The RNG problem this crate refuses to solve itself
//!
//! The RFC is explicit (Context, point 4 under "Recommendation") that the
//! tempting shortcut — reading `RDRAND` directly in the ring-3 process
//! that needs TLS — is wrong specifically *because* it would work with no
//! kernel change at all: that's ambient authority by construction,
//! invisible to the capability system, unattributable in WORM, and
//! untestable under a deterministic QEMU harness. `kernel/src/entropy.rs`'s
//! `SYS_RANDOM` (capability-gated on a `"random"` resource, fails closed)
//! is the correct source — but no syscall stub is shared between the
//! kernel and a separately-linked ring 3 binary (every driver-host in this
//! repo has its own private copy; see e.g. `net-driver-host/src/syscall.rs`'s
//! own doc comment on why), so this crate cannot call it directly. Instead
//! it takes entropy as a caller-supplied [`Entropy`] implementation — the
//! caller's own `syscall::random_u64()`-shaped wrapper, plugged in.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod connection;
mod io;
mod rng;

pub use connection::{
    CertificateDer, CipherSuite, Config, HandshakeError, TlsConnection, MAX_CHAIN_DER_LEN,
};

/// A caller-supplied way to yield the CPU while [`io::BlockingIo`] waits for
/// [`Transport::read`] to have something — this crate has no scheduler of
/// its own to call into (see this module's doc comment on why it can't even
/// call `SYS_RANDOM` directly; the same "no shared code between the kernel
/// and a separately-linked ring 3 binary" reasoning applies to `yield_now`).
/// A no-op implementation is valid (busy-spins instead of cooperating with
/// the scheduler) but wastes a whole time slice per poll on a system with
/// real preemption — every real caller in this codebase yields.
pub trait Yield {
    fn yield_now(&mut self);
}

/// A caller-supplied source of cryptographically strong randomness — see
/// this module's doc comment for why this crate takes it as a parameter
/// rather than reading `SYS_RANDOM` itself. `None` must propagate as a
/// hard failure in any caller of this trait (never silently substituted
/// with a weaker source) — same fail-closed posture `SYS_RANDOM` itself
/// has at the syscall boundary.
pub trait Entropy {
    /// One `u64` of randomness, or `None` if none is currently available
    /// (the underlying capability was denied, or the hardware source is
    /// absent/exhausted — see `kernel/src/entropy.rs`'s own doc comment for
    /// why this never falls back to something weaker instead of returning
    /// `None`).
    fn next_u64(&mut self) -> Option<u64>;
}

/// A caller-supplied byte pipe — TLS records read from and written to
/// whatever transport the caller already has open, most commonly
/// `runix_ipc::sockets`'s `SocketRequest::{Send,Recv}` surface driven over
/// `net-driver-host`, though this trait deliberately doesn't know that:
/// keeping this crate ignorant of `runix_ipc`/sockets specifically is what
/// lets it also work over e.g. a future different transport, or a
/// host-side (desktop/mobile) socket, without a second implementation of
/// the TLS layer itself.
pub trait Transport {
    /// Must be `Debug` — this crate's internal `embedded_io` bridge
    /// (`io::TransportError`) needs it to satisfy `embedded_io::Error`,
    /// which requires `core::error::Error` regardless of what a caller's
    /// concrete transport error actually looks like.
    type Error: core::fmt::Debug;

    /// Reads up to `buf.len()` bytes, returning how many were actually
    /// read. `Ok(0)` means "nothing available right now, try again" (this
    /// codebase's universal non-blocking-IPC convention — see
    /// `kernel::ipc::try_recv`'s callers), not end-of-stream; there is no
    /// end-of-stream concept at this layer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes `buf` in full (or fails) — unlike `read`, TLS record framing
    /// requires the *whole* record's bytes to actually land before the
    /// caller can move on, the same "send a whole logical message, not a
    /// partial one" discipline `kernel::ipc`'s per-port send-lock
    /// convention already exists to protect on the underlying IPC layer.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}
