//! Desktop-side CITADEL/MARSHAL plumbing.
//!
//! This module owns the real network transport for CITADEL Kerkese
//! submission — the "user-space proxy" half of the design documented in
//! `citadel-integration`'s `KerkeseTransport` doc comment: `kernel/` never
//! talks to MARSHAL directly, a hosted `desktop` (mobile later) process
//! does, over HTTP via [`transport::HttpKerkeseTransport`], and [`proxy`]
//! is the standalone TCP server (`src/bin/citadel_proxy.rs`) that accepts
//! `runix_ipc::marshal::MarshalRequest`s from a kernel/user-space caller,
//! parses the carried minimal envelope, runs its own local policy check
//! ([`policy`]), and — only once that passes — builds a real, enriched
//! Kerkese envelope carrying this proxy's own signed Verifier identity
//! ([`identity`]) before forwarding it through that transport. Per
//! `docs/RFC-VERIFIER-IDENTITY.md`'s Option A, this proxy is the second,
//! code-distinct Kerkese principal: the kernel remains the sole Operator
//! (`actor`), and this process — a genuinely separate binary, address
//! space, and trust boundary — is the Verifier. Actually wiring
//! `kernel::marshal_client` to reach this proxy end to end over a real
//! network path (rather than the test-only Python stand-in
//! `kernel/tests/support/marshal_proof_listener.py` answers today) is
//! separate, still-open work — see [`proxy`]'s and [`transport`]'s module
//! docs for exactly what each does and does not do today.

/// The proxy's own Verifier identity (keypair, real `Kerkese`/`KerkeseActor`/
/// `KerkeseVerifier`/`KerkeseSoD` shapes, canonical-payload signing) — see
/// this module's doc comment and `docs/RFC-VERIFIER-IDENTITY.md`'s Option A.
pub mod identity;
/// The proxy's own local policy check, run before it ever attaches
/// [`identity`]'s Verifier identity to a request — see that module's doc
/// comment for exactly what is and isn't checked.
pub mod policy;
pub mod proxy;
pub mod transport;

pub use transport::HttpKerkeseTransport;
