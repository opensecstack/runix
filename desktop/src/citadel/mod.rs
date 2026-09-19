//! Desktop-side CITADEL/MARSHAL plumbing.
//!
//! This module owns the real network transport for CITADEL Kerkese
//! submission — the "user-space proxy" half of the design documented in
//! `citadel-integration`'s `KerkeseTransport` doc comment: `kernel/` never
//! talks to MARSHAL directly, a hosted `desktop` (mobile later) process
//! does, over HTTP via [`transport::HttpKerkeseTransport`], and [`proxy`]
//! is the standalone TCP server (`src/bin/citadel_proxy.rs`) that accepts
//! `runix_ipc::marshal::MarshalRequest`s from a kernel/user-space caller and
//! answers with a `MarshalResponse` built from that transport. Actually
//! wiring `kernel::marshal_client` to reach this proxy end to end over a
//! real network path (rather than the test-only Python stand-in
//! `kernel/tests/support/marshal_proof_listener.py` answers today) is
//! separate, still-open work — see [`proxy`]'s and [`transport`]'s module
//! docs for exactly what each does and does not do today.

pub mod proxy;
pub mod transport;

pub use transport::HttpKerkeseTransport;
