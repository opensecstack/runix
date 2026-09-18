//! Desktop-side CITADEL/MARSHAL plumbing.
//!
//! This module owns the real network transport for CITADEL Kerkese
//! submission — the "user-space proxy" half of the design documented in
//! `citadel-integration`'s `KerkeseTransport` doc comment: `kernel/` never
//! talks to MARSHAL directly, a hosted `desktop` (mobile later) process
//! does, over HTTP via [`transport::HttpKerkeseTransport`]. `kernel/` will
//! eventually reach this proxy over Runix's own `ipc` wire format — that
//! wiring is a separate, still-open task and is deliberately not present
//! here yet (see [`transport`]'s module docs for exactly what this module
//! does and does not do today).

pub mod transport;

pub use transport::HttpKerkeseTransport;
