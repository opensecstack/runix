//! User-space IPC wire types, shared between OS services, the WASM runtime,
//! and CITADEL integration. Distinct from `runix-kernel`'s in-kernel IPC
//! primitives (`kernel/src/ipc.rs`'s fixed-count byte channels) — this crate
//! is the serializable message format that crosses process boundaries.
//!
//! `no_std` + `alloc` by default (`#![cfg_attr(not(feature = "std"), no_std)]`,
//! same split `capability-manager/src/lib.rs` already uses for the same
//! reason): the `sockets` module needs to be usable directly from
//! `net-driver-host`, a freestanding `x86_64-unknown-none` ring 3 binary
//! with no `std` at all — a hand-rolled byte layout duplicated on that
//! side would be exactly the kind of parallel, non-typed wire format this
//! crate exists to avoid. `Envelope`, this crate's other (pre-existing)
//! type, still needs real `std` (`serde_json::Value`) — moved to its own
//! module, gated behind the `std` feature every other consumer gets by
//! default.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
mod envelope;
#[cfg(feature = "std")]
pub use envelope::Envelope;

pub mod fs;
pub mod sockets;
