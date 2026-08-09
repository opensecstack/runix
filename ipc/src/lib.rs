//! User-space IPC wire types, shared between OS services, the WASM runtime,
//! and CITADEL integration. Distinct from `runix-kernel`'s in-kernel IPC
//! primitives — this crate is the serializable message format that crosses
//! process boundaries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub from: String,
    pub to: String,
    pub payload: serde_json::Value,
}
