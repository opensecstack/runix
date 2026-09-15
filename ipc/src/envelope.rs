//! Pre-existing generic message envelope — std-only (`serde_json::Value` has
//! no practical no_std story), gated behind this crate's `std` feature. See
//! `lib.rs`'s doc comment for why `sockets` had to move out from under that
//! same constraint.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub from: String,
    pub to: String,
    pub payload: serde_json::Value,
}
