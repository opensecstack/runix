//! Mobile-specific layers: radio abstraction (RIL), MVNO stack, ARM
//! TrustZone hardware root of trust.
//!
//! The MVNO stack core (Beta item 3) is pure, host-testable policy and
//! bookkeeping -- no hardware, no I/O -- written against `core` + `alloc`
//! only so `kernel-arm` can later depend on it. Enforcement (capability
//! checks, MARSHAL gate, WORM audit) deliberately lives at `kernel-arm`'s
//! syscall boundary, not in here.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

/// Subscriber / account / plan model and its invariants (Beta item 3, step 1).
pub mod account;
/// Pure network-selection decision function (Beta item 3, step 2).
pub mod selection;
