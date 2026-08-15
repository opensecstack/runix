//! Basic SIM provisioning -- the last unstarted item on Alpha mobile's
//! roadmap line ("ARM TrustZone boot, RIL isolation, basic SIM
//! provisioning", see `docs/ROADMAP.md`). A minimal per-slot profile state
//! machine (`Uninitialized -> Provisioned -> Activated`), gated by the
//! *same* capability check `ril_channel.rs`'s SEND/RECV use
//! (`capabilities::check`, generalized from RIL-only in this same slice --
//! see that module's doc comment) -- proving the capability boundary
//! applies uniformly across resource *kinds*, not just within RIL.
//!
//! Deliberately not a real SIM/eSIM implementation: no APDU protocol, no
//! ICCID/IMSI as actual decimal strings (the `SVC` ABI only carries plain
//! `u64` arguments -- a real ICCID/IMSI needs ~15-20 digits, more than one
//! register), no persistence across reboots. `provision`'s "identity" is a
//! single opaque `u64`, good enough to prove a real state machine gated by
//! a real capability check, not a claim this models actual SIM
//! provisioning. A fixed-size-buffer syscall ABI (to carry real
//! ICCID/IMSI strings) is real follow-up work, not something to fake by
//! packing digits into a register.

use spin::Mutex;

/// Arbitrary, matches this crate's other demo scopes (`ril_channel.rs`'s
/// `CHANNEL_COUNT`) -- not a hardware-derived limit.
const SLOT_COUNT: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SimState {
    Uninitialized,
    Provisioned,
    Activated,
}

impl SimState {
    /// The `SYS_SIM_STATUS` return-value encoding -- `svc.rs`'s job to
    /// document as part of the syscall ABI, this module's job to define,
    /// since the state values themselves are what's being encoded.
    pub fn as_status_code(self) -> u64 {
        match self {
            SimState::Uninitialized => 0,
            SimState::Provisioned => 1,
            SimState::Activated => 2,
        }
    }
}

#[derive(Clone, Copy)]
struct SimSlot {
    state: SimState,
    /// Set once `provision` succeeds; stands in for ICCID/IMSI (see this
    /// module's doc comment on why those aren't modeled as real decimal
    /// strings here).
    identity: Option<u64>,
}

const EMPTY_SLOT: SimSlot = SimSlot {
    state: SimState::Uninitialized,
    identity: None,
};

static SLOTS: Mutex<[SimSlot; SLOT_COUNT]> = Mutex::new([EMPTY_SLOT; SLOT_COUNT]);

/// Provisions `slot` with `identity`, if it's currently `Uninitialized`.
/// Re-provisioning an already-provisioned slot is rejected, not
/// overwritten -- a real provisioning flow doesn't let a second identity
/// silently replace the first; that needs an explicit de-provision step
/// this module doesn't implement yet.
pub fn provision(slot: usize, identity: u64) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    if s.state != SimState::Uninitialized {
        return Err(SimError::WrongState(s.state));
    }
    s.identity = Some(identity);
    s.state = SimState::Provisioned;
    Ok(())
}

/// Activates `slot`, if it's currently `Provisioned`. `Uninitialized ->
/// Activated` directly is rejected -- activation without provisioning
/// first isn't a real transition this state machine allows, the same way
/// `capabilities::check` rejects a request for a resource never issued.
pub fn activate(slot: usize) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    if s.state != SimState::Provisioned {
        return Err(SimError::WrongState(s.state));
    }
    s.state = SimState::Activated;
    Ok(())
}

/// Reads `slot`'s current state -- always succeeds for an in-range slot
/// (querying status, unlike provisioning/activating, has no wrong-state
/// error of its own; `Uninitialized` is itself a valid answer).
pub fn status(slot: usize) -> Result<SimState, SimError> {
    let slots = SLOTS.lock();
    let s = slots.get(slot).ok_or(SimError::NoSuchSlot)?;
    Ok(s.state)
}

#[derive(Debug)]
pub enum SimError {
    NoSuchSlot,
    WrongState(SimState),
}

impl core::fmt::Display for SimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SimError::NoSuchSlot => write!(f, "no such SIM slot"),
            SimError::WrongState(s) => write!(f, "wrong state for this operation ({s:?})"),
        }
    }
}
