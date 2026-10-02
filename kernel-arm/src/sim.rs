//! eSIM profile lifecycle -- the Beta-scope successor to Alpha's minimal
//! per-slot SIM provisioning state machine (`Uninitialized -> Provisioned
//! -> Activated`, see `docs/ROADMAP.md`'s Alpha mobile line). Each slot now
//! holds a *bounded collection* of eSIM profiles, each with its own
//! lifecycle state, gated by the *same* capability check `ril_channel.rs`'s
//! SEND/RECV use (`capabilities::check`) -- that gating lives in
//! `capabilities.rs`/`svc.rs`, not here; this module is only the data model
//! and the transition logic.
//!
//! # What this models
//!
//! `ProfileState` mirrors the GSMA RSP (Remote SIM Provisioning) profile
//! lifecycle, simplified to the four states that actually have distinct
//! meaning for an OS-level state machine:
//!
//! - `Created` -- profile container allocated on the (notional) eUICC, but
//!   nothing installed into it yet.
//! - `Disabled` -- installed/downloaded, but not the active profile.
//! - `Enabled` -- *the* active profile on this slot. At most one per slot,
//!   enforced here (see `transition`).
//! - `Deleted` -- permanently removed. Terminal: there is no transition out
//!   of `Deleted`, by design.
//!
//! Legal transitions, and nothing else:
//!
//! ```text
//! Created  -> Disabled   (install / download)
//! Disabled -> Enabled    (enable -- atomically disables the previous
//!                         Enabled profile in the same slot, if any)
//! Enabled  -> Disabled   (disable)
//! Disabled -> Deleted    (delete)
//! ```
//!
//! In particular `Enabled -> Deleted` is **not** legal: deleting the active
//! profile is a `WrongState` error, not an implicit disable-then-delete. A
//! caller that wants that has to disable first and say so, because "delete
//! quietly dropped the slot's active subscription" is exactly the kind of
//! silent side effect a governed path should not have.
//!
//! # What this deliberately is not
//!
//! Not a GSMA SGP.22 implementation and not claiming to be one -- it's a
//! clean-room state machine *inspired by* that lifecycle. Still missing,
//! and still honest about it:
//!
//! - No APDU protocol, no eUICC/ISD-R command set, no ES8+/ES9+/ES10x
//!   interfaces, no activation codes, no SM-DP+ or SM-DS interaction.
//! - `identity` is a single opaque `u64`, not a real ICCID/IMSI. Kept from
//!   the Alpha code and for the same unchanged reason: the `SVC` syscall ABI
//!   only carries plain register arguments, and a real ICCID/IMSI needs
//!   ~15-20 decimal digits -- more than one register. A fixed-size-buffer
//!   syscall ABI is real follow-up work, not something to fake by packing
//!   digits into a register.
//! - No persistence across reboots, no profile metadata (nickname, SPN,
//!   icon), no profile policy rules (PPRs).
//! - `Deleted` profiles keep occupying their entry in the slot's vector --
//!   there is no reclamation, so a slot can be `MAX_PROFILES_PER_SLOT`-full
//!   of nothing but deleted profiles. Honest simplification: profile IDs
//!   stay stable and meaningful for the lifetime of the boot, which matters
//!   more here than reusing four entries.

use alloc::vec::Vec;
use spin::Mutex;

/// Arbitrary, matches this crate's other demo scopes (`ril_channel.rs`'s
/// `CHANNEL_COUNT`) -- not a hardware-derived limit.
const SLOT_COUNT: usize = 4;

/// Bounded on purpose: this is `no_std` kernel code, so "the slot's profile
/// list grows until the heap says no" is not an acceptable failure mode. The
/// specific number is arbitrary (real eUICCs are limited by storage, not by
/// a round constant); what matters is that `create` has a defined,
/// non-allocating-forever answer when the bound is reached.
pub const MAX_PROFILES_PER_SLOT: usize = 4;

/// One eSIM profile's lifecycle state. See this module's doc comment for
/// what each state means and which transitions are legal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProfileState {
    Created,
    Disabled,
    Enabled,
    Deleted,
}

impl ProfileState {
    /// The per-profile status return-value encoding for the (future)
    /// profile-aware syscalls -- `svc.rs`'s job to document as part of the
    /// syscall ABI, this module's job to define, since the state values
    /// themselves are what's being encoded.
    pub fn as_status_code(self) -> u64 {
        match self {
            ProfileState::Created => 0,
            ProfileState::Disabled => 1,
            ProfileState::Enabled => 2,
            ProfileState::Deleted => 3,
        }
    }
}

/// One profile container in one slot. `id` is the profile's handle within
/// its slot (not globally unique -- slot 0's profile 1 and slot 1's profile
/// 1 are different profiles), assigned sequentially by `create` and stable
/// for the lifetime of the boot.
#[derive(Clone, Copy, Debug)]
pub struct EsimProfile {
    pub id: u8,
    /// Set by `install`; stands in for ICCID/IMSI (see this module's doc
    /// comment on why those aren't modeled as real decimal strings here).
    /// `None` while the profile is still `Created` -- a container with
    /// nothing downloaded into it has no identity yet.
    pub identity: Option<u64>,
    pub state: ProfileState,
}

struct SimSlot {
    profiles: Vec<EsimProfile>,
}

impl SimSlot {
    fn find(&self, profile_id: u8) -> Result<usize, SimError> {
        self.profiles
            .iter()
            .position(|p| p.id == profile_id)
            .ok_or(SimError::NoSuchProfile)
    }

    /// The **only** place a profile's state ever changes. Everything public
    /// in this module routes through here, so the two slot-wide invariants
    /// (at most one `Enabled` profile; no direct `Enabled -> Deleted`) have
    /// exactly one enforcement point rather than one per operation.
    ///
    /// Validates fully *before* mutating anything: on `Err` the slot is
    /// untouched, and on `Ok` the enable case has both the
    /// disable-the-previous and enable-the-new writes applied. Since the
    /// caller holds the `SLOTS` lock across this whole call, no other
    /// context can observe the in-between state where zero or two profiles
    /// in this slot are `Enabled`.
    fn transition(&mut self, profile_id: u8, to: ProfileState) -> Result<(), SimError> {
        let idx = self.find(profile_id)?;
        let from = self.profiles[idx].state;

        // The legality table, as one match rather than scattered per-caller
        // checks. Note `Created` is absent as a target: creation is not a
        // transition (that's `create`), so `to == Created` is always
        // rejected, and `Deleted` has no arm as a source, which is what
        // makes it terminal.
        let legal = match to {
            ProfileState::Disabled => {
                from == ProfileState::Created || from == ProfileState::Enabled
            }
            ProfileState::Enabled => from == ProfileState::Disabled,
            ProfileState::Deleted => from == ProfileState::Disabled,
            ProfileState::Created => false,
        };
        if !legal {
            return Err(SimError::WrongState(from));
        }

        // Exactly-one-Enabled: enabling X demotes whatever was Enabled
        // before, in the same critical section as enabling X. Done after
        // validation above, so a rejected enable never disables anything.
        if to == ProfileState::Enabled {
            for p in self.profiles.iter_mut() {
                if p.state == ProfileState::Enabled {
                    p.state = ProfileState::Disabled;
                }
            }
        }

        self.profiles[idx].state = to;
        Ok(())
    }
}

const EMPTY_SLOT: SimSlot = SimSlot {
    profiles: Vec::new(),
};

static SLOTS: Mutex<[SimSlot; SLOT_COUNT]> = Mutex::new([EMPTY_SLOT; SLOT_COUNT]);

/// Allocates a new profile container in `slot` and returns its ID.
///
/// Fails with `SlotFull` once the slot holds `MAX_PROFILES_PER_SLOT`
/// profiles -- including `Deleted` ones, which are never reclaimed (see this
/// module's doc comment). The new profile starts `Created` with no
/// `identity`; `install` is what gives it one.
pub fn create(slot: usize) -> Result<u8, SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    if s.profiles.len() >= MAX_PROFILES_PER_SLOT {
        return Err(SimError::SlotFull);
    }
    let id = s.profiles.len() as u8;
    s.profiles.push(EsimProfile {
        id,
        identity: None,
        state: ProfileState::Created,
    });
    Ok(id)
}

/// Installs (in RSP terms: downloads) a profile into its container:
/// `Created -> Disabled`, setting `identity`.
///
/// A freshly installed profile is `Disabled`, not `Enabled` -- installing a
/// profile does not steal the slot's active subscription out from under
/// whatever is already `Enabled`. `enable` is a separate, explicit step.
/// Re-installing an already-installed profile is rejected (`WrongState`),
/// not silently overwritten with a second identity.
pub fn install(slot: usize, profile_id: u8, identity: u64) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    s.transition(profile_id, ProfileState::Disabled)?;
    // Only after the transition is accepted -- a rejected install leaves no
    // identity behind. `find` cannot fail here: `transition` just resolved
    // the same ID under the same lock.
    let idx = s.find(profile_id)?;
    s.profiles[idx].identity = Some(identity);
    Ok(())
}

/// Enables a profile: `Disabled -> Enabled`, atomically disabling whichever
/// profile in the same slot was `Enabled` before (if any).
///
/// After a successful call exactly one profile in `slot` is `Enabled` -- the
/// requested one. A `Created` profile cannot be enabled directly; install it
/// first.
pub fn enable(slot: usize, profile_id: u8) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    s.transition(profile_id, ProfileState::Enabled)
}

/// Disables the active profile: `Enabled -> Disabled`. Leaves the slot with
/// no `Enabled` profile at all, which is a legitimate state (an eUICC with
/// every profile disabled has no active subscription).
pub fn disable(slot: usize, profile_id: u8) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    s.transition(profile_id, ProfileState::Disabled)
}

/// Deletes a profile: `Disabled -> Deleted`, and only from `Disabled`.
///
/// Deleting an `Enabled` profile is a `WrongState` error -- deliberately not
/// an implicit disable-then-delete (see this module's doc comment).
/// `Deleted` is terminal: a deleted profile's entry stays in the slot as a
/// record and can never transition again.
pub fn delete(slot: usize, profile_id: u8) -> Result<(), SimError> {
    let mut slots = SLOTS.lock();
    let s = slots.get_mut(slot).ok_or(SimError::NoSuchSlot)?;
    s.transition(profile_id, ProfileState::Deleted)
}

/// Reads one profile's current state. Always succeeds for an existing
/// profile in an in-range slot -- querying has no wrong-state error of its
/// own, and `Deleted` is itself a valid answer.
pub fn profile_state(slot: usize, profile_id: u8) -> Result<ProfileState, SimError> {
    let slots = SLOTS.lock();
    let s = slots.get(slot).ok_or(SimError::NoSuchSlot)?;
    let idx = s.find(profile_id)?;
    Ok(s.profiles[idx].state)
}

/// Snapshot of every profile in `slot`, including `Deleted` ones, in ID
/// order. A copy, not a borrow: the real state stays behind the `SLOTS`
/// lock, so callers can't hold a reference into it across a transition.
///
/// `allow(dead_code)`: no caller yet. Unlike the rest of this module's API,
/// this one has no syscall behind it -- `svc.rs`'s SIM syscalls are all
/// single-profile, and a "list every profile in the slot" syscall would
/// need a fixed-size-buffer ABI this crate's register-only `SVC` gate
/// doesn't have (same limitation this module's doc comment records for
/// `identity`). Kept rather than deleted because the MVNO stack work
/// (`docs/BETA_MOBILE_PROGRESS.md`'s Item 3) reads slot-wide profile state
/// from EL1, not through a syscall, and that is this function's caller.
#[allow(dead_code)]
pub fn profiles(slot: usize) -> Result<Vec<EsimProfile>, SimError> {
    let slots = SLOTS.lock();
    let s = slots.get(slot).ok_or(SimError::NoSuchSlot)?;
    Ok(s.profiles.clone())
}

/// The ID of `slot`'s single `Enabled` profile, or `None` if the slot has no
/// active subscription. `Ok(None)` is a normal answer, not an error.
///
/// `allow(dead_code)`: no caller yet, same reasoning as [`profiles`] --
/// the slot-wide "which profile is active" question is an EL1-side query
/// for the MVNO/network-selection work, not something `svc.rs` exposes
/// (EL0 asks per-profile, via `SYS_SIM_STATUS`).
#[allow(dead_code)]
pub fn enabled_profile(slot: usize) -> Result<Option<u8>, SimError> {
    let slots = SLOTS.lock();
    let s = slots.get(slot).ok_or(SimError::NoSuchSlot)?;
    Ok(s.profiles
        .iter()
        .find(|p| p.state == ProfileState::Enabled)
        .map(|p| p.id))
}

#[derive(Debug)]
pub enum SimError {
    NoSuchSlot,
    NoSuchProfile,
    /// `slot` already holds `MAX_PROFILES_PER_SLOT` profile containers.
    SlotFull,
    /// The profile's current state does not permit the requested
    /// transition. Carries the *from* state, which is the part a caller
    /// needs in order to know what to do instead (notably: `Enabled` back
    /// from `delete` means "disable it first").
    WrongState(ProfileState),
}

impl core::fmt::Display for SimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SimError::NoSuchSlot => write!(f, "no such SIM slot"),
            SimError::NoSuchProfile => write!(f, "no such eSIM profile in this slot"),
            SimError::SlotFull => write!(
                f,
                "SIM slot is full ({MAX_PROFILES_PER_SLOT} profile containers)"
            ),
            SimError::WrongState(s) => write!(f, "wrong state for this operation ({s:?})"),
        }
    }
}
