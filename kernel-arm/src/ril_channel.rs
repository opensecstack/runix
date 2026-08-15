//! Per-channel RIL byte mailboxes -- the piece of state `svc.rs`'s
//! `SYS_RIL_SEND`/`SYS_RIL_RECV` actually operate on. Deliberately the
//! simplest thing that lets a capability check gate real I/O instead of
//! just a yes/no access decision: one pending byte per channel, no queue,
//! no backpressure, no real radio protocol underneath -- proving the
//! *isolation boundary* (each operation re-checks the caller's capability
//! against `channel`, not just once at "open" time) is this module's job,
//! not modeling an actual RIL.

use spin::Mutex;

/// Arbitrary, matches `ril_capability`'s demo scope (one EL0 context, a
/// handful of channels) -- not a hardware-derived limit.
const CHANNEL_COUNT: usize = 4;

static CHANNELS: [Mutex<Option<u8>>; CHANNEL_COUNT] = [const { Mutex::new(None) }; CHANNEL_COUNT];

/// Stores `byte` in `channel`'s single-slot mailbox, overwriting whatever
/// was there (no queue -- see this module's doc comment). `Err(())` for an
/// out-of-range channel; the capability check itself (same resource string,
/// `ril_capability::ril_resource`) is `svc::dispatch`'s job, not this
/// module's -- this function trusts its caller already gated the request.
pub fn send(channel: usize, byte: u8) -> Result<(), ()> {
    match CHANNELS.get(channel) {
        Some(slot) => {
            *slot.lock() = Some(byte);
            Ok(())
        }
        None => Err(()),
    }
}

/// Takes (removes, not peeks) `channel`'s pending byte, if any. `None` for
/// both "nothing sent yet" and "out-of-range channel" -- `svc::dispatch`
/// distinguishes those cases with its own sentinel values on the syscall
/// return path, not this function's `Option`.
pub fn recv(channel: usize) -> Option<u8> {
    CHANNELS.get(channel)?.lock().take()
}
