//! General-purpose per-channel byte mailboxes -- the piece of state
//! `svc.rs`'s `SYS_IPC_SEND`/`SYS_IPC_RECV` operate on, and the ARM-side
//! analogue of `kernel/src/ipc.rs`'s "fixed-count byte channels addressed
//! by small integer port ids."
//!
//! Deliberately a *sibling* of `ril_channel.rs`, not a reuse of it: a RIL
//! channel is a specific resource kind with its own meaning (a radio
//! interface link, gated by `capabilities::ril_resource`), while this is a
//! general IPC primitive any future syscall caller can use for arbitrary
//! byte exchange. Sharing one array would mean an `ipc:` capability
//! implicitly reaching RIL traffic (and vice versa) -- the opposite of what
//! the separate resource strings exist to express. So this is its own,
//! newly-addressed channel space with its own capability naming
//! (`capabilities::ipc_resource`).
//!
//! # Why a single-byte mailbox and not a queue
//!
//! `kernel/src/ipc.rs` on the x86_64 side is a real `VecDeque<u8>` with a
//! `CHANNEL_CAPACITY` bound, and its `send`/`recv` *block* by spin-yielding
//! through that kernel's scheduler. Both of those properties exist to serve
//! something this crate does not have yet: multiple concurrently-scheduled
//! threads, one of which can make progress while another waits. `kernel-arm`
//! has exactly one EL0 context (`el0.rs`'s `el0_demo`) and no scheduler, so
//! a capacity bound would never be reached by a second sender and a blocking
//! `recv` would be an unconditional deadlock -- there is nobody to yield to.
//! A one-byte, overwrite-on-send, take-on-recv mailbox is therefore the
//! simplest thing that is *really* a working channel here rather than a
//! simulation of one, and it is the exact shape `ril_channel.rs` has already
//! proven works end to end through the `SVC` gate on this crate.
//!
//! Deliberately *not* the session/response-capability design of
//! `docs/RFC-IPC-RESPONSE-CAPABILITY.md`: that machinery exists to stop one
//! of several concurrent clients from reading another's reply out of a
//! shared queue, which again presupposes concurrent callers. See
//! `docs/BETA_MOBILE_PROGRESS.md`'s Item 2.6 for the same reasoning applied
//! to the MARSHAL transport.
//!
//! Revisit trigger: the first time two threads can genuinely run
//! interleaved here (the scheduler slice of Item 2.4), at which point the
//! x86_64 queue-plus-spin-yield shape becomes meaningful and this should
//! grow into it rather than stay a mailbox.

use spin::Mutex;

/// Arbitrary, matching `ril_channel.rs`'s own demo-scoped count rather than
/// `kernel/src/ipc.rs`'s `PORT_COUNT = 16` -- one EL0 context needs a
/// handful of channels, not a hardware-derived number of them.
const CHANNEL_COUNT: usize = 4;

static CHANNELS: [Mutex<Option<u8>>; CHANNEL_COUNT] = [const { Mutex::new(None) }; CHANNEL_COUNT];

/// Stores `byte` in `channel`'s single-slot mailbox, overwriting whatever
/// was there (no queue -- see this module's doc comment). `Err(())` for an
/// out-of-range channel; the capability check itself (`capabilities::
/// ipc_resource`) is `svc::dispatch`'s job, not this module's -- this
/// function trusts its caller already gated the request, the same trust
/// posture `ril_channel::send` and every function in `kernel/src/ipc.rs`
/// take.
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
/// return path, not this function's `Option`. Non-blocking, unlike
/// `kernel/src/ipc.rs::recv`: there is no other thread to yield to while
/// waiting (see this module's doc comment), so blocking here could only ever
/// hang the one context that exists.
pub fn recv(channel: usize) -> Option<u8> {
    CHANNELS.get(channel)?.lock().take()
}
