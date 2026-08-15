//! `SVC` syscall dispatch -- the ARM-side analogue of
//! `kernel/src/syscall.rs::dispatch` on the x86_64 side. Reached from
//! `el1_vectors.rs`'s vector-8 `SVC` handling; see that module's doc
//! comment for how the syscall number/arg actually get here.
//!
//! Seven syscalls, matching `el0.rs`'s demo exactly (kept in sync by hand,
//! not shared constants -- see `el0.rs`'s own doc comment on why):
//! - `SYS_WRITE`: unconditional -- proves the `SVC` gate itself works,
//!   the same role `kernel/src/syscall.rs`'s `SYS_WRITE` plays for `int
//!   0x80` on the x86_64 side.
//! - `SYS_RIL_ACCESS`: capability-gated through `capabilities::check`,
//!   a bare yes/no decision -- proves the check itself distinguishes an
//!   authorized channel from one it isn't.
//! - `SYS_RIL_SEND`/`SYS_RIL_RECV`: the same capability check, but now
//!   gating real per-channel I/O (`ril_channel.rs`) instead of a bare
//!   decision -- re-checked on *every* operation, not cached from a prior
//!   "open" call, so revoking a capability mid-session (not exercised by
//!   `el0_demo` today, but the model this supports) would deny the very
//!   next `SEND`/`RECV` on that channel, not just a future "open." This
//!   is the RIL isolation boundary, not memory isolation (which `mmu.rs`'s
//!   own doc comment already says doesn't exist at this granularity yet).
//! - `SYS_SIM_PROVISION`/`SYS_SIM_ACTIVATE`/`SYS_SIM_STATUS`: the *same*
//!   capability check applied to a different resource kind (`sim:{slot}`,
//!   not `ril:{channel}`) gating a real state machine (`sim.rs`) instead
//!   of a byte mailbox -- proving the capability boundary is uniform
//!   across resource kinds, not something special-cased for RIL. This is
//!   Alpha mobile's "basic SIM provisioning" roadmap item (see
//!   `docs/ROADMAP.md`).

use crate::serial::write_byte;
use crate::serial_println;

pub const SYS_WRITE: u64 = 1;
pub const SYS_RIL_ACCESS: u64 = 2;
pub const SYS_RIL_SEND: u64 = 3;
pub const SYS_RIL_RECV: u64 = 4;
pub const SYS_SIM_PROVISION: u64 = 5;
pub const SYS_SIM_ACTIVATE: u64 = 6;
pub const SYS_SIM_STATUS: u64 = 7;

/// `SYS_RIL_RECV`'s return-value convention: `0..=255` is a received byte,
/// `256`/`257` are out-of-band sentinels distinct from any real byte value
/// (unlike `SYS_RIL_ACCESS`/`SYS_RIL_SEND`, which only ever report
/// success/denied, `RECV` also has to report "authorized, but nothing sent
/// yet" as a third, distinct outcome).
const RIL_RECV_EMPTY: u64 = 256;
const RIL_RECV_DENIED: u64 = 257;

/// `SYS_SIM_STATUS`'s return-value convention: `0..=2` is a real state
/// (see `sim::SimState::as_status_code`), `3` is denied -- distinct from
/// any real state code, same reasoning as `RIL_RECV_EMPTY`/`RIL_RECV_DENIED`.
const SIM_STATUS_DENIED: u64 = 3;

/// Reads the ARM generic timer's physical counter -- this crate's only
/// available "now," in the total absence of an RTC or the x86_64 kernel's
/// PIT-tick counter (`interrupts::ticks()`). Good enough to prove a
/// capability's expiry window is actually consulted, not a claim that
/// this is wall-clock time.
pub fn now_ticks() -> u64 {
    let cntpct: u64;
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) cntpct);
    }
    cntpct
}

/// The generic timer's actual tick rate (`CNTFRQ_EL0`, fixed by the
/// platform, not something this crate configures). `capabilities`'s
/// expiry window is sized off this rather than a fixed tick count -- a
/// fixed count picked without checking this first (`1_000_000`, tried
/// initially) turned out to be under a millisecond of real time on this
/// platform's frequency, which heap init plus a handful of UART prints
/// between issuance and the first check comfortably exceeds, making
/// every demo token "expire" before `el0_demo` ever got to use it.
pub fn frequency_hz() -> u64 {
    let cntfrq: u64;
    unsafe {
        core::arch::asm!("mrs {}, CNTFRQ_EL0", out(reg) cntfrq);
    }
    cntfrq
}

/// Dispatches one syscall. `num`/`arg1`/`arg2` are EL0's `x0`/`x1`/`x2` at
/// the moment of `svc #0`. Returns the value that becomes EL0's new `x0`
/// once `el1_vectors.rs`'s epilogue `eret`s back -- `0` for success,
/// nonzero for "denied"/"unknown," the same coarse convention
/// `kernel/src/syscall.rs::dispatch` uses (`u64::MAX` for "denied," here
/// `1` -- picked distinct from `0`/success, not required to match the
/// x86_64 side's exact sentinel; `SYS_RIL_RECV` has its own wider
/// convention, see `RIL_RECV_EMPTY`/`RIL_RECV_DENIED`).
pub fn dispatch(num: u64, arg1: u64, arg2: u64) -> u64 {
    match num {
        SYS_WRITE => {
            write_byte(arg1 as u8);
            0
        }
        SYS_RIL_ACCESS => {
            let channel = arg1 as usize;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => {
                    serial_println!(
                        "\nSVC: SYS_RIL_ACCESS channel {} authorized (capability check passed)",
                        channel
                    );
                    0
                }
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_ACCESS channel {} DENIED ({})", channel, e);
                    1
                }
            }
        }
        SYS_RIL_SEND => {
            let channel = arg1 as usize;
            let byte = arg2 as u8;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => match crate::ril_channel::send(channel, byte) {
                    Ok(()) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_SEND channel {} byte {:#x} authorized",
                            channel,
                            byte
                        );
                        0
                    }
                    Err(()) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_SEND channel {} DENIED (no such channel)",
                            channel
                        );
                        1
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_SEND channel {} DENIED ({})", channel, e);
                    1
                }
            }
        }
        SYS_RIL_RECV => {
            let channel = arg1 as usize;
            match check(&crate::capabilities::ril_resource(channel)) {
                Ok(()) => match crate::ril_channel::recv(channel) {
                    Some(byte) => {
                        serial_println!(
                            "\nSVC: SYS_RIL_RECV channel {} authorized, byte {:#x}",
                            channel,
                            byte
                        );
                        byte as u64
                    }
                    None => {
                        serial_println!(
                            "\nSVC: SYS_RIL_RECV channel {} authorized, nothing pending",
                            channel
                        );
                        RIL_RECV_EMPTY
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_RIL_RECV channel {} DENIED ({})", channel, e);
                    RIL_RECV_DENIED
                }
            }
        }
        SYS_SIM_PROVISION => {
            let slot = arg1 as usize;
            let identity = arg2;
            match check(&crate::capabilities::sim_resource(slot)) {
                Ok(()) => match crate::sim::provision(slot, identity) {
                    Ok(()) => {
                        serial_println!(
                            "\nSVC: SYS_SIM_PROVISION slot {} identity {:#x} authorized",
                            slot,
                            identity
                        );
                        0
                    }
                    Err(e) => {
                        serial_println!("\nSVC: SYS_SIM_PROVISION slot {} FAILED ({})", slot, e);
                        1
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_SIM_PROVISION slot {} DENIED ({})", slot, e);
                    1
                }
            }
        }
        SYS_SIM_ACTIVATE => {
            let slot = arg1 as usize;
            match check(&crate::capabilities::sim_resource(slot)) {
                Ok(()) => match crate::sim::activate(slot) {
                    Ok(()) => {
                        serial_println!("\nSVC: SYS_SIM_ACTIVATE slot {} authorized", slot);
                        0
                    }
                    Err(e) => {
                        serial_println!("\nSVC: SYS_SIM_ACTIVATE slot {} FAILED ({})", slot, e);
                        1
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_SIM_ACTIVATE slot {} DENIED ({})", slot, e);
                    1
                }
            }
        }
        SYS_SIM_STATUS => {
            let slot = arg1 as usize;
            match check(&crate::capabilities::sim_resource(slot)) {
                Ok(()) => match crate::sim::status(slot) {
                    Ok(state) => {
                        serial_println!(
                            "\nSVC: SYS_SIM_STATUS slot {} authorized, state {:?}",
                            slot,
                            state
                        );
                        state.as_status_code()
                    }
                    Err(e) => {
                        serial_println!("\nSVC: SYS_SIM_STATUS slot {} FAILED ({})", slot, e);
                        SIM_STATUS_DENIED
                    }
                },
                Err(e) => {
                    serial_println!("\nSVC: SYS_SIM_STATUS slot {} DENIED ({})", slot, e);
                    SIM_STATUS_DENIED
                }
            }
        }
        _ => u64::MAX,
    }
}

fn check(resource: &str) -> Result<(), runix_capability_manager::CapabilityError> {
    crate::capabilities::check(resource, now_ticks())
}
