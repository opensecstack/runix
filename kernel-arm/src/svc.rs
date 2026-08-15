//! `SVC` syscall dispatch -- the ARM-side analogue of
//! `kernel/src/syscall.rs::dispatch` on the x86_64 side. Reached from
//! `el1_vectors.rs`'s vector-8 `SVC` handling; see that module's doc
//! comment for how the syscall number/arg actually get here.
//!
//! Two syscalls, matching `el0.rs`'s demo exactly (kept in sync by hand,
//! not shared constants -- see `el0.rs`'s own doc comment on why):
//! - `SYS_WRITE`: unconditional -- proves the `SVC` gate itself works,
//!   the same role `kernel/src/syscall.rs`'s `SYS_WRITE` plays for `int
//!   0x80` on the x86_64 side.
//! - `SYS_RIL_ACCESS`: capability-gated through `ril_capability::check`,
//!   the same role `SYS_IPC_SEND`'s `capabilities::check` call plays
//!   there -- this is the actual RIL isolation boundary this slice
//!   exists to prove, not memory isolation (which `mmu.rs`'s own doc
//!   comment already says doesn't exist at this granularity yet).

use crate::serial::write_byte;
use crate::serial_println;

pub const SYS_WRITE: u64 = 1;
pub const SYS_RIL_ACCESS: u64 = 2;

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
/// platform, not something this crate configures). `ril_capability`'s
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

/// Dispatches one syscall. `num`/`arg1` are EL0's `x0`/`x1` at the moment
/// of `svc #0`. Returns the value that becomes EL0's new `x0` once
/// `el1_vectors.rs`'s epilogue `eret`s back -- `0` for success, nonzero
/// for "denied"/"unknown," the same coarse convention
/// `kernel/src/syscall.rs::dispatch` uses (`u64::MAX` for "denied," here
/// `1` -- picked distinct from `0`/success, not required to match the
/// x86_64 side's exact sentinel).
pub fn dispatch(num: u64, arg1: u64) -> u64 {
    match num {
        SYS_WRITE => {
            write_byte(arg1 as u8);
            0
        }
        SYS_RIL_ACCESS => {
            let channel = arg1 as usize;
            let resource = crate::ril_capability::ril_resource(channel);
            match crate::ril_capability::check(&resource, now_ticks()) {
                Ok(()) => {
                    serial_println!(
                        "\nSVC: SYS_RIL_ACCESS channel {} authorized (capability check passed)",
                        channel
                    );
                    0
                }
                Err(e) => {
                    serial_println!(
                        "\nSVC: SYS_RIL_ACCESS channel {} DENIED ({})",
                        channel,
                        e
                    );
                    1
                }
            }
        }
        _ => u64::MAX,
    }
}
