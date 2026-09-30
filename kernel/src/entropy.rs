//! RDRAND-backed entropy source for `SYS_RANDOM`. Deliberately RDRAND-only
//! for this first cut — no virtio-rng mix-in yet. Every other virtio device
//! in this repo (`net-driver-host`, `blk-driver-host`) is driven from a
//! ring-3 process over capability-gated port I/O, never from the kernel
//! itself; a kernel-resident virtio-rng driver would be the first virtio
//! surface actually living in the kernel, growing the TCB for a marginal
//! entropy-quality gain over RDRAND alone (present in QEMU/KVM and real
//! hardware). See `docs/RFC-TLS-APPROACH.md`'s "Phase 1 decision" note and
//! `docs/THREAT_MODEL.md` for the single-source trust tradeoff this leaves
//! open.

use core::arch::x86_64::{__cpuid, _rdrand64_step};
use core::sync::atomic::{AtomicU8, Ordering};

const UNKNOWN: u8 = 0;
const AVAILABLE: u8 = 1;
const UNAVAILABLE: u8 = 2;

static RDRAND_STATUS: AtomicU8 = AtomicU8::new(UNKNOWN);

/// CPUID leaf 1, ECX bit 30 — cached after the first call so every
/// `SYS_RANDOM` invocation after boot skips the CPUID round trip.
fn rdrand_available() -> bool {
    match RDRAND_STATUS.load(Ordering::Relaxed) {
        AVAILABLE => return true,
        UNAVAILABLE => return false,
        _ => {}
    }
    let available = __cpuid(1).ecx & (1 << 30) != 0;
    RDRAND_STATUS.store(
        if available { AVAILABLE } else { UNAVAILABLE },
        Ordering::Relaxed,
    );
    available
}

/// `_rdrand64_step` is an intrinsic gated on the `rdrand` target feature,
/// which this kernel's baseline `x86_64-unknown-none` target doesn't enable
/// at compile time — wrapping it in a `#[target_feature]` function and
/// calling that unsafely, only after `rdrand_available()` has confirmed the
/// running CPU actually supports it, is the sanctioned way to use a
/// runtime-detected x86 feature without compiling the whole crate for it.
#[target_feature(enable = "rdrand")]
unsafe fn try_rdrand64() -> Option<u64> {
    let mut value: u64 = 0;
    if _rdrand64_step(&mut value) == 1 {
        Some(value)
    } else {
        None
    }
}

/// One `u64` of hardware randomness, or `None` if RDRAND isn't present or
/// the hardware pool is momentarily exhausted. Retries a bounded number of
/// times per Intel's own guidance (SDM Vol. 1 §7.3.17) before giving up — a
/// spin loop here runs in kernel context on a capability-gated syscall
/// path, so it must have a hard ceiling, not "try until it works."
///
/// Deliberately fails closed: a caller that needs entropy and doesn't get
/// it must not silently fall back to a weaker source (e.g. a
/// `SYS_TICKS`-derived counter) — see this module's doc comment.
const MAX_RETRIES: u32 = 10;

/// Exposed for tests: whether this CPU (as QEMU/hardware actually presents
/// it, not just "the target architecture") has RDRAND at all — lets a test
/// distinguish "denied" from "RDRAND absent in this CPU model" instead of
/// conflating the two into a single passing-or-failing assertion. See
/// `kernel/tests/sys_random.rs`.
pub fn available() -> bool {
    rdrand_available()
}

pub fn read_u64() -> Option<u64> {
    if !rdrand_available() {
        return None;
    }
    for _ in 0..MAX_RETRIES {
        if let Some(value) = unsafe { try_rdrand64() } {
            return Some(value);
        }
    }
    None
}
