//! This binary's own `svc #0` stub — a separate implementation from
//! `runix_kernel_arm::svc::dispatch`, not a shared one, same reasoning
//! `net-driver-host/src/syscall.rs`'s doc comment gives for its own
//! separately-implemented `int 0x80` stub: this is a standalone-linked
//! EL0 program, compiled independently of `kernel-arm`. The syscall *ABI*
//! — `x0` = syscall number in, `x0` = return value out, `x1`/`x2`/`x3` =
//! up to three arguments, all four preserved by the handler except `x0`
//! itself (see `kernel-arm/src/el1_vectors.rs`'s own doc comment on
//! exactly this, "SVC resume" section) — is the only thing connecting the
//! two independently compiled programs for this one syscall.
//!
//! Only [`SYS_WRITE`] is used today (one already-existing, already-stable
//! syscall number in `kernel-arm/src/svc.rs` — see that file; nothing here
//! requires a *new* syscall number to be allocated, unlike the
//! TCP-proof-result reporting `main.rs`'s own doc comment leaves as an
//! explicit `TODO(loader integration)`). Serial output only, for
//! human-readable diagnostics alongside the `u64` result code — matching
//! `net-driver-host/src/main.rs`'s own "write a human-readable line, and
//! separately produce a machine-checkable result" convention.

/// Must match `kernel-arm/src/svc.rs`'s `SYS_WRITE` exactly — this binary's
/// only point of agreement with that dispatch table.
const SYS_WRITE: u64 = 1;

/// # Safety
/// Whatever `num`'s own contract requires. `x1`/`x2`/`x3` are each
/// individually `inout` because `kernel-arm/src/el1_vectors.rs`'s epilogue
/// restores them from the *original* values it saved on entry (not from
/// whatever the handler leaves in them) — so from this caller's point of
/// view they are logically unchanged across the call, but `asm!` still
/// needs the honest `inout` declaration rather than a plain `in`, for the
/// same reason `net-driver-host/src/syscall.rs`'s own doc comment on this
/// exact point records as a real, previously-confirmed bug (the compiler
/// is otherwise free to assume a register it didn't mark clobbered still
/// holds the value it cached there before the call). `x5`..`x8` genuinely
/// are clobbered: `el1_vector_common` saves/restores `x1`-`x4`, `x9`-`x18`,
/// and `x29`/`x30`, but not `x5`-`x8` -- those are caller-saved under
/// AAPCS64 and `svc.rs::dispatch`'s own Rust codegen is free to use them,
/// so they are declared `lateout(..) _` (discarded) here rather than
/// silently assumed preserved.
unsafe fn syscall(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            inout("x0") num => ret,
            inout("x1") arg1 => _,
            inout("x2") arg2 => _,
            inout("x3") arg3 => _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            lateout("x8") _,
        );
    }
    ret
}

pub fn write_byte(byte: u8) {
    // SAFETY: SYS_WRITE's only contract is "write this byte to the serial
    // console" -- no further precondition.
    unsafe {
        syscall(SYS_WRITE, byte as u64, 0, 0);
    }
}

pub fn write_all(bytes: &[u8]) {
    for &byte in bytes {
        write_byte(byte);
    }
}

pub fn write_decimal(mut value: u64) {
    if value == 0 {
        write_byte(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    while value > 0 {
        i -= 1;
        digits[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    write_all(&digits[i..]);
}

pub fn write_hex_byte(byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    write_byte(HEX[(byte >> 4) as usize]);
    write_byte(HEX[(byte & 0xF) as usize]);
}
