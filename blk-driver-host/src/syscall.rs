//! This binary's own `int 0x80` stub — a separate implementation from
//! `kernel::syscall::syscall`, not a shared one, same as
//! `net-driver-host/src/syscall.rs`'s copy: this is a standalone-linked
//! ring 3 program, compiled and linked entirely independently of the
//! kernel. The syscall *ABI* (number in RAX, args in RDI/RSI/RDX) is the
//! only thing connecting them.

const SYS_YIELD: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_PORT_IN: u64 = 4;
const SYS_PORT_OUT: u64 = 5;

/// # Safety
/// Whatever `num`'s own contract requires.
unsafe fn syscall(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") num => ret,
            // `inout(reg) x => _`, not `in(reg) x` — see
            // `net-driver-host/src/syscall.rs`'s much longer account of the
            // real bug this prevents (two back-to-back `port_out` calls
            // with the same literal `width` argument had the second one
            // silently corrupted because the compiler cached the value in
            // a register `syscall::entry`'s remapping shim unconditionally
            // overwrites on every trip through `int 0x80`). Copied here
            // alongside the code it protects, not re-derived.
            inout("rdi") arg1 => _,
            inout("rsi") arg2 => _,
            inout("rdx") arg3 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
        );
    }
    ret
}

pub fn write_byte(byte: u8) {
    unsafe {
        syscall(SYS_WRITE, byte as u64, 0, 0);
    }
}

pub fn write_all(bytes: &[u8]) {
    for &byte in bytes {
        write_byte(byte);
    }
}

pub fn yield_now() {
    unsafe {
        syscall(SYS_YIELD, 0, 0, 0);
    }
}

/// Reads `width` (1/2/4) bytes from I/O `port`, gated by whatever capability
/// this process was spawned with (see `kernel/src/capabilities.rs`'s
/// `authorized_for_ioport`). Returns `None` if denied.
pub fn port_in(port: u16, width: u8) -> Option<u32> {
    let ret = unsafe { syscall(SYS_PORT_IN, port as u64, width as u64, 0) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as u32)
    }
}

/// Writes `value`'s low `width` bytes to I/O `port`. Returns `false` if
/// denied, same conditions as [`port_in`].
pub fn port_out(port: u16, width: u8, value: u32) -> bool {
    let ret = unsafe { syscall(SYS_PORT_OUT, port as u64, width as u64, value as u64) };
    ret != u64::MAX
}
