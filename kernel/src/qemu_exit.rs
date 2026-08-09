//! QEMU-only debug-exit device (`isa-debug-exit`, I/O port 0xf4). Writing a
//! value there makes QEMU itself exit with process exit code
//! `(value << 1) | 1` — a real, host-visible pass/fail signal from inside
//! the guest, which is what makes `tests/*.rs` integration tests (see
//! `../tests/basic_boot.rs` and `xtask`'s `test-runner` subcommand) usable
//! from plain `cargo test` instead of a human eyeballing serial output.
//!
//! Does nothing useful outside QEMU (there's no such device on real
//! hardware) — this is dev/CI-only infrastructure, never wired into the
//! normal boot path in `main.rs`.

use x86_64::instructions::port::Port;

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    unsafe {
        let mut port: Port<u32> = Port::new(0xf4);
        port.write(exit_code as u32);
    }
    // QEMU exits before this executes, as long as `-device
    // isa-debug-exit,iobase=0xf4,iosize=0x04` was actually passed (the
    // xtask test-runner always passes it) — this is just a safety net for
    // running one of these binaries some other way.
    loop {
        x86_64::instructions::hlt();
    }
}
