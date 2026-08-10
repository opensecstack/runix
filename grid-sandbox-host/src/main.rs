//! Grid Sandbox host: a freestanding ring 3 binary hosting the `wasmi`
//! engine (`runix-wasm-runtime`) — Beta's "Grid sandbox isolation"
//! roadmap item, per the architecture decision in the top-level README
//! (`wasm-runtime` runs as its own ring 3 process, not linked into the
//! kernel). Not yet loaded by anything: this crate compiling and, once
//! booted standalone or loaded via `kernel/src/elf.rs`, correctly running
//! `wasmi` on a private heap is the milestone this slice proves — actually
//! wiring it through `elf::Elf64`/`scheduler::spawn_ring3_process` in a
//! real kernel test is the next slice, not this one.
//!
//! Deliberately minimal: no allocator tuning, no dynamic module loading (the
//! guest module is a fixed, build-time-compiled `.wasm`, embedded via
//! `build.rs` — see `src/hello.wat`), no argument/config parsing. This
//! exists to prove the chain works at all — host allocator -> `wasmi`
//! engine -> module instantiation -> host-function import -> guest
//! bytecode execution -> syscall gate back to whatever loaded it — not to
//! be a general-purpose sandbox host yet.
//!
//! # Heap coordination with whoever loads this
//!
//! `HEAP_START`/`HEAP_SIZE` below must already be mapped
//! `PRESENT | WRITABLE | USER_ACCESSIBLE` in this process's address space
//! before `_start` runs — this binary has no privilege to map its own
//! memory (ring 3 code can't touch page tables at all). Coordinating that
//! mapping is the loader's job (see the module doc comment above on what's
//! still missing).

#![no_std]
#![no_main]

extern crate alloc;

use linked_list_allocator::LockedHeap;
use runix_wasm_runtime::WasmRuntime;

/// Arbitrary, fixed private heap region for this process — canonical
/// (leading nibble's top bit clear, same reasoning as every other
/// hand-picked address in this repo; `kernel/tests/process_isolation.rs`'s
/// first attempt hit the non-canonical case for real). Distinct from every
/// VA range the kernel itself already uses (`0x4444`/`0x5555`/`0x6666`/
/// `0x3333`/`0x7777`) — doesn't need to avoid collisions with the kernel's
/// own table at all, though: this runs under its *own* `Cr3`, so `0x2222`
/// here and the kernel's `0x4444` heap coexist in entirely separate
/// address spaces regardless.
pub const HEAP_START: usize = 0x_2222_2222_0000;
/// Generous for one tiny embedded module — `wasmi`'s engine, module, and
/// store all live here alongside the module's own linear memory. No
/// principled sizing yet, same as the kernel's own heap wasn't either
/// until something real needed more (see `allocator::HEAP_SIZE`'s history
/// in the README).
pub const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const SYS_YIELD: u64 = 0;
const SYS_WRITE: u64 = 1;

/// This binary's own `int 0x80` stub — necessarily a separate
/// implementation from `kernel::syscall::syscall`, not a shared one: this
/// is a standalone-linked ring 3 program, compiled and linked entirely
/// independently of the kernel. The syscall *ABI* (number in RAX, args in
/// RDI/RSI/RDX) is the only thing connecting them, the same way a real
/// userspace program's libc defines its own syscall stubs rather than
/// linking against the kernel it calls into.
///
/// # Safety
/// Whatever `num`'s own contract requires — `SYS_WRITE` needs `arg1` to be
/// a byte value, `SYS_YIELD` ignores its arguments entirely.
unsafe fn syscall(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") num => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
        );
    }
    ret
}

fn write_byte(byte: u8) {
    unsafe {
        syscall(SYS_WRITE, byte as u64, 0, 0);
    }
}

fn yield_now() {
    unsafe {
        syscall(SYS_YIELD, 0, 0, 0);
    }
}

/// Compiled from `src/hello.wat` at build time by `build.rs` — see its doc
/// comment for why a build script (host-side `wat` crate) rather than a
/// hand-encoded byte array.
static HELLO_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.wasm"));

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let runtime = WasmRuntime::new();
    match runtime.call_and_capture_output(HELLO_WASM, "run") {
        Ok(output) => write_all(&output),
        // No serial/stderr equivalent reachable from ring 3 today — a
        // single, deliberately distinct byte is the whole error-reporting
        // channel this slice has. A real one needs a syscall bridge with
        // more than one byte of bandwidth, not built yet.
        Err(_) => write_byte(b'!'),
    }

    loop {
        yield_now();
    }
}

fn write_all(bytes: &[u8]) {
    for &byte in bytes {
        write_byte(byte);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No `hlt` here — that's a privileged instruction; executing it from
    // ring 3 would general-protection-fault instead of halting anything.
    write_byte(b'?');
    loop {
        core::hint::spin_loop();
    }
}
