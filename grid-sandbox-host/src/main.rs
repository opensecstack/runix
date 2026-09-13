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
//! `build.rs` — see `src/hello.wat`). The one piece of config this process
//! does read is its own CITADEL-authorized isolation tier (see
//! `GRID_INFO_VA` below) — everything else about the chain works exactly
//! as before: host allocator -> `wasmi` engine -> module instantiation ->
//! host-function import -> guest bytecode execution -> syscall gate back to
//! whatever loaded it — not a general-purpose sandbox host yet.
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
use runix_wasm_runtime::{SandboxLimits, WasmRuntime};

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

/// One fixed page `kernel/src/main.rs` (`load_and_run_grid_sandbox_host`)
/// and `kernel/tests/grid_sandbox_wasm.rs` both write before spawning this
/// process — the CITADEL-authorized isolation tier this instance was
/// granted, as a plain `u8` (0 = T1 Critical, 1 = T2 Trusted, 2 = T3
/// Untrusted). No shared type with the kernel side, deliberately: same "no
/// shared type, just an agreed ABI" approach `net-driver-host`'s
/// `NetBootInfo` already uses across its own kernel/ring-3 boundary — this
/// crate has zero `citadel-integration` dependency and adding one just for
/// a 3-value tag isn't worth the coupling.
const GRID_INFO_VA: usize = 0x_2222_4444_0000;

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
            // `inout(reg) x => _`, not `in(reg) x`: a plain `in` operand
            // only tells the compiler what value the register holds *going
            // in* — it does not mark it clobbered afterward, so the
            // compiler may still assume a physical register keeps holding
            // `arg1`/`arg2`/`arg3` across a *later* call, if it decides to
            // cache a value shared between two nearby call sites. Found for
            // real in `net-driver-host/src/syscall.rs` (see that file's
            // longer account): two back-to-back syscalls both passing a
            // literal argument value had the second one silently corrupted,
            // because `entry`'s own remapping shim (`mov rcx, rdx; mov rdx,
            // rsi; mov rsi, rdi; mov rdi, rax`, below) unconditionally
            // overwrites RDI/RSI/RDX on every trip through `int 0x80`,
            // exactly the same class of hazard as the RCX/R8-R11 clobber
            // already documented here — just not yet observed to bite
            // *this* crate's specific call pattern.
            inout("rdi") arg1 => _,
            inout("rsi") arg2 => _,
            inout("rdx") arg3 => _,
            // `syscall::entry`'s remapping shim (kernel/src/syscall.rs)
            // does `mov rcx, rdx` before `call dispatch` — RCX is clobbered
            // on every trip through `int 0x80`, exactly like
            // `kernel/tests/ring3_cooperative.rs`'s doc comment warns about
            // (that test works around it with a manual push/pop in hand-
            // written asm; this is the same hazard in compiler-generated
            // code, where an undeclared clobber corrupts whatever the
            // compiler happened to be keeping live in RCX across the call
            // instead of merely mis-counting a loop). `dispatch` itself is
            // an ordinary SysV `extern "C"` function, free to use any
            // caller-saved register as scratch, so R8-R11 are equally at
            // risk even though nothing in the shim explicitly touches them.
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
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

    // Unknown/out-of-range tier bytes fall back to the tightest limits
    // (T3) rather than the most generous -- a boot-info page holding
    // garbage (a loader bug, not a byte this process has any way to have
    // produced itself) should never silently grant more trust than
    // intended. This mirrors the fail-closed stance
    // `BootAllowlist::authorize_module_load` already takes for an
    // unrecognized module.
    let tier_byte = unsafe { core::ptr::read_volatile(GRID_INFO_VA as *const u8) };
    let limits = match tier_byte {
        0 => SandboxLimits::t1_critical(),
        1 => SandboxLimits::t2_trusted(),
        _ => SandboxLimits::t3_untrusted(),
    };

    let runtime = WasmRuntime::new_with_limits(limits);
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
