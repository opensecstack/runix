//! A real, measured answer to `docs/RFC-TLS-APPROACH.md`'s last unresolved
//! open question: "does the one-byte-per-syscall IPC transport make a TLS
//! handshake unacceptably slow?" That question was previously answered with
//! an estimate (10-100us/syscall guessed, ~40-400ms for a full handshake) —
//! this measures the real number, in this exact environment (QEMU/TCG,
//! native Windows, no `-cpu`/`-icount` flags — the same environment every
//! other kernel test in this repo runs under).
//!
//! **Why this uses `RDTSC`, not `interrupts::ticks()`**: an earlier version
//! of this benchmark tried to time a tight `int 0x80` loop against the PIT
//! tick counter and found it doesn't advance *at all* during that specific
//! workload, no matter how much real wall-clock time passes — a real,
//! reproducible finding, not a bug in this test's own logic (confirmed by
//! checking that `interrupts::record_yield`/`on_timer_tick` unconditionally
//! bump `TICKS` on every fire, and that this exact kernel/QEMU setup
//! reliably delivers timer ticks in every other passing test). The likely
//! cause: QEMU/TCG's interrupt-pending check runs at translated-block
//! boundaries, and a tight `iretq` -> next `int 0x80` sequence apparently
//! doesn't hit one reliably enough to ever let a pending PIT IRQ preempt —
//! worth knowing as a real risk (a tight syscall loop could in principle
//! starve this kernel's own watchdog/scheduler tick source under TCG) but
//! not something to chase down here; `RDTSC` sidesteps it entirely (a
//! passive counter read, no interrupt delivery involved).
//!
//! `RDTSC`'s frequency isn't directly known, so it's calibrated against
//! `interrupts::ticks()` using `scheduler::yield_now()` — a *different*
//! code path (`int RESCHEDULE_VECTOR`, not `int 0x80`) that every other
//! kernel test in this repo already proves reliably advances `TICKS`.
//!
//! Two numbers, both reported in real microseconds via that calibration:
//!
//! - **`SYS_TICKS` round-trip cost**: the cheapest possible `int 0x80`
//!   round trip this kernel has — no capability check, no IPC state
//!   touched — the floor every other syscall's cost sits on top of.
//! - **`SYS_IPC_SEND`/`SYS_IPC_RECV` round-trip cost**: what a real TLS
//!   handshake byte actually costs today — `authorized_for_port`'s full
//!   Ed25519 signature verification runs on *every* send (no
//!   `is_empty`-style cheap-peek optimization on the send side, only on
//!   receive — see `kernel::ipc::is_empty`'s own doc comment).
//!
//! This is a benchmark, not a pass/fail test — it always exits successfully
//! and reports its numbers via serial output.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::arch::x86_64::_rdtsc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use runix_kernel::syscall::{
    self, SYS_IPC_RECV, SYS_IPC_SEND, SYS_IPC_SESSION_ACCEPT, SYS_IPC_SESSION_OPEN,
    SYS_IPC_SESSION_RECV, SYS_IPC_SESSION_SEND, SYS_TICKS,
};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const MEASUREMENT_PORT: usize = 5;
/// How many PIT ticks to calibrate `RDTSC` against — via `yield_now()`,
/// proven reliable (see this file's own doc comment), not the `int 0x80`
/// loop this benchmark actually cares about timing.
const CALIBRATION_TICKS: u64 = 5;
const PIT_HZ_NUMERATOR: u64 = 1_193_182;
const PIT_HZ_DENOMINATOR: u64 = 65_536;

/// Cycles-per-second, measured live in this exact QEMU/TCG instance rather
/// than assumed from a nominal CPU frequency that TCG emulation may not
/// actually honor.
fn calibrate_cycles_per_second() -> u64 {
    let start_tick = runix_kernel::interrupts::ticks();
    let start_cycles = unsafe { _rdtsc() };
    loop {
        runix_kernel::scheduler::yield_now();
        if runix_kernel::interrupts::ticks() - start_tick >= CALIBRATION_TICKS {
            break;
        }
    }
    let elapsed_cycles = unsafe { _rdtsc() } - start_cycles;
    let elapsed_ticks = runix_kernel::interrupts::ticks() - start_tick;
    // cycles/sec = cycles/tick * ticks/sec = (elapsed_cycles/elapsed_ticks) * (PIT_HZ_NUMERATOR/PIT_HZ_DENOMINATOR)
    elapsed_cycles * PIT_HZ_NUMERATOR / (elapsed_ticks * PIT_HZ_DENOMINATOR)
}

/// Hard ceiling on iterations — a benchmark that can't yet know how
/// expensive one `op()` call is must not risk an effectively unbounded
/// real-wall-clock wait under TCG emulation (this repo already has
/// precedent for a tight-loop-plus-Ed25519-verification combination taking
/// many minutes — see `docs/STATUS.md`'s `SYS_IPC_RECV` performance-
/// regression account). `RDTSC` gives a precise reading even over a
/// modest iteration count, unlike the PIT's coarse ~55ms granularity, so
/// there's no need to chase a long run just for resolution.
fn measure_cycles<F: FnMut()>(mut op: F, max_iterations: u64) -> (u64, u64) {
    let start = unsafe { _rdtsc() };
    for i in 0..max_iterations {
        op();
        if i % 1000 == 999 {
            serial_println!("syscall_cost: ...{} iterations so far", i + 1);
        }
    }
    let elapsed = unsafe { _rdtsc() } - start;
    (max_iterations, elapsed)
}

static BENCHMARK_DONE: AtomicBool = AtomicBool::new(false);

/// The actual benchmark, run on a *spawned* thread rather than the bare
/// boot/placeholder thread — every other passing kernel test in this repo
/// does its real work this way (`sys_random.rs`, `ipc_session.rs`, etc.),
/// and an earlier version of this file that ran everything directly on the
/// boot thread saw `interrupts::ticks()` never advance at all, no matter
/// how much real wall-clock time passed — this file's own top doc comment
/// covers the likely QEMU/TCG cause, but the practical fix is simply to
/// match the pattern every other test already proves works.
extern "C" fn benchmark_thread() -> ! {
    serial_println!("syscall_cost: calibrating RDTSC against interrupts::ticks()...");
    let cycles_per_second = calibrate_cycles_per_second();
    serial_println!(
        "syscall_cost: calibration: {} cycles/second (via {} PIT ticks)",
        cycles_per_second,
        CALIBRATION_TICKS
    );

    let cycles_to_micros = |cycles: u64| -> u64 { cycles * 1_000_000 / cycles_per_second };

    // --- Measurement 1: SYS_TICKS, the cheapest possible int 0x80 round
    // trip (no capability check, no IPC state touched) ---
    serial_println!("syscall_cost: measuring SYS_TICKS (10,000 iterations)...");
    let (tick_iterations, tick_cycles) = measure_cycles(
        || unsafe {
            syscall::syscall(SYS_TICKS, 0, 0, 0);
        },
        10_000,
    );
    let tick_micros_total = cycles_to_micros(tick_cycles);
    let tick_micros_per_op = tick_micros_total / tick_iterations.max(1);

    // --- Measurement 2: SYS_IPC_SEND + SYS_IPC_RECV, a real capability-
    // gated round trip -- what one real TLS handshake byte actually costs
    // today. Self-grants a `port:<n>` capability the same way several
    // existing kernel tests' boot threads already do
    // (`grant_current_extra_capability`'s own doc comment).
    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let token = runix_capability_manager::CapabilityToken::issue(
        "syscall_cost_benchmark",
        runix_kernel::capabilities::port_resource(MEASUREMENT_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    runix_kernel::scheduler::grant_current_extra_capability(token);

    serial_println!("syscall_cost: measuring SYS_IPC_SEND+SYS_IPC_RECV (500 round trips)...");
    let (ipc_iterations, ipc_cycles) = measure_cycles(
        || unsafe {
            syscall::syscall(SYS_IPC_SEND, MEASUREMENT_PORT as u64, 0xAA, 0);
            syscall::syscall(SYS_IPC_RECV, MEASUREMENT_PORT as u64, 0, 0);
        },
        500,
    );
    let ipc_micros_total = cycles_to_micros(ipc_cycles);
    // Each iteration is one SEND *and* one RECV -- report both the
    // per-iteration (round-trip) cost and the per-syscall cost, since the
    // RFC's own handshake-cost estimate counts syscalls, not round trips.
    let ipc_micros_per_roundtrip = ipc_micros_total / ipc_iterations.max(1);
    let ipc_micros_per_syscall = ipc_micros_per_roundtrip / 2;

    serial_println!(
        "syscall_cost: SYS_TICKS: {} iterations, {} cycles ({} us total) -> {} us/syscall",
        tick_iterations,
        tick_cycles,
        tick_micros_total,
        tick_micros_per_op
    );
    serial_println!(
        "syscall_cost: SYS_IPC_SEND+SYS_IPC_RECV: {} round trips, {} cycles ({} us total) -> {} us/roundtrip, {} us/syscall",
        ipc_iterations,
        ipc_cycles,
        ipc_micros_total,
        ipc_micros_per_roundtrip,
        ipc_micros_per_syscall
    );

    // --- Measurement 3: the "Option C" session primitive
    // (`kernel/src/ipc.rs`'s `SESSIONS` table, `docs/RFC-IPC-RESPONSE-
    // CAPABILITY.md`) -- authorizes *once*, at SESSION_OPEN/ACCEPT time,
    // then every SESSION_SEND/RECV after that is an O(1) `ThreadId`
    // compare, not a repeated Ed25519 verification. One thread can be both
    // a session's owner and its accepted server (nothing about
    // `is_participant` requires them to differ) -- self-paired, same
    // single-thread shape as measurement 2 above, so the comparison is
    // apples to apples.
    let session_id = {
        let open_ret =
            unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, MEASUREMENT_PORT as u64, 0, 0) };
        assert_ne!(
            open_ret,
            u64::MAX,
            "SESSION_OPEN denied -- benchmark setup bug"
        );
        let accept_ret =
            unsafe { syscall::syscall(SYS_IPC_SESSION_ACCEPT, MEASUREMENT_PORT as u64, 0, 0) };
        assert_ne!(
            accept_ret,
            u64::MAX,
            "SESSION_ACCEPT denied -- benchmark setup bug"
        );
        assert_eq!(
            open_ret, accept_ret,
            "self-paired open/accept should yield the same session"
        );
        open_ret
    };

    serial_println!("syscall_cost: measuring SYS_IPC_SESSION_SEND+RECV (500 round trips)...");
    let (session_iterations, session_cycles) = measure_cycles(
        || unsafe {
            syscall::syscall(SYS_IPC_SESSION_SEND, session_id, 0xAA, 0);
            syscall::syscall(SYS_IPC_SESSION_RECV, session_id, 0, 0);
        },
        500,
    );
    let session_micros_total = cycles_to_micros(session_cycles);
    let session_micros_per_roundtrip = session_micros_total / session_iterations.max(1);
    let session_micros_per_syscall = session_micros_per_roundtrip / 2;

    serial_println!(
        "syscall_cost: SYS_IPC_SESSION_SEND+RECV: {} round trips, {} cycles ({} us total) -> {} us/roundtrip, {} us/syscall",
        session_iterations,
        session_cycles,
        session_micros_total,
        session_micros_per_roundtrip,
        session_micros_per_syscall
    );
    serial_println!(
        "syscall_cost: session primitive is ~{}x cheaper per syscall than the fixed-port capability-gated path ({} us vs {} us)",
        ipc_micros_per_syscall / session_micros_per_syscall.max(1),
        ipc_micros_per_syscall,
        session_micros_per_syscall
    );

    // A realistic TLS 1.3 handshake with an ECDSA/Ed25519 cert: ~1,500-
    // 3,000 bytes round-trip (docs/RFC-TLS-APPROACH.md's own researched
    // figure) -- report what that costs at the *measured* per-syscall rate.
    for handshake_bytes in [1_500u64, 3_000u64] {
        let estimated_syscalls = handshake_bytes * 2; // one send + one recv per byte
        let fixed_port_micros = estimated_syscalls * ipc_micros_per_syscall;
        let session_micros = estimated_syscalls * session_micros_per_syscall;
        serial_println!(
            "syscall_cost: estimated {}-byte TLS handshake ({} syscalls): fixed-port {} ms ({}), session primitive {} ms ({})",
            handshake_bytes,
            estimated_syscalls,
            fixed_port_micros / 1000,
            if fixed_port_micros / 1000 > 300 { "EXCEEDS 300ms" } else { "fits within 300ms" },
            session_micros / 1000,
            if session_micros / 1000 > 300 { "EXCEEDS 300ms" } else { "fits within 300ms" }
        );
    }

    serial_println!("syscall_cost: PASS -- measurement complete, see numbers above");
    BENCHMARK_DONE.store(true, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("bootloader did not map physical memory"),
    );
    let mapper = unsafe { runix_kernel::memory::init(physical_memory_offset) };
    let frame_allocator =
        unsafe { runix_kernel::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    runix_kernel::memory::install(mapper, frame_allocator);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        runix_kernel::allocator::init_heap(mapper, frame_allocator)
    })
    .expect("heap initialization failed");

    runix_kernel::scheduler::init();
    runix_kernel::scheduler::spawn(benchmark_thread);

    while !BENCHMARK_DONE.load(Ordering::SeqCst) {
        runix_kernel::scheduler::yield_now();
    }

    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("syscall_cost: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
