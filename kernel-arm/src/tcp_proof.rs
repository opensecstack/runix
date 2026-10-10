//! Beta mobile item 2.5 "Stage 3: real outbound TCP at EL0" -- the
//! loader-integration slice `net-driver-host-arm/src/main.rs`'s own module
//! doc comment leaves as a `TODO(loader integration)`: discover the
//! virtio-net device, build a fresh [`AddressSpace`], map everything that
//! binary's fixed `NetBootInfo` contract expects into it, load its real
//! compiled ELF, and `eret` into it -- then read back a single flat
//! `net-driver-host-arm::ProofResult` code through one purpose-built `SVC`.
//!
//! Structurally the second caller of [`crate::el0_exec`]'s one-shot
//! EL1-to-EL0 continuation, after `el0_proof.rs` -- see that module's own
//! doc comment for the mechanism itself (`enter_el0`/`resume_el1`, the
//! single-continuation-slot cost, why no separate kernel-entry stack is
//! needed). This module supplies a *different* payload (a real compiled
//! binary rather than a hand-assembled one) and a different, simpler
//! observation (one result code rather than three bytes plus hardware
//! register checks), through [`SYS_NET_PROOF_DONE`](crate::svc::SYS_NET_PROOF_DONE)
//! rather than reusing `el0_proof.rs`'s own syscall -- see that constant's
//! doc comment in `svc.rs` for why the two stay separate numbers.
//!
//! # Why this binary needs real address-space wiring that `el0_proof.rs`'s
//! hand-assembled image never did
//!
//! `net-driver-host-arm` is a genuine virtio-mmio network driver plus a
//! `smoltcp` TCP client, not a three-instruction proof payload: it needs a
//! private heap, a mapped virtio-mmio register window, physically
//! contiguous virtqueue descriptor/avail/used-ring regions, and a page per
//! packet buffer -- none of which `el0_proof.rs`'s payload needed. All of
//! that address-space/mapping/loading setup now lives in
//! [`crate::net_process`] (extracted from this module once a second caller
//! -- a per-syscall MARSHAL-transport path -- was about to need the exact
//! same setup for a different `net-driver-host-arm` mode); see that
//! module's own doc comment for the full "private, one-sided, hand-synced
//! contract" reasoning, the virtio-mmio capability-check sequence, and why
//! the virtqueue regions need their own contiguous-allocation path. This
//! module keeps only what's specific to the TCP proof itself: today's fixed
//! `NetBootInfo` contents (nothing beyond what [`crate::net_process::setup`]
//! computes on its own), the one-shot EL0 excursion's observations, and the
//! thread that drives it.

use crate::el0_exec;
use crate::net_process;
use crate::process;
use crate::serial_println;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// The compiled `net-driver-host-arm` binary. Built separately
/// (`cd net-driver-host-arm && cargo build --target aarch64-unknown-none
/// --release`, via `rustup run stable-x86_64-pc-windows-gnu` on this
/// environment) -- the same manual-build-step convention
/// `kernel/tests/net_driver_tcp.rs` documents for its own `include_bytes!`
/// of `net-driver-host`.
static NET_DRIVER_HOST_ARM_ELF: &[u8] = include_bytes!(
    "../../net-driver-host-arm/target/aarch64-unknown-none/release/net-driver-host-arm"
);

// ---------------------------------------------------------------------------
// The one-shot EL1-to-EL0 continuation, and this proof's own observations
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Observation {
    thread_root: u64,
    svc_spsr: u64,
    svc_elr: u64,
    svc_root: u64,
    /// The `ProofResult` code `net-driver-host-arm` reported, or `u64::MAX`
    /// if the excursion ended some other way (a fault) before reporting
    /// one.
    result: u64,
    fault: Option<(u64, u64, u64, u64)>,
}

static OBSERVED: Mutex<Observation> = Mutex::new(Observation {
    thread_root: 0,
    svc_spsr: 0,
    svc_elr: 0,
    svc_root: 0,
    result: u64::MAX,
    fault: None,
});

/// Set by [`net_tcp_proof_thread`] once it has printed its verdict -- the
/// boot thread's bounded yield loop in [`prove_net_tcp`] stops on this.
static FINISHED: AtomicBool = AtomicBool::new(false);

/// `LoadedImage::entry`/`stack_top`/the address space's own root, handed to
/// the spawned thread through statics for the same reason
/// `el0_proof.rs::IMAGE_ENTRY`/`IMAGE_STACK_TOP`/`IMAGE_ROOT` are:
/// `scheduler::spawn_with_address_space` takes a bare `extern "C" fn() -> !`
/// with no argument slot.
static IMAGE_ENTRY: AtomicU64 = AtomicU64::new(0);
static IMAGE_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static IMAGE_ROOT: AtomicU64 = AtomicU64::new(0);

/// True only while *this module's own* EL0 excursion is in flight --
/// unlike `el0_proof::continuation_live`, which is simply
/// `el0_exec::continuation_live()` (correct only because nothing else ever
/// shared that one continuation slot with it until this module existed).
/// `el0_exec`'s continuation slot is a single global, so
/// `el0_exec::continuation_live()` alone cannot tell *whose* excursion is
/// live -- this flag is what lets `el1_vectors.rs` route a fault to the
/// right proof's `abort_from_fault` instead of `el0_proof`'s, which would
/// record it in the wrong `OBSERVED` and leave this module's own bounded
/// wait to time out with no diagnostic. Set once, before the one `eret`
/// this module ever performs; never explicitly cleared, since ANDing with
/// `el0_exec::continuation_live()` (false again once the excursion ends,
/// one way or the other) already makes [`continuation_live`] false
/// afterwards.
static TCP_PROOF_ACTIVE: AtomicBool = AtomicBool::new(false);

/// See [`TCP_PROOF_ACTIVE`]'s doc comment for why this is not simply
/// `el0_exec::continuation_live()`.
pub fn continuation_live() -> bool {
    TCP_PROOF_ACTIVE.load(Ordering::Relaxed) && el0_exec::continuation_live()
}

/// `svc.rs`'s [`crate::svc::SYS_NET_PROOF_DONE`] arm: records the reported
/// `ProofResult` code plus the hardware's own account of where the `SVC`
/// came from, then resumes the EL1 continuation -- never returning to EL0.
/// Mirrors `el0_proof::finish`'s shape exactly; see that function's doc
/// comment for why claim/record/resume is split this way between this
/// module and [`el0_exec`].
pub fn finish(result: u64) -> u64 {
    let Some(saved_sp) = el0_exec::take_continuation() else {
        return u64::MAX;
    };
    {
        let mut observed = OBSERVED.lock();
        observed.result = result;
        observed.svc_spsr = el0_exec::read_spsr_el1();
        observed.svc_elr = el0_exec::read_elr_el1();
        observed.svc_root = process::active_root();
    }
    // SAFETY: `saved_sp` was written by `el0_exec::enter_el0` on this
    // thread's own kernel stack, still live; see `el0_proof::finish`'s
    // identical safety comment.
    unsafe { el0_exec::resume_el1(saved_sp) }
}

/// Reached from `el1_vectors.rs` when this module's EL0 process takes a
/// synchronous exception that is not its `SVC`. Mirrors
/// `el0_proof::abort_from_fault` exactly, recording into this module's own
/// [`OBSERVED`] instead.
///
/// # Safety
/// Only valid from a synchronous lower-EL exception taken while
/// [`continuation_live`] is true -- see `el0_exec::abort_from_fault`'s own
/// contract.
pub unsafe fn abort_from_fault(vector: u64, esr: u64, far: u64, elr: u64) -> ! {
    unsafe {
        el0_exec::abort_from_fault(|| {
            OBSERVED.lock().fault = Some((vector, esr, far, elr));
        })
    }
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

/// This process's EL1 side: observe the live `TTBR0_EL1`, `eret` into the
/// loaded `net-driver-host-arm` entry point, and -- resumed here by
/// [`finish`] or [`abort_from_fault`] -- report the verdict. Mirrors
/// `el0_proof::el0_proof_thread`'s shape exactly.
extern "C" fn net_tcp_proof_thread() -> ! {
    {
        let mut observed = OBSERVED.lock();
        observed.thread_root = process::active_root();
    }

    let entry = IMAGE_ENTRY.load(Ordering::Relaxed);
    let stack_top = IMAGE_STACK_TOP.load(Ordering::Relaxed);
    serial_println!(
        "Runix ARM kernel: net TCP proof thread at EL1, TTBR0_EL1={:#x} (own address space), \
         about to eret to {:#x} with SP_EL0={:#x}",
        OBSERVED.lock().thread_root,
        entry,
        stack_top
    );

    TCP_PROOF_ACTIVE.store(true, Ordering::Relaxed);

    // SAFETY: `entry`/`stack_top` are `loader::load`'s own verified output
    // for the address space this thread owns and which is active right now
    // (the scheduler installed it on resume); `el0_exec`'s continuation
    // slot is a writable static that outlives this call. The process
    // reaches EL1 only through the `SVC` `finish` handles, or a fault
    // `abort_from_fault` converts into a reported failure.
    unsafe { el0_exec::enter_el0(entry, stack_top, el0_exec::continuation_slot()) };

    report();
    FINISHED.store(true, Ordering::Relaxed);
    loop {
        crate::scheduler::yield_now();
    }
}

/// Renders a `net-driver-host-arm::ProofResult` code without depending on
/// that crate (there is no shared type for this boundary -- see this
/// module's doc comment).
fn result_name(result: u64) -> &'static str {
    match result {
        0 => "Pass",
        1 => "DeviceProbeFailed",
        2 => "FeatureNegotiationFailed",
        3 => "QueueSetupFailed",
        4 => "TcpConnectTimedOut",
        5 => "TcpReplyMismatch",
        _ => "<unknown>",
    }
}

/// Compares every observation against what a genuine EL0 excursion must
/// produce and prints one greppable `PASS`/`FAILED` line. Mirrors
/// `el0_proof.rs::report`'s structure.
fn report() {
    let observed = OBSERVED.lock();
    let root = IMAGE_ROOT.load(Ordering::Relaxed);

    if let Some((vector, esr, far, elr)) = observed.fault {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- the EL0 process faulted instead of \
             finishing (vector {}, ESR_EL1={:#x} EC={:#x}, FAR_EL1={:#x}, ELR_EL1={:#x})",
            vector,
            esr,
            (esr >> 26) & 0x3F,
            far,
            elr
        );
        return;
    }

    let from_el0 = observed.svc_spsr & el0_exec::SPSR_MODE_MASK == el0_exec::SPSR_MODE_EL0T;
    let root_followed = observed.thread_root == root && observed.svc_root == root;

    serial_println!(
        "Runix ARM kernel: net TCP proof observed SPSR_EL1={:#x} (EL0t={}), TTBR0_EL1 thread={:#x} \
         svc={:#x} space={:#x}, result={} ({})",
        observed.svc_spsr,
        from_el0,
        observed.thread_root,
        observed.svc_root,
        root,
        observed.result,
        result_name(observed.result)
    );

    if observed.result == 0 && from_el0 && root_followed {
        serial_println!(
            "Runix ARM kernel: net TCP proof PASS -- a real compiled net-driver-host-arm \
             process brought up a virtio-mmio network device at EL0 and completed a real TCP \
             round trip over QEMU's guestfwd bridge"
        );
    } else {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- result={} ({}) came_from_el0={} \
             ttbr0_followed_schedule={}",
            observed.result,
            result_name(observed.result),
            from_el0,
            root_followed
        );
    }
}

/// Builds the address space, wires up every private region
/// `net-driver-host-arm` needs, loads it, spawns a thread that owns it, and
/// schedules it for real.
///
/// The address-space/mapping/loading setup itself is
/// [`crate::net_process::setup`] -- this function supplies today's
/// TCP-proof-mode [`net_process::NetBootInfo`] contents (nothing beyond what
/// that function computes on its own, so an all-zero value) and keeps the
/// proof-specific tail: handing the loaded image to [`net_tcp_proof_thread`]
/// through the `IMAGE_*` statics, the actual
/// `scheduler::spawn_with_address_space` call, and the bounded wait for a
/// result.
///
/// Called from `nonsecure.rs`'s shared EL1 bring-up right after
/// `el0_proof::prove_el0_process` -- it needs everything that proof needs
/// (the MMU, the heap, the scheduler's run queue) plus one more
/// prerequisite: `virtio_mmio::probe()` having something to find, which
/// only needs the MMU's Device block (already up by this point in the boot
/// sequence).
pub fn prove_net_tcp() {
    let scan = crate::virtio_mmio::probe();
    let Some(dev) = scan.net else {
        serial_println!("Runix ARM kernel: net TCP proof FAILED -- no virtio-net device found");
        return;
    };

    // Nothing beyond what `net_process::setup` computes on its own -- see
    // its own doc comment on why it still takes a `NetBootInfo` by value.
    // `mode: 0` (TCP-proof mode, the only mode this module ever drives) --
    // `remote_ip`/`remote_port`/`request_len` are all ignored by
    // `net-driver-host-arm` in that mode, so left zero.
    let info = net_process::NetBootInfo {
        mmio_base: 0,
        rx_queue_phys: 0,
        tx_queue_phys: 0,
        rx_buffer_phys: [0; net_process::RX_BUFFER_COUNT],
        tx_buffer_phys: [0; net_process::TX_BUFFER_COUNT],
        mode: 0,
        remote_ip: [0; 4],
        remote_port: 0,
        local_port: 0,
        request_len: 0,
    };

    let (space, loaded, _response_phys) =
        match net_process::setup(NET_DRIVER_HOST_ARM_ELF, &dev, info, None) {
            Ok(result) => result,
            Err(reason) => {
                serial_println!("Runix ARM kernel: net TCP proof FAILED -- {}", reason);
                return;
            }
        };

    IMAGE_ENTRY.store(loaded.entry, Ordering::Relaxed);
    IMAGE_STACK_TOP.store(loaded.stack_top, Ordering::Relaxed);
    IMAGE_ROOT.store(space.root(), Ordering::Relaxed);

    serial_println!(
        "Runix ARM kernel: net TCP proof image entry={:#x} stack_top={:#x} segment_pages={} \
         stack_pages={} (root={:#x}, slot={}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        loaded.entry,
        loaded.stack_top,
        loaded.segment_pages,
        loaded.stack_pages,
        space.root(),
        dev.slot,
        dev.mac[0],
        dev.mac[1],
        dev.mac[2],
        dev.mac[3],
        dev.mac[4],
        dev.mac[5],
    );

    if let Err(err) = crate::scheduler::spawn_with_address_space(net_tcp_proof_thread, space) {
        serial_println!("Runix ARM kernel: net TCP proof FAILED -- spawn: {}", err);
        return;
    }

    // Bounded for the same reason `el0_proof::prove_el0_process`'s loop is:
    // a switch that never comes back must surface as a FAIL line, not a
    // hang. The real TCP round trip happens entirely *inside* the one EL0
    // excursion (`net-driver-host-arm`'s own up-to-2,000,000-iteration
    // internal retry loop), so the boot thread is only ever waiting for one
    // scheduler handoff plus one `SVC` back, not polling network state
    // itself -- 64 yields is as generous here as it is there.
    let mut yields = 0;
    while !FINISHED.load(Ordering::Relaxed) && yields < 64 {
        crate::scheduler::yield_now();
        yields += 1;
    }
    if !FINISHED.load(Ordering::Relaxed) {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- the EL0 thread never reported back after \
             {} boot-thread yields",
            yields
        );
    }
}
