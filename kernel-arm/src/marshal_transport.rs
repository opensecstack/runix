//! Beta mobile item 2.6 "Stage 4: wire `esim_marshal::evaluate` to a real
//! transport" -- the per-syscall counterpart of `tcp_proof.rs`'s one-shot
//! boot-time proof: loads the *same compiled* `net-driver-host-arm` binary
//! a second way (`info.mode == 1`, see `net_process::NetBootInfo`'s doc
//! comment), asking it to relay a caller-supplied MARSHAL request to a
//! configurable remote address instead of running the fixed TCP-proof
//! demo exchange, then decodes whatever `runix_ipc::marshal::MarshalResponse`
//! bytes come back.
//!
//! Structurally the third caller of [`crate::el0_exec`]'s one-shot
//! EL1-to-EL0 continuation, after `el0_proof.rs` and `tcp_proof.rs` -- see
//! `tcp_proof.rs`'s own doc comment for the mechanism itself. Unlike those
//! two (each driven once, from the boot sequence), [`evaluate`] is called
//! *per syscall* -- every `SYS_SIM_ENABLE`/`SYS_SIM_DELETE` (and, since Beta
//! item 3.4, `SYS_MVNO_BIND`/`SUSPEND`/`REACTIVATE`) that reaches
//! `esim_marshal::evaluate` drives one fresh excursion, with its own fresh
//! `AddressSpace` and thread (there is no process-reuse mechanism in this
//! crate yet -- see `process.rs`'s own doc comment on why a scheduled
//! thread owns exactly one `AddressSpace` for its whole lifetime).
//!
//! # Mirrors `kernel/src/grid_sandbox.rs`'s `shadow_marshal_evaluate`
//!
//! Same `MARSHAL_PROXY`-configured/`None`-short-circuits-to-`Unreachable`
//! shape as that function's own `SHADOW_MARSHAL_PROXY`, same Kerkese-JSON
//! request-building convention (`dry_run: true`, a minimal but genuinely
//! well-formed envelope), and the same outcome mapping
//! (`MarshalResponse::Decision{outcome,..}` passes through;
//! `MarshalResponse::Error(_)`, an undecodable reply, or no reply at all
//! are all `ShadowMarshalOutcome::Unreachable`). The transport underneath
//! differs -- that function reaches a user-space MARSHAL proxy via
//! `marshal_client::evaluate` over `kernel/`'s own general IPC surface;
//! this module has no user-space IPC story at all yet, so it reaches the
//! network directly, through a dedicated per-call EL0 process
//! ([`crate::net_process`]) the same way `tcp_proof.rs` does.
//!
//! # `esim_marshal::evaluate`'s real body
//!
//! [`esim_marshal::evaluate`](crate::esim_marshal::evaluate) now delegates
//! here unconditionally -- this module's own [`evaluate`] *is* the "real
//! transport" `esim_marshal.rs`'s doc comment described as its own future
//! replacement for its always-`Unreachable` stub body.

use crate::el0_exec;
use crate::net_process;
use crate::serial_println;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use runix_citadel_integration::ShadowMarshalOutcome;
use runix_ipc::marshal::{MarshalOutcome, MarshalRequest, MarshalResponse};
use runix_kernel_arm::marshal_action::{marshal_local_port, MarshalAction};
use spin::Mutex;

/// The compiled `net-driver-host-arm` binary -- the same ELF `tcp_proof.rs`
/// loads, just driven in its other mode. Two `include_bytes!`s of the same
/// file (this one and `tcp_proof.rs`'s own) rather than a shared `static`:
/// each module stays independently readable, and the compiler/linker
/// deduplicate the actual bytes regardless.
static NET_DRIVER_HOST_ARM_ELF: &[u8] = include_bytes!(
    "../../net-driver-host-arm/target/aarch64-unknown-none/release/net-driver-host-arm"
);

// ---------------------------------------------------------------------------
// Configured proxy address -- mirrors x86_64's `SHADOW_MARSHAL_PROXY`
// ---------------------------------------------------------------------------

/// `None` (the default) short-circuits [`evaluate`] straight to
/// [`ShadowMarshalOutcome::Unreachable`] with **no process spawned at
/// all** -- matching `grid_sandbox::shadow_marshal_evaluate`'s own `None =>
/// Unreachable` arm exactly, not a stronger "fail closed if unconfigured"
/// policy, which would be a different decision than this module gets to
/// make on its own (see `docs/MARSHAL-ENFORCEMENT-POLICY.md`).
static MARSHAL_PROXY: Mutex<Option<([u8; 4], u16)>> = Mutex::new(None);

/// Configures the remote MARSHAL proxy address [`evaluate`] connects to.
/// For a boot-sequence demo or a future test harness -- not called from
/// anywhere in this crate's own normal (unconfigured) boot path by default.
pub fn set_marshal_proxy(ip: [u8; 4], port: u16) {
    *MARSHAL_PROXY.lock() = Some((ip, port));
}

/// Reverts to the unconfigured (fail-open) state -- see [`MARSHAL_PROXY`]'s
/// own doc comment. `allow(dead_code)`: no caller in this crate's own boot
/// sequence needs this today (`nonsecure.rs` only ever calls
/// [`set_marshal_proxy`], never this), but a future test harness that wants
/// to exercise both the configured and unconfigured paths within the same
/// boot needs a way back to unconfigured -- provided now, alongside its
/// setter, rather than added only once that harness exists.
#[allow(dead_code)]
pub fn clear_marshal_proxy() {
    *MARSHAL_PROXY.lock() = None;
}

// ---------------------------------------------------------------------------
// The one-shot EL1-to-EL0 continuation, and this transport's own observations
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Observation {
    /// `net-driver-host-arm`'s own `status` (`0` = got reply bytes, `1` =
    /// connect failed/timed out), or `u64::MAX` if the excursion ended some
    /// other way (a fault) before reporting one.
    status: u64,
    response_len: u64,
    fault: Option<(u64, u64, u64, u64)>,
}

static OBSERVED: Mutex<Observation> = Mutex::new(Observation {
    status: u64::MAX,
    response_len: 0,
    fault: None,
});

/// Set by [`marshal_transport_thread`] once its EL0 excursion has ended one
/// way or the other -- [`evaluate`]'s bounded yield loop stops on this, the
/// same shape as `tcp_proof::FINISHED`.
static FINISHED: AtomicBool = AtomicBool::new(false);

/// `LoadedImage::entry`/`stack_top`/the address space's own root, handed to
/// the spawned thread through statics -- same reason `tcp_proof.rs`'s
/// `IMAGE_*` statics exist (`scheduler::spawn_with_address_space` takes a
/// bare `extern "C" fn() -> !` with no argument slot).
static IMAGE_ENTRY: AtomicU64 = AtomicU64::new(0);
static IMAGE_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// The response region's own physical (== kernel-identity-mapped) base,
/// from [`net_process::setup`] -- see that function's own doc comment for
/// why reading through it directly, after the excursion ends, is sound.
static RESPONSE_PHYS: AtomicU64 = AtomicU64::new(0);

/// True only while *this module's own* EL0 excursion is in flight -- see
/// `tcp_proof::TCP_PROOF_ACTIVE`'s doc comment for why `el0_exec`'s single
/// shared continuation slot needs this per-caller flag at all, and why it
/// is never explicitly cleared (ANDing with `el0_exec::continuation_live()`
/// already makes [`continuation_live`] false again once this excursion
/// ends, one way or the other).
/// Count of MARSHAL evaluations started this boot; feeds
/// `marshal_local_port` so each gets its own TCP source port.
static EVALUATION_COUNTER: AtomicU64 = AtomicU64::new(0);

static MARSHAL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// See [`MARSHAL_ACTIVE`]'s doc comment for why this is not simply
/// `el0_exec::continuation_live()`.
pub fn continuation_live() -> bool {
    MARSHAL_ACTIVE.load(Ordering::Relaxed) && el0_exec::continuation_live()
}

/// `svc.rs`'s `SYS_MARSHAL_PROOF_DONE` arm: records the reported
/// `status`/`response_len` pair, then resumes the EL1 continuation --
/// never returning to EL0. Mirrors `tcp_proof::finish`'s shape, now with
/// two reported values instead of one (see
/// `net-driver-host-arm::_start`'s own doc comment on `SYS_MARSHAL_PROOF_DONE`
/// for why this payload shape differs from `SYS_NET_PROOF_DONE`'s).
pub fn finish(status: u64, response_len: u64) -> u64 {
    let Some(saved_sp) = el0_exec::take_continuation() else {
        return u64::MAX;
    };
    {
        let mut observed = OBSERVED.lock();
        observed.status = status;
        observed.response_len = response_len;
    }
    // SAFETY: `saved_sp` was written by `el0_exec::enter_el0` on this
    // thread's own kernel stack, still live; see `tcp_proof::finish`'s
    // identical safety comment.
    unsafe { el0_exec::resume_el1(saved_sp) }
}

/// Reached from `el1_vectors.rs` when this module's EL0 process takes a
/// synchronous exception that is not its `SVC`. Mirrors
/// `tcp_proof::abort_from_fault` exactly, recording into this module's own
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

/// This process's EL1 side: `eret` into the loaded `net-driver-host-arm`
/// entry point (in MARSHAL-request mode), and -- resumed here by
/// [`finish`] or [`abort_from_fault`] -- signal completion. Mirrors
/// `tcp_proof::net_tcp_proof_thread`'s shape; unlike that proof thread this
/// one has no `report()` of its own (the printable verdict is
/// [`evaluate`]'s job, since it alone knows the eSIM operation/slot/profile
/// this excursion was for).
extern "C" fn marshal_transport_thread() -> ! {
    let entry = IMAGE_ENTRY.load(Ordering::Relaxed);
    let stack_top = IMAGE_STACK_TOP.load(Ordering::Relaxed);

    MARSHAL_ACTIVE.store(true, Ordering::Relaxed);

    // SAFETY: `entry`/`stack_top` are `loader::load`'s own verified output
    // for the address space this thread owns and which is active right now
    // (the scheduler installed it on resume); `el0_exec`'s continuation
    // slot is a writable static that outlives this call. The process
    // reaches EL1 only through the `SVC` `finish` handles, or a fault
    // `abort_from_fault` converts into a reported failure.
    unsafe { el0_exec::enter_el0(entry, stack_top, el0_exec::continuation_slot()) };

    FINISHED.store(true, Ordering::Relaxed);
    // Never dropped, same reasoning as `tcp_proof::net_tcp_proof_thread`'s
    // trailing loop: this thread's `AddressSpace` -- and in particular the
    // response region [`RESPONSE_PHYS`] points at -- must stay mapped and
    // allocated until [`evaluate`] has finished reading it back, which
    // happens on a different thread (the one that called [`evaluate`])
    // after this one reports `FINISHED`. Looping forever instead of
    // returning (there is nowhere to return *to* -- this is a scheduled
    // thread, not a call) keeps that memory alive indefinitely; this
    // thread, and the address space/process it owns, are simply never
    // reclaimed. Acceptable for this slice's proof-of-transport scope, the
    // same scope `tcp_proof.rs` and `el0_proof.rs` already accept for their
    // own one-shot threads -- a real process-lifecycle/reap mechanism is a
    // later slice's job, not this one's.
    loop {
        crate::scheduler::yield_now();
    }
}

// ---------------------------------------------------------------------------
// evaluate()
// ---------------------------------------------------------------------------

/// Evaluates one governed action ([`MarshalAction`]: an eSIM `enable`/`delete`
/// or one of the three MVNO account mutations) against a real MARSHAL
/// deployment, if one is configured ([`set_marshal_proxy`]) --
/// `esim_marshal::evaluate`'s real transport body, see this module's own doc
/// comment. Prints `MARSHAL evaluation for <label>: <Outcome>`.
///
/// **Callers must hold no spin lock** (e.g. `mvno`'s registry): the configured
/// path can run a nested EL0 excursion, which re-enters the kernel through
/// `SVC` and reschedules.
///
/// `None` configured (the default): returns
/// [`ShadowMarshalOutcome::Unreachable`] with no process spawned at all --
/// see [`MARSHAL_PROXY`]'s own doc comment.
///
/// Configured: builds a minimal, genuinely well-formed Kerkese-shaped
/// request (`dry_run: true`), encodes it as a [`MarshalRequest`], loads a
/// fresh `net-driver-host-arm` process in MARSHAL-request mode
/// ([`net_process::setup`]) pointed at the configured remote address,
/// spawns and runs it to completion (bounded, same 64-yield budget
/// `tcp_proof.rs`'s own boot-thread wait uses), and decodes whatever
/// [`MarshalResponse`] bytes came back. Any failure along the way --
/// no virtio-net device, `net_process::setup` failing, the spawn itself
/// failing, the excursion faulting, never reporting back, reporting a
/// connect failure, or reporting bytes that don't decode as a
/// `MarshalResponse::Decision` -- collapses to
/// [`ShadowMarshalOutcome::Unreachable`], the same "no usable Decision"
/// bucket `grid_sandbox::shadow_marshal_evaluate` uses for every one of its
/// own non-`Decision` outcomes.
pub fn evaluate(action: &MarshalAction<'_>, principal: &str) -> ShadowMarshalOutcome {
    let Some((remote_ip, remote_port)) = *MARSHAL_PROXY.lock() else {
        return ShadowMarshalOutcome::Unreachable;
    };

    // `svc.rs`'s `SYS_SIM_ENABLE`/`SYS_SIM_DELETE` reach this function from
    // *inside* an SVC exception taken from `el0_demo`'s own EL0 context --
    // this call is therefore nested inside an already-in-flight SVC, not
    // run from EL1 boot-sequence code the way `el0_proof.rs`/`tcp_proof.rs`
    // call `el0_exec` directly. `evaluate_configured` below may itself drive
    // a full nested `el0_exec` excursion (its own `eret` into
    // `net-driver-host-arm`, its own `SVC` back), which overwrites the real
    // `ELR_EL1`/`SPSR_EL1`/`SP_EL0` hardware registers as a side effect --
    // see `el0_exec::write_spsr_el1`'s own doc comment for why that is
    // otherwise invisible until `el1_vectors.rs`'s epilogue `eret`s `el0_demo`
    // back to the *inner* excursion's leftover state instead of its own.
    // Saving and restoring these three registers around the nested call is
    // what keeps that outer `eret` correct regardless of what happens in
    // between.
    let saved_elr = el0_exec::read_elr_el1();
    let saved_spsr = el0_exec::read_spsr_el1();
    let saved_sp_el0 = el0_exec::read_sp_el0();

    let outcome = evaluate_configured(action, principal, remote_ip, remote_port);

    el0_exec::write_elr_el1(saved_elr);
    el0_exec::write_spsr_el1(saved_spsr);
    el0_exec::write_sp_el0(saved_sp_el0);

    serial_println!(
        "Runix ARM kernel: MARSHAL evaluation for {}: {:?}",
        action.label(),
        outcome
    );

    outcome
}

fn evaluate_configured(
    action: &MarshalAction<'_>,
    principal: &str,
    remote_ip: [u8; 4],
    remote_port: u16,
) -> ShadowMarshalOutcome {
    let scan = crate::virtio_mmio::probe();
    let Some(dev) = scan.net else {
        serial_println!(
            "Runix ARM kernel: MARSHAL evaluation for {}: no virtio-net \
             device found",
            action.label()
        );
        return ShadowMarshalOutcome::Unreachable;
    };

    // Same "dry_run: true, minimal but genuinely well-formed envelope"
    // convention as `grid_sandbox::shadow_marshal_evaluate`'s own
    // `kerkese_json`; the per-action fields (eSIM slot/profile, MVNO
    // account/slot/profile) are `MarshalAction`'s job -- pure builders with
    // host tests, see `marshal_action.rs`.
    let kerkese_json = action.kerkese_json(principal);
    let encoded = MarshalRequest {
        kerkese_json: kerkese_json.into_bytes(),
    }
    .encode();

    let info = net_process::NetBootInfo {
        mmio_base: 0,
        rx_queue_phys: 0,
        tx_queue_phys: 0,
        rx_buffer_phys: [0; net_process::RX_BUFFER_COUNT],
        tx_buffer_phys: [0; net_process::TX_BUFFER_COUNT],
        mode: 1,
        remote_ip,
        remote_port,
        // A distinct source port per evaluation: every evaluation is a
        // fresh process that never tears its flow down, so reusing one
        // fixed port made SLIRP reject every SYN after the first.
        local_port: marshal_local_port(EVALUATION_COUNTER.fetch_add(1, Ordering::Relaxed)),
        // Overwritten by `net_process::setup` to match `encoded`'s own
        // (possibly clamped) length -- see that function's doc comment.
        request_len: 0,
    };

    let (space, loaded, response_phys) =
        match net_process::setup(NET_DRIVER_HOST_ARM_ELF, &dev, info, Some(&encoded)) {
            Ok(result) => result,
            Err(reason) => {
                serial_println!(
                    "Runix ARM kernel: MARSHAL evaluation for {}: setup \
                     failed ({})",
                    action.label(),
                    reason
                );
                return ShadowMarshalOutcome::Unreachable;
            }
        };
    // `setup` always returns `Some` when given `Some(request_bytes)` (see
    // its own doc comment) -- `None` here would mean this function's own
    // call above stopped passing `Some`, not a real runtime condition.
    let Some(response_phys) = response_phys else {
        serial_println!(
            "Runix ARM kernel: MARSHAL evaluation for {}: setup did not \
             return a response region",
            action.label()
        );
        return ShadowMarshalOutcome::Unreachable;
    };

    IMAGE_ENTRY.store(loaded.entry, Ordering::Relaxed);
    IMAGE_STACK_TOP.store(loaded.stack_top, Ordering::Relaxed);
    RESPONSE_PHYS.store(response_phys, Ordering::Relaxed);
    FINISHED.store(false, Ordering::Relaxed);
    {
        let mut observed = OBSERVED.lock();
        observed.status = u64::MAX;
        observed.response_len = 0;
        observed.fault = None;
    }

    if let Err(err) = crate::scheduler::spawn_with_address_space(marshal_transport_thread, space) {
        serial_println!(
            "Runix ARM kernel: MARSHAL evaluation for {}: spawn failed ({})",
            action.label(),
            err
        );
        return ShadowMarshalOutcome::Unreachable;
    }

    // Bounded for the same reason `tcp_proof.rs`'s own boot-thread wait is:
    // a switch that never comes back must surface as Unreachable, not a
    // hang. The real TCP round trip happens entirely inside the one EL0
    // excursion's own bounded internal retry loop, so this is only ever
    // waiting for one scheduler handoff plus one `SVC` back.
    let mut yields = 0;
    while !FINISHED.load(Ordering::Relaxed) && yields < 64 {
        crate::scheduler::yield_now();
        yields += 1;
    }
    if !FINISHED.load(Ordering::Relaxed) {
        serial_println!(
            "Runix ARM kernel: MARSHAL evaluation for {}: the EL0 thread \
             never reported back after {} boot-thread yields",
            action.label(),
            yields
        );
        return ShadowMarshalOutcome::Unreachable;
    }

    let (status, response_len, faulted) = {
        let observed = OBSERVED.lock();
        (
            observed.status,
            observed.response_len,
            observed.fault.is_some(),
        )
    };

    if faulted {
        serial_println!(
            "Runix ARM kernel: MARSHAL evaluation for {}: the EL0 process \
             faulted instead of finishing",
            action.label()
        );
        return ShadowMarshalOutcome::Unreachable;
    }

    if status != 0 || response_len == 0 {
        return ShadowMarshalOutcome::Unreachable;
    }

    let len = (response_len as usize).min(net_process::MARSHAL_BUFFER_CAPACITY);
    // SAFETY: `response_phys` is a kernel-identity-mapped physical address
    // `net_process::setup` mapped for this excursion's own address space;
    // that space is never dropped (`marshal_transport_thread` loops forever
    // after reporting `FINISHED` -- see that function's own doc comment),
    // so the frame is still live. `len` is clamped to
    // `MARSHAL_BUFFER_CAPACITY`, the exact size `setup` mapped.
    let bytes = unsafe { core::slice::from_raw_parts(response_phys as *const u8, len) };

    match MarshalResponse::decode(bytes) {
        Some((MarshalResponse::Decision { outcome, .. }, _)) => match outcome {
            MarshalOutcome::Execute => ShadowMarshalOutcome::Execute,
            MarshalOutcome::Refuse => ShadowMarshalOutcome::Refuse,
            MarshalOutcome::HardStop => ShadowMarshalOutcome::HardStop,
        },
        Some((MarshalResponse::Error(_), _)) | None => ShadowMarshalOutcome::Unreachable,
    }
}
