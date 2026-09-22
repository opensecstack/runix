//! Multi-instance `grid-sandbox-host` spawning: the factored form of what
//! `main.rs`'s `load_and_run_grid_sandbox_host` (Phase B7) does once at
//! boot, generalized to run any number of independent instances of the same
//! binary — one per app, in the Grid Sandbox model. See
//! `runix_citadel_integration::InstanceManifestEntry`'s doc comment for why
//! a single module-wide CITADEL grant isn't enough here: reusing it across
//! every instance would be ambient authority, so [`spawn_instance`] calls
//! `citadel::demo_authorize_instance` once per `instance_id`, and issues a
//! capability token scoped to that instance alone (see
//! `capabilities::grid_instance_resource`) — never a token or authorization
//! decision shared across instances.
//!
//! Every spawned instance gets its own [`AddressSpace`] (so its heap and
//! ring-3 stack are backed by physically distinct frames from any other
//! instance's, even though both map the *same* virtual addresses —
//! `grid-sandbox-host` hardcodes `HEAP_START`/`GRID_INFO_VA` etc. into its
//! own binary, since ring 3 code can't map its own memory, so every
//! instance necessarily uses the same VAs; isolation comes from each
//! instance's own private page tables, not from VA separation). This means
//! the ELF's entry point is deterministic across every call (same compiled
//! binary, same link addresses every parse) — safe to stash in one shared
//! `static`, read back by one shared trampoline, even though multiple
//! instances may be spawned in succession before any of them actually runs.

use crate::capabilities;
use crate::citadel::{self, SandboxTier};
use crate::elf::Elf64;
use crate::marshal_client;
use crate::process::AddressSpace;
use crate::scheduler;
use crate::serial_println;
use crate::userspace;
use alloc::format;
use core::fmt;
use ed25519_dalek::SigningKey;
use lazy_static::lazy_static;
use runix_capability_manager::CapabilityToken;
use runix_citadel_integration::{CitadelError, ShadowMarshalOutcome, WormLog};
use runix_ipc::marshal::{MarshalOutcome, MarshalRequest, MarshalResponse};
use spin::Mutex;
use x86_64::structures::paging::{Page, PageTableFlags};
use x86_64::VirtAddr;

/// Same compiled binary `main.rs`'s Phase B7 loads — see that module's own
/// `GRID_SANDBOX_HOST_ELF` doc comment for the `include_bytes!` build-order
/// requirement (`grid-sandbox-host` must already be built for
/// `x86_64-unknown-none` before this crate compiles).
static GRID_SANDBOX_HOST_ELF: &[u8] =
    include_bytes!("../../grid-sandbox-host/target/x86_64-unknown-none/release/grid-sandbox-host");

/// Must match `grid-sandbox-host/src/main.rs`'s own `HEAP_START`/`HEAP_SIZE`
/// — see `main.rs`'s original `GRID_SANDBOX_HEAP_START` doc comment for the
/// full reasoning (that binary has no privilege to map its own memory, and
/// the 8 MiB size backs a real `T1Critical`-tier `memory.grow`, not just an
/// abstract limiter check).
pub const HEAP_START: u64 = 0x_2222_2222_0000;
pub const HEAP_SIZE: u64 = 8 * 1024 * 1024;
pub const STACK_VA: u64 = 0x_2222_3333_0000;
pub const STACK_SIZE: u64 = 4096 * 4;
/// The one page `grid-sandbox-host` reads at startup to learn its
/// CITADEL-assigned sandbox tier.
pub const INFO_VA: u64 = 0x_2222_4444_0000;
/// Offset into the `INFO_VA` page `grid-sandbox-host` writes its own
/// boot-level tier-correctness result to (whether a real `memory.grow`
/// sized to succeed only under `T1Critical` actually did) — see
/// `grid-sandbox-host/src/main.rs`'s own `GRID_GROW_RESULT_OFFSET`.
pub const GROW_RESULT_OFFSET: usize = 128;
pub const GROW_RESULT_SUCCEEDED: u8 = 1;
pub const GROW_RESULT_FAILED: u8 = 2;

/// The tier byte `grid-sandbox-host` reads at [`INFO_VA`] to select its
/// `wasm-runtime` resource limits — same `0`/`1`/`2` convention `main.rs`'s
/// `GridBootInfo` doc comment establishes.
#[repr(C)]
struct GridBootInfo {
    tier: u8,
}

fn tier_byte(tier: SandboxTier) -> u8 {
    match tier {
        SandboxTier::T1Critical => 0,
        SandboxTier::T2Trusted => 1,
        SandboxTier::T3Untrusted => 2,
    }
}

/// Where a shadow-mode MARSHAL evaluation (see [`spawn_instance`]'s own doc
/// comment) should reach a MARSHAL proxy, if one is configured at all. There
/// is no live, reachable CITADEL deployment in any dev/CI/QEMU scenario
/// today (see `kernel/src/marshal_client.rs`'s own doc comment) — a
/// hardcoded production address would just be a fail-*open* default nobody
/// actually validated, the opposite of the "fails closed if unconfigured"
/// discipline `desktop::citadel::transport::HttpKerkeseTransport` already
/// applies. So the default is `None` ("no proxy configured"), treated as the
/// expected common case: [`spawn_instance`] then records an `Unreachable`
/// shadow outcome without attempting any network I/O at all, rather than
/// spending even a bounded budget of syscalls discovering that nobody is
/// listening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowMarshalProxyConfig {
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub local_port: u16,
}

static SHADOW_MARSHAL_PROXY: Mutex<Option<ShadowMarshalProxyConfig>> = Mutex::new(None);

/// Configures (or clears, with `None`) where [`spawn_instance`]'s shadow
/// MARSHAL evaluation should look for a proxy — see
/// [`ShadowMarshalProxyConfig`]'s own doc comment for why the default is
/// unconfigured rather than a hardcoded address. Exists mainly for tests
/// (e.g. `kernel/tests/grid_sandbox_marshal_shadow.rs`) that stand up a real
/// listener and want to prove the evaluation call reaches it; a real
/// deployment would call this once at boot, from wherever it learns the
/// proxy's address, same as it would configure any other service endpoint.
pub fn set_shadow_marshal_proxy(config: Option<ShadowMarshalProxyConfig>) {
    *SHADOW_MARSHAL_PROXY.lock() = config;
}

/// Bounded, fail-fast poll budget for [`spawn_instance`]'s shadow MARSHAL
/// evaluation — deliberately much smaller than `marshal_proxy_e2e.rs`'s
/// 200_000-iteration budget (a test can afford to wait for a real listener
/// on the other end of a `guestfwd` bridge; a production spawn must not
/// meaningfully slow down over an absent or slow proxy). At this budget, a
/// completely unreachable proxy costs on the order of a couple thousand
/// syscall attempts and a handful of `yield_now` calls, not a stall visible
/// to whatever's waiting on this instance to spawn.
const SHADOW_MARSHAL_MAX_ITERS: u32 = 2_000;

// Every shadow MARSHAL evaluation `spawn_instance` performs is recorded
// here, through the same tamper-evident `WormLog` mechanism
// `BootAllowlist`/`InstanceAllowlist` already use for real boot-time/
// instance authorization decisions — see
// `WormLog::record_shadow_marshal_evaluation`'s own doc comment for why a
// parallel logging path was deliberately not added instead. A dedicated
// log, not appended to either allowlist's own (per-allowlist) log: those
// are owned internally by `BootAllowlist`/`InstanceAllowlist` and dropped
// with the throwaway allowlist `citadel::demo_authorize_instance` builds
// per call (see that function's own doc comment) — there is nothing
// long-lived to append to there. This log is `grid_sandbox`'s own, exactly
// as `capabilities.rs`'s `REVOCATIONS` is that module's own long-lived
// state.
lazy_static! {
    static ref SHADOW_MARSHAL_LOG: Mutex<WormLog> = Mutex::new(WormLog::default());
}

/// This crate's read-only view onto [`SHADOW_MARSHAL_LOG`] — what
/// `kernel/tests/grid_sandbox_marshal_shadow.rs` inspects to confirm a
/// shadow evaluation was actually recorded.
pub fn shadow_marshal_log_entries() -> alloc::vec::Vec<runix_citadel_integration::WormEntry> {
    SHADOW_MARSHAL_LOG.lock().entries().to_vec()
}

/// Performs [`spawn_instance`]'s MARSHAL evaluation for an already-authorized
/// `(module_id, instance_id)` pair, records the outcome in
/// [`SHADOW_MARSHAL_LOG`] exactly as before (this observability path is
/// unchanged by real enforcement — see `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s
/// "WormLog side effects"), and now also **returns** the outcome so
/// [`enforce_marshal_decision`] can act on it. The name is kept (matches
/// `SHADOW_MARSHAL_LOG`/`SHADOW_MARSHAL_PROXY`/existing tests) even though
/// this function's result is no longer purely observational as of the
/// real-enforcement change — see [`spawn_instance`]'s own doc comment for
/// what actually gates the spawn now.
///
/// Builds a minimal, genuinely well-formed Kerkese-shaped request
/// (`dry_run: true` — see `runix_ipc::marshal`'s own doc comment for why
/// `kerkese_json` is an opaque blob no hop in this chain parses) and calls
/// [`marshal_client::evaluate`] with [`SHADOW_MARSHAL_MAX_ITERS`], the
/// bounded, fail-fast budget appropriate for a spawn path rather than a
/// test.
fn shadow_marshal_evaluate(module_id: &str, instance_id: &str) -> ShadowMarshalOutcome {
    let config = *SHADOW_MARSHAL_PROXY.lock();
    let outcome = match config {
        None => ShadowMarshalOutcome::Unreachable,
        Some(config) => {
            // Per `docs/RFC-VERIFIER-IDENTITY.md`'s Option A: the kernel
            // only ever asserts an `actor` (as a real, shaped
            // `KerkeseActor`-equivalent object, not a bare string) and
            // never claims a `verifier` identity of its own — attaching a
            // real, code-distinct Verifier identity (and the `sod` block
            // Gate 3's same-identity check actually keys on) is
            // `desktop/src/citadel/proxy.rs`'s job, after its own local
            // policy check passes. See that module's `identity`/`policy`
            // submodules for what fills in the rest of this envelope
            // before it ever reaches CITADEL.
            let kerkese_json = format!(
                r#"{{"kerkese_version":"1.0","dry_run":true,"action":{{"type":"grid_sandbox.spawn_instance","module_id":"{module_id}","instance_id":"{instance_id}"}},"actor":{{"user_id":"kernel:grid_sandbox","role":"operator"}},"execution_id":"{instance_id}"}}"#
            );
            let request = MarshalRequest {
                kerkese_json: kerkese_json.into_bytes(),
            };
            match marshal_client::evaluate(
                config.remote_ip,
                config.remote_port,
                config.local_port,
                &request,
                SHADOW_MARSHAL_MAX_ITERS,
            ) {
                Some(MarshalResponse::Decision { outcome, .. }) => match outcome {
                    MarshalOutcome::Execute => ShadowMarshalOutcome::Execute,
                    MarshalOutcome::Refuse => ShadowMarshalOutcome::Refuse,
                    MarshalOutcome::HardStop => ShadowMarshalOutcome::HardStop,
                },
                Some(MarshalResponse::Error(_)) | None => ShadowMarshalOutcome::Unreachable,
            }
        }
    };
    serial_println!(
        "grid_sandbox: MARSHAL evaluation for instance {:?}: {:?} (see enforce_marshal_decision \
         for whether this gates the spawn)",
        instance_id,
        outcome
    );
    SHADOW_MARSHAL_LOG
        .lock()
        .record_shadow_marshal_evaluation(module_id, instance_id, outcome);
    outcome
}

/// Runtime MARSHAL-enforcement failure for a spawn that already passed
/// CITADEL's boot-time allowlist gate (`citadel::demo_authorize_instance`,
/// which returns [`CitadelError`]). Deliberately a **separate** enum rather
/// than a new `CitadelError` variant — see
/// `docs/MARSHAL-ENFORCEMENT-POLICY.md`'s "`spawn_instance` return type and
/// control flow" section for the full tradeoff. Short version: `CitadelError`
/// is a closed set of *boot-time, module/instance-allowlist* failures
/// (`NotAllowlisted`, `HashMismatch`, `InvalidSignature`, ...) — conceptually
/// "is this binary/instance allowed to exist at all." A MARSHAL enforcement
/// failure is a different kind of thing: a *runtime governance* decision
/// ("CITADEL says don't run this right now"), and this is deliberately the
/// first of what the policy doc expects to be several runtime enforcement
/// gates (IPC sends to T1 services, T3 memory-allocation requests, ...).
/// Folding those into `CitadelError` over time would conflate two failure
/// categories callers legitimately want to handle differently (a
/// `NotAllowlisted` binary is never getting spawned no matter what; a
/// `MarshalEnforcementError::Blocked` spawn might succeed later once
/// governance's opinion changes) — a new, dedicated enum per the policy
/// doc's option 2 keeps that distinction explicit from the start rather than
/// retrofitting it once a second gate exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarshalEnforcementError {
    /// A reachable MARSHAL proxy returned `Refuse` or `HardStop` for this
    /// spawn. Carries the exact outcome so a caller/log message can tell
    /// the two apart without re-deriving it.
    Blocked(ShadowMarshalOutcome),
}

impl fmt::Display for MarshalEnforcementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarshalEnforcementError::Blocked(outcome) => {
                write!(f, "MARSHAL enforcement blocked this spawn: {outcome:?}")
            }
        }
    }
}

/// What [`spawn_instance`] hands back on failure: either the boot-time
/// authorization gate refused this `(module_id, instance_id)`
/// ([`CitadelError`], via `citadel::demo_authorize_instance`), or a
/// reachable MARSHAL proxy refused it at runtime
/// ([`MarshalEnforcementError`], via [`enforce_marshal_decision`]). See
/// [`MarshalEnforcementError`]'s own doc comment for why these stay two
/// variants of one wrapper instead of being merged into `CitadelError`
/// directly.
#[derive(Debug)]
pub enum SpawnInstanceError {
    Authorization(CitadelError),
    MarshalEnforcement(MarshalEnforcementError),
}

impl fmt::Display for SpawnInstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnInstanceError::Authorization(e) => write!(f, "{e}"),
            SpawnInstanceError::MarshalEnforcement(e) => write!(f, "{e}"),
        }
    }
}

impl From<CitadelError> for SpawnInstanceError {
    fn from(e: CitadelError) -> Self {
        SpawnInstanceError::Authorization(e)
    }
}

impl From<MarshalEnforcementError> for SpawnInstanceError {
    fn from(e: MarshalEnforcementError) -> Self {
        SpawnInstanceError::MarshalEnforcement(e)
    }
}

/// The real enforcement gate — Option B from
/// `docs/MARSHAL-ENFORCEMENT-POLICY.md`: fail-open when there is nothing
/// to honor (no proxy configured, or a configured proxy that couldn't be
/// reached), fail-closed only when a reachable MARSHAL actually said no.
///
/// Takes the [`ShadowMarshalOutcome`] [`shadow_marshal_evaluate`] already
/// computed rather than re-deriving it or re-checking [`SHADOW_MARSHAL_PROXY`]
/// itself: `shadow_marshal_evaluate` already collapses "no proxy configured"
/// and "configured but unreachable" into the same [`ShadowMarshalOutcome::Unreachable`]
/// variant (see that function's `match config` — both arms produce
/// `Unreachable`), which is exactly the pair of cases Option B treats
/// identically (fail-open). So a single match on the four outcome variants
/// is a complete, correct implementation of the policy doc's
/// "check config -> attempt contact -> check decision" pseudocode, without
/// duplicating the proxy-config lookup or the network attempt.
fn enforce_marshal_decision(outcome: ShadowMarshalOutcome) -> Result<(), MarshalEnforcementError> {
    match outcome {
        // No proxy configured, or configured but unreachable: fail-open —
        // preserves "doesn't break anything when unconfigured", per the
        // policy doc's Option B rationale.
        ShadowMarshalOutcome::Unreachable => Ok(()),
        // Reachable and MARSHAL approved: allow.
        ShadowMarshalOutcome::Execute => Ok(()),
        // Reachable and MARSHAL said no: fail-closed. Real teeth.
        ShadowMarshalOutcome::Refuse | ShadowMarshalOutcome::HardStop => {
            Err(MarshalEnforcementError::Blocked(outcome))
        }
    }
}

/// What [`spawn_instance`] hands back to its caller once a `grid-sandbox-host`
/// instance is loaded and running.
pub struct SpawnedInstance {
    /// The instance's own `GridBootInfo`/grow-result page — a distinct
    /// physical frame per instance (each instance's `AddressSpace` mapped
    /// its own private page at the same VA), so polling one instance's
    /// [`GROW_RESULT_OFFSET`] byte can never observe another instance's
    /// result.
    pub info: &'static mut [u8; 4096],
    /// The capability token issued for this instance alone, scoped to
    /// `capabilities::grid_instance_resource(instance_id)` — verifies only
    /// against that exact resource string, never another instance's.
    pub token: CapabilityToken,
}

/// Authorizes (via `citadel::demo_authorize_instance`, scoped to exactly
/// this `instance_id`), loads, and spawns one `grid-sandbox-host` instance
/// as a real, isolated ring 3 process — the multi-instance generalization of
/// `main.rs`'s `load_and_run_grid_sandbox_host`. Fail-closed: an
/// unauthorized `(module_id, instance_id)` pair is never parsed, loaded, or
/// run, same contract `demo_authorize`/`BootAllowlist` already give the
/// single-instance boot path.
///
/// Callers spawning N instances call this once per instance with a distinct
/// `instance_id` — never reusing one instance's authorization decision or
/// capability token for another, even though every instance loads the exact
/// same binary.
///
/// Once `citadel::demo_authorize_instance` already succeeds, this function
/// also performs a real-time MARSHAL evaluation via [`shadow_marshal_evaluate`]
/// (name kept for continuity with `SHADOW_MARSHAL_LOG`/tests — it still
/// records the outcome there exactly as before) and gates the spawn on the
/// result through [`enforce_marshal_decision`], per the approved Option B
/// policy in `docs/MARSHAL-ENFORCEMENT-POLICY.md`:
///
/// - No proxy configured (`SHADOW_MARSHAL_PROXY == None`, the default in
///   every dev/CI/QEMU scenario today), or a configured proxy that's
///   unreachable: **fail-open** — the spawn proceeds. Preserves "doesn't
///   break anything when unconfigured," the property shadow mode always had.
/// - A reachable proxy that answers `Execute`: allowed.
/// - A reachable proxy that answers `Refuse` or `HardStop`: **fail-closed**
///   — this function returns `Err(SpawnInstanceError::MarshalEnforcement(_))`
///   *before* the ELF is parsed, before any `AddressSpace` is created, and
///   before any capability token is issued. Nothing gets spawned; a blocked
///   instance is never started and then killed.
///
/// This is real enforcement, not observation — see the policy doc for the
/// full fail-open/fail-closed tradeoff analysis and why Option A
/// (fail-closed on any non-`Execute`, including unreachable) was rejected.
pub fn spawn_instance(
    instance_id: &str,
    tier: SandboxTier,
    now: u64,
    signing_key: &SigningKey,
) -> Result<SpawnedInstance, SpawnInstanceError> {
    let tier = citadel::demo_authorize_instance(
        "grid-sandbox-host",
        instance_id,
        GRID_SANDBOX_HOST_ELF,
        tier,
    )?;
    serial_println!(
        "grid_sandbox: instance {:?} authorized by CITADEL instance allowlist at tier {:?}",
        instance_id,
        tier
    );

    // Real enforcement gate (Option B, docs/MARSHAL-ENFORCEMENT-POLICY.md):
    // evaluate, record in WormLog (unchanged observability), then act on
    // the outcome — fail-open on unconfigured/unreachable, fail-closed on a
    // reachable Refuse/HardStop. Placed after the real
    // `demo_authorize_instance` gate above, never before it, and strictly
    // before any ELF parsing/loading/address-space setup below: a blocked
    // spawn must never reach those.
    let marshal_outcome = shadow_marshal_evaluate("grid-sandbox-host", instance_id);
    enforce_marshal_decision(marshal_outcome)?;

    let elf = Elf64::parse(GRID_SANDBOX_HOST_ELF)
        .expect("grid-sandbox-host failed to parse as a valid ELF64 binary");

    let mut space = AddressSpace::new();
    let entry = elf
        .load_segments(&mut space)
        .expect("grid-sandbox-host failed to load its PT_LOAD segments");

    // The ELF loader only maps what the ELF itself declares — the payload's
    // heap and ring 3 stack are runtime-only regions with no PT_LOAD
    // segment behind them, so mapping those is this loader's job. Every
    // instance maps the exact same VAs (see this module's own doc comment
    // for why) into its own private `AddressSpace`, so no two instances'
    // heaps/stacks ever share a physical frame.
    let heap_start_page = Page::containing_address(VirtAddr::new(HEAP_START));
    let heap_end_page = Page::containing_address(VirtAddr::new(HEAP_START + HEAP_SIZE - 1));
    let heap_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        // A freshly allocated frame carries whatever its previous owner
        // left in it, not guaranteed-zero.
        space.map_private_page(page, heap_flags).fill(0);
    }

    let stack_start_page = Page::containing_address(VirtAddr::new(STACK_VA));
    let stack_end_page = Page::containing_address(VirtAddr::new(STACK_VA + STACK_SIZE - 1));
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(stack_start_page, stack_end_page) {
        space.map_private_page(page, stack_flags);
    }

    let info_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let info_page = Page::containing_address(VirtAddr::new(INFO_VA));
    let info_content = space.map_private_page(info_page, info_flags);
    info_content.fill(0);
    unsafe {
        core::ptr::write_volatile(
            info_content.as_mut_ptr() as *mut GridBootInfo,
            GridBootInfo {
                tier: tier_byte(tier),
            },
        );
    }

    // Capability grant: scoped to exactly this instance, never a
    // module-wide token another instance could also present — see
    // `capabilities::grid_instance_resource`'s doc comment.
    let resource = capabilities::grid_instance_resource(instance_id);
    let token = CapabilityToken::issue(
        instance_id,
        resource,
        now,
        now + 1_000_000,
        "demo-key",
        signing_key,
    );

    #[allow(static_mut_refs)]
    unsafe {
        ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process_with_capability(trampoline, space, Some(token.clone()));

    Ok(SpawnedInstance {
        info: info_content,
        token,
    })
}

/// `entry` (the ELF's own entry point, `_start` in `grid-sandbox-host`) is
/// only known at runtime, parsed from the loaded binary — but deterministic
/// across every call (same compiled binary, same link addresses every
/// parse), so one shared `static`/trampoline pair is safe to reuse across
/// every spawned instance. See this module's own doc comment.
static mut ENTRY_POINT: u64 = 0;

extern "C" fn trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { ENTRY_POINT };
    unsafe {
        userspace::enter_usermode(VirtAddr::new(entry), VirtAddr::new(STACK_VA + STACK_SIZE));
    }
}
