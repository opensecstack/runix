//! EL1 -> EL0 transition -- the ARM-side analogue of
//! `kernel/src/userspace.rs`'s ring 0 -> ring 3 transition. Everything
//! before this module (boot, exception vectors, GIC, the MMU) ran
//! entirely at EL1; this is where an actual restricted, capability-gated
//! context starts existing, the shape the eventual RIL isolation boundary
//! takes.
//!
//! Alpha scope: one hand-written EL0 function (`el0_demo`, self-contained
//! naked asm, the same reasoning as `userspace::user_hello` on the
//! x86_64 side -- no calls into normal EL1 code, since EL0 can only ever
//! reach EL1 through the `SVC` gate, not by jumping into arbitrary EL1
//! code). It exercises the full syscall surface: `SYS_WRITE` (proves the
//! gate itself works, unconditionally); `SYS_RIL_ACCESS` for an
//! authorized and an unauthorized channel (proves the capability check
//! distinguishes the two); `SYS_RIL_SEND`/`SYS_RIL_RECV` round-tripping a
//! real byte through the authorized channel and getting denied on the
//! unauthorized one (proves the check gates actual I/O, `ril_channel.rs`,
//! not just a bare decision); then the eSIM profile lifecycle
//! (`SYS_SIM_CREATE`/`INSTALL`/`ENABLE`/`DISABLE`/`DELETE`/`STATUS`)
//! walking an authorized slot's first profile through its real state
//! machine (`sim.rs`) and getting denied on an unauthorized slot --
//! proving the *same* capability check gates a second,
//! differently-shaped resource kind, not something special-cased for RIL;
//! and finally `SYS_IPC_SEND`/`SYS_IPC_RECV` round-tripping a byte through
//! a general-purpose IPC channel (`ipc_channel.rs`) and getting denied on
//! an unauthorized channel number.
//!
//! Beta item 3.3 extends the eSIM walk with the MVNO account layer (see the
//! "MVNO" section below): `SYS_MVNO_BIND` before the first `ENABLE`, a
//! suspend/denied-enable/reactivate/re-enable cycle around the existing
//! `DELETE`-must-fail check, an unbound-profile enable denial, and
//! account-99 capability denials. Every pre-existing syscall and ordering
//! assertion below is kept.
//!
//! Beta item 4.3 adds the data policy walk (`SYS_DATA_ACCOUNT` /
//! `SESSION_OPEN` / `SESSION_CLOSE` / `RECONCILE`, see "The data policy
//! additions" below). None of those four is MARSHAL-gated; the follow-up
//! `SYS_DATA_RESET` (the governed usage-period reset, which lifts a cap) IS,
//! so the walk performs exactly eight evaluations. `SYS_DATA_PERIOD` (the
//! read-only billing-period advice) is not gated and adds none.
//!
//! # Why the IPC walk is sequential send-then-recv from one context
//!
//! The IPC pair is exercised exactly the way the RIL pair already is: this
//! one EL0 context issues `SEND` on channel 0, then later issues `RECV` on
//! the *same* channel and echoes the byte back out through `SYS_WRITE`.
//! There is no second thread, because there is no scheduler in this crate
//! yet (see `capabilities.rs`'s own doc comment) -- and none is needed to
//! prove what this slice claims: that a general byte channel exists, that
//! the `SVC` gate carries a real payload byte into and back out of it, and
//! that the capability check is consulted on *every* operation rather than
//! cached. Genuine two-thread IPC becomes exercisable once the scheduler
//! slice of `docs/BETA_MOBILE_PROGRESS.md`'s Item 2.4 lands; it is not what
//! the channel mechanism itself needs in order to be real.
//!
//! # What the eSIM part of the walk is actually proving
//!
//! The sequence is `CREATE(0)` -> `STATUS` (`Created`) -> `INSTALL(0, 0,
//! 0x1234)` -> `STATUS` (`Disabled`) -> `ENABLE` -> `STATUS` (`Enabled`)
//! -> **`DELETE` (must fail)** -> `DISABLE` -> `STATUS` (`Disabled`) ->
//! `DELETE` (succeeds) -> `STATUS` (`Deleted`), then `CREATE(99)` and
//! `STATUS(99, 0)` on an unauthorized slot. Three things in there are load
//! -bearing rather than decorative:
//!
//! - The **first `DELETE` is expected to fail.** The profile is still
//!   `Enabled`, and `sim.rs`'s state machine forbids a direct `Enabled ->
//!   Deleted` transition (see its doc comment on why that isn't an
//!   implicit disable-then-delete). Running it here proves that invariant
//!   holds *at the syscall boundary* -- i.e. that `svc.rs` actually
//!   propagates the rejection to EL0 rather than swallowing it -- not just
//!   inside `sim.rs` in isolation.
//! - **`ENABLE` succeeding** proves `esim_marshal.rs`'s fail-open gate
//!   does not block a legitimate authorized operation. A gate that denied
//!   everything would pass a "denials happen" test and fail this one.
//! - `INSTALL` is the **first caller of the third syscall argument**
//!   (`identity`, in `x3`) -- the one `el1_vectors.rs`'s ABI widening
//!   exists for. Nothing else in this demo uses `x3`, so if that load's
//!   stack offset were wrong, this is the syscall that would show it (as a
//!   garbage identity in `svc.rs`'s `SYS_SIM_INSTALL` print).
//!
//! # The MVNO additions
//!
//! `BIND(0,0,0)` sits between `INSTALL` and the first `ENABLE` because
//! `svc.rs`'s MVNO gate refuses to enable an unbound profile. After the first
//! `ENABLE`/`STATUS` the walk runs `SUSPEND(0)` (forced disable + audit),
//! `STATUS` (Disabled), `ENABLE` (**DENIED (MVNO ...)**, the account is
//! Suspended), `REACTIVATE(0)`, `ENABLE` (authorized again) and `STATUS`
//! (Enabled) -- ending Enabled so the existing `DELETE`-must-fail /
//! `DISABLE` / `DELETE` sequence runs unchanged. The successful `DELETE`
//! also releases the binding (kernel-side). Afterwards a second profile is
//! created and installed in slot 0 but never bound, and its `ENABLE` is
//! denied (MVNO), proving the gate fails closed. Finally `BIND(99, ..)` and
//! `SUSPEND(99)` are denied for lack of a capability, and `BIND(0, 0, 2)` is
//! denied because the account capability is held but the profile capability
//! (`sim:0:2`) is not -- `BIND` needs both. The three MVNO syscalls
//! are MARSHAL-gated too (Beta item 3.4; transparent here: Unreachable and
//! Execute both pass), so the MVNO/eSIM part of the walk performs seven
//! evaluations per boot (bind, enable, suspend, reactivate, enable, delete x2);
//! the data reset below adds an eighth (`data.reset_usage`).
//!
//! # The data policy additions
//!
//! Immediately after the first `ENABLE`/`STATUS (Enabled)` (profile 0 is bound
//! to account 0 and Enabled there) and before `SUSPEND(0)`: `SESSION_OPEN`
//! (allow, usage 0), `SESSION_OPEN` with the roaming flag (denied
//! RoamingDataNotAllowed), `ACCOUNT(0, 900)` (engine requests a throttle),
//! `SESSION_OPEN` (allow-throttled), `ACCOUNT(0, 700)` (total 1600: engine
//! REQUESTS suspension), `SESSION_OPEN` (denied CapExceeded), `RECONCILE`
//! (raises `UsageOverCapNotRestricted` and `AnomalousUsageNoEscalation`). The
//! existing `SUSPEND(0)` that follows IS the caller carrying out that
//! request through the governed path. After the forced-disable `STATUS`:
//! `RECONCILE` (the usage incidents are gone; the still-open session on the
//! now-Disabled profile raises `SessionWithoutEnabledProfile`),
//! `SESSION_CLOSE` (the caller finishing the restriction), `RECONCILE` (clean).
//! That last reconcile is deliberately placed while the account is Suspended:
//! once reactivated it is Active with usage still over threshold and no
//! billing-period reset, which the reconciler would rightly flag again.
//! Denial proofs: `SESSION_OPEN(0, 0, 1)` on the installed-but-unbound
//! profile, and `SESSION_OPEN(99, ..)` / `ACCOUNT(99, ..)` with no capability.
//!
//! The governed reset sits after the second `ENABLE`/`STATUS (Enabled)` (the
//! account is Active again, profile 0 Enabled and bound, usage still 1600 of a
//! 1000-byte cap, no session open) and before the `INSTALL`/`DELETE`-must-fail
//! steps, which only need the profile Enabled: `SESSION_OPEN` (DENIED
//! CapExceeded -- the cap is still in force), `RESET(0)` (authorized, usage
//! 1600 -> 0, MARSHAL-gated), `SESSION_OPEN` (allowed -- service restored),
//! `RECONCILE` (zero incidents: an open session on an Enabled profile under
//! the cap, and no `UsageRegression` because the reset cleared the
//! reconciler's memory), `SESSION_CLOSE`. `RESET(99)` is the denial proof
//! (no `data:reset:99` capability). That is the sequence when the reset is
//! AUTHORIZED (a reachable MARSHAL that answers Execute). In the plain boot
//! configurations there is no MARSHAL proxy, the evaluation is `Unreachable`,
//! and the reset is FAIL-CLOSED (ADR 0003): `RESET(0)` is DENIED, usage stays
//! 1600, the next `SESSION_OPEN` is still DENIED CapExceeded, `RECONCILE`
//! reports one incident (`anomalous-usage-no-escalation`: the over-cap
//! account was never restricted) and `SESSION_CLOSE` is refused (no session is
//! open). CI asserts the plain-boot sequence.
//!
//! The billing-period advice (`SYS_DATA_PERIOD`, read-only, not MARSHAL-gated,
//! no new MARSHAL evaluation) is called twice with account 0 and once with 99.
//! `PERIOD(0)` right after the `ACCOUNT(0, 700)` feed returns 1: the 500 ms demo
//! period, which started at tick 0, is long over, so a reset is REQUESTED
//! (nothing is reset). `PERIOD(0)` again right after the post-reset
//! `SESSION_OPEN` returns 0 if the reset was authorized (it started the next
//! period) and 1 if it was denied (a denied reset starts no period; the request
//! is still outstanding). `PERIOD(99)` is the capability-denial proof.
//!
//! The denial half intentionally uses `CREATE(99)`/`STATUS(99, 0)` rather
//! than repeating every operation on slot 99: the point is that the
//! capability check is consulted per operation on a resource the context
//! holds no token for, which two operations establish as well as six.
//! Separately, the *delete-specific* capability scoping
//! (`capabilities::sim_delete_resource`) is what makes the successful
//! `DELETE` on slot 0 meaningful -- it only passes because `nonsecure.rs`
//! issues that second, distinct token alongside the general profile one.

use core::arch::naked_asm;

pub const EL0_STACK_SIZE: usize = 4096 * 4;

// The field is never read through Rust -- only its address (computed in
// `drop_to_el0`) and its raw memory (as EL0's stack, written directly by
// the CPU) are ever used. Same pattern as `main.rs`'s `BOOT_STACK`.
//
// `repr(align(4096))`, not just `align(16)`: `mmu.rs`'s page-granular EL0
// mapping (see its doc comment on why block-granular `AP[1]=1` isn't used)
// needs this to start on its own page boundary, not share a 4 KiB page
// with unrelated EL1-only static data -- sharing would force that
// neighboring data to also be EL0-accessible, or force this stack to not
// be, since `AP[2:1]` is a whole-page property.
#[repr(align(4096))]
#[allow(dead_code)]
struct El0Stack([u8; EL0_STACK_SIZE]);

#[unsafe(no_mangle)]
static mut EL0_STACK: El0Stack = El0Stack([0; EL0_STACK_SIZE]);

/// The stack's base address -- `mmu.rs` needs this (alongside
/// [`EL0_STACK_SIZE`]) to compute which page-table entries to mark
/// EL0-accessible. Exactly the range `drop_to_el0` hands EL0 as `SP_EL0`
/// (`[base, base + EL0_STACK_SIZE)`), 4 KiB-aligned per `El0Stack`'s
/// `repr(align(4096))`.
pub fn stack_base() -> u64 {
    core::ptr::addr_of!(EL0_STACK) as u64
}

/// `SPSR_EL1` value `eret` restores `PSTATE` from: `M[3:0] = 0b0000`
/// selects EL0t (EL0 has no SP0/SPx distinction the way EL1/EL2/EL3 do --
/// it always uses `SP_EL0`). `DAIF = 1111` masks Debug/SError/IRQ/FIQ on
/// entry, same reasoning as `nonsecure.rs`'s `SPSR_EL1H_MASKED`: nothing
/// here depends on interrupts firing at EL0 yet, and masking doesn't
/// affect `SVC` (a synchronous exception, never DAIF-maskable) --
/// `el0_demo`'s syscalls still reach `svc.rs` regardless.
const SPSR_EL0T_MASKED: u64 = 0b1111 << 6;

/// Sets up `SPSR_EL1`/`ELR_EL1`/`SP_EL0` and executes `eret` -- the actual
/// EL1 -> EL0 drop. Never returns as far as *this* call chain is
/// concerned: `eret` is a jump, and the only way back to EL1 is a future
/// `SVC` trap, which resumes inside `svc.rs`'s dispatcher, not here.
///
/// # Safety
/// `entry` must point at code that's self-contained enough to run
/// correctly at EL0: no calls into ordinary EL1 code (EL0 can only
/// re-enter EL1 through `SVC`). Data access (loads/stores, including an
/// implicit stack push/pop) is only valid within the specific pages
/// `mmu.rs::install` actually marks `AP[2:1]=0b01` for -- this stack
/// (`EL0_STACK`, sized/located via [`stack_base`]/[`EL0_STACK_SIZE`]) and
/// `entry`'s own code page. Anywhere else in this crate's Normal region
/// stays EL1-only (`AP[2:1]=0b00`) -- see `mmu.rs`'s doc comment on
/// `Level3Table` for why the whole 1 GiB block never gets `AP[1]=1` at
/// once (a real, reproducible QEMU hang), and why page-granular mapping
/// is the fix rather than a workaround.
pub unsafe fn drop_to_el0(entry: u64) -> ! {
    // Computed here, not with `adrp`/`add` scratch instructions inside the
    // asm block below: `options(noreturn)` forbids declaring any register
    // (even a plain `out(reg) _` clobber) as an asm output, since the
    // compiler assumes control never returns to observe it -- so there is
    // no way to reserve a scratch register for the address computation
    // inside that block. Doing the arithmetic in ordinary Rust first and
    // passing the final value in as a normal `in(reg)` operand sidesteps
    // the restriction entirely.
    let stack_top = unsafe {
        core::ptr::addr_of!(EL0_STACK.0)
            .cast::<u8>()
            .add(EL0_STACK_SIZE) as u64
    };
    unsafe {
        core::arch::asm!(
            "msr SPSR_EL1, {spsr}",
            "msr ELR_EL1, {entry}",
            "msr SP_EL0, {stack_top}",
            "eret",
            spsr = in(reg) SPSR_EL0T_MASKED,
            entry = in(reg) entry,
            stack_top = in(reg) stack_top,
            options(noreturn),
        );
    }
}

/// Must match `svc.rs`'s dispatch table exactly; duplicated here (not
/// shared via a `const` module both sides import) for the same reason
/// `grid-sandbox-host/src/main.rs` duplicates the x86_64 syscall ABI
/// numbers instead of sharing them with `kernel/src/syscall.rs`: this is a
/// standalone-linked EL0 binary in spirit (even though it's compiled into
/// the same image today), and only the syscall *ABI* connects the two
/// sides, not shared Rust items.
const SYS_WRITE: u64 = 1;
const SYS_RIL_ACCESS: u64 = 2;
const SYS_RIL_SEND: u64 = 3;
const SYS_RIL_RECV: u64 = 4;
const SYS_SIM_CREATE: u64 = 5;
const SYS_SIM_INSTALL: u64 = 6;
const SYS_SIM_ENABLE: u64 = 7;
const SYS_SIM_DISABLE: u64 = 8;
const SYS_SIM_DELETE: u64 = 9;
const SYS_SIM_STATUS: u64 = 10;
const SYS_IPC_SEND: u64 = 11;
const SYS_IPC_RECV: u64 = 12;
// 13..=15 are the EL1-continuation syscalls (`svc.rs`'s `SYS_*_PROOF_DONE`),
// which this EL0 context never issues. 16..=18 are the MVNO set (Beta item
// 3.3); kept in sync with `svc.rs` by hand, like everything above.
const SYS_MVNO_BIND: u64 = 16;
const SYS_MVNO_SUSPEND: u64 = 17;
const SYS_MVNO_REACTIVATE: u64 = 18;
// 19..=22 are the data policy set (Beta item 4.3); kept in sync with `svc.rs`
// by hand, like everything above.
const SYS_DATA_ACCOUNT: u64 = 19;
const SYS_DATA_SESSION_OPEN: u64 = 20;
const SYS_DATA_SESSION_CLOSE: u64 = 21;
const SYS_DATA_RECONCILE: u64 = 22;
// 23 is the governed usage-period reset (MARSHAL-gated).
const SYS_DATA_RESET: u64 = 23;
// 24 is the read-only billing-period advice (capability-checked, not gated).
const SYS_DATA_PERIOD: u64 = 24;

/// The EL0 demo itself. `.balign 4096` for the same reason
/// `userspace::user_hello` does: this crate's EL0 permissions *are*
/// page-granular now (see `mmu.rs`'s doc comment on `Level3Table`), and
/// `mmu::install` relies on this function occupying exactly one page to
/// mark it `AP[2:1]=0b01` without also granting EL0 access to any
/// neighboring EL1-only code that happened to share a page.
///
/// # Safety
/// Never call this directly -- only ever reached via `drop_to_el0`'s
/// `eret`, running at EL0 with `SP_EL0` already valid.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn el0_demo() -> ! {
    naked_asm!(
        ".balign 4096",
        // SYS_WRITE('U') -- proves the SVC gate itself works.
        "mov x0, {sys_write}",
        "mov x1, #85", // 'U'
        "svc #0",
        // Real EL0 *data* access proof -- push a byte onto our own stack
        // and read it back, both genuine loads/stores through SP_EL0, not
        // just instruction fetch (which never needed AP[2:1] at all --
        // only UXN/PXN gate execute permission). Echoed via SYS_WRITE so
        // the round trip is visible in the serial log: reaching this print
        // means mmu.rs's page-granular AP[2:1]=0b01 mapping for this
        // stack's own pages actually grants EL0 read/write, the thing
        // `AP[2:1]` on the *whole* 1 GiB block reproducibly hung QEMU on
        // (see mmu.rs's doc comment on `Level3Table` for that
        // investigation) -- confining the bit to this small, dedicated
        // region instead of the block containing the vector table sidesteps
        // it entirely.
        "mov x3, #0x42", // 'B'
        "strb w3, [sp, #-16]!",
        "ldrb w4, [sp]",
        "add sp, sp, #16",
        "mov x0, {sys_write}",
        "mov x1, x4",
        "svc #0",
        // SYS_RIL_ACCESS(0) -- a channel this context holds a capability
        // for (see capabilities::issue_and_hold's caller in nonsecure.rs).
        // x0 on return: 0 = authorized, nonzero = denied.
        "mov x0, {sys_ril_access}",
        "mov x1, #0",
        "svc #0",
        // SYS_RIL_ACCESS(99) -- a channel with no matching capability.
        "mov x0, {sys_ril_access}",
        "mov x1, #99",
        "svc #0",
        // SYS_RIL_SEND(0, 'A') -- authorized channel, real payload byte.
        "mov x0, {sys_ril_send}",
        "mov x1, #0",
        "mov x2, #65", // 'A'
        "svc #0",
        // SYS_RIL_RECV(0) -- reads the byte just sent back; x0 on return
        // is the byte itself (0..=255), not a bare status code (see
        // svc.rs's RIL_RECV_EMPTY/RIL_RECV_DENIED). Moved into x1 and
        // echoed via SYS_WRITE so the round trip is visible in the serial
        // log, not just asserted by the return value.
        "mov x0, {sys_ril_recv}",
        "mov x1, #0",
        "svc #0",
        "mov x1, x0",
        "mov x0, {sys_write}",
        "svc #0",
        // SYS_RIL_SEND(99, 'Z') -- unauthorized channel: denied before
        // ril_channel::send ever runs, proving the check re-gates I/O on
        // every operation, not just once at "open" time.
        "mov x0, {sys_ril_send}",
        "mov x1, #99",
        "mov x2, #90", // 'Z'
        "svc #0",
        // SYS_RIL_RECV(99) -- likewise denied.
        "mov x0, {sys_ril_recv}",
        "mov x1, #99",
        "svc #0",
        // SYS_SIM_CREATE(0) -- authorized at slot level (sim:0); allocates
        // slot 0's first profile container. x0 on return is the new profile
        // ID (0, being the first) -- not a 0/1 status code, see svc.rs's
        // SIM_CREATE_FAILED for the sentinel that distinguishes the two.
        "mov x0, {sys_sim_create}",
        "mov x1, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 0 (Created): a container
        // with nothing installed into it yet.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_INSTALL(0, 0, 0x1234) -- Created -> Disabled. The *only*
        // syscall here that uses the third argument (x3): `identity` stands
        // in for ICCID/IMSI (see sim.rs's doc comment on why this is one
        // opaque u64, not a real digit string), and carrying it alongside
        // slot and profile at once is what the ABI widening in
        // el1_vectors.rs exists for.
        "mov x0, {sys_sim_install}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0x1234",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 1 (Disabled): installed, but
        // deliberately not made the slot's active profile by install alone.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_MVNO_BIND(account 0, slot 0, profile 0) -- binds the freshly
        // installed profile to the demo account (opened by the kernel at
        // boot; EL0 cannot open accounts). Must precede the ENABLE below:
        // svc.rs's MVNO gate refuses to enable a profile bound to no
        // account. Uses all three argument registers (x1 account, x2 slot,
        // x3 profile).
        "mov x0, {sys_mvno_bind}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_SIM_ENABLE(0, 0) -- Disabled -> Enabled, routed through
        // esim_marshal's gate. Expected to SUCCEED: proves the fail-open
        // stub doesn't block a legitimate authorized operation.
        "mov x0, {sys_sim_enable}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 2 (Enabled).
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // --- Data policy demo (Beta item 4.3). Placed here deliberately:
        // profile 0 is bound to account 0 and Enabled right now, which is the
        // only moment a data session can be allowed, and it precedes the
        // MARSHAL-gated SYS_MVNO_SUSPEND below, which is the CALLER carrying
        // out the engine's suspension request. None of these data syscalls
        // (nor SYS_DATA_PERIOD) is MARSHAL-gated (only SYS_DATA_RESET, further
        // down, is).
        // The plan is the kernel's DEMO entitlement for account 0: cap 1000
        // bytes, throttle at 80%, no roaming, suspension requested at 150%.
        // SYS_DATA_SESSION_OPEN(0, 0, 0) -- usage 0: allowed. x3 packs the
        // profile (bits 0..=7) and the roaming flag (bit 8); see svc.rs.
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(0, 0, 0 | roaming) -- DENIED
        // RoamingDataNotAllowed: the plan does not cover roaming. The
        // already-open home session is left alone (closing is the caller's
        // act, never the policy path's).
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0x100",
        "svc #0",
        // SYS_DATA_ACCOUNT(0, 900) -- usage 900/1000 = 90% >= the 80%
        // throttle point: the engine REQUESTS a throttle (x0 = 2). Nothing is
        // throttled by this syscall; it only meters and advises.
        "mov x0, {sys_data_account}",
        "mov x1, #0",
        "mov x2, #900",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(0, 0, 0) -- now allowed-throttled (re-open of
        // the live session: refreshed, not duplicated).
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_ACCOUNT(0, 700) -- total 1600 >= 150% of the cap: the
        // engine REQUESTS suspension (x0 = 3). Requested, not done: the
        // account is still Active and the session still open afterwards.
        "mov x0, {sys_data_account}",
        "mov x1, #0",
        "mov x2, #700",
        "svc #0",
        // SYS_DATA_PERIOD(0) -- returns code 1: the billing period has ELAPSED,
        // so a reset is REQUESTED (advice only: nothing is reset, and nothing
        // resets on a schedule). Account 0's DEMO period starts at tick 0 and
        // lasts 500 ms, and the counter is already seconds old here (24
        // reclamation evaluations, the TCP proof and two MARSHAL evaluations
        // precede this point), so "elapsed" has a wide margin on any host.
        // Placed BEFORE the next RECONCILE on purpose: this call records the
        // tick the request was first issued, which is what starts the
        // reconciler's (long, DEMO) grace for an unactioned request.
        "mov x0, {sys_data_period}",
        "mov x1, #0",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(0, 0, 0) -- DENIED CapExceeded: usage is past
        // the cap. The existing session is still open (not closed for us).
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_RECONCILE -- observes the drift between that request and
        // reality: the account is Active with an open session at 160% of its
        // cap, so it raises UsageOverCapNotRestricted and
        // AnomalousUsageNoEscalation. Evidence only; nothing is corrected.
        "mov x0, {sys_data_reconcile}",
        "svc #0",
        // SYS_MVNO_SUSPEND(0) while profile 0 is Enabled -- the registry
        // flips the account to Suspended and svc.rs force-disables the
        // profile, then re-audits (the "audit clean" line). A distinct
        // capability (mvno:suspend:0) from bind/reactivate (mvno:account:0).
        // This is also the CALLER carrying out the data engine's
        // SuspendAccount request (SYS_DATA_ACCOUNT returned 3 above), through
        // the governed path: capability, MARSHAL gate, WORM.
        "mov x0, {sys_mvno_suspend}",
        "mov x1, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 1 (Disabled): the forced
        // disable really reached sim.rs.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_DATA_RECONCILE -- the suspension satisfied the engine's
        // request: the two usage incidents are gone (the account is no longer
        // Active). What remains is a real finding: the data session was never
        // closed, and it now sits on a Disabled profile
        // (SessionWithoutEnabledProfile). Suspending does not close sessions
        // behind the caller's back; that is the caller's act, next.
        "mov x0, {sys_data_reconcile}",
        "svc #0",
        // SYS_DATA_SESSION_CLOSE(0, 0, 0) -- the caller applying the rest of
        // the restriction (audited).
        "mov x0, {sys_data_session_close}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_RECONCILE -- clean: no incidents. (Placed while the
        // account is Suspended: after REACTIVATE it is Active again with
        // usage still over threshold and no billing reset, which the
        // reconciler would correctly flag again.)
        "mov x0, {sys_data_reconcile}",
        "svc #0",
        // SYS_SIM_ENABLE(0, 0) -- now DENIED (MVNO ...): the capability
        // passes, but the owning account is Suspended. Refused before the
        // MARSHAL round trip and before sim::enable.
        "mov x0, {sys_sim_enable}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_MVNO_REACTIVATE(0) -- Suspended -> Active. Profiles stay
        // Disabled until explicitly enabled again.
        "mov x0, {sys_mvno_reactivate}",
        "mov x1, #0",
        "svc #0",
        // SYS_SIM_ENABLE(0, 0) -- authorized again, restoring the Enabled
        // state the DELETE-must-fail check below depends on.
        "mov x0, {sys_sim_enable}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 2 (Enabled) again.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // --- Governed usage-period reset. State here: account 0 Active,
        // profile 0 Enabled and bound, usage 1600/1000, no session open (the
        // session was closed before the reactivation).
        // SYS_DATA_SESSION_OPEN(0, 0, 0) -- DENIED CapExceeded: the cap is
        // still in force, so service has not been restored.
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_RESET(0) -- capability data:reset:0, then MARSHAL
        // (data.reset_usage, the walk's eighth evaluation), then usage
        // 1600 -> 0 with the reconciler's memory cleared. Closes no session.
        "mov x0, {sys_data_reset}",
        "mov x1, #0",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(0, 0, 0) -- now Allow: service restored.
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_PERIOD(0) -- where the reset was AUTHORIZED, the governed
        // reset also started the next billing period (start = the tick it took
        // effect), so this reads ACTIVE (code 0). Where the reset was DENIED
        // (fail-closed with no MARSHAL proxy, or Refuse) nothing started a
        // period: it still reads ELAPSED (code 1) and the request is still
        // outstanding -- which is itself the proof that a denied reset starts
        // no new period.
        "mov x0, {sys_data_period}",
        "mov x1, #0",
        "svc #0",
        // SYS_DATA_RECONCILE -- 0 incidents: the account is under its cap and
        // Active with an open session on an Enabled profile, and the reset
        // cleared last_used so 1600 -> 0 is not reported as a UsageRegression.
        "mov x0, {sys_data_reconcile}",
        "svc #0",
        // SYS_DATA_SESSION_CLOSE(0, 0, 0) -- the caller finishing the session.
        "mov x0, {sys_data_session_close}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        // SYS_DATA_RESET(99) -- no data:reset:99 capability: DENIED before any
        // state is read, MARSHAL consulted or counter touched.
        "mov x0, {sys_data_reset}",
        "mov x1, #99",
        "svc #0",
        // SYS_DATA_PERIOD(99) -- no data:session:99 capability: DENIED before
        // any period is read or any marker written.
        "mov x0, {sys_data_period}",
        "mov x1, #99",
        "svc #0",
        // SYS_SIM_INSTALL(0, 0, 0x6666) -- expected to FAIL: re-installing
        // over the live Enabled profile would swap its identity (and, with
        // the old shared transition table, demote it). sim.rs now allows
        // install from Created only, so this is WrongState(Enabled) and the
        // profile's identity stays 0x1234.
        "mov x0, {sys_sim_install}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #0x6666",
        "svc #0",
        // SYS_SIM_DELETE(0, 0) -- expected to FAIL, and that failure is the
        // point: the capability check passes (sim:delete:0:0 is held) and
        // the MARSHAL gate passes, but the profile is still Enabled and
        // sim.rs forbids Enabled -> Deleted outright. See this module's doc
        // comment.
        "mov x0, {sys_sim_delete}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_DISABLE(0, 0) -- Enabled -> Disabled. No MARSHAL gate
        // (recoverable direction), still audited.
        "mov x0, {sys_sim_disable}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 1 (Disabled) again.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_DELETE(0, 0) again -- now legal from Disabled, so this
        // one succeeds where the identical call above was rejected.
        "mov x0, {sys_sim_delete}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // SYS_SIM_STATUS(0, 0) -- expect state 3 (Deleted), terminal.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #0",
        "svc #0",
        // Unbound-profile proof: a second profile in slot 0, installed (so
        // it is genuinely Disabled and enable would succeed at the sim.rs
        // level) but never bound to any account. Its per-profile capability
        // (sim:0:1) is issued in nonsecure.rs for exactly this.
        "mov x0, {sys_sim_create}",
        "mov x1, #0",
        "svc #0",
        "mov x0, {sys_sim_install}",
        "mov x1, #0",
        "mov x2, #1",
        "mov x3, #0x5678",
        "svc #0",
        // SYS_SIM_ENABLE(0, 1) -- DENIED (MVNO NotBound): fail closed on an
        // unbound profile, even though the capability is held.
        "mov x0, {sys_sim_enable}",
        "mov x1, #0",
        "mov x2, #1",
        "svc #0",
        // SYS_SIM_STATUS(0, 1) -- still state 1 (Disabled): the denied
        // enable changed nothing.
        "mov x0, {sys_sim_status}",
        "mov x1, #0",
        "mov x2, #1",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(0, 0, 1) -- DENIED (profile not bound to this
        // account): the capability is held and the profile exists, but it has
        // no owner. Fail closed before the policy engine is consulted.
        "mov x0, {sys_data_session_open}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #1",
        "svc #0",
        // SYS_MVNO_BIND(99, 0, 1) / SYS_MVNO_SUSPEND(99) -- an account this
        // context holds no capability for: DENIED before the registry is
        // consulted, re-checked per call like every other syscall here.
        "mov x0, {sys_mvno_bind}",
        "mov x1, #99",
        "mov x2, #0",
        "mov x3, #1",
        "svc #0",
        "mov x0, {sys_mvno_suspend}",
        "mov x1, #99",
        "svc #0",
        // SYS_DATA_SESSION_OPEN(99, 0, 0) / SYS_DATA_ACCOUNT(99, 1) -- an
        // account this context holds no data capability for: DENIED before
        // any state is read or changed.
        "mov x0, {sys_data_session_open}",
        "mov x1, #99",
        "mov x2, #0",
        "mov x3, #0",
        "svc #0",
        "mov x0, {sys_data_account}",
        "mov x1, #99",
        "mov x2, #1",
        "svc #0",
        // SYS_MVNO_BIND(0, 0, 2) -- the account capability (mvno:account:0)
        // IS held but the profile capability (sim:0:2) is NOT (nonsecure.rs
        // deliberately issues none): DENIED naming the profile resource.
        // Proves BIND needs both, not just account access.
        "mov x0, {sys_mvno_bind}",
        "mov x1, #0",
        "mov x2, #0",
        "mov x3, #2",
        "svc #0",
        // SYS_SIM_CREATE(99) -- unauthorized slot: denied before
        // sim::create ever runs, same "checked on every operation, not
        // cached from an open call" property SYS_RIL_SEND(99) proves.
        "mov x0, {sys_sim_create}",
        "mov x1, #99",
        "svc #0",
        // SYS_SIM_STATUS(99, 0) -- likewise denied.
        "mov x0, {sys_sim_status}",
        "mov x1, #99",
        "mov x2, #0",
        "svc #0",
        // SYS_IPC_SEND(0, 'I') -- a general-purpose IPC channel this context
        // holds a capability for (`ipc:0`, issued in nonsecure.rs alongside
        // the RIL/SIM ones). A separate channel space from RIL's, so the
        // `ril:0` token above does not authorize this.
        "mov x0, {sys_ipc_send}",
        "mov x1, #0",
        "mov x2, #73", // 'I'
        "svc #0",
        // SYS_IPC_RECV(0) -- reads that byte back; x0 on return is the byte
        // itself (see svc.rs's IPC_RECV_EMPTY/IPC_RECV_DENIED for the
        // sentinels that aren't bytes). Echoed via SYS_WRITE so the round
        // trip is visible in the serial log, same convention as the RIL
        // round trip above.
        "mov x0, {sys_ipc_recv}",
        "mov x1, #0",
        "svc #0",
        "mov x1, x0",
        "mov x0, {sys_write}",
        "svc #0",
        // SYS_IPC_SEND(99, 'Z') -- unauthorized channel: denied before
        // ipc_channel::send ever runs.
        "mov x0, {sys_ipc_send}",
        "mov x1, #99",
        "mov x2, #90", // 'Z'
        "svc #0",
        // SYS_IPC_RECV(99) -- likewise denied.
        "mov x0, {sys_ipc_recv}",
        "mov x1, #99",
        "svc #0",
        "1:",
        "wfe",
        "b 1b",
        // Pad out to the *next* page boundary -- `.balign 4096` at the top
        // only aligns this function's *start*; without this, the linker is
        // free to pack whatever comes next (in the build that first
        // exposed this bug, `el1_exception_vectors` itself) into the same
        // page's remaining, otherwise-unused space, since this function's
        // real body is nowhere near 4 KiB. `mmu::install` marks this whole
        // page `AP[2:1]=0b01` (EL0-accessible) based on this function's
        // start address alone -- anything sharing the page becomes
        // EL0-accessible too, silently. This is what actually made the
        // EL1-only vector table EL0-accessible last time, retriggering the
        // exact QEMU instruction-fetch bug `Level3Table`'s doc comment
        // describes, just confined to a smaller region.
        ".balign 4096",
        sys_write = const SYS_WRITE,
        sys_ril_access = const SYS_RIL_ACCESS,
        sys_ril_send = const SYS_RIL_SEND,
        sys_ril_recv = const SYS_RIL_RECV,
        sys_sim_create = const SYS_SIM_CREATE,
        sys_sim_install = const SYS_SIM_INSTALL,
        sys_sim_enable = const SYS_SIM_ENABLE,
        sys_sim_disable = const SYS_SIM_DISABLE,
        sys_sim_delete = const SYS_SIM_DELETE,
        sys_sim_status = const SYS_SIM_STATUS,
        sys_ipc_send = const SYS_IPC_SEND,
        sys_ipc_recv = const SYS_IPC_RECV,
        sys_mvno_bind = const SYS_MVNO_BIND,
        sys_mvno_suspend = const SYS_MVNO_SUSPEND,
        sys_mvno_reactivate = const SYS_MVNO_REACTIVATE,
        sys_data_account = const SYS_DATA_ACCOUNT,
        sys_data_session_open = const SYS_DATA_SESSION_OPEN,
        sys_data_session_close = const SYS_DATA_SESSION_CLOSE,
        sys_data_reconcile = const SYS_DATA_RECONCILE,
        sys_data_reset = const SYS_DATA_RESET,
        sys_data_period = const SYS_DATA_PERIOD,
    );
}
