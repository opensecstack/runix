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
    );
}
