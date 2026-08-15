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
//! code). It calls `SYS_WRITE` (proving the syscall gate itself works,
//! unconditionally) and `SYS_RIL_ACCESS` twice -- once for a channel it
//! holds a capability for, once for one it doesn't -- proving `svc.rs`'s
//! capability check actually distinguishes the two, not just that EL0
//! code can reach EL1 at all.

use core::arch::naked_asm;

const EL0_STACK_SIZE: usize = 4096 * 4;

// The field is never read through Rust -- only its address (computed in
// `drop_to_el0`) and its raw memory (as EL0's stack, written directly by
// the CPU) are ever used. Same pattern as `main.rs`'s `BOOT_STACK`.
#[repr(align(16))]
#[allow(dead_code)]
struct El0Stack([u8; EL0_STACK_SIZE]);

#[unsafe(no_mangle)]
static mut EL0_STACK: El0Stack = El0Stack([0; EL0_STACK_SIZE]);

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
/// re-enter EL1 through `SVC`), and no EL0 *data* access (loads/stores,
/// including an implicit stack push/pop) -- `mmu.rs`'s `AP[2:1]` for this
/// block is `0b00` (EL1-only data access) today, not `0b01`, see that
/// module's doc comment on `normal_block_descriptor` for why the
/// architecturally-correct bit is reverted rather than set. Instruction
/// *fetch* still works regardless (governed by `UXN`/`PXN`, not `AP`,
/// and this block sets neither) -- which is exactly why `el0_demo` (pure
/// `mov`/`svc`/`wfe`, no loads or stores) runs fine under this
/// constraint today.
pub unsafe fn drop_to_el0(entry: u64) -> ! {
    // Computed here, not with `adrp`/`add` scratch instructions inside the
    // asm block below: `options(noreturn)` forbids declaring any register
    // (even a plain `out(reg) _` clobber) as an asm output, since the
    // compiler assumes control never returns to observe it -- so there is
    // no way to reserve a scratch register for the address computation
    // inside that block. Doing the arithmetic in ordinary Rust first and
    // passing the final value in as a normal `in(reg)` operand sidesteps
    // the restriction entirely.
    let stack_top =
        unsafe { core::ptr::addr_of!(EL0_STACK.0).cast::<u8>().add(EL0_STACK_SIZE) as u64 };
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

/// `SYS_WRITE`/`SYS_RIL_ACCESS` -- must match `svc.rs`'s dispatch table
/// exactly; duplicated here (not shared via a `const` module both sides
/// import) for the same reason `grid-sandbox-host/src/main.rs` duplicates
/// the x86_64 syscall ABI numbers instead of sharing them with
/// `kernel/src/syscall.rs`: this is a standalone-linked EL0 binary in
/// spirit (even though it's compiled into the same image today), and only
/// the syscall *ABI* connects the two sides, not shared Rust items.
const SYS_WRITE: u64 = 1;
const SYS_RIL_ACCESS: u64 = 2;

/// The EL0 demo itself. `.balign 4096` for the same reason
/// `userspace::user_hello` does: keeping it on its own page matters once
/// EL0 permissions become page-granular instead of the whole 1 GiB block
/// (see `mmu.rs`'s `AP_EL0_RW` doc comment) -- not load-bearing today,
/// but the right habit to already be in.
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
        // SYS_RIL_ACCESS(0) -- a channel this context holds a capability
        // for (see ril_capability::issue_and_set_current's caller in
        // nonsecure.rs). x0 on return: 0 = authorized, nonzero = denied.
        "mov x0, {sys_ril}",
        "mov x1, #0",
        "svc #0",
        // SYS_RIL_ACCESS(99) -- a channel with no matching capability.
        "mov x0, {sys_ril}",
        "mov x1, #99",
        "svc #0",
        "1:",
        "wfe",
        "b 1b",
        sys_write = const SYS_WRITE,
        sys_ril = const SYS_RIL_ACCESS,
    );
}
