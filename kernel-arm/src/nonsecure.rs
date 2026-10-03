//! The actual TrustZone boundary: dropping from EL3 (Secure Monitor) to
//! EL1 Non-secure via `eret`. Everything before this module (boot, UART,
//! exception vectors) ran entirely inside the Secure world -- this is the
//! first line separating "trusted, privileged Runix code" from "the
//! eventual Non-secure kernel that RIL/SIM/app code will actually run
//! under," which is the whole reason TrustZone matters for this project's
//! threat model (see the root README's sandbox tiers).
//!
//! Alpha scope: prove the transition itself works -- reach EL1, confirm it
//! via `CurrentEL`, and confirm (as best `EL1` code can) that it landed in
//! the Non-secure world, not just "some EL1." No return path to EL3, no
//! SMC handling for the Non-secure side to call back into Secure Monitor
//! services, no real Non-secure kernel -- this is the drop itself, once.

use crate::serial_println;
use core::arch::naked_asm;

const EL1_STACK_SIZE: usize = 4096 * 16;

#[repr(align(16))]
#[allow(dead_code)]
struct El1Stack([u8; EL1_STACK_SIZE]);

#[unsafe(no_mangle)]
static mut EL1_STACK: El1Stack = El1Stack([0; EL1_STACK_SIZE]);

/// `SCR_EL3` (Secure Configuration Register) bits this sets:
/// - `NS` (bit 0) = 1: the next lower EL runs Non-secure -- this is the
///   actual security-state switch; everything else here is just getting a
///   valid EL1 execution context to land in.
/// - `RW` (bit 10) = 1: EL1 executes in AArch64 state, not AArch32 --
///   Runix has no 32-bit-mode plans (see `vectors.rs`'s doc comment on the
///   AArch32 vector group).
const SCR_EL3_NS: u64 = 1 << 0;
const SCR_EL3_RW: u64 = 1 << 10;

/// `SPSR_EL3` (Saved Program Status Register) value `eret` restores
/// `PSTATE` from: `M[3:0] = 0b0101` selects EL1h (EL1 using its own
/// `SP_EL1`, not borrowing `SP_EL0`) -- matches `SP_EL1` being set
/// explicitly below, not left as whatever `_start` happened to leave it.
/// `DAIF = 1111` (bits 6-9) masks Debug/SError/IRQ/FIQ on entry to EL1:
/// deliberate for this first landing -- EL1 has no exception vector table
/// of its own installed yet (unlike EL3's, see `vectors.rs`), so anything
/// that traps before one exists needs to stay masked rather than fault
/// into nothing.
const SPSR_EL1H_MASKED: u64 = 0b0101 | (0b1111 << 6);

/// Sets up `SCR_EL3`/`SPSR_EL3`/`ELR_EL3`/`SP_EL1` and executes `eret` --
/// the actual EL3 -> EL1 Non-secure drop. Never returns: `eret` is a jump,
/// not a call, and nothing in this crate transitions back to EL3 yet (see
/// this module's doc comment).
///
/// # Safety
/// Must only be called once, from EL3, with EL3's own stack still valid
/// (this function itself still runs at EL3, right up until `eret`) --
/// `el1_entry`'s own stack (`EL1_STACK`) is set up here, not shared with
/// whatever called this.
pub unsafe fn drop_to_el1_nonsecure() -> ! {
    unsafe {
        core::arch::asm!(
            "msr SCR_EL3, {scr}",
            "msr SPSR_EL3, {spsr}",
            "adrp x0, {entry}",
            "add x0, x0, :lo12:{entry}",
            "msr ELR_EL3, x0",
            "adrp x1, {stack}",
            "add x1, x1, :lo12:{stack}",
            "add x1, x1, {stack_size}",
            "msr SP_EL1, x1",
            "eret",
            scr = in(reg) SCR_EL3_NS | SCR_EL3_RW,
            spsr = in(reg) SPSR_EL1H_MASKED,
            entry = sym el1_entry_trampoline,
            stack = sym EL1_STACK,
            stack_size = const EL1_STACK_SIZE,
            options(noreturn),
        );
    }
}

/// `eret`'s actual landing point -- naked because, like `_start`, it's
/// reached with no call stack (a jump, not a call: there's no return
/// address on any stack pointing back to `drop_to_el1_nonsecure`), just an
/// already-valid `SP_EL1` (set by `drop_to_el1_nonsecure` before `eret`).
/// Immediately hands off to a normal Rust function once that's true.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn el1_entry_trampoline() -> ! {
    naked_asm!("b {e}", e = sym el1_entry);
}

fn current_el() -> u8 {
    let current_el: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el);
    }
    ((current_el >> 2) & 0b11) as u8
}

/// Reads `SCR_EL3`... except `SCR_EL3` doesn't exist at EL1 (it's an EL3-only
/// register -- reading it here would itself trap). What EL1 code *can*
/// check is indirect: whether a Secure-only resource behaves as
/// inaccessible/different from EL1. `dumping ELR_EL3`/`SCR_EL3` isn't
/// possible from here by design (that's the isolation working) --
/// reaching this function at `CurrentEL == EL1` immediately after
/// `drop_to_el1_nonsecure` set `SCR_EL3.NS = 1` and `eret`'d is the
/// available proof at Alpha's scope, *when an EL3 phase ran at all*: a
/// real security-state switch happened, evidenced by the mechanism used
/// to get here, not by EL1 re-deriving it after the fact.
///
/// Also reachable a second way, from `main.rs::rust_start::el1_entry_no_el3`:
/// when the platform never had an EL3 to begin with (e.g. QEMU's `-M virt`
/// without `secure=on`, which resets straight to EL1), there is no Secure
/// Monitor phase to run and no `SCR_EL3.NS` switch to make -- see
/// `rust_start`'s own doc comment for why skipping straight to EL1 setup,
/// instead of still trying to run the EL3-only boot phase, is the fix for
/// that path rather than a shortcut around it. Both entry points set
/// `CPACR_EL1.FPEN` and print their own (different) account of *how* EL1
/// was reached before falling into the shared `el1_setup` -- printing
/// "dropped from EL3" here when no EL3 ever ran would be actively false,
/// not just imprecise.
#[unsafe(no_mangle)]
pub extern "C" fn el1_entry() -> ! {
    set_cpacr_fpen();
    serial_println!("Runix ARM kernel: reached EL1 (dropped from EL3, SCR_EL3.NS=1)");
    el1_setup()
}

/// See `el1_entry`'s doc comment -- the no-EL3 counterpart, called directly
/// from `rust_start` rather than via `drop_to_el1_nonsecure`'s `eret`.
pub extern "C" fn el1_entry_no_el3() -> ! {
    set_cpacr_fpen();
    serial_println!(
        "Runix ARM kernel: EL1 entered directly -- no EL3 ever ran, so no \
         security-state switch to report"
    );
    el1_setup()
}

/// `CPACR_EL1.FPEN` (bits [21:20]) traps FP/SIMD access by default at
/// reset -- and compiler-generated code can use NEON registers for things
/// as mundane as a string copy (observed for real: one `serial_println!`
/// call with no format arguments faulted here with `ESR_EL1.EC=0x7`,
/// "FP/SIMD access trapped", while earlier ones with the exact same shape
/// didn't -- the compiler's own memcpy-lowering threshold, not anything
/// this code does deliberately). Set to `0b11` (access permitted from EL0
/// and EL1, uncontrolled) before any other EL1 code runs -- in particular
/// before the very first print, on *either* entry path -- rather than
/// debug this class of trap on a case-by-case basis.
fn set_cpacr_fpen() {
    unsafe {
        core::arch::asm!(
            "mrs x0, CPACR_EL1",
            "orr x0, x0, #0x300000", // FPEN = 0b11 at bits [21:20]
            "msr CPACR_EL1, x0",
            "isb",
            out("x0") _,
        );
    }
}

/// Shared EL1 bring-up, common to both ways of reaching EL1 (see
/// `el1_entry`'s doc comment) -- MMU, heap, capability issuance, and the
/// drop to EL0 don't care how EL1 was reached, only that `CPACR_EL1.FPEN`
/// is already set (both callers do this before calling in).
fn el1_setup() -> ! {
    serial_println!("Runix ARM kernel: CurrentEL = EL{}", current_el());

    // Install EL1's own exception vector table *before* touching the MMU:
    // VBAR_EL1 defaults to 0 at reset, so a fault here before this point
    // (in particular, from a wrong mmu::install page table entry) jumps
    // into whatever raw bytes sit at physical address 0x200, silently --
    // see el1_vectors.rs's doc comment for how that was actually found.
    crate::el1_vectors::install();
    serial_println!("Runix ARM kernel: VBAR_EL1 installed");

    unsafe {
        crate::mmu::install();
    }
    serial_println!("Runix ARM kernel: MMU enabled (SCTLR_EL1.M=1, identity-mapped)");

    // Prove translation is actually active and correct, not just that
    // SCTLR_EL1.M didn't crash on write: `AT S1E1R` asks the MMU hardware
    // itself to translate a VA (UART0's) and report the result in
    // PAR_EL1, the same mechanism a real page-fault handler would use to
    // inspect a faulting address. Reaching this print at all already
    // proves *something* (an identity-map error would instruction-abort
    // into EL1's nonexistent vector table immediately after SCTLR_EL1.M's
    // write, right on the next fetch -- not further down the function
    // like this), but PAR_EL1's F bit and physical-address field
    // independently confirm it.
    let uart_va: u64 = 0x0900_0000;
    let par_el1: u64;
    unsafe {
        core::arch::asm!(
            "at S1E1R, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) uart_va,
            par = out(reg) par_el1,
        );
    }
    let translation_faulted = par_el1 & 1 != 0;
    let translated_pa = par_el1 & 0x000F_FFFF_FFFF_F000;
    serial_println!(
        "Runix ARM kernel: AT S1E1R UART0 VA {:#x} -> PAR_EL1={:#x} (fault={}, PA={:#x})",
        uart_va,
        par_el1,
        translation_faulted,
        translated_pa
    );

    // virtio-mmio device discovery (see `virtio_mmio.rs`): scan the `virt`
    // machine's 32-slot MMIO window for a network device and read its MAC.
    // Needs the MMU's Device block (installed above) but nothing else --
    // no heap, no EL0, no interrupts. Informational only: a missing device
    // is reported, not fatal, since nothing downstream depends on it yet
    // (QEMU only attaches one when `-netdev`/`-device virtio-net-device`
    // are on the command line).
    let scan = crate::virtio_mmio::probe();
    match scan.net {
        Some(dev) => {
            serial_println!(
                "Runix ARM kernel: virtio-mmio net device at slot {}, version {}, vendor {:#x}, \
                 MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                dev.slot,
                dev.version,
                dev.vendor_id,
                dev.mac[0],
                dev.mac[1],
                dev.mac[2],
                dev.mac[3],
                dev.mac[4],
                dev.mac[5],
            );

            // Stage 1 (see `virtio_net.rs` and
            // `docs/BETA_MOBILE_PROGRESS.md` item 2.2): virtqueue
            // bring-up plus one hand-built ARP round trip against
            // QEMU/SLIRP, proving the virtqueue mechanism end to end.
            // Same "informational, not fatal" stance as the discovery
            // above -- nothing downstream of here depends on networking
            // yet, and a kernel that refuses to finish booting because an
            // optional emulated NIC didn't answer would be strictly worse
            // for every other boot path (the no-`-netdev` case included).
            match crate::virtio_net::arp_round_trip(&dev) {
                Ok(reply) => serial_println!(
                    "Runix ARM kernel: virtio-net ARP reply from {}.{}.{}.{}, sender MAC \
                     {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (used_len {}, tx_completed {})",
                    reply.sender_ip[0],
                    reply.sender_ip[1],
                    reply.sender_ip[2],
                    reply.sender_ip[3],
                    reply.sender_mac[0],
                    reply.sender_mac[1],
                    reply.sender_mac[2],
                    reply.sender_mac[3],
                    reply.sender_mac[4],
                    reply.sender_mac[5],
                    reply.used_len,
                    reply.tx_completed,
                ),
                Err(err) => serial_println!("Runix ARM kernel: virtio-net ARP FAILED -- {}", err),
            }
        }
        None => serial_println!(
            "Runix ARM kernel: virtio-mmio no net device found ({} populated slot(s) of 32)",
            scan.populated_slots
        ),
    }

    // Heap: needed from here on -- capability-manager's CapabilityToken
    // uses String/Vec internally. Safe now (not before): the heap range
    // falls inside mmu.rs's Normal block, which is mapped and writable as
    // of the MMU install above.
    unsafe {
        crate::heap::init();
    }
    serial_println!("Runix ARM kernel: heap initialized");

    // Per-process address-space separation (`process.rs`, Stage 5 slice 2 of
    // docs/BETA_MOBILE_PROGRESS.md item 2.4): build two independent
    // `TTBR0_EL1`-rooted table sets, map the same VA privately in each, and
    // prove a real register switch makes that one VA resolve to different
    // physical memory. Runs here because it needs the MMU on (above) and the
    // heap (above) and nothing else -- in particular not EL0, a scheduler,
    // or the ELF loader, none of which exist yet. There is no real caller
    // for the primitive itself at this stage; this is its proof, the same
    // role `kernel/tests/process_isolation.rs` plays on x86_64.
    crate::process::prove_isolation();

    // The ELF loader (`loader.rs` + `load_proof.rs`, Stage 5 slice 3 of
    // docs/BETA_MOBILE_PROGRESS.md item 2.4): load a hand-assembled
    // two-segment AArch64 image into a fresh address space with real
    // per-segment W^X permissions and a zero-filled BSS tail, then read it
    // back through the loaded VAs after a genuine TTBR0_EL1 switch and ask
    // the MMU itself (AT S1E0R/S1E0W) what EL0 may do with each page.
    // Directly after the isolation proof because it needs exactly the same
    // prerequisites -- the MMU and the heap -- and nothing is executed:
    // there is no EL0 drop of a loaded image yet (combining the loader with
    // the scheduler below is the next step after this slice).
    crate::load_proof::prove_load();

    // The cooperative scheduler (`scheduler.rs`, Stage 5 slice 5 of
    // docs/BETA_MOBILE_PROGRESS.md item 2.4): spawn three EL1 kernel
    // threads that each print and record three tagged rounds, yielding
    // between them, and assert the *observed* order actually interleaved
    // (A0,B0,C0,A1,...) rather than running each thread to completion --
    // the property that proves register/stack context switching, not just
    // that spawning several things didn't crash. Same placement reasoning
    // as the two proofs above: it needs the heap (thread stacks) and
    // nothing else -- no EL0, no address space, no syscalls. Returns
    // normally with the proof threads parked in the run queue; nothing
    // below here yields, so they never run again (no thread exit in this
    // slice, by design).
    crate::scheduler::prove_scheduling();

    // The first real EL0 process (`el0_proof.rs`, the "combining slices
    // 3-5" step of docs/BETA_MOBILE_PROGRESS.md item 2.4): build an
    // address space, load a hand-assembled image into it with loader.rs,
    // spawn a *scheduled* thread that owns that space, and have the
    // scheduler install its TTBR0_EL1 as it resumes it -- then `eret` into
    // the loaded entry point, read and write through the process's own
    // private mappings at EL0, and come back to EL1 through one
    // purpose-built syscall. Must come after prove_scheduling (it needs the
    // run queue that `init`s there) and after the heap and MMU like every
    // proof above; the verdict is checked against hardware state (SPSR_EL1,
    // ELR_EL1, TTBR0_EL1, AT S1E0R), not this code's bookkeeping.
    crate::el0_proof::prove_el0_process();

    // Issue demo capabilities authorizing RIL channel 0 and SIM slot 0
    // (plus, below, slot 0's profile 0 and its separate delete scope) --
    // stands in for a real issuer (CITADEL MARSHAL) the same way every
    // other demo trust root in this repo does. el0_demo (el0.rs) will
    // request channel/slot 0 (authorized) and channel/slot 99 (not, for
    // both resource kinds) to prove svc.rs's capability check actually
    // distinguishes the two -- uniformly across RIL and SIM, not just
    // within RIL (see `capabilities.rs`'s doc comment on why it holds a
    // *set* of tokens now, not a single one).
    let now = crate::svc::now_ticks();
    crate::capabilities::issue_and_hold(crate::capabilities::ril_resource(0), now);
    serial_println!("Runix ARM kernel: RIL capability issued (channel 0, demo trust root)");
    crate::capabilities::issue_and_hold(crate::capabilities::sim_resource(0), now);
    serial_println!("Runix ARM kernel: SIM capability issued (slot 0, demo trust root)");
    // The eSIM lifecycle needs two *more* resources beyond slot 0, because
    // `svc.rs` scopes its SIM syscalls three ways, not one (see its doc
    // comment): slot-level `sim:0` authorizes only SYS_SIM_CREATE, the
    // per-profile `sim:0:0` authorizes install/enable/disable/status on the
    // profile that CREATE produces, and the delete-specific `sim:delete:0:0`
    // authorizes SYS_SIM_DELETE and nothing else. Issuing all three here --
    // rather than one broad token -- is what makes el0_demo's walk a real
    // test of that scoping instead of a test of a single ambient grant.
    //
    // Profile 0 specifically: `sim::create` assigns IDs sequentially from
    // 0, and el0_demo's CREATE is the first one in slot 0, so the ID it
    // gets back is 0. Issuing for profile 0 before it exists is fine -- a
    // capability names a resource string, not a live object.
    crate::capabilities::issue_and_hold(crate::capabilities::sim_profile_resource(0, 0), now);
    serial_println!(
        "Runix ARM kernel: eSIM profile capability issued (slot 0 profile 0, demo trust root)"
    );
    crate::capabilities::issue_and_hold(crate::capabilities::sim_delete_resource(0, 0), now);
    serial_println!(
        "Runix ARM kernel: eSIM delete capability issued (slot 0 profile 0, demo trust root)"
    );
    // The general-purpose IPC channel space (`ipc_channel.rs`) is addressed
    // separately from RIL's, so it needs its own grant -- an `ril:0` token
    // deliberately does not reach `ipc:0`. Same channel 0 / channel 99
    // authorized-vs-not split el0_demo uses for every other resource kind.
    crate::capabilities::issue_and_hold(crate::capabilities::ipc_resource(0), now);
    serial_println!("Runix ARM kernel: IPC capability issued (channel 0, demo trust root)");

    // The RIL isolation boundary and basic SIM provisioning: drop to EL0,
    // capability-gated through the SVC syscall gate (svc.rs) exactly like
    // SYS_IPC_SEND gates capability-checked IPC on the x86_64 side. Never
    // returns -- el0_demo (el0.rs) runs its SVC calls and then spins
    // forever; there is no scheduler here yet to hand control to anything
    // else.
    unsafe {
        crate::el0::drop_to_el0(crate::el0::el0_demo as *const () as u64);
    }
}
