//! Interrupt Descriptor Table + exception handlers + hardware IRQs (PIC).

use crate::{gdt, serial_println};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

/// The 8259 PIC's default vectors (0-15) collide with CPU exceptions, so
/// remap them past the last exception vector (31) — standard practice, see
/// https://wiki.osdev.org/8259_PIC.
const PIC_1_OFFSET: u8 = 32;
const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum InterruptIndex {
    Timer = PIC_1_OFFSET,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Incremented on every timer IRQ — also every real preemption tick, see
/// `on_timer_tick`.
static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// **Backstop, not the primary defense anymore.** Used to be the *only*
/// thing standing between a thread that never calls `yield_now()` and the
/// whole kernel silently hanging forever — see `scheduler.rs`'s module doc
/// comment for the real fix now in place: every timer tick forces a
/// reschedule regardless of what's running, so a thread that never
/// cooperates no longer blocks anything (T1 Critical's <300ms MARSHAL
/// real-time constraint — see README's "Sandbox tiers" — needed exactly
/// this, not just faster detection). What this still catches: `reschedule`
/// itself panicking, hanging, or somehow never getting called at all (a
/// bug in the mechanism, not in a thread using it) — genuinely different
/// failure classes than "a thread forgot to yield," which preemption now
/// makes irrelevant on its own. `kernel/tests/watchdog.rs` was rewritten
/// to prove *that* — real recovery, not just detection — once this landed.
///
/// Lock-free by necessity: this is checked from `on_timer_tick`, which
/// fires with `RFLAGS.IF=0` (an interrupt gate) — nothing else can be
/// mid-`SCHEDULER.lock()` while this runs, so a plain atomic isn't required
/// for *that* reason anymore, but stays lock-free anyway: reading it here
/// must never itself be what causes a hang this is supposed to catch.
static LAST_YIELD_TICK: AtomicU64 = AtomicU64::new(0);

/// Off until `scheduler::init()` arms it — stays armed permanently after
/// that now (nothing disarms it anymore). Safe to leave on across a ring 3
/// handoff, unlike before real preemption existed: back when `user_hello`
/// was entered via a raw `userspace::enter_usermode` call invisible to the
/// scheduler, its intentional forever-spin (never calling `yield_now()`)
/// would eventually trip this watchdog on perfectly intended behavior, so
/// `main.rs` disarmed it first. Now `user_hello` runs as a real, preemptible
/// scheduler thread (`scheduler::spawn_ring3_shared`) — the timer keeps
/// forcing a `reschedule` every tick regardless of whether it cooperates,
/// which is exactly what keeps [`LAST_YIELD_TICK`] moving and this watchdog
/// quiet.
static WATCHDOG_ARMED: AtomicBool = AtomicBool::new(false);

/// ~20 PIT ticks at the default (unreprogrammed) ~18.2 Hz rate this kernel
/// runs at — a little over a second. Long enough that the demo's own
/// yield-every-iteration threads never come close to tripping it, short
/// enough that a genuinely stuck thread is caught well within a human
/// noticing something's wrong, let alone a CI run timing out.
const WATCHDOG_THRESHOLD_TICKS: u64 = 20;

/// Called from `scheduler::reschedule` on every call, whether triggered by
/// a voluntary `yield_now()` or an involuntary timer tick, and whether or
/// not it actually switches to another thread — any of those is proof the
/// mechanism itself is still alive.
pub fn record_yield() {
    LAST_YIELD_TICK.store(ticks(), Ordering::Relaxed);
}

pub fn arm_watchdog() {
    record_yield();
    WATCHDOG_ARMED.store(true, Ordering::Relaxed);
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        // `timer_entry` is naked, not `extern "x86-interrupt" fn` — it
        // needs to capture the *complete* register state (a
        // `scheduler::TrapFrame`) for real preemption to be able to resume
        // it later, which the typed interrupt-calling-convention ABI
        // doesn't expose. Same raw-address registration `syscall::entry`
        // already uses, below.
        unsafe {
            idt[InterruptIndex::Timer.as_u8()]
                .set_handler_addr(x86_64::VirtAddr::new(timer_entry as *const () as u64))
                .set_present(true);
        }
        // `crate::syscall::entry` is a naked function, not
        // `extern "x86-interrupt" fn` — it doesn't fit `set_handler_fn`'s
        // typed signature, hence the raw-address variant. Software
        // interrupts (like this one) also need `set_present(true)`, which
        // hardware-triggered gates get for free from `set_handler_fn`.
        unsafe {
            idt[crate::syscall::VECTOR]
                .set_handler_addr(x86_64::VirtAddr::new(
                    crate::syscall::entry as *const () as u64,
                ))
                .set_present(true)
                // The `int` instruction checks CPL <= gate DPL — left at
                // the default (Ring0), a ring 3 caller's `int 0x80` would
                // general-protection-fault before ever reaching `entry`.
                // Ring 3 exists from Phase 7 onward, so the gate has to
                // actually admit it.
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }
        // `scheduler::reschedule_entry`, same reasoning as `timer_entry`
        // above (needs a full `TrapFrame`, not the typed ABI) — kernel-only
        // (default Ring0 DPL), unlike `syscall::VECTOR`: every caller,
        // including a ring 3 thread's `SYS_YIELD`, already reaches
        // `scheduler::yield_now()` from inside `syscall::dispatch`, i.e.
        // from ring 0.
        unsafe {
            idt[crate::scheduler::RESCHEDULE_VECTOR]
                .set_handler_addr(x86_64::VirtAddr::new(
                    crate::scheduler::reschedule_entry as *const () as u64,
                ))
                .set_present(true);
        }
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

/// Remaps the PIC and masks every IRQ line except the timer (IRQ0). Only the
/// timer has a handler wired up so far — an unmasked, unhandled IRQ (e.g.
/// keyboard) would hit an IDT entry with no handler and general-protection
/// fault the kernel.
///
/// # Safety
/// Must only be called once, and only after `init_idt()` — hardware
/// interrupts must not be enabled (`sti`) until both the IDT and the PIC
/// remap are in place.
pub unsafe fn init_pics() {
    use x86_64::instructions::port::Port;

    unsafe {
        PICS.lock().initialize();

        let mut master_mask: Port<u8> = Port::new(0x21);
        let mut slave_mask: Port<u8> = Port::new(0xA1);
        master_mask.write(0b1111_1110u8); // unmask IRQ0 (timer) only
        slave_mask.write(0xffu8); // mask every slave-PIC line
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("Accessed Address: {:?}", Cr2::read());
    serial_println!("Error Code: {:?}", error_code);
    serial_println!("{:#?}", stack_frame);
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!(
        "EXCEPTION: GENERAL PROTECTION FAULT, error_code: {}",
        error_code
    );
    serial_println!("{:#?}", stack_frame);
    loop {
        x86_64::instructions::hlt();
    }
}

/// Entry point installed at the timer IRQ vector. Naked, not
/// `extern "x86-interrupt" fn` — see this module's IDT-registration comment
/// on why real preemption needs the *complete* register state
/// (`scheduler::TrapFrame`) a typed interrupt handler doesn't expose.
/// Structurally identical to `scheduler::reschedule_entry` (same GPR
/// push/pop sequence, same final `iretq`) — the only difference is what
/// Rust function each calls in between, which is exactly the point: one
/// mechanism, two triggers.
///
/// # Safety
/// Never call this directly — reached only by the CPU delivering IRQ0
/// (timer), which guarantees a matching hardware-pushed frame already sits
/// on the stack for the final `iretq` to consume.
#[unsafe(naked)]
unsafe extern "C" fn timer_entry() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        // See `scheduler::reschedule_entry`'s identical line for why this
        // is required, not optional: a hardware interrupt (this one) can
        // land with RSP at any alignment, unlike a real `call` site, and
        // `on_timer_tick` is an ordinary Rust function that can't safely
        // assume otherwise. Discarded, not restored, afterward — the very
        // next instruction unconditionally replaces RSP with whichever
        // frame `on_timer_tick` returns.
        "and rsp, -16",
        "call {on_timer_tick}",
        "mov rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        on_timer_tick = sym on_timer_tick,
    );
}

/// The actual preemption tick: EOI, bump `TICKS`, the watchdog backstop
/// check (see its own doc comment on why this is a backstop now, not the
/// primary defense), then hand off to `scheduler::reschedule` — every
/// timer tick forces a reschedule attempt, unconditionally, regardless of
/// what's currently running. `frame` is a complete `TrapFrame` (hardware
/// fields + `timer_entry`'s GPR pushes); the return value is what
/// `timer_entry` resumes from — the same frame unchanged (nothing else was
/// runnable) or a different thread's.
extern "C" fn on_timer_tick(frame: *mut crate::scheduler::TrapFrame) -> *mut crate::scheduler::TrapFrame {
    let now = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }

    // End-of-interrupt is sent *before* this check, not after: a watchdog
    // panic still needs the PIC acknowledged so a debugger/QEMU monitor
    // attached afterward isn't left looking at a wedged interrupt
    // controller on top of the thing that actually paniced.
    if WATCHDOG_ARMED.load(Ordering::Relaxed)
        && now.saturating_sub(LAST_YIELD_TICK.load(Ordering::Relaxed)) > WATCHDOG_THRESHOLD_TICKS
    {
        panic!(
            "scheduler watchdog: no reschedule succeeded for over {} ticks — \
             the preemption mechanism itself is stuck, not just an uncooperative thread",
            WATCHDOG_THRESHOLD_TICKS
        );
    }

    // `boot::init()` enables interrupts well before `main.rs` ever calls
    // `scheduler::init()` — the timer starts ticking immediately, with no
    // scheduler yet to reschedule against. Without this check, the very
    // first tick during that window would hit `reschedule`'s
    // `SCHEDULER.lock().expect(...)` and panic — confirmed for real the
    // first time this shipped (`scheduler::init() not called`, fired
    // during Phase 3, well before Phase 5 ever calls `scheduler::init()`).
    // Resuming the interrupted context unchanged is always correct here:
    // it's exactly what `reschedule` itself does whenever nothing else is
    // runnable, just decided one step earlier.
    if !crate::scheduler::is_initialized() {
        return frame;
    }

    crate::scheduler::reschedule(frame)
}
