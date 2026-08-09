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

/// Incremented on every timer IRQ. The base a preemptive scheduler (next
/// phase) will tick against — nothing schedules off it yet.
static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Cooperative-scheduler watchdog: **detection, not preemption.** There's
/// no timer-interrupt-driven context switch yet (see `scheduler.rs`'s
/// module doc comment) — a thread that never calls `yield_now()` still
/// can't be forcibly interrupted and moved aside. What this *does* do is
/// turn "the whole kernel silently hangs forever" into a loud, immediate,
/// diagnosable panic instead — the same "detect deterministically instead
/// of silently misbehaving" trade guard pages made for stack overflows
/// (see the top-level README). Not a substitute for real preemption, which
/// is what T1 Critical's <300ms MARSHAL real-time constraint (see README's
/// "Sandbox tiers") actually needs — this only guarantees a hang is *found*
/// quickly, not that the system keeps making progress through one.
///
/// Lock-free by necessity: this is checked from `timer_interrupt_handler`,
/// which can fire while any code — including code already holding
/// `scheduler::SCHEDULER`'s lock, mid-`yield_now()` — is running. Taking
/// that same lock here would deadlock the CPU against itself the moment an
/// interrupt landed inside its own critical section. Plain atomics avoid
/// that entirely, at the cost of not being able to inspect the run queue
/// (so this can't tell *which* thread is stuck, only that *something* has
/// gone too long without any thread cooperating).
static LAST_YIELD_TICK: AtomicU64 = AtomicU64::new(0);

/// Off until `scheduler::init()` arms it, and deliberately turned back off
/// before a ring 3 handoff (see `userspace::enter_usermode`'s call site in
/// `main.rs`) — ring 3 code doesn't call `yield_now()` at all yet (see
/// `userspace.rs`'s doc comment on why `SYS_YIELD` is meaningless there
/// today), so leaving the watchdog armed across that handoff would
/// eventually panic on perfectly intended behavior, not a real hang.
static WATCHDOG_ARMED: AtomicBool = AtomicBool::new(false);

/// ~20 PIT ticks at the default (unreprogrammed) ~18.2 Hz rate this kernel
/// runs at — a little over a second. Long enough that the demo's own
/// yield-every-iteration threads never come close to tripping it, short
/// enough that a genuinely stuck thread is caught well within a human
/// noticing something's wrong, let alone a CI run timing out.
const WATCHDOG_THRESHOLD_TICKS: u64 = 20;

/// Called from `scheduler::yield_now()` on every call, whether or not it
/// actually switches to another thread — a system with only one runnable
/// thread that keeps calling `yield_now()` in its own loop is still
/// cooperating, even though no context switch happens.
pub fn record_yield() {
    LAST_YIELD_TICK.store(ticks(), Ordering::Relaxed);
}

pub fn arm_watchdog() {
    record_yield();
    WATCHDOG_ARMED.store(true, Ordering::Relaxed);
}

pub fn disarm_watchdog() {
    WATCHDOG_ARMED.store(false, Ordering::Relaxed);
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
        idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
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

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
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
            "scheduler watchdog: no thread called yield_now() for over {} ticks — \
             something is stuck without cooperating",
            WATCHDOG_THRESHOLD_TICKS
        );
    }
}
