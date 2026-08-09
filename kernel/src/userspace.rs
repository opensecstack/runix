//! Ring 0 -> ring 3 transition: the kernel's first (and so far only)
//! user-space process. Just enough to prove the boundary actually works —
//! a real code page the CPU will fetch from at CPL 3, a real stack it runs
//! on, and the syscall gate (`int 0x80`, see `syscall.rs`) as the only way
//! back into the kernel. This is the threshold where a Capability Manager
//! starts to matter: there's finally something outside the kernel that
//! needs permission to do anything.

use crate::gdt;
use core::arch::naked_asm;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

pub const USER_STACK_START: usize = 0x_5555_5555_0000;
pub const USER_STACK_SIZE: usize = 4096 * 4;

/// Maps a fresh, user-accessible stack and returns its top address.
///
/// This is a brand new mapping, so `Mapper::map_to`'s parent-table flags
/// (derived from the leaf `flags` passed here) propagate `USER_ACCESSIBLE`
/// to every page-table level it creates along the way — unlike
/// `allow_user_access` below, which has to fix up an *existing* (already
/// kernel-only) mapping's ancestor entries by hand.
pub fn map_user_stack(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    let stack_start = VirtAddr::new(USER_STACK_START as u64);
    let stack_end = stack_start + USER_STACK_SIZE as u64 - 1u64;
    let start_page = Page::containing_address(stack_start);
    let end_page = Page::containing_address(stack_end);

    let flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    for page in Page::range_inclusive(start_page, end_page) {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    Ok(stack_start + USER_STACK_SIZE as u64)
}

/// Grants ring 3 access to the (already kernel-mapped) page containing
/// `addr`, by marking every level of its page-table ancestry
/// user-accessible. `update_flags`/`set_flags_p{4,3,2}_entry` each touch
/// exactly one level — the P4/P3/P2 entries here pre-date this call (the
/// bootloader created them for kernel-only use), so `map_to`'s
/// flag-propagation trick doesn't apply retroactively; each level needs
/// fixing up explicitly.
///
/// # Safety
/// `addr` must be a valid, currently-mapped kernel code address whose
/// containing 4 KiB page is safe to expose to ring 3 — i.e. it contains
/// nothing but the user-mode entry point itself, not arbitrary kernel code
/// or data that would leak into an unprivileged address space.
pub unsafe fn allow_user_access(mapper: &mut impl Mapper<Size4KiB>, addr: VirtAddr) {
    let page = Page::<Size4KiB>::containing_address(addr);
    let parent_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    unsafe {
        mapper
            .set_flags_p4_entry(page, parent_flags)
            .expect("p4 entry for user code page")
            .flush_all();
        mapper
            .set_flags_p3_entry(page, parent_flags)
            .expect("p3 entry for user code page")
            .flush_all();
        mapper
            .set_flags_p2_entry(page, parent_flags)
            .expect("p2 entry for user code page")
            .flush_all();
        // Leaf entry: present + user-accessible, deliberately dropping
        // WRITABLE (it's code) and leaving NO_EXECUTE unset (it must stay
        // executable).
        mapper
            .update_flags(
                page,
                PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            )
            .expect("leaf entry for user code page")
            .flush();
    }
}

/// Builds the `iretq` frame that drops the CPU from ring 0 to ring 3 and
/// jumps to `entry` running on `stack_top`. There's no return path —
/// unlike a syscall, nothing "called" user code, so nothing is waiting for
/// it back. Meant to be the last thing the boot thread ever does.
///
/// # Safety
/// `entry` must point at code whose containing page is already ring
/// 3-accessible (see `allow_user_access`) and self-contained enough to run
/// correctly there — no calls into normal kernel code, which stays
/// supervisor-only. `stack_top` must be the top of a mapped, writable,
/// user-accessible stack (see `map_user_stack`).
pub unsafe fn enter_usermode(entry: VirtAddr, stack_top: VirtAddr) -> ! {
    let (code_selector, data_selector) = gdt::user_selectors();
    unsafe {
        core::arch::asm!(
            // Reload the data segment registers now, while still at CPL 0
            // — loading a selector only requires max(CPL, RPL) <= DPL, and
            // 0/3/3 satisfies that same as 3/3/3 would after the jump. SS
            // isn't reloaded here; `iretq` pops it (and RSP) together as
            // part of the ring change itself.
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov fs, {data_sel:x}",
            "mov gs, {data_sel:x}",
            "push {data_sel}",
            "push {stack_top}",
            "push {rflags}",
            "push {code_sel}",
            "push {entry}",
            "iretq",
            data_sel = in(reg) u64::from(data_selector.0),
            code_sel = in(reg) u64::from(code_selector.0),
            stack_top = in(reg) stack_top.as_u64(),
            entry = in(reg) entry.as_u64(),
            rflags = in(reg) 0x202u64, // bit 1 reserved-as-1, bit 9 = IF (keep interrupts enabled)
            options(noreturn),
        );
    }
}

/// The kernel's first user-space code. Hand-written in asm, not normal
/// Rust, for two reasons: it must live on its own 4 KiB page (`.balign
/// 4096`, so `allow_user_access` can grant ring 3 access to *only* this
/// code, nothing else in the kernel's `.text`), and it can't call into any
/// other kernel function — those live on supervisor-only pages a ring 3
/// `call`/`jmp` can't reach.
///
/// Prints "USR\n" one byte at a time through [`crate::syscall::SYS_WRITE`]
/// (proving the syscall gate accepts a genuine CPL 3 caller — see the DPL
/// fix in `interrupts.rs`), then spins forever. Deliberately *not*
/// `SYS_YIELD`: that reaches `scheduler::yield_now()`, which saves and
/// restores a per-thread stack pointer — meaningless here, since a ring 3
/// trap back into the kernel always runs on the single shared
/// `TSS.privilege_stack_table[0]` stack, not a stack the scheduler is
/// tracking for this "thread". Giving ring 3 threads their own
/// kernel-entry stack (so they can cooperate with the scheduler like any
/// other thread) is future work, once there's more than one of them.
///
/// # Safety
/// Never call this directly — it's only ever reached by jumping the CPU to
/// it via `enter_usermode`, from a page already made ring 3-accessible by
/// `allow_user_access`. Calling it as a normal Rust function would run its
/// raw asm body (including the leading `.balign 4096` padding) in the
/// current, wrong context.
#[unsafe(naked)]
pub unsafe extern "C" fn user_hello() -> ! {
    naked_asm!(
        ".balign 4096",
        "mov eax, 1",  // SYS_WRITE
        "mov edi, 85", // 'U'
        "int 0x80",
        "mov eax, 1",
        "mov edi, 83", // 'S'
        "int 0x80",
        "mov eax, 1",
        "mov edi, 82", // 'R'
        "int 0x80",
        "mov eax, 1",
        "mov edi, 10", // '\n'
        "int 0x80",
        "2:",
        "jmp 2b",
    );
}
