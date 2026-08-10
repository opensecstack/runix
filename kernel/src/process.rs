//! Per-process address spaces: a real, hardware-enforced privacy boundary
//! between processes, not just per-thread stacks within one shared page
//! table (`scheduler.rs`). This is the shared prerequisite both
//! `wasm-runtime` rehosting and the network stack's ring 3 driver are
//! blocked on — see the top-level README's network-stack section and the
//! "no per-process address space" gap in the threat model.
//!
//! Deliberately scoped narrow for this first slice: building and switching
//! into a real, isolated address space, proven by writing distinct data
//! into two processes' private pages at the *same* virtual address and
//! reading back the right one depending on which `Cr3` is loaded
//! (`kernel/tests/process_isolation.rs`). Not yet an ELF loader, and not
//! yet ring 3 execution inside one of these — that needs ring 3 threads to
//! get their own kernel-entry stack so they can `SYS_YIELD` back into the
//! scheduler cooperatively, which `userspace.rs` already flags as future
//! work. Running real code inside one of these address spaces is the next
//! slice, not this one.

use crate::memory;
use alloc::collections::BTreeSet;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::mapper::{Translate, TranslateResult};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::VirtAddr;

/// A private top-level page table (PML4) — the actual unit of isolation on
/// x86_64: everything reachable from a given `Cr3` value is exactly what a
/// process (or the kernel) can address, nothing more.
pub struct AddressSpace {
    p4_frame: PhysFrame,
    /// Which top-level (P4) slots have already been detached from whatever
    /// this space was seeded from — see [`map_private_page`]'s doc comment
    /// for why this has to be tracked instead of re-detaching on every
    /// call: one P4 slot spans 512 GiB, so a single loaded binary's several
    /// segments (see the ELF loader) very likely share one slot, and
    /// re-clearing it on a later call would silently erase whatever an
    /// earlier call in that same slot already built.
    detached_p4_slots: BTreeSet<u16>,
}

impl AddressSpace {
    /// Builds a new, independent address space seeded from whichever table
    /// is *currently* active (almost always the kernel's own boot-time
    /// table) — every top-level entry is copied, not linked, so mutating
    /// this space's table can never reach back and mutate the original.
    /// Kernel-space mappings (code, heap, the physical-memory-offset
    /// mapping) stay reachable this way — critical, since the CPU has to
    /// keep fetching *kernel* instructions immediately after a `Cr3`
    /// switch into this space, and interrupt/syscall handling needs the
    /// kernel's own data structures reachable no matter which address
    /// space is current.
    ///
    /// Copying the top-level entries means this space's kernel-space
    /// sub-tables (P3/P2/P1) are *physically shared* with the table it was
    /// seeded from, not deep-copied — intentional: kernel mappings are
    /// meant to be identical everywhere, and deep-copying every level down
    /// to 4 KiB leaves would be enormous overhead for no benefit. Only the
    /// specific top-level slots a caller later touches via
    /// [`map_private_page`] ever become privately owned.
    ///
    /// That sharing is by *pointer* (the P4 entry, copied verbatim, still
    /// points at the exact same P3 frame the source table uses) — it only
    /// works for a slot that already has a P3 table to point at when this
    /// runs. A P4 slot that's still empty at copy time copies as "not
    /// present," full stop; anything mapped into that same slot in the
    /// source table *afterward* is invisible here, because there was
    /// nothing yet to share a pointer to. If this `AddressSpace` will ever
    /// run as a `scheduler`-managed thread (`scheduler::spawn_with_address_space`),
    /// call `scheduler::init()` first — it reserves the thread-stack
    /// region's P4 slot up front specifically so this can't bite a thread
    /// trying to run on its own, not-yet-existing-at-copy-time stack. See
    /// `kernel/tests/scheduler_address_space.rs` for the double fault this
    /// caused before that reservation existed.
    pub fn new() -> Self {
        let (active_frame, _) = Cr3::read();
        memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            let p4_frame = frame_allocator
                .allocate_frame()
                .expect("out of physical memory for a new address space");
            let active_table = unsafe { memory::frame_as_page_table(active_frame) };
            let new_table = unsafe { memory::frame_as_page_table(p4_frame) };
            new_table.clone_from(active_table);
            AddressSpace {
                p4_frame,
                detached_p4_slots: BTreeSet::new(),
            }
        })
    }

    /// Maps a fresh, private page at `page` with `flags` — *within this
    /// address space only*. The first time a given P4 slot is touched (see
    /// `detached_p4_slots`), and only the first time, that slot's copied
    /// top-level entry is cleared before mapping: kernel space very likely
    /// already has something there, and detaching it means the new
    /// mapping's P3/P2/P1 chain is built fresh and privately owned by
    /// *this* address space, never touching whatever the table this space
    /// was seeded from still points at for that slot. A later call into
    /// the *same* slot (e.g. a second segment of the same loaded binary,
    /// almost certain — one P4 slot spans 512 GiB) must **not** repeat
    /// that clear, or it would silently erase the mapping the earlier call
    /// in that slot just built.
    ///
    /// Returns a `&'static mut` into the new page's content, reachable
    /// *right now* through the physical-memory-offset mapping regardless
    /// of which `Cr3` is currently loaded and regardless of whether `flags`
    /// includes `WRITABLE` — callers (e.g. the ELF loader, writing a
    /// read-only segment's initial content) don't need to [`activate`]
    /// this address space, and aren't bound by the process-facing
    /// permissions they just asked for.
    pub fn map_private_page(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> &'static mut [u8; 4096] {
        let frame = memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            frame_allocator
                .allocate_frame()
                .expect("out of physical memory for a new process-private page")
        });
        self.map_frame(page, frame, flags);
        let virt = memory::physical_memory_offset() + frame.start_address().as_u64();
        unsafe { &mut *virt.as_mut_ptr::<[u8; 4096]>() }
    }

    /// Maps an *already-existing* physical frame at `page` within this
    /// address space, instead of allocating a fresh one — for exposing a
    /// kernel-compiled code page (a hand-written ring 3 entry point's own
    /// `.text`, found via `memory::translate_kernel_addr`) as
    /// user-accessible at a private VA, without copying its bytes. Same
    /// "detach the P4 slot once" logic as [`map_private_page`] — see its
    /// doc comment.
    ///
    /// # Safety
    /// `frame` must be backed by real, currently-valid physical memory for
    /// as long as this mapping exists — true for any frame still owned by
    /// whatever mapped it originally (e.g. the kernel's own `.text`, which
    /// is never freed), but this function has no way to verify that at the
    /// call site.
    pub unsafe fn map_existing_frame(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame,
        flags: PageTableFlags,
    ) {
        self.map_frame(page, frame, flags);
    }

    fn map_frame(&mut self, page: Page<Size4KiB>, frame: PhysFrame, flags: PageTableFlags) {
        memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            let index = u16::from(page.p4_index());
            if self.detached_p4_slots.insert(index) {
                let table = unsafe { memory::frame_as_page_table(self.p4_frame) };
                table[page.p4_index()].set_unused();
            }

            let level_4_table = unsafe { memory::frame_as_page_table(self.p4_frame) };
            let mut this_mapper =
                unsafe { OffsetPageTable::new(level_4_table, memory::physical_memory_offset()) };

            unsafe {
                this_mapper
                    .map_to(page, frame, flags, frame_allocator)
                    .expect("failed to map a page")
                    .flush();
            }
        });
    }

    /// This address space's top-level frame, for callers (`scheduler.rs`)
    /// that need to *compare* it against whatever's currently loaded before
    /// deciding whether a `Cr3` write (and the TLB flush that comes with
    /// it) is actually necessary — [`activate`](Self::activate) itself
    /// always writes unconditionally, which is fine for a one-off switch
    /// but wasteful on `yield_now`'s hot path if most switches are between
    /// threads that don't have an address space of their own at all.
    pub fn p4_frame(&self) -> PhysFrame {
        self.p4_frame
    }

    /// Loads this address space's table into `Cr3`, returning whatever was
    /// active before (frame *and* flags, as a pair — not just the frame) —
    /// the caller is responsible for eventually restoring it via
    /// [`restore`]. Returning the pair matters even though this kernel
    /// never sets a non-zero `Cr3Flags` (no PCID) today: restoring a bare
    /// frame with whatever flags happen to be active *at restore time*
    /// (rather than the ones that were actually paired with that frame)
    /// would be silently wrong the moment that stops being true.
    ///
    /// # Safety
    /// Same contract `Cr3::write` itself carries: the code and stack
    /// currently executing, and anything an interrupt handler might need,
    /// must remain correctly mapped in the *new* table. True here for
    /// kernel space, since [`new`](Self::new) always seeds from a
    /// currently-active table's kernel-space entries — but this type has
    /// no way to verify that at the call site, so the caller is trusted.
    pub unsafe fn activate(&self) -> (PhysFrame, Cr3Flags) {
        let previous = Cr3::read();
        unsafe {
            Cr3::write(self.p4_frame, previous.1);
        }
        previous
    }

    /// Looks up what (if anything) is mapped at `addr` within this address
    /// space, without needing to [`activate`] it first — a debugging/
    /// testing aid (see `kernel/tests/elf_loader.rs`, which uses this to
    /// verify the ELF loader translated each segment's real permissions
    /// instead of just checking content landed in the right place) built
    /// directly on the `x86_64` crate's own `Translate` trait, not custom
    /// table-walking logic.
    pub fn translate(&self, addr: VirtAddr) -> TranslateResult {
        let level_4_table = unsafe { memory::frame_as_page_table(self.p4_frame) };
        let mapper =
            unsafe { OffsetPageTable::new(level_4_table, memory::physical_memory_offset()) };
        mapper.translate(addr)
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Restores a previously active table, saved from an earlier
/// [`AddressSpace::activate`] call — takes the exact `(frame, flags)` pair
/// `activate` returned, not just a frame, so the flags that actually
/// belonged to that table are what come back, not whatever flags happen to
/// be active right now. A free function, not a method on `AddressSpace`,
/// since the frame being restored isn't necessarily this (or any)
/// `AddressSpace` instance's own — it's usually the kernel's original
/// boot-time table.
///
/// # Safety
/// Same contract as [`AddressSpace::activate`].
pub unsafe fn restore((frame, flags): (PhysFrame, Cr3Flags)) {
    unsafe {
        Cr3::write(frame, flags);
    }
}
