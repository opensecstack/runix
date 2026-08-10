//! Physical/virtual memory management: access to the active page table, and
//! a frame allocator built from the bootloader's memory map.

use alloc::vec::Vec;
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// Stashed by `init` — `process.rs` needs this later to view *other*
/// physical frames (freshly allocated page tables for a new address space,
/// not just the currently-active one) as `&mut PageTable`, the same trick
/// `active_level_4_table` below uses for the boot-time table. Zero until
/// `init` runs; nothing reads it before then.
static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

/// # Safety
/// `physical_memory_offset` must be the virtual address at which the
/// bootloader mapped the entirety of physical memory (see `main.rs`'s
/// `BootloaderConfig`, which sets `mappings.physical_memory =
/// Some(Mapping::Dynamic)` to make that mapping exist at all), and this must
/// only be called once — it hands out a `&'static mut` to the live page
/// table.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::Relaxed);
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}

/// The offset stashed by `init`. Panics (reads back `0`, then every
/// physical-memory-offset access built on it will fault) if called before
/// `init` — same "must run first" contract every other function in this
/// module already has.
pub fn physical_memory_offset() -> VirtAddr {
    VirtAddr::new(PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed))
}

/// The kernel's own boot-time top-level page table frame, captured once by
/// [`install`] — before anything has ever built a `process::AddressSpace`,
/// so this is guaranteed to be the *original* shared kernel table, not
/// whichever table happened to be active whenever this was first called.
/// `scheduler.rs` needs this to know what to switch `Cr3` back to when
/// scheduling a plain kernel thread (one with no `process::AddressSpace`
/// of its own) after having run a thread that had one.
static KERNEL_P4_FRAME: Mutex<Option<PhysFrame>> = Mutex::new(None);

/// Panics if [`install`] hasn't run yet — same "must run first" contract
/// every other function in this module already has.
pub fn kernel_p4_frame() -> PhysFrame {
    KERNEL_P4_FRAME
        .lock()
        .expect("memory::install() not called yet")
}

/// Views an arbitrary physical frame as a page table, via the same
/// "physical memory is fully mapped at a known offset" trick
/// `active_level_4_table` uses for the *currently active* table — this is
/// the general form, for building a brand-new address space's page table
/// (see `process::AddressSpace::new`) before it's ever loaded into `Cr3`.
///
/// # Safety
/// `frame` must be backed by real, currently-mapped physical memory (true
/// for any frame handed out by [`BootInfoFrameAllocator`]), and the caller
/// is responsible for `frame` actually holding page-table-shaped content by
/// the time anything reads it as one — a freshly allocated frame's content
/// is whatever physical memory happened to contain, not zeroed.
pub unsafe fn frame_as_page_table(frame: PhysFrame) -> &'static mut PageTable {
    let virt = physical_memory_offset() + frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

/// # Safety
/// Same requirement as `init`: `physical_memory_offset` must be accurate,
/// and this must only be called once.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    unsafe { &mut *page_table_ptr }
}

/// Bump allocator over the bootloader's `Usable` memory regions, with a
/// free-list on top so frames handed back via [`FrameDeallocator`] actually
/// get reused instead of the physical-memory pool only ever growing. Until
/// this existed, every mapped page (thread stacks in particular — see
/// `scheduler::exit_current_thread`) was permanently lost the moment
/// whatever mapped it stopped needing it; nothing here ever ran long enough
/// for that to matter until threads could actually exit.
pub struct BootInfoFrameAllocator {
    memory_regions: &'static MemoryRegions,
    next: usize,
    /// LIFO on purpose: reusing the most recently freed frame first (rather
    /// than FIFO/sorted) is the simplest possible free-list and needs no
    /// extra bookkeeping — good enough for "reuse what's freed" without
    /// pretending to be a real buddy/slab allocator.
    freed: Vec<PhysFrame>,
}

impl BootInfoFrameAllocator {
    /// # Safety
    /// `memory_regions` must be a valid, accurate description of usable
    /// physical memory, as handed to us by the bootloader.
    pub unsafe fn init(memory_regions: &'static MemoryRegions) -> Self {
        BootInfoFrameAllocator {
            memory_regions,
            next: 0,
            freed: Vec::new(),
        }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.memory_regions
            .iter()
            .filter(|region| region.kind == MemoryRegionKind::Usable)
            .flat_map(|region| (region.start..region.end).step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.freed.pop() {
            return Some(frame);
        }
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

impl FrameDeallocator<Size4KiB> for BootInfoFrameAllocator {
    /// # Safety
    /// `frame` must have come from this allocator's [`allocate_frame`] and
    /// must no longer be mapped anywhere (the caller must have already
    /// unmapped every page pointing at it) — handing back a frame that's
    /// still live in some page table would let a future `allocate_frame`
    /// call hand the *same* physical memory out twice, simultaneously.
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame) {
        self.freed.push(frame);
    }
}

static MAPPER_AND_FRAME_ALLOCATOR: Mutex<
    Option<(OffsetPageTable<'static>, BootInfoFrameAllocator)>,
> = Mutex::new(None);

/// Hands the live mapper and frame allocator over to a single global slot
/// every module that needs to map memory after boot reaches through
/// [`with_mapper_and_frame_allocator`] — `scheduler` (thread-stack guard
/// pages), `userspace` (the ring 3 stack + code-page grant), and
/// `allocator` (the kernel heap) all go through this instead of `main.rs`
/// threading `&mut mapper, &mut frame_allocator` through every call site.
/// There must be exactly one live `BootInfoFrameAllocator` in the kernel —
/// two independent copies could hand out the same physical frame twice.
///
/// # Safety
/// Must only be called once, right after `init`/`BootInfoFrameAllocator::init`
/// produce `mapper`/`frame_allocator`, before anything else tries to map
/// memory.
pub fn install(mapper: OffsetPageTable<'static>, frame_allocator: BootInfoFrameAllocator) {
    let (frame, _) = x86_64::registers::control::Cr3::read();
    *KERNEL_P4_FRAME.lock() = Some(frame);
    *MAPPER_AND_FRAME_ALLOCATOR.lock() = Some((mapper, frame_allocator));
}

/// Runs `f` with mutable access to the installed mapper and frame
/// allocator. Panics if [`install`] hasn't run yet.
pub fn with_mapper_and_frame_allocator<R>(
    f: impl FnOnce(&mut OffsetPageTable<'static>, &mut BootInfoFrameAllocator) -> R,
) -> R {
    let mut guard = MAPPER_AND_FRAME_ALLOCATOR.lock();
    let (mapper, frame_allocator) = guard.as_mut().expect("memory::install() not called yet");
    f(mapper, frame_allocator)
}

/// Finds the physical frame backing `addr` in the kernel's own table — for
/// `process::AddressSpace::map_existing_frame` callers that want to expose
/// an already-compiled kernel code page (a hand-written ring 3 entry
/// point's own `.text`) at a private VA in some other address space,
/// without copying its bytes. `None` if `addr` isn't mapped at all in the
/// kernel's table, or is mapped at a larger page size than 4 KiB (this
/// kernel never maps kernel `.text` any other way, so that's not expected
/// in practice, just not something this function claims to handle).
pub fn translate_kernel_addr(addr: VirtAddr) -> Option<PhysFrame> {
    use x86_64::structures::paging::mapper::{MappedFrame, Translate, TranslateResult};
    with_mapper_and_frame_allocator(|mapper, _frame_allocator| match mapper.translate(addr) {
        TranslateResult::Mapped {
            frame: MappedFrame::Size4KiB(frame),
            ..
        } => Some(frame),
        _ => None,
    })
}
