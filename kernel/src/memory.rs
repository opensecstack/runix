//! Physical/virtual memory management: access to the active page table, and
//! a frame allocator built from the bootloader's memory map.

use alloc::vec::Vec;
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use spin::Mutex;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// # Safety
/// `physical_memory_offset` must be the virtual address at which the
/// bootloader mapped the entirety of physical memory (see `main.rs`'s
/// `BootloaderConfig`, which sets `mappings.physical_memory =
/// Some(Mapping::Dynamic)` to make that mapping exist at all), and this must
/// only be called once — it hands out a `&'static mut` to the live page
/// table.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
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
