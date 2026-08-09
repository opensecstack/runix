//! Kernel heap: a fixed virtual range, page-mapped on boot, backed by
//! `linked_list_allocator` so `alloc::{Vec, Box, String, ...}` work inside
//! the kernel.

use linked_list_allocator::LockedHeap;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0x_4444_4444_0000;
// Was 100 KiB (fine when nothing but the Phase 3 smoke test used the heap).
// Each scheduler thread's stack alone is 16 KiB (`scheduler::STACK_SIZE`),
// and `main.rs`'s demo now spawns 7 of them (112 KiB) on top of capability
// token issuance/verification's own allocations — hit this for real: a
// `memory allocation of 16384 bytes failed` panic (exactly one thread
// stack) once the demo grew past what 100 KiB could hold. 1 MiB has
// headroom for the current demo plus a fair bit of future growth; there's
// no principled sizing here yet, just "enough, with room to spare."
pub const HEAP_SIZE: usize = 1024 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}
