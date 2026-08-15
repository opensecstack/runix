//! A private heap for this crate -- needed now that `capability-manager`
//! (`String`/`Vec` internally) is a real dependency, not because anything
//! before this ever allocated.
//!
//! No new mapping work needed to make this safe: `mmu.rs`'s Normal
//! (`0x4000_0000`-`0x7FFF_FFFF`) block already covers this region as a
//! side effect of being a coarse 1 GiB block rather than fine-grained
//! per-page mappings -- picking any unused address range inside it and
//! calling it "the heap" is enough, unlike `kernel/src/allocator.rs` on
//! the x86_64 side, which has to map each heap page individually because
//! `kernel/`'s paging is 4 KiB-granular from the start.
//!
//! `0x4100_0000` (16 MiB past this crate's own load address,
//! `0x4008_0000` -- see `linker.ld`) is comfortably clear of code, data,
//! `BOOT_STACK`, and `EL1_STACK`, all of which live in the tens-of-KiB
//! range right after the load address.

use linked_list_allocator::LockedHeap;

const HEAP_START: usize = 0x_4100_0000;
const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// # Safety
/// Must run after `mmu::install` (the heap range must be mapped and
/// writable -- true today because it falls inside the Normal block, but
/// this function doesn't check that itself) and must run exactly once.
pub unsafe fn init() {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
}
