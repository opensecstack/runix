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
/// 4 MiB -- grown from the original 256 KiB once `tcp_proof.rs` (Beta
/// mobile item 2.5) needed real headroom: a `net-driver-host-arm` address
/// space alone maps its own private 256 KiB heap, 1 `NetBootInfo` page, two
/// 3-page virtqueue regions, and 12 packet-buffer pages (~332 KiB), *on
/// top of* its loaded ELF segments/stack and this crate's own translation
/// tables for that address space -- comfortably more than 256 KiB once
/// every proof that already ran before it (`process::prove_isolation`,
/// `load_proof::prove_load`, `scheduler::prove_scheduling`,
/// `el0_proof::prove_el0_process`) is accounted for too, none of which
/// ever frees what it allocated (`process.rs` has no `Drop` -- see its own
/// doc comment). Confirmed by hitting the old size's exact
/// `AddressSpaceError::OutOfMemory` for real in QEMU, not sized by guesswork.
/// Still comfortably inside the Normal block's headroom before
/// `vm::PRIVATE_REGION_BASE` (`0x8000_0000`) and well under `-M virt`'s
/// default RAM size.
const HEAP_SIZE: usize = 4 * 1024 * 1024;

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

/// Heap range `[start, end)` as addresses -- what `reclaim::plan_frees`
/// validates every frame against before anything is freed, so an MMIO or
/// stray address can never reach the allocator's `dealloc`.
pub fn range() -> (u64, u64) {
    (HEAP_START as u64, (HEAP_START + HEAP_SIZE) as u64)
}

/// Bytes currently free in the heap (all free holes, including fragmented
/// ones). The reclamation proof's watermark: it must not drain across
/// repeated evaluations.
pub fn free_bytes() -> usize {
    ALLOCATOR.lock().free()
}

/// Bytes currently allocated from the heap.
pub fn used_bytes() -> usize {
    ALLOCATOR.lock().used()
}
