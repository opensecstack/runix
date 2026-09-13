//! Block driver host, Phase 1 (see docs/STATUS.md's filesystem-driver
//! section): brings up the legacy virtio-blk transport on top of the same
//! virtqueue mechanics `net-driver-host` already proved for virtio-net
//! (`virtio.rs`'s doc comment covers what's shared vs. genuinely new —
//! descriptor chaining), and proves it with a real round trip: write one
//! sector to the device, read it back, check the exact bytes. No
//! filesystem format (FAT32 or otherwise) is parsed here at all — that's
//! explicitly a later phase, once this transport is trusted.
//!
//! This process never gets raw port-I/O privilege itself — every register
//! access goes through the capability-gated `SYS_PORT_IN`/`SYS_PORT_OUT`
//! syscalls (`syscall.rs`), scoped by the kernel to exactly this device's
//! BAR0 register range at spawn time (`kernel/src/main.rs`'s
//! `load_and_run_blk_driver_host`), same as `net-driver-host`. The
//! virtqueue ring and the one request-buffer page are plain memory the
//! kernel mapped directly into this process's address space — this
//! process has no way to learn its own *physical* memory addresses, so the
//! kernel computes them at map time and hands them over in
//! [`BlkBootInfo`], a fixed, pre-agreed memory page (same "no shared type,
//! just an agreed ABI" convention `NetBootInfo`/`GridBootInfo` already
//! established for their own kernel/ring-3 boundaries).

#![no_std]
#![no_main]

mod syscall;
mod virtio;

use linked_list_allocator::LockedHeap;
use syscall::{write_all, write_byte, yield_now};
use virtio::{VirtioBlk, Virtqueue};

/// Small — this Phase 1 slice does no dynamic allocation at all (no
/// `alloc` crate even linked); kept only because `LockedHeap` needs
/// *some* backing region to exist even if this driver never actually
/// calls into the global allocator. Matches the "generous for what this
/// slice needs, not tuned further" honesty every other fixed-size
/// constant in this codebase already uses.
pub const HEAP_START: usize = 0x_0999_1111_0000;
pub const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// One fixed page `kernel/src/main.rs` (`load_and_run_blk_driver_host`)
/// and `kernel/tests/blk_driver_rw.rs` both write before spawning this
/// process. Must match `kernel/src/main.rs`'s own `BlkBootInfo` exactly
/// (`repr(C)`, same field order) — the only contract connecting the two
/// independently compiled crates for this struct.
#[repr(C)]
struct BlkBootInfo {
    io_base: u16,
    _pad: u16,
    /// Physical base of a `3 * QUEUE_ALIGN`-byte region backing this
    /// driver's one request queue — matching virtual base [`BLK_QUEUE_VA`].
    queue_phys: u64,
    /// Physical base of the one page backing this driver's request buffer
    /// (header + data + status, see the layout constants below) —
    /// matching virtual base [`BLK_REQBUF_VA`].
    reqbuf_phys: u64,
}

const BLK_INFO_VA: usize = 0x_0999_3333_0000;
const BLK_QUEUE_VA: usize = 0x_0999_4444_0000;
const BLK_REQBUF_VA: usize = 0x_0999_5555_0000;

/// Offset into the `BLK_INFO_VA` page this process writes its own
/// PASS/FAIL result byte to — same convention `NetBootInfo`'s
/// `NET_RESULT_OFFSET`/`GridBootInfo`'s `GRID_GROW_RESULT_OFFSET` already
/// established (kernel writes the request, ring-3 process writes the
/// result, both in one shared page). `0` (the page's own zero-fill from
/// the loader) means "not yet run".
const BLK_RESULT_OFFSET: usize = 128;
const BLK_RESULT_PASS: u8 = 1;
const BLK_RESULT_FAIL: u8 = 2;

/// One request queue — virtio-blk legacy has exactly one, unlike
/// virtio-net's separate RX/TX pair.
const REQUEST_QUEUE_INDEX: u16 = 0;

/// Request buffer layout within the single `BLK_REQBUF_VA` page: header
/// (type + reserved + sector, matching `struct virtio_blk_req`'s wire
/// format), then one 512-byte sector's worth of data, then the
/// device-written status byte. All three fit comfortably in one 4 KiB
/// page (528 bytes used of 4096), so no need for the header/data/status
/// parts to live on separate pages — virtio only requires each part be
/// its own *descriptor* (since they have different read/write directions),
/// not its own page.
const REQBUF_HEADER_OFFSET: usize = 0;
const REQBUF_HEADER_LEN: usize = 16;
const REQBUF_DATA_OFFSET: usize = REQBUF_HEADER_OFFSET + REQBUF_HEADER_LEN;
const SECTOR_SIZE: usize = 512;
const REQBUF_STATUS_OFFSET: usize = REQBUF_DATA_OFFSET + SECTOR_SIZE;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_S_OK: u8 = 0;

/// Fixed 512-byte pattern written to sector 0 then read back — exact bytes
/// checked, not just "a read completed", same "real round-trip, exact
/// bytes checked" discipline every prior phase in this codebase applies
/// (`net-driver-host`'s ICMP/TCP proofs, `is_arp_reply`'s opcode check).
const TEST_PATTERN_PREFIX: &[u8] = b"RUNIX-BLK-PROOF-1234567890ABCDEF";

/// Writes a `virtio_blk_req` header (type, reserved=0, sector) at `base`
/// via unaligned writes — the request buffer page has no alignment
/// guarantee beyond "4 KiB page start", and 16 bytes doesn't force 8-byte
/// alignment for the `sector` field on its own.
fn write_header(base: *mut u8, req_type: u32, sector: u64) {
    unsafe {
        core::ptr::write_unaligned(base.add(REQBUF_HEADER_OFFSET) as *mut u32, req_type.to_le());
        core::ptr::write_unaligned(base.add(REQBUF_HEADER_OFFSET + 4) as *mut u32, 0u32);
        core::ptr::write_unaligned(
            base.add(REQBUF_HEADER_OFFSET + 8) as *mut u64,
            sector.to_le(),
        );
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let info = unsafe { &*(BLK_INFO_VA as *const BlkBootInfo) };
    let blk = VirtioBlk::probe(info.io_base);

    write_all(b"blk-driver-host: virtio-blk probed, capacity=");
    write_decimal(blk.capacity_sectors);
    write_all(b" sectors\n");

    let qsize = blk.queue_size(REQUEST_QUEUE_INDEX);
    blk.set_queue_address(REQUEST_QUEUE_INDEX, info.queue_phys);
    let mut queue = unsafe { Virtqueue::new(BLK_QUEUE_VA, qsize) };
    queue.init_avail_flags();
    blk.mark_ready();

    let base = BLK_REQBUF_VA as *mut u8;
    let data_ptr = unsafe { base.add(REQBUF_DATA_OFFSET) };
    let status_ptr = unsafe { base.add(REQBUF_STATUS_OFFSET) };
    let header_phys = info.reqbuf_phys + REQBUF_HEADER_OFFSET as u64;
    let data_phys = info.reqbuf_phys + REQBUF_DATA_OFFSET as u64;
    let status_phys = info.reqbuf_phys + REQBUF_STATUS_OFFSET as u64;

    let mut pattern = [0u8; SECTOR_SIZE];
    pattern[..TEST_PATTERN_PREFIX.len()].copy_from_slice(TEST_PATTERN_PREFIX);

    // --- Write sector 0 ---
    unsafe {
        core::ptr::copy_nonoverlapping(pattern.as_ptr(), data_ptr, SECTOR_SIZE);
        // Sentinel the status byte to something neither `VIRTIO_BLK_S_OK`
        // nor a lucky leftover zero could produce by accident, so a
        // completion that somehow skipped writing status is still
        // distinguishable from a real OK.
        core::ptr::write_volatile(status_ptr, 0xFFu8);
    }
    write_header(base, VIRTIO_BLK_T_OUT, 0);
    unsafe {
        // Write request: the device only *reads* header/data, and only
        // *writes* status.
        queue.post_chain(&[
            (header_phys, REQBUF_HEADER_LEN as u32, false),
            (data_phys, SECTOR_SIZE as u32, false),
            (status_phys, 1, true),
        ]);
    }
    virtio::notify(info.io_base, REQUEST_QUEUE_INDEX);

    let write_completed = poll_for_completion(&mut queue);
    let write_status = unsafe { core::ptr::read_volatile(status_ptr) };
    write_all(b"blk-driver-host: write completed=");
    write_byte(if write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(write_status as u64);
    write_byte(b'\n');

    // --- Read sector 0 back ---
    // Zero the data buffer first -- a passing read must be because the
    // device actually wrote the pattern back, not because the buffer
    // already happened to hold it from the write above.
    unsafe {
        core::ptr::write_bytes(data_ptr, 0, SECTOR_SIZE);
        core::ptr::write_volatile(status_ptr, 0xFFu8);
    }
    write_header(base, VIRTIO_BLK_T_IN, 0);
    unsafe {
        // Read request: the device *writes* both data and status.
        queue.post_chain(&[
            (header_phys, REQBUF_HEADER_LEN as u32, false),
            (data_phys, SECTOR_SIZE as u32, true),
            (status_phys, 1, true),
        ]);
    }
    virtio::notify(info.io_base, REQUEST_QUEUE_INDEX);

    let read_completed = poll_for_completion(&mut queue);
    let read_status = unsafe { core::ptr::read_volatile(status_ptr) };
    let mut read_back = [0u8; SECTOR_SIZE];
    unsafe {
        core::ptr::copy_nonoverlapping(data_ptr, read_back.as_mut_ptr(), SECTOR_SIZE);
    }
    let bytes_match = read_back == pattern;

    write_all(b"blk-driver-host: read completed=");
    write_byte(if read_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(read_status as u64);
    write_all(b" bytes_match=");
    write_byte(if bytes_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = write_completed
        && write_status == VIRTIO_BLK_S_OK
        && read_completed
        && read_status == VIRTIO_BLK_S_OK
        && bytes_match;

    if pass {
        write_all(b"blk-driver-host: sector round trip OK (Phase 1 PASS)\n");
    } else {
        write_all(b"blk-driver-host: sector round trip FAILED (Phase 1 FAIL)\n");
    }

    unsafe {
        core::ptr::write_volatile(
            (BLK_INFO_VA + BLK_RESULT_OFFSET) as *mut u8,
            if pass {
                BLK_RESULT_PASS
            } else {
                BLK_RESULT_FAIL
            },
        );
    }

    loop {
        yield_now();
    }
}

/// Same bound and reasoning as every other phase's poll loop in this
/// codebase (net-driver-host's ICMP/TCP proofs): a real device answers
/// promptly in practice, so this bound exists purely to make a genuinely
/// broken driver report failure instead of hanging the boot forever.
fn poll_for_completion(queue: &mut Virtqueue) -> bool {
    for i in 0..2_000_000u32 {
        if queue.poll_used().is_some() {
            return true;
        }
        if i % 10_000 == 0 {
            yield_now();
        }
    }
    false
}

/// No `alloc`/`format!` linked in this crate (see `HEAP_SIZE`'s doc
/// comment — this slice does no dynamic allocation) — a tiny hand-rolled
/// decimal writer is simpler than pulling in `alloc` just for this.
fn write_decimal(mut value: u64) {
    if value == 0 {
        write_byte(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    while value > 0 {
        i -= 1;
        digits[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    write_all(&digits[i..]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No `hlt` here — that's a privileged instruction; executing it from
    // ring 3 would general-protection-fault instead of halting anything.
    write_byte(b'?');
    loop {
        core::hint::spin_loop();
    }
}
