//! Block driver host. Phase 1 (see docs/STATUS.md's filesystem-driver
//! section) brings up the legacy virtio-blk transport on top of the same
//! virtqueue mechanics `net-driver-host` already proved for virtio-net
//! (`virtio.rs`'s doc comment covers what's shared vs. genuinely new —
//! descriptor chaining), and proves it with a real round trip: write one
//! sector, read it back, check the exact bytes. Phase 2 builds a read-only
//! FAT32 walk on top of that transport (`lib.rs`'s pure, property-tested
//! parser — see that file's doc comment for the testing-rigor reasoning):
//! locate one file by its 8.3 name in the root directory, walk its cluster
//! chain, read its exact contents. Neither phase writes to the filesystem,
//! and Phase 2 never touches subdirectories or long filenames — see
//! `lib.rs`'s doc comment for the full scope statement.
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

use blk_driver_host::{fat_entry_at, is_end_of_chain, parse_short_dir_entry, BootSectorInfo};
use linked_list_allocator::LockedHeap;
use syscall::{write_all, write_byte, yield_now};
use virtio::{VirtioBlk, Virtqueue};

/// Small — this driver does no dynamic allocation at all (no `alloc`
/// crate even linked); kept only because `LockedHeap` needs *some*
/// backing region to exist even though nothing here calls into the
/// global allocator. Matches the "generous for what this slice needs, not
/// tuned further" honesty every other fixed-size constant in this
/// codebase already uses.
pub const HEAP_START: usize = 0x_0999_1111_0000;
pub const HEAP_SIZE: usize = 256 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// One fixed page `kernel/src/main.rs` (`load_and_run_blk_driver_host`)
/// and `kernel/tests/blk_driver_rw.rs`/`blk_fat32_read.rs` all write
/// before spawning this process. Must match `kernel/src/main.rs`'s own
/// `BlkBootInfo` exactly (`repr(C)`, same field order) — the only
/// contract connecting the two independently compiled crates for this
/// struct.
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
    /// Whether this run should attempt the Phase 2 FAT32 proof after
    /// Phase 1's sector round trip — same reasoning
    /// `NetBootInfo::attempt_tcp` already documents: without a real FAT32
    /// image attached, attempting this would read garbage sectors and add
    /// wall-clock time to a boot/test that's supposed to stay fast. `0` on
    /// the real boot path and `kernel/tests/blk_driver_rw.rs`; `1` only in
    /// `kernel/tests/blk_fat32_read.rs`, which alone attaches a real FAT32
    /// image.
    attempt_fat32: u8,
}

const BLK_INFO_VA: usize = 0x_0999_3333_0000;
const BLK_QUEUE_VA: usize = 0x_0999_4444_0000;
const BLK_REQBUF_VA: usize = 0x_0999_5555_0000;

/// Offset into the `BLK_INFO_VA` page this process writes its Phase 1
/// PASS/FAIL result byte to — same convention `NetBootInfo`'s
/// `NET_RESULT_OFFSET`/`GridBootInfo`'s `GRID_GROW_RESULT_OFFSET` already
/// established (kernel writes the request, ring-3 process writes the
/// result, both in one shared page). `0` (the page's own zero-fill from
/// the loader) means "not yet run".
const BLK_RESULT_OFFSET: usize = 128;
/// Phase 2's own result byte, one past the Phase 1 one above — read only
/// by `kernel/tests/blk_fat32_read.rs`; `blk_driver_rw.rs` never looks at
/// this offset, same "+1, coexists without either side needing to change"
/// convention `NetBootInfo::NET_TCP_RESULT_OFFSET` already established.
const BLK_FAT32_RESULT_OFFSET: usize = 129;
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

/// Fixed 512-byte pattern written to sector 0 then read back in Phase 1 —
/// exact bytes checked, not just "a read completed", same "real
/// round-trip, exact bytes checked" discipline every prior phase in this
/// codebase applies (`net-driver-host`'s ICMP/TCP proofs, `is_arp_reply`'s
/// opcode check).
const TEST_PATTERN_PREFIX: &[u8] = b"RUNIX-BLK-PROOF-1234567890ABCDEF";

/// The 8.3 short name Phase 2 searches the root directory for — raw,
/// space-padded on-disk form (see `ShortDirEntry::name`'s doc comment in
/// `lib.rs`). Must match whatever `kernel/tests/support/make_fat32_image.sh`
/// actually writes into its fixture image's root directory.
const TARGET_FILE_NAME: [u8; 11] = *b"HELLO   TXT";

/// The exact contents Phase 2 expects to read back from `TARGET_FILE_NAME`
/// — must match `make_fat32_image.sh`'s fixture byte-for-byte (one shared
/// expectation, not independently duplicated on each side, to avoid a
/// silent fixture/expectation drift the tests would otherwise never
/// catch).
const EXPECTED_FILE_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem.\n";

/// A single request's worth of scratch state plus the virtqueue it posts
/// to — bundles what Phase 1's write/read-back proof and Phase 2's FAT32
/// walk both need (many sector reads, one request in flight at a time) so
/// neither has to repeat the descriptor/pointer bookkeeping by hand.
struct BlkDevice {
    queue: Virtqueue,
    io_base: u16,
    base: *mut u8,
    header_phys: u64,
    data_phys: u64,
    status_phys: u64,
    data_ptr: *mut u8,
    status_ptr: *mut u8,
}

impl BlkDevice {
    fn request(&mut self, req_type: u32, sector: u64, data_writable: bool) -> (bool, u8) {
        write_header(self.base, req_type, sector);
        unsafe {
            self.queue.post_chain(&[
                (self.header_phys, REQBUF_HEADER_LEN as u32, false),
                (self.data_phys, SECTOR_SIZE as u32, data_writable),
                (self.status_phys, 1, true),
            ]);
        }
        virtio::notify(self.io_base, REQUEST_QUEUE_INDEX);
        let completed = poll_for_completion(&mut self.queue);
        let status = unsafe { core::ptr::read_volatile(self.status_ptr) };
        (completed, status)
    }

    /// Reads `sector` into a fresh 512-byte buffer, or `None` if the
    /// request didn't complete or the device reported a non-OK status —
    /// every later caller (the Phase 1 read-back check, every sector
    /// Phase 2's FAT32 walk touches) treats "couldn't read this sector"
    /// as a reason to stop, not to guess.
    fn read_sector(&mut self, sector: u64) -> Option<[u8; SECTOR_SIZE]> {
        unsafe {
            core::ptr::write_bytes(self.data_ptr, 0, SECTOR_SIZE);
            core::ptr::write_volatile(self.status_ptr, 0xFFu8);
        }
        let (completed, status) = self.request(VIRTIO_BLK_T_IN, sector, true);
        if !completed || status != VIRTIO_BLK_S_OK {
            return None;
        }
        let mut buf = [0u8; SECTOR_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(self.data_ptr, buf.as_mut_ptr(), SECTOR_SIZE);
        }
        Some(buf)
    }

    fn write_sector(&mut self, sector: u64, data: &[u8; SECTOR_SIZE]) -> (bool, u8) {
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.data_ptr, SECTOR_SIZE);
            core::ptr::write_volatile(self.status_ptr, 0xFFu8);
        }
        self.request(VIRTIO_BLK_T_OUT, sector, false)
    }
}

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
    let mut dev = BlkDevice {
        queue,
        io_base: info.io_base,
        base,
        header_phys: info.reqbuf_phys + REQBUF_HEADER_OFFSET as u64,
        data_phys: info.reqbuf_phys + REQBUF_DATA_OFFSET as u64,
        status_phys: info.reqbuf_phys + REQBUF_STATUS_OFFSET as u64,
        data_ptr: unsafe { base.add(REQBUF_DATA_OFFSET) },
        status_ptr: unsafe { base.add(REQBUF_STATUS_OFFSET) },
    };

    // Phase 1's own proof writes a test pattern to sector 0 -- fine on the
    // zero-filled scratch image `blk_driver_rw.rs` uses, but sector 0 is
    // the boot sector on a real FAT32 volume. Running both proofs back to
    // back against the *same* image would have Phase 1 silently destroy
    // the very boot sector Phase 2 is about to parse -- confirmed for
    // real, not theoretical: the first attempt at this did exactly that,
    // and Phase 2 failed with "boot sector did not parse as FAT32" even
    // though the fixture image was genuinely valid. `blk_driver_rw.rs`
    // already proves Phase 1 independently on its own scratch image, so
    // there's nothing to gain from re-running it here against a FAT32
    // image it would only corrupt.
    if info.attempt_fat32 != 0 {
        let phase2_pass = run_fat32_proof(&mut dev);
        unsafe {
            core::ptr::write_volatile(
                (BLK_INFO_VA + BLK_FAT32_RESULT_OFFSET) as *mut u8,
                if phase2_pass {
                    BLK_RESULT_PASS
                } else {
                    BLK_RESULT_FAIL
                },
            );
        }
    } else {
        let phase1_pass = run_sector_roundtrip_proof(&mut dev);
        unsafe {
            core::ptr::write_volatile(
                (BLK_INFO_VA + BLK_RESULT_OFFSET) as *mut u8,
                if phase1_pass {
                    BLK_RESULT_PASS
                } else {
                    BLK_RESULT_FAIL
                },
            );
        }
    }

    loop {
        yield_now();
    }
}

/// Phase 1: write a fixed pattern to sector 0, zero the local buffer (so a
/// passing read can't be a false positive from leftover memory), read
/// sector 0 back, and check both the status byte and exact byte equality.
fn run_sector_roundtrip_proof(dev: &mut BlkDevice) -> bool {
    let mut pattern = [0u8; SECTOR_SIZE];
    pattern[..TEST_PATTERN_PREFIX.len()].copy_from_slice(TEST_PATTERN_PREFIX);

    let (write_completed, write_status) = dev.write_sector(0, &pattern);
    write_all(b"blk-driver-host: write completed=");
    write_byte(if write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(write_status as u64);
    write_byte(b'\n');

    let read_back = dev.read_sector(0);
    let bytes_match = read_back == Some(pattern);

    write_all(b"blk-driver-host: read completed=");
    write_byte(if read_back.is_some() { b'1' } else { b'0' });
    write_all(b" bytes_match=");
    write_byte(if bytes_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = write_completed && write_status == VIRTIO_BLK_S_OK && bytes_match;
    if pass {
        write_all(b"blk-driver-host: sector round trip OK (Phase 1 PASS)\n");
    } else {
        write_all(b"blk-driver-host: sector round trip FAILED (Phase 1 FAIL)\n");
    }
    pass
}

/// Phase 2: read the boot sector, walk the root directory's cluster chain
/// looking for [`TARGET_FILE_NAME`], walk that file's own cluster chain,
/// and check its exact contents against [`EXPECTED_FILE_CONTENTS`]. Every
/// step uses `lib.rs`'s bounds-checked, property-tested parser — nothing
/// here trusts an on-disk field without going through it first.
fn run_fat32_proof(dev: &mut BlkDevice) -> bool {
    let Some(boot_sector) = dev.read_sector(0) else {
        write_all(b"blk-driver-host: FAT32 FAIL - could not read boot sector\n");
        return false;
    };
    let Some(info) = BootSectorInfo::parse(&boot_sector) else {
        write_all(b"blk-driver-host: FAT32 FAIL - boot sector did not parse as FAT32\n");
        return false;
    };

    let Some(entry) = find_entry_in_directory(dev, &info, info.root_cluster, &TARGET_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - target file not found in root directory\n");
        return false;
    };

    if entry.is_dir {
        write_all(b"blk-driver-host: FAT32 FAIL - target name is a directory, not a file\n");
        return false;
    }

    // Fixed-size read buffer -- no `alloc` linked in this crate (see
    // `HEAP_SIZE`'s doc comment). Big enough for this phase's fixed test
    // fixture with headroom; a file larger than this is a test-fixture
    // bug, not something this proof needs to handle generically yet.
    const MAX_FILE_BYTES: usize = 4096;
    let mut file_buf = [0u8; MAX_FILE_BYTES];
    let read_len = (entry.file_size as usize).min(MAX_FILE_BYTES);

    let mut cluster = entry.first_cluster;
    let mut written = 0usize;
    // Same defensive iteration cap every cluster-chain walk in this
    // function uses -- a corrupt or cyclic FAT must make this driver
    // report failure, not spin forever.
    for _ in 0..1024u32 {
        if written >= read_len {
            break;
        }
        let Some(sector0) = info.cluster_to_sector(cluster) else {
            break;
        };
        for s in 0..u32::from(info.sectors_per_cluster) {
            if written >= read_len {
                break;
            }
            let Some(sector) = dev.read_sector(u64::from(sector0) + u64::from(s)) else {
                write_all(b"blk-driver-host: FAT32 FAIL - could not read file data sector\n");
                return false;
            };
            let take = (read_len - written).min(SECTOR_SIZE);
            file_buf[written..written + take].copy_from_slice(&sector[..take]);
            written += take;
        }
        if written >= read_len {
            break;
        }
        let Some(next) = next_cluster_in_chain(dev, &info, cluster) else {
            break;
        };
        if is_end_of_chain(next) {
            break;
        }
        cluster = next;
    }

    let contents_match = written >= EXPECTED_FILE_CONTENTS.len()
        && &file_buf[..EXPECTED_FILE_CONTENTS.len()] == EXPECTED_FILE_CONTENTS;

    write_all(b"blk-driver-host: FAT32 file_size=");
    write_decimal(u64::from(entry.file_size));
    write_all(b" bytes_read=");
    write_decimal(written as u64);
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_byte(b'\n');

    if contents_match {
        write_all(b"blk-driver-host: FAT32 file located and read correctly (Phase 2 PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 file contents did not match (Phase 2 FAIL)\n");
    }
    contents_match
}

/// Scans every 32-byte entry of `dir_cluster`'s cluster chain for
/// `target_name`, returning the first match (this driver's fixture never
/// has duplicates; the first match is the only meaningful one). Stops
/// early at the end-of-directory marker (`entry[0] == 0x00`) — checked
/// directly here, not via `parse_short_dir_entry` (which folds that case
/// into `None` the same as a deleted/LFN entry, since a caller merely
/// scanning for one name treats all three as "not a match" — this caller
/// specifically needs "stop scanning entirely" instead, see that
/// function's own doc comment in `lib.rs`).
fn find_entry_in_directory(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    dir_cluster: u32,
    target_name: &[u8; 11],
) -> Option<blk_driver_host::ShortDirEntry> {
    let mut cluster = dir_cluster;
    for _ in 0..1024u32 {
        let sector0 = info.cluster_to_sector(cluster)?;
        for s in 0..u32::from(info.sectors_per_cluster) {
            let sector = dev.read_sector(u64::from(sector0) + u64::from(s))?;
            for chunk in sector.chunks_exact(32) {
                if chunk[0] == 0x00 {
                    return None; // end of directory, nothing left to scan
                }
                let entry_bytes: [u8; 32] = chunk.try_into().unwrap();
                if let Some(entry) = parse_short_dir_entry(&entry_bytes) {
                    if entry.name == *target_name {
                        return Some(entry);
                    }
                }
            }
        }
        let next = next_cluster_in_chain(dev, info, cluster)?;
        if is_end_of_chain(next) {
            return None;
        }
        cluster = next;
    }
    None
}

/// Reads whichever FAT sector holds `cluster`'s entry and extracts it —
/// `fat_entry_at`'s own bounds check operates relative to the *sector*
/// buffer passed in, so the cluster index passed to it is `cluster`'s
/// position *within that one sector*, not its absolute value.
fn next_cluster_in_chain(dev: &mut BlkDevice, info: &BootSectorInfo, cluster: u32) -> Option<u32> {
    let bytes_per_sector = u32::from(info.bytes_per_sector);
    let byte_offset = cluster.checked_mul(4)?;
    let fat_sector_index = byte_offset / bytes_per_sector;
    let offset_in_sector = byte_offset % bytes_per_sector;
    let fat_sector = info.fat_start_sector.checked_add(fat_sector_index)?;

    let sector = dev.read_sector(u64::from(fat_sector))?;
    let relative_cluster = offset_in_sector / 4;
    fat_entry_at(&sector, relative_cluster)
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
/// comment — this driver does no dynamic allocation) — a tiny hand-rolled
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
