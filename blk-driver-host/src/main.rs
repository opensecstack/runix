//! Block driver host. Phase 1 (see docs/STATUS.md's filesystem-driver
//! section) brings up the legacy virtio-blk transport on top of the same
//! virtqueue mechanics `net-driver-host` already proved for virtio-net
//! (`virtio.rs`'s doc comment covers what's shared vs. genuinely new —
//! descriptor chaining), and proves it with a real round trip: write one
//! sector, read it back, check the exact bytes. Phase 2 builds a read-only
//! FAT32 walk on top of that transport (`lib.rs`'s pure, property-tested
//! parser — see that file's doc comment for the testing-rigor reasoning):
//! locate one file by its 8.3 or long (VFAT LFN) name in the root
//! directory or one level of subdirectory, walk its cluster chain, read
//! its exact contents. No writes anywhere in this crate — see `lib.rs`'s
//! doc comment for the full scope statement.
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

use blk_driver_host::{
    fat_entry_at, is_end_of_chain, parse_lfn_fragment, parse_short_dir_entry, short_name_checksum,
    BootSectorInfo,
};
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
    /// Filesystem driver, Phase 3: whether this run should enter the
    /// request-serving loop after locating [`TARGET_FILE_NAME`], instead
    /// of running Phase 1's or Phase 2's own self-contained proof. `0` on
    /// the real boot path and every earlier test; `1` only in
    /// `kernel/tests/blk_fs_ipc.rs`, which alone spawns a second process
    /// to actually send a request over [`FS_REQUEST_PORT`].
    serve_fs_requests: u8,
}

/// Filesystem driver, Phase 3's fixed IPC ports — must match
/// `kernel/src/main.rs`'s own `BLK_FS_REQUEST_PORT`/`BLK_FS_RESPONSE_PORT`
/// constants exactly (same "no shared type, just an agreed ABI/protocol"
/// convention as every other kernel/ring-3 boundary in this codebase).
const FS_REQUEST_PORT: usize = 8;
const FS_RESPONSE_PORT: usize = 9;

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

/// Filesystem driver, Phase 2 extension: subdirectory traversal.
/// `find_entry_in_directory` already takes any starting cluster — this is
/// the first proof it actually works one level deep, not just at the
/// root. Names must match `make_fat32_image.sh`'s fixture byte-for-byte,
/// same convention as [`TARGET_FILE_NAME`].
const SUBDIR_NAME: [u8; 11] = *b"SUBDIR     ";
const NESTED_FILE_NAME: [u8; 11] = *b"NESTED  TXT";
const NESTED_EXPECTED_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: nested file inside a real subdirectory.\n";

/// Filesystem driver, Phase 2 extension: multi-cluster coverage.
/// `HELLO.TXT` (68 bytes) fits in the fixture's single 512-byte cluster —
/// never exercising `next_cluster_in_chain`/`is_end_of_chain` beyond one
/// cluster. `BIG.TXT` is sized to span several. Its content is generated,
/// not stored as a 3000-byte literal, identically on both sides (this
/// function and `make_fat32_image.sh`'s own `python3` one-liner) — one
/// formula, not two copies that could quietly drift apart.
const BIG_FILE_NAME: [u8; 11] = *b"BIG     TXT";
const BIG_FILE_LEN: usize = 3000;
fn expected_big_file_byte(i: usize) -> u8 {
    b'0' + (i % 10) as u8
}

/// Filesystem driver, Phase 4: long filenames. `long-filename-test.txt`
/// (22 ASCII characters) doesn't fit 8.3, so `make_fat32_image.sh`'s
/// `mcopy` wrote it as real VFAT LFN entries plus a short-name fallback
/// (`LONG-F~1.TXT`) — this driver locates it by its *real* name, not the
/// fallback. ASCII-only matching, named as this slice's explicit limit
/// (see `find_entry_by_long_name`'s own doc comment for why that's
/// enough for now).
const LONG_FILE_NAME_ASCII: &[u8] = b"long-filename-test.txt";
const LONG_FILE_EXPECTED_CONTENTS: &[u8] =
    b"RUNIX-FAT32-PROOF: located via a real long filename, not 8.3.\n";

/// Filesystem driver, Phase 5: a first real write. Deliberately the
/// smallest write that means anything: `WRITE.TXT` is exactly 512 bytes
/// (one sector, one cluster on this fixture), so overwriting its content
/// needs zero free-cluster allocation, zero FAT chain modification, zero
/// directory-entry size-field update, and zero partial-sector
/// read-modify-write — each of those is a distinct way a bug could
/// actually corrupt a real filesystem, and each is explicitly the next
/// slice after this one, not attempted here (see `run_write_proof`'s own
/// doc comment).
const WRITE_FILE_NAME: [u8; 11] = *b"WRITE   TXT";
fn write_pattern_byte(i: usize) -> u8 {
    b'Z' - (i % 26) as u8
}

/// Filesystem driver, Phase 6, part B: a real partial-sector write plus a
/// `file_size` update — still no free-cluster allocation, no FAT chain
/// modification, no create/delete (see `run_partial_write_proof`'s own
/// doc comment for the full list of what's still deferred and why).
/// `PARTIAL.TXT` starts at exactly 512 bytes of `partial_initial_byte`;
/// this phase overwrites only the first `PARTIAL_NEW_LEN` bytes with
/// `partial_new_byte` and shrinks the visible file size to match.
const PARTIAL_FILE_NAME: [u8; 11] = *b"PARTIAL TXT";
const PARTIAL_NEW_LEN: usize = 300;
fn partial_initial_byte(i: usize) -> u8 {
    b'a' + (i % 26) as u8
}
fn partial_new_byte(i: usize) -> u8 {
    b'0' + (i % 10) as u8
}

/// Filesystem driver, Phase 7, part A: chain growth. `GROW.TXT` starts at
/// exactly one full cluster (512 bytes, `grow_initial_byte`'s `X`/`Y`/`Z`
/// cycle) — no existing slack, so growing it *requires* allocating and
/// linking a genuinely new cluster, isolated from "fill a partial final
/// cluster" (already proven separately by Phase 6's partial-write proof).
const GROW_FILE_NAME: [u8; 11] = *b"GROW    TXT";
const GROW_INITIAL_LEN: usize = 512;
const GROW_APPEND_LEN: usize = 200;
fn grow_initial_byte(i: usize) -> u8 {
    match i % 3 {
        0 => b'X',
        1 => b'Y',
        _ => b'Z',
    }
}
fn grow_append_byte(i: usize) -> u8 {
    b'0' + (i % 10) as u8
}

/// Filesystem driver, Phase 7, part B: delete. A small, disposable
/// single-cluster file whose only purpose is to be deleted by
/// `run_delete_proof`, freeing both its directory slot and its cluster for
/// part C's create proof to reuse.
const DELETE_FILE_NAME: [u8; 11] = *b"DELETE_MTXT";

/// Filesystem driver, Phase 7, part C: create. A brand-new file that
/// exists nowhere in the fixture until this driver creates it, reusing the
/// directory slot and (expected, though not required for correctness)
/// cluster `run_delete_proof` just freed.
const CREATE_FILE_NAME: [u8; 11] = *b"CREATED TXT";
fn create_content_byte(i: usize) -> u8 {
    b'A' + (i % 26) as u8
}
const CREATE_FILE_LEN: usize = 64;

/// FAT directory-entry attribute byte for a plain read/write file —
/// written into the new short entry `run_create_proof` builds from
/// scratch. `0x20` = `ATTR_ARCHIVE`, the same bit `mkfs.fat`/`mcopy` set on
/// every other regular file already in this fixture (confirmed by
/// dumping a real short entry's attribute byte, not assumed from spec).
const ATTR_ARCHIVE: u8 = 0x20;

/// The standard FAT "this entry is deleted" marker — writing it as a
/// directory entry's first byte is what makes the existing, unmodified
/// parser (`parse_short_dir_entry`, `find_entry_in_directory`) correctly
/// treat the slot as absent, the same way it already treats a real
/// `mkfs.fat`-produced deleted entry.
const DELETED_ENTRY_MARKER: u8 = 0xE5;

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
    if info.serve_fs_requests != 0 {
        // Same sector-0 corruption hazard `attempt_fat32`'s branch already
        // documents: this mode reads (never writes) the boot sector, so it
        // shares that branch's exclusivity with Phase 1's write proof.
        match dev.read_sector(0).and_then(|s| BootSectorInfo::parse(&s)) {
            Some(boot_info) => run_fs_ipc_server(&mut dev, &boot_info),
            None => write_all(b"blk-driver-host: FS server FAIL - boot sector did not parse\n"),
        }
    } else if info.attempt_fat32 != 0 {
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

    let mut file_buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, &info, &entry, &mut file_buf);

    let contents_match = written >= EXPECTED_FILE_CONTENTS.len()
        && &file_buf[..EXPECTED_FILE_CONTENTS.len()] == EXPECTED_FILE_CONTENTS;

    write_all(b"blk-driver-host: FAT32 file_size=");
    write_decimal(u64::from(entry.file_size));
    write_all(b" bytes_read=");
    write_decimal(written as u64);
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let subdir_pass = run_subdir_proof(dev, &info);
    let big_file_pass = run_big_file_proof(dev, &info);
    let long_name_pass = run_long_name_proof(dev, &info);
    let write_pass = run_write_proof(dev, &info);
    let partial_write_pass = run_partial_write_proof(dev, &info);
    let grow_pass = run_grow_proof(dev, &info);
    let delete_pass = run_delete_proof(dev, &info);
    let create_pass = run_create_proof(dev, &info);

    let pass = contents_match
        && subdir_pass
        && big_file_pass
        && long_name_pass
        && write_pass
        && partial_write_pass
        && grow_pass
        && delete_pass
        && create_pass;
    if pass {
        write_all(b"blk-driver-host: FAT32 file located and read correctly (Phase 2 PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 file contents did not match (Phase 2 FAIL)\n");
    }
    pass
}

/// Walks one level into [`SUBDIR_NAME`] and reads [`NESTED_FILE_NAME`] back
/// — the first proof `find_entry_in_directory`'s already-generic
/// `dir_cluster` parameter actually works one level deep, not just at the
/// root.
fn run_subdir_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some(subdir) = find_entry_in_directory(dev, info, info.root_cluster, &SUBDIR_NAME) else {
        write_all(b"blk-driver-host: FAT32 FAIL - SUBDIR not found in root directory\n");
        return false;
    };
    if !subdir.is_dir {
        write_all(b"blk-driver-host: FAT32 FAIL - SUBDIR is not actually a directory\n");
        return false;
    }
    let Some(nested) = find_entry_in_directory(dev, info, subdir.first_cluster, &NESTED_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - NESTED.TXT not found inside SUBDIR\n");
        return false;
    };

    let mut buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, info, &nested, &mut buf);
    let matches = written >= NESTED_EXPECTED_CONTENTS.len()
        && &buf[..NESTED_EXPECTED_CONTENTS.len()] == NESTED_EXPECTED_CONTENTS;

    write_all(b"blk-driver-host: FAT32 subdir nested_bytes_read=");
    write_decimal(written as u64);
    write_all(b" contents_match=");
    write_byte(if matches { b'1' } else { b'0' });
    write_byte(b'\n');
    matches
}

/// Reads [`BIG_FILE_NAME`] back in full and checks every byte against
/// [`expected_big_file_byte`] — the first real exercise of
/// `next_cluster_in_chain`/`is_end_of_chain` beyond a single cluster (the
/// fixture's 512-byte clusters mean this file's 3000 bytes span several).
fn run_big_file_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some(entry) = find_entry_in_directory(dev, info, info.root_cluster, &BIG_FILE_NAME) else {
        write_all(b"blk-driver-host: FAT32 FAIL - BIG.TXT not found in root directory\n");
        return false;
    };

    let mut buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, info, &entry, &mut buf);
    let matches = written == BIG_FILE_LEN
        && buf[..written]
            .iter()
            .enumerate()
            .all(|(i, &b)| b == expected_big_file_byte(i));

    write_all(b"blk-driver-host: FAT32 big_file_bytes_read=");
    write_decimal(written as u64);
    write_all(b" contents_match=");
    write_byte(if matches { b'1' } else { b'0' });
    write_byte(b'\n');
    matches
}

/// Locates `long-filename-test.txt` by its real name (not the `LONG-F~1.TXT`
/// short-name fallback `mkfs.fat` also wrote) and reads it back.
fn run_long_name_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some(entry) = find_entry_by_long_name(dev, info, info.root_cluster, LONG_FILE_NAME_ASCII)
    else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - long-filename-test.txt not found by its real name\n",
        );
        return false;
    };

    let mut buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, info, &entry, &mut buf);
    let matches = written >= LONG_FILE_EXPECTED_CONTENTS.len()
        && &buf[..LONG_FILE_EXPECTED_CONTENTS.len()] == LONG_FILE_EXPECTED_CONTENTS;

    write_all(b"blk-driver-host: FAT32 long_name_bytes_read=");
    write_decimal(written as u64);
    write_all(b" contents_match=");
    write_byte(if matches { b'1' } else { b'0' });
    write_byte(b'\n');

    let case_insensitive_match = run_case_insensitive_long_name_proof(dev, info);
    matches && case_insensitive_match
}

/// Same real fixture file Phase 4 already proved locating by its exact
/// case — this searches for it with an all-uppercase target instead,
/// proving `long_name_matches`'s ASCII case-folding actually works,
/// against the exact same on-disk bytes, no new fixture needed.
const LONG_FILE_NAME_ASCII_UPPER: &[u8] = b"LONG-FILENAME-TEST.TXT";

fn run_case_insensitive_long_name_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let found =
        find_entry_by_long_name(dev, info, info.root_cluster, LONG_FILE_NAME_ASCII_UPPER).is_some();
    write_all(b"blk-driver-host: FAT32 case_insensitive_long_name_match=");
    write_byte(if found { b'1' } else { b'0' });
    write_byte(b'\n');
    found
}

/// Locates `WRITE.TXT`, overwrites its one sector with a fixed pattern
/// (`write_pattern_byte`), and reads that same sector back via a *fresh*
/// `dev.read_sector` call — not a cached buffer; `read_sector` always
/// re-issues a real virtio-blk request, so this is a genuine round trip
/// through the device emulation, the same rigor Phase 1's own sector
/// round-trip already established, just at a FAT32-located sector instead
/// of a hardcoded one.
///
/// Deliberately does **not** assert anything about the file's *prior*
/// content — only "write X, read back X" — so this stays correct and
/// idempotent even run twice against the same fixture image without
/// regenerating it (a second run's "prior content" would already be `X`
/// from the first run, which is fine, not a failure condition worth
/// encoding).
///
/// What this does **not** attempt, on purpose: this fixture file is
/// exactly one cluster, so there is exactly one sector to locate and
/// overwrite — a general write path would need to walk the *whole* chain
/// the way `read_file_contents` does for a multi-cluster file. Also out
/// of scope here: growing or shrinking the file (free-cluster allocation,
/// FAT chain extension/truncation), updating the directory entry's size
/// field, creating or deleting entries, and read-modify-write for a
/// partial (non-sector-aligned) final sector. Each is a distinct way a
/// bug could actually corrupt a real filesystem rather than just fail a
/// read — each is the next real slice, not this one.
fn run_write_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some(entry) = find_entry_in_directory(dev, info, info.root_cluster, &WRITE_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - WRITE.TXT not found in root directory\n");
        return false;
    };
    let Some(sector) = info.cluster_to_sector(entry.first_cluster) else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - WRITE.TXT's cluster did not resolve to a sector\n",
        );
        return false;
    };

    let mut new_content = [0u8; SECTOR_SIZE];
    for (i, byte) in new_content.iter_mut().enumerate() {
        *byte = write_pattern_byte(i);
    }

    let (write_completed, write_status) = dev.write_sector(u64::from(sector), &new_content);
    let read_back = dev.read_sector(u64::from(sector));
    let matches = read_back == Some(new_content);

    write_all(b"blk-driver-host: FAT32 write completed=");
    write_byte(if write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(write_status as u64);
    write_all(b" read_back_matches=");
    write_byte(if matches { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = write_completed && write_status == VIRTIO_BLK_S_OK && matches;
    if pass {
        write_all(b"blk-driver-host: FAT32 write proof OK (Phase 5 PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 write proof FAILED (Phase 5 FAIL)\n");
    }
    pass
}

/// Overwrites `PARTIAL.TXT`'s first `PARTIAL_NEW_LEN` bytes with a new
/// pattern (real read-modify-write — bytes `PARTIAL_NEW_LEN..512` must
/// survive unchanged) and shrinks its directory entry's `file_size` to
/// match, then confirms both through the *ordinary, unmodified read
/// path* (`find_entry_in_directory` + `read_file_contents`) — not just an
/// isolated field mutated in isolation.
///
/// What this does **not** attempt, on purpose, same as `run_write_proof`:
/// no free-cluster allocation (the new content still fits within the
/// file's one already-allocated cluster), no FAT chain modification, no
/// creating or deleting directory entries. Each is its own way a bug
/// could actually corrupt a real filesystem rather than just fail a read
/// — each is the next real slice, not this one.
fn run_partial_write_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((entry, dir_sector, dir_offset)) =
        find_entry_with_location(dev, info, info.root_cluster, &PARTIAL_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - PARTIAL.TXT not found in root directory\n");
        return false;
    };
    let Some(data_sector) = info.cluster_to_sector(entry.first_cluster) else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - PARTIAL.TXT's cluster did not resolve to a sector\n",
        );
        return false;
    };

    // Real read-modify-write: read the existing sector, splice in the new
    // pattern for bytes [0..PARTIAL_NEW_LEN), leave the rest untouched.
    let Some(mut sector_buf) = dev.read_sector(u64::from(data_sector)) else {
        write_all(b"blk-driver-host: FAT32 FAIL - could not read PARTIAL.TXT's data sector\n");
        return false;
    };
    for (i, byte) in sector_buf.iter_mut().enumerate().take(PARTIAL_NEW_LEN) {
        *byte = partial_new_byte(i);
    }
    let (write_completed, write_status) = dev.write_sector(u64::from(data_sector), &sector_buf);

    // Patch just the file_size field (bytes 28..32 of the 32-byte entry)
    // in the *directory's* sector -- read-modify-write again, for the
    // same reason: every other entry already in that sector must survive
    // untouched.
    let size_write_ok = match dev.read_sector(u64::from(dir_sector)) {
        Some(mut dir_buf) => {
            let size_offset = dir_offset + 28;
            dir_buf[size_offset..size_offset + 4]
                .copy_from_slice(&(PARTIAL_NEW_LEN as u32).to_le_bytes());
            let (completed, status) = dev.write_sector(u64::from(dir_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    // Verification 1: through the ordinary, unmodified read path -- a
    // fresh lookup must now report the new size and content.
    let mut read_buf = [0u8; MAX_FILE_BYTES];
    let (size_visible, contents_match) =
        match find_entry_in_directory(dev, info, info.root_cluster, &PARTIAL_FILE_NAME) {
            Some(fresh_entry) => {
                let written = read_file_contents(dev, info, &fresh_entry, &mut read_buf);
                let size_ok = fresh_entry.file_size as usize == PARTIAL_NEW_LEN;
                let contents_ok = written == PARTIAL_NEW_LEN
                    && read_buf[..PARTIAL_NEW_LEN]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == partial_new_byte(i));
                (size_ok, contents_ok)
            }
            None => (false, false),
        };

    // Verification 2: the untouched tail of the sector, read directly
    // (bypassing file_size) -- must still be the *original* pattern, not
    // zeroed or clobbered by a naive full-sector overwrite. This is the
    // check a full-sector-overwrite bug would fail even though check 1
    // above could still pass.
    let tail_preserved = match dev.read_sector(u64::from(data_sector)) {
        Some(fresh_sector) => fresh_sector[PARTIAL_NEW_LEN..SECTOR_SIZE]
            .iter()
            .enumerate()
            .all(|(i, &b)| b == partial_initial_byte(PARTIAL_NEW_LEN + i)),
        None => false,
    };

    write_all(b"blk-driver-host: FAT32 partial write completed=");
    write_byte(if write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(write_status as u64);
    write_all(b" size_write_ok=");
    write_byte(if size_write_ok { b'1' } else { b'0' });
    write_all(b" size_visible=");
    write_byte(if size_visible { b'1' } else { b'0' });
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_all(b" tail_preserved=");
    write_byte(if tail_preserved { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = write_completed
        && write_status == VIRTIO_BLK_S_OK
        && size_write_ok
        && size_visible
        && contents_match
        && tail_preserved;
    if pass {
        write_all(b"blk-driver-host: FAT32 partial write/resize proof OK (Phase 6 PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 partial write/resize proof FAILED (Phase 6 FAIL)\n");
    }
    pass
}

/// Writes `value` (masked to the low 28 bits FAT32 actually uses) into
/// `cluster`'s entry, in **every** FAT copy (`info.num_fats`), not just the
/// first — confirmed against the real fixture that `mkfs.fat` keeps all
/// copies byte-identical, so leaving a second copy stale would be exactly
/// the kind of silent latent inconsistency a stricter reader (or a real
/// OS) could someday notice, even though this driver's own reads only ever
/// consult the first copy. Each copy is patched via real read-modify-write
/// (preserving the entry's top 4 reserved bits, never assumed zero) —
/// same discipline `run_partial_write_proof`'s directory-entry patch
/// already established for "safely patch 4 bytes inside a larger sector."
fn write_fat_entry(dev: &mut BlkDevice, info: &BootSectorInfo, cluster: u32, value: u32) -> bool {
    let bytes_per_sector = u32::from(info.bytes_per_sector);
    let Some(byte_offset) = cluster.checked_mul(4) else {
        return false;
    };
    let fat_sector_index = byte_offset / bytes_per_sector;
    let offset_in_sector = (byte_offset % bytes_per_sector) as usize;
    let masked = value & 0x0FFF_FFFF;

    for fat_copy in 0..u32::from(info.num_fats) {
        let Some(copy_base) = info
            .fat_start_sector
            .checked_add(info.fat_size_32 * fat_copy)
        else {
            return false;
        };
        let Some(fat_sector) = copy_base.checked_add(fat_sector_index) else {
            return false;
        };
        let Some(mut sector) = dev.read_sector(u64::from(fat_sector)) else {
            return false;
        };
        let existing = u32::from_le_bytes(
            sector[offset_in_sector..offset_in_sector + 4]
                .try_into()
                .unwrap(),
        );
        let reserved_top_bits = existing & 0xF000_0000;
        let new_value = reserved_top_bits | masked;
        sector[offset_in_sector..offset_in_sector + 4].copy_from_slice(&new_value.to_le_bytes());
        let (completed, status) = dev.write_sector(u64::from(fat_sector), &sector);
        if !completed || status != VIRTIO_BLK_S_OK {
            return false;
        }
    }
    true
}

/// Scans the FAT sequentially from cluster 2 upward for the first entry
/// that reads as `0x00000000` (free), reading one sector at a time and
/// checking every entry it holds before moving to the next sector — not a
/// naive one-entry-at-a-time re-read of the same sector. Bounded the same
/// defensive way every other scan in this module is: a corrupt or
/// exhausted FAT must report `None`, not spin forever or wrap around into
/// nonsense. Confirmed against the real fixture image that free clusters
/// begin at 15, well within this bound.
fn allocate_free_cluster(dev: &mut BlkDevice, info: &BootSectorInfo) -> Option<u32> {
    let bytes_per_sector = u32::from(info.bytes_per_sector);
    let entries_per_sector = bytes_per_sector / 4;
    let total_fat_sectors = info.fat_size_32;

    for fat_sector_index in 0..total_fat_sectors {
        let fat_sector = info.fat_start_sector.checked_add(fat_sector_index)?;
        let sector = dev.read_sector(u64::from(fat_sector))?;
        for entry_in_sector in 0..entries_per_sector {
            let cluster = fat_sector_index
                .checked_mul(entries_per_sector)?
                .checked_add(entry_in_sector)?;
            if cluster < 2 {
                continue; // clusters 0/1 are reserved, never allocatable
            }
            if fat_entry_at(&sector, entry_in_sector) == Some(0) {
                return Some(cluster);
            }
        }
    }
    None
}

/// Filesystem driver, Phase 7, part A: grows `GROW.TXT` (starting at
/// exactly one full cluster, no existing slack) by allocating one new
/// cluster, writing new content into it, linking it into the chain, and
/// updating `file_size` to match. Link ordering matters: the new cluster's
/// own EOC marker is written *before* the old last cluster is repointed at
/// it, so a crash landing between the two writes leaves either "chain
/// unchanged, new cluster an orphan" (harmless, recoverable by a future
/// allocation scan) or "chain already extended" — never a chain pointing
/// at a half-initialized cluster.
///
/// What this does **not** attempt, on purpose: growing by more than one
/// cluster per call, filling a partial (non-full) final cluster before
/// allocating (Phase 6 already proved partial-sector RMW separately), and
/// any concurrent access (single-writer, same as every other write this
/// driver performs).
fn run_grow_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((entry, dir_sector, dir_offset)) =
        find_entry_with_location(dev, info, info.root_cluster, &GROW_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - GROW.TXT not found in root directory\n");
        return false;
    };

    // Walk to the file's current last cluster -- generic, not assuming
    // single-cluster, via the same chain-walk shape every other function
    // here uses.
    let mut last_cluster = entry.first_cluster;
    let mut walk_ok = true;
    for _ in 0..1024u32 {
        match next_cluster_in_chain(dev, info, last_cluster) {
            Some(next) if !is_end_of_chain(next) => last_cluster = next,
            Some(_) => break,
            None => {
                walk_ok = false;
                break;
            }
        }
    }
    if !walk_ok {
        write_all(b"blk-driver-host: FAT32 FAIL - could not walk GROW.TXT's existing chain\n");
        return false;
    }

    let Some(new_cluster) = allocate_free_cluster(dev, info) else {
        write_all(b"blk-driver-host: FAT32 FAIL - no free cluster available to grow GROW.TXT\n");
        return false;
    };
    let Some(new_sector) = info.cluster_to_sector(new_cluster) else {
        write_all(b"blk-driver-host: FAT32 FAIL - new cluster did not resolve to a sector\n");
        return false;
    };

    let mut new_content = [0u8; SECTOR_SIZE];
    for (i, byte) in new_content.iter_mut().enumerate().take(GROW_APPEND_LEN) {
        *byte = grow_append_byte(i);
    }
    let (data_write_completed, data_write_status) =
        dev.write_sector(u64::from(new_sector), &new_content);

    // New cluster fully initialized (content written, own EOC marker set)
    // *before* anything points to it.
    let new_cluster_eoc_ok = write_fat_entry(dev, info, new_cluster, 0x0FFF_FFFF);
    let link_ok = write_fat_entry(dev, info, last_cluster, new_cluster);

    let new_size = (GROW_INITIAL_LEN + GROW_APPEND_LEN) as u32;
    let size_write_ok = match dev.read_sector(u64::from(dir_sector)) {
        Some(mut dir_buf) => {
            let size_offset = dir_offset + 28;
            dir_buf[size_offset..size_offset + 4].copy_from_slice(&new_size.to_le_bytes());
            let (completed, status) = dev.write_sector(u64::from(dir_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    // Verification: through the ordinary, unmodified read path -- reading
    // the full new size *requires* walking across the freshly-created
    // link, exercising the exact chain-walking code this slice exists to
    // prove.
    let mut read_buf = [0u8; MAX_FILE_BYTES];
    let (size_visible, contents_match) =
        match find_entry_in_directory(dev, info, info.root_cluster, &GROW_FILE_NAME) {
            Some(fresh_entry) => {
                let written = read_file_contents(dev, info, &fresh_entry, &mut read_buf);
                let size_ok = fresh_entry.file_size == new_size;
                let contents_ok = written == new_size as usize
                    && read_buf[..GROW_INITIAL_LEN]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == grow_initial_byte(i))
                    && read_buf[GROW_INITIAL_LEN..written]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == grow_append_byte(i));
                (size_ok, contents_ok)
            }
            None => (false, false),
        };

    write_all(b"blk-driver-host: FAT32 grow data_write_completed=");
    write_byte(if data_write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(data_write_status as u64);
    write_all(b" new_cluster_eoc_ok=");
    write_byte(if new_cluster_eoc_ok { b'1' } else { b'0' });
    write_all(b" link_ok=");
    write_byte(if link_ok { b'1' } else { b'0' });
    write_all(b" size_write_ok=");
    write_byte(if size_write_ok { b'1' } else { b'0' });
    write_all(b" size_visible=");
    write_byte(if size_visible { b'1' } else { b'0' });
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = data_write_completed
        && data_write_status == VIRTIO_BLK_S_OK
        && new_cluster_eoc_ok
        && link_ok
        && size_write_ok
        && size_visible
        && contents_match;
    if pass {
        write_all(b"blk-driver-host: FAT32 chain growth proof OK (Phase 7a PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 chain growth proof FAILED (Phase 7a FAIL)\n");
    }
    pass
}

/// Filesystem driver, Phase 7, part B: deletes `DELETE_ME.TXT` by walking
/// its (bounded, generic) cluster chain and zeroing every cluster's FAT
/// entry, then marking its directory entry's first byte
/// [`DELETED_ENTRY_MARKER`] — every other field is left as-is, undefined by
/// spec, harmless since part C's create overwrites the whole slot anyway.
///
/// Verified two ways: (1) `find_entry_in_directory` no longer finds it —
/// proving `0xE5` is actually *honored* by the write side, not just the
/// already-proven (since Phase 2) parsing side; (2) `allocate_free_cluster`
/// immediately afterward returns exactly the cluster just freed — not just
/// "some free cluster exists somewhere," but proof that *this specific*
/// cluster is now genuinely available, which part C's create then actually
/// exercises.
fn run_delete_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((entry, dir_sector, dir_offset)) =
        find_entry_with_location(dev, info, info.root_cluster, &DELETE_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - DELETE_ME.TXT not found in root directory\n");
        return false;
    };
    let freed_cluster = entry.first_cluster;

    let mut cluster = entry.first_cluster;
    let mut free_ok = true;
    for _ in 0..1024u32 {
        let next = next_cluster_in_chain(dev, info, cluster);
        if !write_fat_entry(dev, info, cluster, 0) {
            free_ok = false;
            break;
        }
        match next {
            Some(n) if !is_end_of_chain(n) => cluster = n,
            _ => break,
        }
    }

    let marker_write_ok = match dev.read_sector(u64::from(dir_sector)) {
        Some(mut dir_buf) => {
            dir_buf[dir_offset] = DELETED_ENTRY_MARKER;
            let (completed, status) = dev.write_sector(u64::from(dir_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    let no_longer_found =
        find_entry_in_directory(dev, info, info.root_cluster, &DELETE_FILE_NAME).is_none();
    let freed_cluster_reusable = allocate_free_cluster(dev, info) == Some(freed_cluster);

    write_all(b"blk-driver-host: FAT32 delete free_ok=");
    write_byte(if free_ok { b'1' } else { b'0' });
    write_all(b" marker_write_ok=");
    write_byte(if marker_write_ok { b'1' } else { b'0' });
    write_all(b" no_longer_found=");
    write_byte(if no_longer_found { b'1' } else { b'0' });
    write_all(b" freed_cluster_reusable=");
    write_byte(if freed_cluster_reusable { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = free_ok && marker_write_ok && no_longer_found && freed_cluster_reusable;
    if pass {
        write_all(b"blk-driver-host: FAT32 delete proof OK (Phase 7b PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 delete proof FAILED (Phase 7b FAIL)\n");
    }
    pass
}

/// Filesystem driver, Phase 7, part C: creates `CREATED.TXT` from scratch,
/// reusing the directory slot `run_delete_proof` just freed — this phase's
/// create only ever reuses an *already-deleted* slot; if none exists, it
/// fails closed rather than growing the directory into a new cluster
/// (explicitly out of scope, named up front). Allocates a cluster via
/// [`allocate_free_cluster`] (expected, though not required for
/// correctness, to be the exact cluster part B just freed), writes content
/// into it, marks it EOC, and writes a complete new 32-byte short entry
/// into the reused slot.
fn run_create_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((deleted_sector, deleted_offset)) = find_deleted_slot(dev, info, info.root_cluster)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - no deleted slot available to reuse for create\n");
        return false;
    };

    let Some(new_cluster) = allocate_free_cluster(dev, info) else {
        write_all(b"blk-driver-host: FAT32 FAIL - no free cluster available for create\n");
        return false;
    };
    let Some(new_sector) = info.cluster_to_sector(new_cluster) else {
        write_all(b"blk-driver-host: FAT32 FAIL - new cluster did not resolve to a sector\n");
        return false;
    };

    let mut content = [0u8; SECTOR_SIZE];
    for (i, byte) in content.iter_mut().enumerate().take(CREATE_FILE_LEN) {
        *byte = create_content_byte(i);
    }
    let (data_write_completed, data_write_status) =
        dev.write_sector(u64::from(new_sector), &content);
    let eoc_ok = write_fat_entry(dev, info, new_cluster, 0x0FFF_FFFF);

    let entry_write_ok = match dev.read_sector(u64::from(deleted_sector)) {
        Some(mut dir_buf) => {
            let mut new_entry = [0u8; 32];
            new_entry[0..11].copy_from_slice(&CREATE_FILE_NAME);
            new_entry[11] = ATTR_ARCHIVE;
            let cluster_hi = ((new_cluster >> 16) & 0xFFFF) as u16;
            let cluster_lo = (new_cluster & 0xFFFF) as u16;
            new_entry[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
            new_entry[26..28].copy_from_slice(&cluster_lo.to_le_bytes());
            new_entry[28..32].copy_from_slice(&(CREATE_FILE_LEN as u32).to_le_bytes());
            dir_buf[deleted_offset..deleted_offset + 32].copy_from_slice(&new_entry);
            let (completed, status) = dev.write_sector(u64::from(deleted_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    let mut read_buf = [0u8; MAX_FILE_BYTES];
    let (found_and_correct_size, contents_match) =
        match find_entry_in_directory(dev, info, info.root_cluster, &CREATE_FILE_NAME) {
            Some(fresh_entry) => {
                let written = read_file_contents(dev, info, &fresh_entry, &mut read_buf);
                let size_ok = fresh_entry.file_size as usize == CREATE_FILE_LEN;
                let contents_ok = written == CREATE_FILE_LEN
                    && read_buf[..CREATE_FILE_LEN]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == create_content_byte(i));
                (size_ok, contents_ok)
            }
            None => (false, false),
        };

    write_all(b"blk-driver-host: FAT32 create data_write_completed=");
    write_byte(if data_write_completed { b'1' } else { b'0' });
    write_all(b" status=");
    write_decimal(data_write_status as u64);
    write_all(b" eoc_ok=");
    write_byte(if eoc_ok { b'1' } else { b'0' });
    write_all(b" entry_write_ok=");
    write_byte(if entry_write_ok { b'1' } else { b'0' });
    write_all(b" found_and_correct_size=");
    write_byte(if found_and_correct_size { b'1' } else { b'0' });
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = data_write_completed
        && data_write_status == VIRTIO_BLK_S_OK
        && eoc_ok
        && entry_write_ok
        && found_and_correct_size
        && contents_match;
    if pass {
        write_all(b"blk-driver-host: FAT32 create proof OK (Phase 7c PASS)\n");
    } else {
        write_all(b"blk-driver-host: FAT32 create proof FAILED (Phase 7c FAIL)\n");
    }
    pass
}

/// Scans `dir_cluster`'s cluster chain for the first entry whose first
/// byte is [`DELETED_ENTRY_MARKER`], returning its on-disk location — used
/// only by `run_create_proof`'s "reuse a deleted slot" path. Deliberately
/// distinct from `find_entry_in_directory`'s `chunk[0] == 0x00` check
/// (end-of-directory): a deleted slot is a live, reusable hole *within*
/// the directory, not the end of it, so scanning continues past it either
/// way — this function just also remembers the first one seen.
fn find_deleted_slot(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    dir_cluster: u32,
) -> Option<(u32, usize)> {
    let mut cluster = dir_cluster;
    for _ in 0..1024u32 {
        let sector0 = info.cluster_to_sector(cluster)?;
        for s in 0..u32::from(info.sectors_per_cluster) {
            let sector_num = u64::from(sector0) + u64::from(s);
            let sector = dev.read_sector(sector_num)?;
            for (index, chunk) in sector.chunks_exact(32).enumerate() {
                if chunk[0] == 0x00 {
                    return None; // end of directory, no deleted slot found
                }
                if chunk[0] == DELETED_ENTRY_MARKER {
                    return Some((sector_num as u32, index * 32));
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

/// Maximum LFN fragments this driver reconstructs across — 5 fragments *
/// 13 UTF-16 code units = 65, comfortably past `long-filename-test.txt`'s
/// 22 characters. A name needing more than this is treated as "not
/// matched" (fail closed), not a buffer overrun — see the bounds check on
/// `idx` below.
const MAX_LFN_FRAGMENTS: usize = 5;

/// Same scan shape as [`find_entry_in_directory`], but matching a real
/// long name instead of an 8.3 short one — walks 32-byte entries,
/// accumulating consecutive LFN fragments (in whatever order they arrive;
/// they're stored highest-sequence-first, so fragments are collected into
/// a fixed array indexed by `sequence - 1` and read back out in ascending
/// order once complete) until hitting the short entry they describe.
/// Fragments are only trusted if every sequence `1..=is_last.sequence` was
/// actually seen *and* the short entry's own checksum
/// ([`short_name_checksum`]) matches what every fragment claimed — an
/// incomplete or orphaned run (e.g. left behind by a deletion that only
/// removed the short entry) is never silently accepted.
///
/// ASCII-only comparison: `target_ascii` is zero-extended to `u16` and
/// compared directly against the reconstructed UTF-16, which is correct
/// for any real ASCII name (this driver's whole fixture set) but not a
/// general Unicode-aware match — real LFN names can hold any UTF-16, this
/// slice only ever needs to *find* one it already knows the ASCII spelling
/// of.
fn find_entry_by_long_name(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    dir_cluster: u32,
    target_ascii: &[u8],
) -> Option<blk_driver_host::ShortDirEntry> {
    let mut cluster = dir_cluster;
    let mut fragments = [[0u16; 13]; MAX_LFN_FRAGMENTS];
    let mut have = [false; MAX_LFN_FRAGMENTS];
    let mut pending_checksum: Option<u8> = None;
    let mut fragment_count = 0usize;

    for _ in 0..1024u32 {
        let sector0 = info.cluster_to_sector(cluster)?;
        for s in 0..u32::from(info.sectors_per_cluster) {
            let sector = dev.read_sector(u64::from(sector0) + u64::from(s))?;
            for chunk in sector.chunks_exact(32) {
                if chunk[0] == 0x00 {
                    return None; // end of directory
                }
                let entry_bytes: [u8; 32] = chunk.try_into().unwrap();

                if let Some(fragment) = parse_lfn_fragment(&entry_bytes) {
                    let idx = (fragment.sequence - 1) as usize;
                    if idx < MAX_LFN_FRAGMENTS {
                        fragments[idx] = fragment.chars;
                        have[idx] = true;
                        if fragment.is_last {
                            fragment_count = fragment.sequence as usize;
                            pending_checksum = Some(fragment.checksum);
                        }
                    }
                    continue;
                }

                if let Some(entry) = parse_short_dir_entry(&entry_bytes) {
                    if let Some(expected_checksum) = pending_checksum {
                        let complete = fragment_count > 0 && (0..fragment_count).all(|i| have[i]);
                        let checksum_ok = expected_checksum == short_name_checksum(&entry.name);
                        if complete
                            && checksum_ok
                            && long_name_matches(&fragments[..fragment_count], target_ascii)
                        {
                            return Some(entry);
                        }
                    }
                }
                // A short entry (matched or not) always ends whatever LFN
                // run preceded it -- reset for the next one.
                pending_checksum = None;
                fragment_count = 0;
                have = [false; MAX_LFN_FRAGMENTS];
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

/// Reconstructs the UTF-16 name from `fragments` (ascending sequence
/// order — index 0 is sequence 1, the *start* of the name) and compares
/// it against `target_ascii`, zero-extended to `u16`. Stops at the first
/// `0x0000` terminator, same as the spec requires readers to.
fn long_name_matches(fragments: &[[u16; 13]], target_ascii: &[u8]) -> bool {
    let mut target = target_ascii.iter();
    for fragment in fragments {
        for &c in fragment {
            if c == 0x0000 {
                return target.next().is_none();
            }
            match target.next() {
                Some(&expected) if ascii_case_insensitive_eq(c, expected) => continue,
                _ => return false,
            }
        }
    }
    // Ran out of fragments without hitting a terminator -- only a match if
    // the target was also fully consumed (an exact multiple-of-13-chars
    // name with no trailing NUL fragment, which this fixture never
    // produces, but correctness shouldn't depend on that).
    target.next().is_none()
}

/// Real FAT/VFAT lookups are case-insensitive (LFN preserves *display*
/// case, but matching isn't case-sensitive) — folds `'A'..='Z'` and
/// `'a'..='z'` together on both sides before comparing. ASCII-only, named
/// as this function's own limit: a general Unicode-aware fold (accented
/// characters, locale-specific rules like Turkish dotless i) is a
/// separate, still-open non-goal, not something this driver's fixture set
/// (or its real use case — matching a name this driver already knows the
/// ASCII spelling of) needs.
fn ascii_case_insensitive_eq(utf16_char: u16, ascii_byte: u8) -> bool {
    let folded_ascii = ascii_byte.to_ascii_lowercase();
    let folded_utf16 = if (u16::from(b'A')..=u16::from(b'Z')).contains(&utf16_char) {
        utf16_char + 0x20
    } else {
        utf16_char
    };
    folded_utf16 == u16::from(folded_ascii)
}

/// Fixed-size read buffer -- no `alloc` linked in this crate (see
/// `HEAP_SIZE`'s doc comment). Big enough for this phase's fixed test
/// fixtures with headroom; a file larger than this is a test-fixture bug,
/// not something this driver needs to handle generically yet.
const MAX_FILE_BYTES: usize = 4096;

/// Walks `entry`'s cluster chain, copying up to `buf.len()` (or
/// `entry.file_size`, whichever is smaller) bytes into `buf`, and returns
/// how many bytes were actually written. Shared by Phase 2's own
/// self-contained proof (`run_fat32_proof`) and Phase 3's request-serving
/// loop (`run_fs_ipc_server`) — extracted specifically so both go through
/// the exact same chain-walking code, not two copies that could quietly
/// drift apart.
fn read_file_contents(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    entry: &blk_driver_host::ShortDirEntry,
    buf: &mut [u8],
) -> usize {
    let read_len = (entry.file_size as usize).min(buf.len());
    let mut cluster = entry.first_cluster;
    let mut written = 0usize;
    // Same defensive iteration cap every cluster-chain walk in this
    // module uses -- a corrupt or cyclic FAT must make this driver report
    // failure, not spin forever.
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
                write_all(b"blk-driver-host: FAIL - could not read file data sector\n");
                return written;
            };
            let take = (read_len - written).min(SECTOR_SIZE);
            buf[written..written + take].copy_from_slice(&sector[..take]);
            written += take;
        }
        if written >= read_len {
            break;
        }
        let Some(next) = next_cluster_in_chain(dev, info, cluster) else {
            break;
        };
        if is_end_of_chain(next) {
            break;
        }
        cluster = next;
    }
    written
}

/// Filesystem driver, Phase 3: locates [`TARGET_FILE_NAME`] once, then
/// serves at most one request over the fixed IPC ports (see
/// `FS_REQUEST_PORT`/`FS_RESPONSE_PORT`) -- one trigger byte in, a 2-byte
/// little-endian length header plus that many content bytes out. "At most
/// one" matches every other phase's "prove it once" scope; a real
/// multi-request service is future work once there's more than one
/// process that might ever ask.
fn run_fs_ipc_server(dev: &mut BlkDevice, info: &BootSectorInfo) {
    let Some(entry) = find_entry_in_directory(dev, info, info.root_cluster, &TARGET_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FS server FAIL - target file not found\n");
        return;
    };

    let mut file_buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, info, &entry, &mut file_buf);

    write_all(b"blk-driver-host: FS server ready, waiting for a request\n");

    // Same poll-bound discipline as every other wait loop in this
    // codebase: a real request arrives promptly in practice, so this bound
    // exists purely to make "nobody ever asked" report as a clean timeout
    // instead of hanging the boot forever.
    let mut got_request = false;
    for i in 0..2_000_000u32 {
        if syscall::ipc_try_recv(FS_REQUEST_PORT).is_some() {
            got_request = true;
            break;
        }
        if i % 10_000 == 0 {
            yield_now();
        }
    }

    if !got_request {
        write_all(b"blk-driver-host: FS server FAIL - no request received within poll bound\n");
        return;
    }

    write_all(b"blk-driver-host: FS server got a request, replying with ");
    write_decimal(written as u64);
    write_all(b" bytes\n");

    let len_bytes = (written as u16).to_le_bytes();
    let _ = syscall::ipc_send(FS_RESPONSE_PORT, len_bytes[0]);
    let _ = syscall::ipc_send(FS_RESPONSE_PORT, len_bytes[1]);
    for &byte in &file_buf[..written] {
        let _ = syscall::ipc_send(FS_RESPONSE_PORT, byte);
    }
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

/// Same scan as [`find_entry_in_directory`], but also returns *where* the
/// short entry itself lives (`(sector, offset_in_sector)`) — needed only
/// by a caller that intends to patch a field of the entry in place (Phase
/// 6's `file_size` update), which `find_entry_in_directory` itself never
/// needs to know. A new function rather than a changed return type on the
/// existing one, so every current caller keeps compiling unchanged.
fn find_entry_with_location(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    dir_cluster: u32,
    target_name: &[u8; 11],
) -> Option<(blk_driver_host::ShortDirEntry, u32, usize)> {
    let mut cluster = dir_cluster;
    for _ in 0..1024u32 {
        let sector0 = info.cluster_to_sector(cluster)?;
        for s in 0..u32::from(info.sectors_per_cluster) {
            let sector_num = u64::from(sector0) + u64::from(s);
            let sector = dev.read_sector(sector_num)?;
            for (index, chunk) in sector.chunks_exact(32).enumerate() {
                if chunk[0] == 0x00 {
                    return None;
                }
                let entry_bytes: [u8; 32] = chunk.try_into().unwrap();
                if let Some(entry) = parse_short_dir_entry(&entry_bytes) {
                    if entry.name == *target_name {
                        return Some((entry, sector_num as u32, index * 32));
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
