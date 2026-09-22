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

extern crate alloc;

mod syscall;
mod virtio;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use blk_driver_host::{
    encode_short_name, fat_entry_at, is_end_of_chain, parse_lfn_fragment, parse_short_dir_entry,
    short_name_checksum, BootSectorInfo, FsInfoSector, FSINFO_UNKNOWN,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use linked_list_allocator::LockedHeap;
use runix_capability_manager::CapabilityToken;
use runix_ipc::fs::{FsError, FsRequest, FsResponse};
use syscall::{write_all, write_byte, yield_now};
use virtio::{VirtioBlk, Virtqueue};

/// Demo capability trust root: **the same fixed seed**
/// `kernel/src/capabilities.rs`'s `DEMO_SEED` uses — a token
/// `kernel/src/capabilities.rs` issues (or a test issues via that same
/// module) has to verify against the identical public key here, or every
/// per-file authorization check in [`verify_file_token`] would reject a
/// legitimately-issued token. Not a real secret (see that module's own
/// doc comment for the full reasoning) — this driver only ever needs the
/// *public* half, but reconstructing it from the seed keeps the two
/// independently-compiled crates trivially in sync instead of hand-copying
/// a raw public-key byte string that could silently drift from the
/// signing side.
///
/// Gated behind `insecure-demo-keys` (on by default — see `Cargo.toml`),
/// same convention and same reasoning as `kernel/src/capabilities.rs`'s
/// own feature: there is no real key provisioning yet, so a release build
/// that disables default features gets a compile error here instead of a
/// silently-shipped demo trust root.
#[cfg(not(feature = "insecure-demo-keys"))]
compile_error!(
    "main.rs's hardcoded Ed25519 demo trust root (verify_file_token) requires the \
     `insecure-demo-keys` feature. There is no real key provisioning yet -- if this is \
     meant to ship, that has to exist first. If this is still an alpha/dev build, \
     re-enable default features."
);

const DEMO_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn demo_verifying_key() -> VerifyingKey {
    SigningKey::from_bytes(&DEMO_SEED).verifying_key()
}

/// The resource-string convention a per-file capability token must match
/// -- mirrors `kernel/src/capabilities.rs`'s own `file_resource`; a token
/// issued via that function for `name` verifies against exactly this
/// string. Not shared code between the two crates (same "no shared type,
/// just an agreed convention" reasoning as every other kernel/ring-3
/// boundary in this codebase) -- kept in sync by both sides using the same
/// literal `"file:{name}"` shape, checked end to end by
/// `kernel/tests/blk_fs_ipc.rs`.
fn file_resource(name: &str) -> String {
    format!("file:{name}")
}

/// Verifies `token` was validly signed by the demo trust root, hasn't
/// expired (checked against [`syscall::ticks`] -- see that function's own
/// doc comment for why this driver needs a syscall for "now" at all), and
/// is scoped to exactly `file:<name>`, not some other resource -- the
/// per-request authorization [`runix_ipc::fs`]'s own doc comment names as
/// the actual point of embedding a capability token in every request,
/// rather than relying solely on the coarser port-level capability the
/// kernel's `SYS_IPC_SEND` gate already checks.
///
/// Deliberately does **not** consult a revocation list: this driver has
/// no access to the kernel's own `capabilities::REVOCATIONS` state (it's
/// kernel-internal, not exposed over any syscall) -- a revoked-but-not-yet-
/// expired file token would still verify here. Named explicitly as a known
/// limitation, not silently assumed solved: closing it needs either a new
/// syscall exposing revocation status or routing file-capability
/// revocation through the kernel's existing `SYS_IPC_SEND` gate instead
/// (e.g. a dedicated revocation-check port), neither of which exists yet.
fn verify_file_token(token: &CapabilityToken, name: &str) -> bool {
    let now = syscall::ticks();
    token
        .verify(&demo_verifying_key(), &file_resource(name), now)
        .is_ok()
}

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
/// Filesystem driver, Phase 8: a second, independently capability-gated
/// port for write requests against [`WRITE_FILE_NAME`] — a caller needs a
/// capability scoped to `port_resource(FS_WRITE_REQUEST_PORT)` specifically,
/// separate from whatever authorizes reading [`TARGET_FILE_NAME`] on
/// [`FS_REQUEST_PORT`]. One port per file, reusing the existing
/// `port_resource` convention exactly as `SYS_IPC_SEND` already enforces
/// it — not a new resource-string kind (a real path-scoped capability
/// convention for arbitrary/dynamic filenames stays open, see
/// `docs/THREAT_MODEL.md`). Must match `kernel/src/main.rs`'s own
/// `BLK_FS_WRITE_REQUEST_PORT` constant exactly.
const FS_WRITE_REQUEST_PORT: usize = 10;

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

/// Filesystem driver, structural gap closed: multi-cluster allocation.
/// `MULTI.TXT` starts at exactly one full cluster (512 bytes, same
/// no-existing-slack setup as [`GROW_FILE_NAME`]) — `run_multi_cluster_grow_proof`
/// appends [`MULTI_APPEND_LEN`] bytes (spanning two more clusters) in a
/// *single* [`allocate_cluster_chain`] call, isolated on purpose from
/// Phase 7a's `run_grow_proof` (one new cluster per call).
const MULTI_FILE_NAME: [u8; 11] = *b"MULTI   TXT";
const MULTI_INITIAL_LEN: usize = 512;
const MULTI_APPEND_LEN: usize = 700;
fn multi_initial_byte(i: usize) -> u8 {
    b'm' + (i % 5) as u8
}
fn multi_append_byte(i: usize) -> u8 {
    b'0' + (i % 10) as u8
}

/// Filesystem driver, structural gap closed: directory growth.
/// `GROWDIR.TXT` is never present in the fixture image itself — it's
/// created entirely at runtime by `run_directory_growth_proof`, once
/// `make_fat32_image.sh`'s filler entries plus Phase 7's own delete+create
/// have left the root directory's one existing cluster with no reusable
/// slot anywhere in it, forcing a genuine, first-of-its-kind
/// directory-chain extension.
const GROWDIR_FILE_NAME: [u8; 11] = *b"GROWDIR TXT";
const GROWDIR_FILE_LEN: usize = 40;
fn growdir_content_byte(i: usize) -> u8 {
    if i % 2 == 0 {
        b'G'
    } else {
        b'D'
    }
}

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
    let multi_grow_pass = run_multi_cluster_grow_proof(dev, &info);
    let delete_pass = run_delete_proof(dev, &info);
    let create_pass = run_create_proof(dev, &info);
    let directory_growth_pass = run_directory_growth_proof(dev, &info);
    let fsinfo_hint_pass = run_fsinfo_hint_proof(dev, &info);

    let pass = contents_match
        && subdir_pass
        && big_file_pass
        && long_name_pass
        && write_pass
        && partial_write_pass
        && grow_pass
        && multi_grow_pass
        && fsinfo_hint_pass
        && delete_pass
        && create_pass
        && directory_growth_pass;
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

/// Locates `target_name` and resolves its first (and, for every file this
/// helper is used against, only) cluster to a sector — shared by
/// `run_write_proof` (Phase 5's self-contained proof) and Phase 8's IPC
/// write handler (`handle_write_request`), so both go through the exact
/// same lookup, not two copies that could quietly drift apart. Only valid
/// for a whole-single-sector file, same limit `run_write_proof` already
/// documented; a general write path would need to walk the whole chain
/// the way `read_file_contents` does.
fn resolve_single_sector_file(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    target_name: &[u8; 11],
) -> Option<u32> {
    let entry = find_entry_in_directory(dev, info, info.root_cluster, target_name)?;
    info.cluster_to_sector(entry.first_cluster)
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
    let Some(sector) = resolve_single_sector_file(dev, info, &WRITE_FILE_NAME) else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - WRITE.TXT not found or its cluster did not resolve to a sector\n",
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

    // Structural gap closed: the FSInfo free-cluster-count hint. Captured
    // from the *first* FAT copy's existing entry before any write happens
    // -- every copy is kept byte-identical by this same function (see its
    // own doc comment), so the first copy's masked value is exactly the
    // "was this cluster free before this call" answer the hint update
    // below needs. `None` (a read failure) means "don't know" -- treated
    // the same as "no transition", not a guess.
    let mut previous_masked: Option<u32> = None;

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
        if fat_copy == 0 {
            previous_masked = Some(existing & 0x0FFF_FFFF);
        }
        let reserved_top_bits = existing & 0xF000_0000;
        let new_value = reserved_top_bits | masked;
        sector[offset_in_sector..offset_in_sector + 4].copy_from_slice(&new_value.to_le_bytes());
        let (completed, status) = dev.write_sector(u64::from(fat_sector), &sector);
        if !completed || status != VIRTIO_BLK_S_OK {
            return false;
        }
    }

    // A transition strictly between "free" (0) and "used" (nonzero) is the
    // only case the hint tracks -- a link rewrite between two already-used
    // values (e.g. extending a chain's tail pointer) changes no cluster's
    // free/used status, so it must not double-count. Best-effort: a
    // missing/invalid FSInfo sector (`adjust_fsinfo_free_count`'s own doc
    // comment) silently skips the update rather than failing this whole,
    // already-committed write.
    if let Some(previous) = previous_masked {
        match (previous == 0, masked == 0) {
            (true, false) => adjust_fsinfo_free_count(dev, info, -1),
            (false, true) => adjust_fsinfo_free_count(dev, info, 1),
            _ => {}
        }
    }
    true
}

/// Reads the FSInfo sector, and if it parses as a real FSInfo structure
/// with a *known* (not [`FSINFO_UNKNOWN`]) `free_count`, applies `delta`
/// (`+1`/`-1` from [`write_fat_entry`]'s own transition detection) and
/// writes it back — the structural gap `docs/STATUS.md`'s filesystem-
/// driver section named ("the FSInfo sector's free-cluster-count/
/// next-free hint... a real OS reading this volume afterward would see a
/// stale hint"). Silently does nothing if the sector doesn't parse (no
/// FSInfo sector on this volume, or a corrupt one) or if `free_count`
/// already reads as "unknown" -- this driver's own correctness never
/// depends on the hint (`allocate_free_cluster` always scans the FAT
/// itself), so there's nothing to fail here that would mean anything to
/// the caller, which has already committed its own FAT write regardless.
fn adjust_fsinfo_free_count(dev: &mut BlkDevice, info: &BootSectorInfo, delta: i32) {
    let Some(mut sector) = dev.read_sector(u64::from(info.fsinfo_sector)) else {
        return;
    };
    let Some(mut fsinfo) = FsInfoSector::parse(&sector) else {
        return;
    };
    if fsinfo.free_count == FSINFO_UNKNOWN {
        return;
    }
    fsinfo.free_count = if delta < 0 {
        fsinfo.free_count.saturating_sub(delta.unsigned_abs())
    } else {
        fsinfo.free_count.saturating_add(delta as u32)
    };
    fsinfo.encode_into(&mut sector);
    let _ = dev.write_sector(u64::from(info.fsinfo_sector), &sector);
}

/// Writes `0` (free) into every entry in `clusters` — the rollback half of
/// [`allocate_cluster_chain`]: if that function can't reserve as many
/// clusters as it was asked for, every cluster it *did* reserve so far in
/// that same call must be freed back, not left permanently claimed but
/// unused by anything. Best-effort: a write failure partway through a
/// rollback is already a device-level fault this driver has no clean way
/// to recover from either way, so this doesn't itself report success or
/// failure — the caller that triggered the rollback is already reporting
/// its own failure regardless.
fn free_clusters(dev: &mut BlkDevice, info: &BootSectorInfo, clusters: &[u32]) {
    for &cluster in clusters {
        let _ = write_fat_entry(dev, info, cluster, 0);
    }
}

/// Structural gap closed: the FSInfo free-cluster-count hint actually
/// tracks real allocations/frees, not just this driver's own (already
/// FSInfo-independent) internal bookkeeping. Self-contained, deliberately
/// isolated from every other proof in this file: reads the hint before
/// touching anything, allocates one cluster (mirroring
/// [`allocate_free_cluster`] + [`write_fat_entry`]'s exact commit
/// sequence every real allocation site in this module uses), confirms the
/// hint dropped by exactly one, frees that same cluster back via
/// [`write_fat_entry`], and confirms the hint returned to its original
/// value — proving both directions of [`adjust_fsinfo_free_count`]'s
/// transition detection, not just one.
fn run_fsinfo_hint_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some(before_sector) = dev.read_sector(u64::from(info.fsinfo_sector)) else {
        write_all(b"blk-driver-host: FAT32 FAIL - could not read FSInfo sector\n");
        return false;
    };
    let Some(before) = FsInfoSector::parse(&before_sector) else {
        write_all(b"blk-driver-host: FAT32 FAIL - FSInfo sector did not parse\n");
        return false;
    };
    if before.free_count == FSINFO_UNKNOWN {
        write_all(b"blk-driver-host: FAT32 FSInfo hint unknown, skipping (fixture limitation)\n");
        // Nothing this driver can meaningfully check against an
        // intentionally-unmaintained hint -- not a failure of this
        // driver's own write path, so this doesn't fail the whole boot.
        return true;
    }

    let Some(cluster) = allocate_free_cluster(dev, info) else {
        write_all(b"blk-driver-host: FAT32 FAIL - no free cluster available for FSInfo proof\n");
        return false;
    };
    if !write_fat_entry(dev, info, cluster, blk_driver_host::CHAIN_EOC_MARKER) {
        write_all(b"blk-driver-host: FAT32 FAIL - could not mark cluster used for FSInfo proof\n");
        return false;
    }

    let after_allocate_ok = match dev
        .read_sector(u64::from(info.fsinfo_sector))
        .and_then(|s| FsInfoSector::parse(&s))
    {
        Some(after) => after.free_count == before.free_count - 1,
        None => false,
    };

    if !write_fat_entry(dev, info, cluster, 0) {
        write_all(b"blk-driver-host: FAT32 FAIL - could not free cluster back for FSInfo proof\n");
        return false;
    }

    let after_free_ok = match dev
        .read_sector(u64::from(info.fsinfo_sector))
        .and_then(|s| FsInfoSector::parse(&s))
    {
        Some(after) => after.free_count == before.free_count,
        None => false,
    };

    write_all(b"blk-driver-host: FAT32 fsinfo_hint before=");
    write_decimal(u64::from(before.free_count));
    write_all(b" after_allocate_ok=");
    write_byte(if after_allocate_ok { b'1' } else { b'0' });
    write_all(b" after_free_ok=");
    write_byte(if after_free_ok { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = after_allocate_ok && after_free_ok;
    if pass {
        write_all(b"blk-driver-host: FAT32 FSInfo hint proof OK\n");
    } else {
        write_all(b"blk-driver-host: FAT32 FSInfo hint proof FAILED\n");
    }
    pass
}

/// Filesystem driver, structural gap closed: allocates `count` fresh,
/// mutually linked clusters in a single call — the multi-cluster
/// generalization of [`allocate_free_cluster`] (still used internally, once
/// per new cluster) that Phase 7's own doc comment named as "not attempted,
/// unchanged" ("allocating or linking more than one cluster in a single
/// grow/create call"). On success, `out[..count]` holds the reserved
/// cluster numbers in chain order (`out[0]` is the new chain's head) and
/// every one of them already has its own correct FAT entry written (link
/// to its successor, or [`blk_driver_host::CHAIN_EOC_MARKER`] for the last)
/// — the caller can splice this whole chain onto an existing one with a
/// single further link write, the same "new chain fully initialized before
/// anything points at it" precondition `run_grow_proof` already established
/// for the single-cluster case.
///
/// Two-pass by necessity: [`allocate_free_cluster`] only ever finds a
/// cluster currently reading as `0x00000000` in the FAT, so each
/// newly-found cluster must be marked non-zero (reserved, temporarily as
/// its own EOC marker) *before* scanning for the next one — otherwise a
/// second scan in the same call would find and "reserve" the exact same
/// cluster already claimed a moment earlier — a single call reserving the
/// same cluster twice would be a correctness bug regardless of whether any
/// concurrency exists. Once all `count` clusters
/// are reserved this way, a second pass rewrites every entry via
/// [`blk_driver_host::chain_link_values`] — the last cluster's rewrite
/// happens to write back the same EOC value its reservation step already
/// gave it, harmless and simpler than special-casing it.
///
/// Fails closed on any error (not enough free clusters, or a write
/// failure): every cluster reserved so far in *this* call is freed back via
/// [`free_clusters`] before returning `false` — never half-committed.
///
/// **Not re-entrancy-safe, and does not need to be — verified, not
/// assumed** (`docs/STATUS.md`'s "concurrent *allocators*" gap). This
/// function yields to the scheduler while it runs (every `write_fat_entry`
/// goes through `dev.write_sector` → `poll_for_completion`'s `yield_now`),
/// so a *second* concurrent caller would observe a half-reserved chain.
/// Two independent properties of this driver mean no second caller can
/// exist today, both checked against the code rather than inferred from
/// this comment's earlier bare assertion that "no concurrency exists":
///
/// 1. Every call site of this function and of [`allocate_free_cluster`]
///    lives in `_start`'s `attempt_fat32` branch ([`run_grow_proof`],
///    [`run_multi_cluster_grow_proof`], [`run_create_proof`],
///    [`run_directory_growth_proof`], [`run_fsinfo_hint_proof`]), which is
///    *mutually exclusive* with the `serve_fs_requests` branch that enters
///    [`run_fs_ipc_server`]. Nothing reachable over IPC allocates at all:
///    [`handle_write_ipc_request`] writes exactly one already-allocated
///    sector and rejects anything else.
/// 2. This process is a single ring 3 thread (spawned once via
///    `scheduler::spawn_ring3_process_with_capabilities`) with no second
///    thread, no async executor and no interrupt handler of its own.
///    [`run_fs_ipc_server`] calls its handler inline and cannot begin
///    decoding the next request until the current one has fully returned.
///    The kernel's scheduler *is* timer-preemptive, but preemption
///    suspends and later resumes this same context — it never produces a
///    second one — and no other process holds the virtio-blk io-port
///    capability needed to touch the FAT at all.
///
/// `kernel/tests/blk_fs_concurrent_write.rs` is the QEMU proof of the
/// serialization half (two genuinely racing callers, two *mutating*
/// requests, both files intact afterwards). Property 2 is what would have
/// to be re-verified — and this function given a real mutual-exclusion
/// guard — if this driver ever gains internal concurrency (per-client
/// scheduled tasks instead of one sequential loop, say), or if any
/// allocating operation is exposed over IPC.
fn allocate_cluster_chain(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    count: usize,
    out: &mut [u32],
) -> bool {
    if count == 0 || out.len() < count {
        return false;
    }

    let mut reserved = 0usize;
    while reserved < count {
        let Some(cluster) = allocate_free_cluster(dev, info) else {
            free_clusters(dev, info, &out[..reserved]);
            return false;
        };
        if !write_fat_entry(dev, info, cluster, blk_driver_host::CHAIN_EOC_MARKER) {
            free_clusters(dev, info, &out[..reserved]);
            return false;
        }
        out[reserved] = cluster;
        reserved += 1;
    }

    for (cluster, value) in blk_driver_host::chain_link_values(&out[..count]) {
        if !write_fat_entry(dev, info, cluster, value) {
            free_clusters(dev, info, &out[..count]);
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
        if let Some(cluster) = blk_driver_host::first_free_cluster_in_fat_sector(
            &sector,
            fat_sector_index,
            entries_per_sector,
        ) {
            return Some(cluster);
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
/// reusing the directory slot `run_delete_proof` just freed. Allocates a
/// cluster via [`allocate_free_cluster`] (expected, though not required for
/// correctness, to be the exact cluster part B just freed), writes content
/// into it, marks it EOC, and writes a complete new 32-byte short entry
/// into the reused slot.
///
/// Slot lookup goes through [`find_or_grow_create_slot`] (structural gap
/// closed: this used to be `find_deleted_slot`, which only ever considered
/// an already-deleted slot and failed closed otherwise, never growing the
/// directory) — here it's still expected to find `DELETE_M.TXT`'s
/// just-freed slot without needing to grow anything; `run_directory_growth_proof`
/// is what actually exercises this same function's growth branch, once the
/// fixture's root directory has no reusable slot left anywhere in it.
fn run_create_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((deleted_sector, deleted_offset)) =
        find_or_grow_create_slot(dev, info, info.root_cluster)
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

/// Filesystem driver, structural gap closed: grows `MULTI.TXT` (starting at
/// exactly one full cluster, no existing slack — same setup as
/// [`run_grow_proof`]'s `GROW.TXT`) by [`MULTI_APPEND_LEN`] bytes, spanning
/// *two* brand-new clusters allocated and linked together in a single
/// [`allocate_cluster_chain`] call — Phase 7's own "not attempted,
/// unchanged" item ("allocating or linking more than one cluster in a
/// single grow/create call"), isolated from `run_grow_proof`'s
/// one-cluster-at-a-time case the same way that function was isolated from
/// Phase 6's partial-fill case.
///
/// Ordering safety: both new clusters have their content written and their
/// mutual FAT links already correct (via `allocate_cluster_chain`, which
/// itself writes each new cluster's link before returning) *before* the
/// existing last cluster of `MULTI.TXT`'s current chain is repointed at the
/// new chain's head — the same "fully initialize, then splice in" sequence
/// `run_grow_proof` proved for one new cluster, now proved for two written
/// and linked together in the same call.
fn run_multi_cluster_grow_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((entry, dir_sector, dir_offset)) =
        find_entry_with_location(dev, info, info.root_cluster, &MULTI_FILE_NAME)
    else {
        write_all(b"blk-driver-host: FAT32 FAIL - MULTI.TXT not found in root directory\n");
        return false;
    };

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
        write_all(b"blk-driver-host: FAT32 FAIL - could not walk MULTI.TXT's existing chain\n");
        return false;
    }

    let mut new_clusters = [0u32; 2];
    if !allocate_cluster_chain(dev, info, 2, &mut new_clusters) {
        write_all(
            b"blk-driver-host: FAT32 FAIL - could not allocate two clusters for MULTI.TXT in one call\n",
        );
        return false;
    }

    let mut data_writes_ok = true;
    for (k, &cluster) in new_clusters.iter().enumerate() {
        let Some(sector) = info.cluster_to_sector(cluster) else {
            data_writes_ok = false;
            break;
        };
        let mut content = [0u8; SECTOR_SIZE];
        let base = k * SECTOR_SIZE;
        for (i, byte) in content.iter_mut().enumerate() {
            let global_i = base + i;
            if global_i >= MULTI_APPEND_LEN {
                break;
            }
            *byte = multi_append_byte(global_i);
        }
        let (completed, status) = dev.write_sector(u64::from(sector), &content);
        if !completed || status != VIRTIO_BLK_S_OK {
            data_writes_ok = false;
            break;
        }
    }

    // Both new clusters fully initialized (content written, mutual FAT
    // links already correct) before the existing chain is repointed at the
    // new chain's head.
    let link_ok = write_fat_entry(dev, info, last_cluster, new_clusters[0]);

    let new_size = (MULTI_INITIAL_LEN + MULTI_APPEND_LEN) as u32;
    let size_write_ok = match dev.read_sector(u64::from(dir_sector)) {
        Some(mut dir_buf) => {
            let size_offset = dir_offset + 28;
            dir_buf[size_offset..size_offset + 4].copy_from_slice(&new_size.to_le_bytes());
            let (completed, status) = dev.write_sector(u64::from(dir_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    let mut read_buf = [0u8; MAX_FILE_BYTES];
    let (size_visible, contents_match) =
        match find_entry_in_directory(dev, info, info.root_cluster, &MULTI_FILE_NAME) {
            Some(fresh_entry) => {
                let written = read_file_contents(dev, info, &fresh_entry, &mut read_buf);
                let size_ok = fresh_entry.file_size == new_size;
                let contents_ok = written == new_size as usize
                    && read_buf[..MULTI_INITIAL_LEN]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == multi_initial_byte(i))
                    && read_buf[MULTI_INITIAL_LEN..written]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == multi_append_byte(i));
                (size_ok, contents_ok)
            }
            None => (false, false),
        };

    write_all(b"blk-driver-host: FAT32 multi-cluster grow data_writes_ok=");
    write_byte(if data_writes_ok { b'1' } else { b'0' });
    write_all(b" link_ok=");
    write_byte(if link_ok { b'1' } else { b'0' });
    write_all(b" size_write_ok=");
    write_byte(if size_write_ok { b'1' } else { b'0' });
    write_all(b" size_visible=");
    write_byte(if size_visible { b'1' } else { b'0' });
    write_all(b" contents_match=");
    write_byte(if contents_match { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = data_writes_ok && link_ok && size_write_ok && size_visible && contents_match;
    if pass {
        write_all(b"blk-driver-host: FAT32 multi-cluster grow proof OK\n");
    } else {
        write_all(b"blk-driver-host: FAT32 multi-cluster grow proof FAILED\n");
    }
    pass
}

/// Filesystem driver, structural gap closed: creates `GROWDIR.TXT` when the
/// root directory's already-allocated cluster chain is genuinely full.
/// `make_fat32_image.sh`'s filler entries size the fixture's root directory
/// so that, after Phase 7's own delete + create leave it at exactly the
/// same occupancy as before (one slot freed, the same slot immediately
/// reused), there is no deleted or end-of-directory sentinel slot anywhere
/// left in it — the first real exercise of [`find_or_grow_create_slot`]'s
/// growth branch (`grow_directory`), not just its "reuse an existing slot"
/// one (already exercised, unchanged, by `run_create_proof` reusing
/// `DELETE_M.TXT`'s freed slot).
fn run_directory_growth_proof(dev: &mut BlkDevice, info: &BootSectorInfo) -> bool {
    let Some((slot_sector, slot_offset)) = find_or_grow_create_slot(dev, info, info.root_cluster)
    else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - directory growth did not produce a usable slot\n",
        );
        return false;
    };

    let Some(new_cluster) = allocate_free_cluster(dev, info) else {
        write_all(b"blk-driver-host: FAT32 FAIL - no free cluster available for GROWDIR.TXT\n");
        return false;
    };
    let Some(new_sector) = info.cluster_to_sector(new_cluster) else {
        write_all(
            b"blk-driver-host: FAT32 FAIL - GROWDIR.TXT's new cluster did not resolve to a sector\n",
        );
        return false;
    };

    let mut content = [0u8; SECTOR_SIZE];
    for (i, byte) in content.iter_mut().enumerate().take(GROWDIR_FILE_LEN) {
        *byte = growdir_content_byte(i);
    }
    let (data_write_completed, data_write_status) =
        dev.write_sector(u64::from(new_sector), &content);
    let eoc_ok = write_fat_entry(dev, info, new_cluster, 0x0FFF_FFFF);

    let entry_write_ok = match dev.read_sector(u64::from(slot_sector)) {
        Some(mut dir_buf) => {
            let mut new_entry = [0u8; 32];
            new_entry[0..11].copy_from_slice(&GROWDIR_FILE_NAME);
            new_entry[11] = ATTR_ARCHIVE;
            let cluster_hi = ((new_cluster >> 16) & 0xFFFF) as u16;
            let cluster_lo = (new_cluster & 0xFFFF) as u16;
            new_entry[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
            new_entry[26..28].copy_from_slice(&cluster_lo.to_le_bytes());
            new_entry[28..32].copy_from_slice(&(GROWDIR_FILE_LEN as u32).to_le_bytes());
            dir_buf[slot_offset..slot_offset + 32].copy_from_slice(&new_entry);
            let (completed, status) = dev.write_sector(u64::from(slot_sector), &dir_buf);
            completed && status == VIRTIO_BLK_S_OK
        }
        None => false,
    };

    let mut read_buf = [0u8; MAX_FILE_BYTES];
    let (found_and_correct_size, contents_match) =
        match find_entry_in_directory(dev, info, info.root_cluster, &GROWDIR_FILE_NAME) {
            Some(fresh_entry) => {
                let written = read_file_contents(dev, info, &fresh_entry, &mut read_buf);
                let size_ok = fresh_entry.file_size as usize == GROWDIR_FILE_LEN;
                let contents_ok = written == GROWDIR_FILE_LEN
                    && read_buf[..GROWDIR_FILE_LEN]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == growdir_content_byte(i));
                (size_ok, contents_ok)
            }
            None => (false, false),
        };

    // The real point of this phase: confirm the *directory itself* actually
    // grew a new cluster -- not just that the file happened to get created
    // somehow. The root directory's chain must now be more than one
    // cluster long.
    let root_chain_grew = match next_cluster_in_chain(dev, info, info.root_cluster) {
        Some(next) => !is_end_of_chain(next),
        None => false,
    };

    write_all(b"blk-driver-host: FAT32 directory growth data_write_completed=");
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
    write_all(b" root_chain_grew=");
    write_byte(if root_chain_grew { b'1' } else { b'0' });
    write_byte(b'\n');

    let pass = data_write_completed
        && data_write_status == VIRTIO_BLK_S_OK
        && eoc_ok
        && entry_write_ok
        && found_and_correct_size
        && contents_match
        && root_chain_grew;
    if pass {
        write_all(b"blk-driver-host: FAT32 directory growth proof OK\n");
    } else {
        write_all(b"blk-driver-host: FAT32 directory growth proof FAILED\n");
    }
    pass
}

/// Filesystem driver, structural gap closed: locates a slot in
/// `dir_cluster`'s chain a new short entry can be written into, growing the
/// directory by one cluster (via [`grow_directory`]) if every
/// already-allocated cluster in the chain is genuinely full — no deleted
/// (`0xE5`) and no end-of-directory (`0x00`) sentinel slot anywhere in it.
/// Named as Phase 7's own "not attempted, unchanged" item ("growing the
/// *directory* itself").
///
/// Per-sector decision goes through [`blk_driver_host::find_reusable_slot`]
/// — the same pure logic tested on the host in `lib.rs` — rather than
/// re-deriving "is this slot reusable" inline. This closes a second gap
/// along the way, not just the multi-cluster one: the function this
/// replaced (`find_deleted_slot`) only ever considered an *already-deleted*
/// slot and failed closed the moment it hit a `0x00` sentinel, meaning a
/// directory that had simply never had anything deleted from it could
/// never create past its first still-unused sentinel slot even when there
/// was obviously room. This function tries the sentinel too before ever
/// concluding growth is needed.
fn find_or_grow_create_slot(
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
            if let Some(index) = blk_driver_host::find_reusable_slot(&sector) {
                return Some((sector_num as u32, index * 32));
            }
        }
        let next = next_cluster_in_chain(dev, info, cluster)?;
        if is_end_of_chain(next) {
            return grow_directory(dev, info, cluster);
        }
        cluster = next;
    }
    None
}

/// Allocates and links exactly one new cluster onto `last_cluster` (the
/// last cluster of a directory chain already confirmed, by
/// [`find_or_grow_create_slot`], to have no reusable slot anywhere in it),
/// zeroes every byte of it, and returns its first slot — `(sector, 0)` —
/// for the caller to write a new short entry into. An all-zero cluster is
/// already a valid, empty directory cluster on its own: entry `0` at offset
/// `0` reads as the end-of-directory sentinel, the same as any other
/// cluster's trailing unused entries.
///
/// Ordering safety, same discipline `run_grow_proof`'s own doc comment
/// established for a file chain: [`allocate_cluster_chain`] reserves the
/// new cluster and gives it its own EOC marker *before* this function
/// zeroes its content, and only once the zero-fill write has itself
/// completed does this link `last_cluster` onto it — a crash at any point
/// before that final link leaves the new cluster an unreferenced (harmless)
/// orphan, never a directory chain pointing at a half-initialized cluster.
fn grow_directory(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    last_cluster: u32,
) -> Option<(u32, usize)> {
    let mut new_clusters = [0u32; 1];
    if !allocate_cluster_chain(dev, info, 1, &mut new_clusters) {
        return None;
    }
    let new_cluster = new_clusters[0];
    let sector0 = info.cluster_to_sector(new_cluster)?;

    let zeroed = [0u8; SECTOR_SIZE];
    for s in 0..u32::from(info.sectors_per_cluster) {
        let sector_num = u64::from(sector0) + u64::from(s);
        let (completed, status) = dev.write_sector(sector_num, &zeroed);
        if !completed || status != VIRTIO_BLK_S_OK {
            // Leave the reserved-but-unlinked cluster as an orphan rather
            // than risk linking a half-zeroed cluster into the directory
            // chain -- a future allocation scan can't reclaim it (its FAT
            // entry still reads as EOC, not free), but a device write
            // failing this deep is already a fault this driver has no
            // clean way to recover from either way.
            return None;
        }
    }

    if !write_fat_entry(dev, info, last_cluster, new_cluster) {
        return None;
    }
    Some((sector0, 0))
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

/// Locates `name` (an arbitrary display-form ASCII filename arriving over
/// IPC — see [`runix_ipc::fs::FsRequest`]) in `dir_cluster`, trying the
/// short-name path first ([`encode_short_name`] + [`find_entry_in_directory`])
/// and falling back to the long-name path ([`find_entry_by_long_name`])
/// when `name` doesn't fit 8.3 — the generalization of every existing
/// fixed-name lookup in this file (each of which only ever had to handle
/// one hardcoded name, known in advance to fit whichever path it used) to
/// a name this driver doesn't know ahead of time. Item 1's actual point:
/// this is the one lookup [`run_fs_ipc_server`] now calls for *any*
/// requested filename, not a fixed port-per-file mapping decided at spawn
/// time.
fn find_entry_by_display_name(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    dir_cluster: u32,
    name: &str,
) -> Option<blk_driver_host::ShortDirEntry> {
    if let Some(short) = encode_short_name(name.as_bytes()) {
        if let Some(entry) = find_entry_in_directory(dev, info, dir_cluster, &short) {
            return Some(entry);
        }
    }
    find_entry_by_long_name(dev, info, dir_cluster, name.as_bytes())
}

/// Same lookup [`resolve_single_sector_file`] already does for a fixed
/// name, generalized to an arbitrary display-form name — the write IPC
/// path's own scope limit (see [`handle_write_ipc_request`]'s doc
/// comment): only ever a name that fits 8.3 ([`encode_short_name`]),
/// matching every write this driver has ever supported (single sector, no
/// resize, no long-name directory entries to patch).
fn resolve_single_sector_file_by_name(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    name: &str,
) -> Option<u32> {
    let short = encode_short_name(name.as_bytes())?;
    resolve_single_sector_file(dev, info, &short)
}

/// Filesystem driver, structural gap closed: [`handle_read_ipc_request`]
/// verifies `token` against `file:<name>` ([`verify_file_token`]) before
/// ever touching the device — the per-caller, per-file authorization
/// [`runix_ipc::fs`]'s own doc comment names as the actual point of this
/// slice, checked here rather than only at the coarser port level the
/// kernel's own `SYS_IPC_SEND` gate already enforces (unchanged: a caller
/// still needs a `port:<n>` capability to reach this server at all).
fn handle_read_ipc_request(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    name: &str,
    token: &CapabilityToken,
) -> FsResponse {
    if !verify_file_token(token, name) {
        return FsResponse::Error(FsError::Unauthorized);
    }
    let Some(entry) = find_entry_by_display_name(dev, info, info.root_cluster, name) else {
        return FsResponse::Error(FsError::NotFound);
    };
    if entry.is_dir {
        return FsResponse::Error(FsError::NotFound);
    }
    let mut buf = [0u8; MAX_FILE_BYTES];
    let written = read_file_contents(dev, info, &entry, &mut buf);
    FsResponse::Data(Vec::from(&buf[..written]))
}

/// Same per-file authorization check as [`handle_read_ipc_request`], for
/// the write path. Deliberately narrower than the read path, same
/// restriction every write this driver has ever supported has had: `data`
/// must be exactly `SECTOR_SIZE` bytes (one sector, the target file's
/// entire capacity) — no resize, no free-cluster allocation, no directory-
/// entry creation over IPC. Each of those stays internal-only (Phase 7's
/// own proofs), not exposed to a caller yet.
fn handle_write_ipc_request(
    dev: &mut BlkDevice,
    info: &BootSectorInfo,
    name: &str,
    token: &CapabilityToken,
    data: &[u8],
) -> FsResponse {
    if !verify_file_token(token, name) {
        return FsResponse::Error(FsError::Unauthorized);
    }
    if data.len() != SECTOR_SIZE {
        return FsResponse::Error(FsError::BadRequest);
    }
    let Some(sector) = resolve_single_sector_file_by_name(dev, info, name) else {
        return FsResponse::Error(FsError::NotFound);
    };
    let mut payload = [0u8; SECTOR_SIZE];
    payload.copy_from_slice(data);
    let (completed, status) = dev.write_sector(u64::from(sector), &payload);
    if completed && status == VIRTIO_BLK_S_OK {
        FsResponse::Ok
    } else {
        FsResponse::Error(FsError::DeviceFailed)
    }
}

/// Defensive cap on how many not-yet-decodable bytes [`run_fs_ipc_server`]
/// will accumulate per port before giving up and discarding them. Without
/// this, a sender that never completes a well-formed
/// [`runix_ipc::fs::FsRequest`] (a bug, or a hostile process holding a
/// valid port-level capability but not bothering to speak the real wire
/// format) could grow `read_buf`/`write_buf` without bound — every field
/// `FsRequest::decode` itself checks is already bounded
/// ([`runix_ipc::fs::MAX_NAME_LEN`]/`MAX_TOKEN_FIELD_LEN`/`MAX_DATA_LEN`),
/// but `decode` returning `None` doesn't distinguish "need more bytes yet"
/// from "this header already claims more than any bound allows" — both
/// look identical to a caller that just keeps accumulating. A real request
/// never approaches this size (see those same bounds); this exists purely
/// to make a broken/hostile sender's own buffer bounded, not to be a
/// meaningful limit on any legitimate message.
const FS_MAX_PENDING_BYTES: usize = 8192;

fn send_fs_response(response: &FsResponse) {
    for byte in response.encode() {
        let _ = syscall::ipc_send(FS_RESPONSE_PORT, byte);
    }
}

/// Filesystem driver, Phase 3/8's fixed-port, fixed-filename IPC surface,
/// generalized: **dynamic filenames plus per-request, per-file
/// authorization**, closing the two gaps `docs/STATUS.md`'s Phase 8
/// section named as the next trigger ("an arbitrary path sent at request
/// time instead of one fixed target name... a real path-scoped capability
/// convention"). [`FS_REQUEST_PORT`]/[`FS_WRITE_REQUEST_PORT`] are still
/// fixed, kernel-capability-gated ports (a caller still needs a
/// `port:<n>` grant to reach this server at all — unchanged, see
/// `kernel/src/syscall.rs`'s `SYS_IPC_SEND`), but each now carries a real
/// [`runix_ipc::fs::FsRequest`] naming *which* file and presenting a
/// [`CapabilityToken`] scoped to exactly that file — verified by this
/// driver itself ([`verify_file_token`]) on every single request, not
/// once at spawn time. Two different files served over the same read
/// port in one boot is the actual proof this closes (see
/// `kernel/tests/blk_fs_ipc.rs`), where Phase 8 could only ever serve one.
///
/// **Concurrency: what this loop does and does not guarantee, verified in
/// QEMU rather than assumed.** This loop is strictly sequential — one
/// in-flight request at a time across *both* ports. The two
/// `ipc_try_recv` blocks below run one after the other in the same
/// iteration, and each one's handler is called inline and runs to
/// completion (device round trips and response send included) before
/// anything else is decoded; there is no second thread, no async executor
/// and no interrupt-driven re-entry into this process to overlap two
/// handlers.
///
/// Two separate hazards, both now closed:
///
/// * *Concurrent senders* — two callers' multi-byte messages interleaving
///   their bytes in the underlying fixed-capacity channel
///   (`kernel/src/ipc.rs`'s `Channel`) before either decodes, producing a
///   well-formed but wrong "franken-request". Fixed in the IPC layer by
///   the per-port advisory send lock (`kernel::ipc::begin_send`/
///   `end_send`, `SYS_IPC_SEND_LOCK`/`SYS_IPC_SEND_UNLOCK`); proven by
///   `kernel/tests/blk_fs_concurrent.rs`.
/// * *Concurrent handlers* — two fully-arrived requests being served at
///   once, which is what would matter for anything mutating (a write, and
///   in principle an allocation). Foreclosed by this loop's own shape
///   above; proven by `kernel/tests/blk_fs_concurrent_write.rs`, where two
///   racing callers each land a full-sector write on a *different* file
///   and both files afterwards hold exactly their own writer's bytes.
///
/// See [`allocate_cluster_chain`]'s doc comment for why "concurrent
/// allocators" specifically cannot arise today (allocation isn't reachable
/// from this loop at all), and for exactly which of those properties would
/// have to be re-established if this driver ever gained real internal
/// concurrency.
fn run_fs_ipc_server(dev: &mut BlkDevice, info: &BootSectorInfo) {
    write_all(b"blk-driver-host: FS server ready, serving read/write requests\n");

    let mut read_buf: Vec<u8> = Vec::new();
    let mut write_buf: Vec<u8> = Vec::new();
    let mut requests_served = 0u32;

    // Same poll-bound discipline as every other wait loop in this
    // codebase: real requests arrive promptly in practice, so this bound
    // exists purely to make "a test that sends N requests" report a clean
    // result instead of hanging the boot forever waiting for an N+1th
    // request that was never going to come.
    //
    // Bumped from `2_000_000` to `20_000_000`, confirmed by real
    // reproduction (not guessed) the same way `poll_for_completion`'s own
    // bound already had to grow once: with per-request Ed25519 signature
    // verification now in the mix (`verify_file_token`) and each request
    // arriving byte-by-byte through a 32-byte channel
    // (`kernel/src/ipc.rs`'s `CHANNEL_CAPACITY`), five sequential
    // request/response round trips in one boot (the actual shape
    // `kernel/tests/blk_fs_ipc.rs` now exercises) accumulate enough
    // cooperative-scheduler round-trip overhead — more so under TCG, which
    // interprets guest instructions far slower than KVM, the same
    // "`poll_for_completion`'s own bound had to grow for exactly this
    // reason" note already on this file — that the unbumped budget ran out
    // mid-way through the fifth request: its sender got stuck forever
    // (`SYS_IPC_SEND`'s internal spin-yield keeps waiting for room a
    // receiver that already exited its own loop will never make), never
    // completing, while this loop itself reported "4 requests served" and
    // returned normally. Not a logic bug in the request-handling code
    // itself — every byte that *did* arrive decoded and served correctly;
    // this loop simply stopped listening too soon.
    for i in 0..20_000_000u32 {
        if let Some(byte) = syscall::ipc_try_recv(FS_REQUEST_PORT) {
            read_buf.push(byte);
            if let Some((request, consumed)) = FsRequest::decode(&read_buf) {
                read_buf.drain(..consumed);
                if let FsRequest::Read { name, token } = request {
                    write_all(b"blk-driver-host: FS server got a read request for ");
                    write_all(name.as_bytes());
                    write_byte(b'\n');
                    let response = handle_read_ipc_request(dev, info, &name, &token);
                    send_fs_response(&response);
                    requests_served += 1;
                }
                // A `Write` variant arriving on the read port is malformed
                // by construction (a well-behaved client only ever encodes
                // `FsRequest::Write` towards `FS_WRITE_REQUEST_PORT`) --
                // silently dropped, matching every other "untrusted input
                // fails closed, not loudly" parser in this module.
            } else if read_buf.len() > FS_MAX_PENDING_BYTES {
                read_buf.clear();
            }
        }

        if let Some(byte) = syscall::ipc_try_recv(FS_WRITE_REQUEST_PORT) {
            write_buf.push(byte);
            if let Some((request, consumed)) = FsRequest::decode(&write_buf) {
                write_buf.drain(..consumed);
                if let FsRequest::Write { name, token, data } = request {
                    write_all(b"blk-driver-host: FS server got a write request for ");
                    write_all(name.as_bytes());
                    write_byte(b'\n');
                    let response = handle_write_ipc_request(dev, info, &name, &token, &data);
                    send_fs_response(&response);
                    requests_served += 1;
                }
            } else if write_buf.len() > FS_MAX_PENDING_BYTES {
                write_buf.clear();
            }
        }

        if i % 10_000 == 0 {
            yield_now();
        }
    }

    write_all(b"blk-driver-host: FS server served ");
    write_decimal(requests_served as u64);
    write_all(b" request(s) total\n");
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
///
/// Bumped from `2_000_000` (filesystem driver, directory-growth/multi-
/// cluster-allocation regression, confirmed by real reproduction, not
/// guessed): on a QEMU instance actually running under TCG -- no working
/// KVM device, which is exactly what GitHub Actions' hosted runners give
/// you -- confirmed by forcing `-accel tcg` locally and reproducing CI's
/// *exact* failure signature byte-for-byte (Phase 6's write timing out
/// with `completed=0 status=255`, cascading into every later phase) --
/// this same busy-spin-with-periodic-yield loop can spend its entire
/// budget before a real, legitimately-in-flight virtio-blk completion
/// actually lands, purely because TCG interprets guest instructions
/// (this loop's own iterations included) far slower than KVM does, not
/// because the device dropped the request. Confirmed the fix, not just
/// the theory: with this same forced-TCG repro and a *fresh* fixture
/// image (a stale, already-mutated-by-a-prior-run image was a separate,
/// unrelated false lead this investigation ruled out first), every
/// phase passes once this budget is large enough that the loop never
/// actually exhausts it (confirmed via a temporary instrumented build
/// that logged every timeout; none fired at this bound).
fn poll_for_completion(queue: &mut Virtqueue) -> bool {
    for i in 0..100_000_000u32 {
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
