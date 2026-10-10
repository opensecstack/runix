//! Shared address-space/mapping/loading setup for spawning a
//! `net-driver-host-arm` process -- extracted out of `tcp_proof.rs` (Beta
//! mobile item 2.5) before a second caller needs the exact same setup for a
//! different `net-driver-host-arm` *mode* (a per-syscall MARSHAL-transport
//! path, `marshal_transport.rs`, sending a MARSHAL request instead of the
//! fixed TCP-proof PING/PONG). Same precedent `el0_exec.rs` already set for
//! `el0_proof.rs`: extract the generic mechanism the moment a second caller
//! is about to exist, rather than duplicate it and unify later.
//!
//! `tcp_proof.rs` keeps everything proof-specific (the `OBSERVED`/
//! `TCP_PROOF_ACTIVE` statics, its own thread entry point, `finish`,
//! `abort_from_fault`, `report`, and the actual
//! `scheduler::spawn_with_address_space` call plus the bounded wait for the
//! result) -- this module only builds the address space, maps everything
//! `net-driver-host-arm`'s own fixed `NetBootInfo` contract expects into it,
//! and loads the real compiled ELF. See `tcp_proof.rs`'s own doc comment for
//! the full background on *why* this binary needs real address-space wiring
//! (private heap, mapped virtio-mmio register window, physically contiguous
//! virtqueue regions, per-packet-buffer pages) that a hand-assembled EL0
//! payload never did.
//!
//! # [`NetBootInfo`] growing a `mode` field
//!
//! [`NetBootInfo`] here mirrors `net-driver-host-arm::NetBootInfo` byte for
//! byte (same "private, one-sided, hand-synced contract" precedent
//! `tcp_proof.rs`'s own doc comment already explains for why this isn't
//! shared through a crate). Today it holds only the fields [`setup`] itself
//! computes while mapping (the device window VA, the virtqueue regions'
//! physical bases, the per-buffer physical addresses) -- there is nothing
//! here for a caller to supply yet. The MARSHAL-transport caller is expected
//! to need more (a mode selector, a remote address, request/response
//! buffers) that only *it* knows the shape of; growing this struct to add
//! those fields, and populating them before calling [`setup`], is that
//! caller's job -- not something guessed at or stubbed out here ahead of
//! time. [`setup`] takes a filled-in `NetBootInfo` by value specifically so
//! that caller can set its own fields first; every field defined here today
//! is overwritten with this function's own computed value regardless of
//! what the caller passed in, so a caller with nothing extra to say (like
//! `tcp_proof.rs` today) can pass an all-zero value.

use crate::capabilities;
use crate::process::AddressSpace;
use alloc::alloc::{alloc_zeroed, Layout};
use runix_kernel_arm::elf::{Elf64, ElfError};
use runix_kernel_arm::loader::{self, LoadedImage, LoaderError};
use runix_kernel_arm::vm::GRANULE_4KIB;

/// `ElfError`'s own [`core::fmt::Display`] arms are all static text (no
/// embedded runtime values), so this reproduces the exact same message as a
/// `&'static str` instead of losing it to a generic "parse failed" the way
/// collapsing to [`Result::map_err`]`(|_| ...)` would.
fn elf_error_message(e: ElfError) -> &'static str {
    match e {
        ElfError::TooShort => "image is shorter than an ELF64 header",
        ElfError::BadMagic => "not an ELF image (bad magic)",
        ElfError::Not64Bit => "not ELFCLASS64",
        ElfError::NotLittleEndian => "not ELFDATA2LSB (little-endian)",
        ElfError::NotAarch64 => "e_machine is not EM_AARCH64",
        ElfError::NotExecutable => "e_type is not ET_EXEC",
        ElfError::UnexpectedProgramHeaderSize => "e_phentsize is not 56",
        ElfError::ProgramHeadersOutOfBounds => "program header table runs past the image",
        ElfError::SegmentOutOfBounds => "PT_LOAD segment range runs past the image",
        ElfError::SegmentSmallerThanFileContent => "PT_LOAD segment has p_memsz < p_filesz",
        ElfError::NoLoadableSegments => "no PT_LOAD segment",
    }
}

/// `LoaderError`'s own [`core::fmt::Display`] embeds runtime values (`vaddr`,
/// `page`, `entry`, ...) in some arms, which don't fit a `&'static str` --
/// this keeps the same category of message with the dynamic detail dropped,
/// rather than collapsing every variant to one generic "load failed".
fn loader_error_message(e: LoaderError) -> &'static str {
    match e {
        LoaderError::SegmentNotReadable => "PT_LOAD segment is not readable (no PF_R)",
        LoaderError::SegmentWritableAndExecutable => {
            "PT_LOAD segment is both writable and executable (W^X violation)"
        }
        LoaderError::SegmentOutsideWindow { .. } => {
            "PT_LOAD segment is outside the loadable window"
        }
        LoaderError::OverlappingSegments { .. } => "two PT_LOAD segments share the same page",
        LoaderError::EntryPointNotExecutable { .. } => {
            "entry point is not inside an executable segment"
        }
        LoaderError::MapFailed { reason, .. } => reason,
    }
}

// ---------------------------------------------------------------------------
// net-driver-host-arm's own fixed contract, duplicated by hand
// ---------------------------------------------------------------------------
//
// Every constant below must match `net-driver-host-arm/src/main.rs`'s own
// definition exactly -- see this module's and `tcp_proof.rs`'s doc comments
// for why that is a deliberate duplication, not an oversight. Both callers
// need this identical layout, since the ELF being loaded is still
// `net-driver-host-arm`'s own binary either way, compiled against these same
// fixed addresses regardless of which mode it runs in.

/// Matches `net-driver-host-arm::HEAP_START`/`HEAP_SIZE` (256 KiB = 64
/// pages) exactly.
const NET_HEAP_START: u64 = 0x_8800_0000;
const NET_HEAP_PAGES: u64 = 64;

const NET_INFO_VA: u64 = 0x_8810_0000;
const NET_RXQ_VA: u64 = 0x_8820_0000;
const NET_TXQ_VA: u64 = 0x_8830_0000;
const NET_RXBUF_VA: u64 = 0x_8840_0000;
const NET_TXBUF_VA: u64 = 0x_8850_0000;

/// `net-driver-host-arm::virtio_net::QUEUE_ALIGN` is one page (`GRANULE_4KIB`
/// here); three rings per queue (descriptor table, avail ring, used ring).
const QUEUE_REGION_PAGES: u64 = 3;

/// Matches `net-driver-host-arm::smoltcp_device::RX_BUFFER_COUNT`/
/// `TX_BUFFER_COUNT`.
pub const RX_BUFFER_COUNT: usize = 8;
pub const TX_BUFFER_COUNT: usize = 4;

/// This module's own choice of VA for the mapped virtio-mmio register
/// window -- not fixed by `net-driver-host-arm` the way the constants above
/// are (that binary only ever dereferences whatever `NetBootInfo::mmio_base`
/// says), so any VA inside the private window that doesn't collide with the
/// loaded ELF's own low segments or the fixed VAs above is correct. Chosen
/// well clear of both.
const NET_MMIO_VA: u64 = 0x_8900_0000;

/// Duplicated from `virtio_mmio.rs`'s own private `SLOT_STRIDE`, same
/// reasoning `capabilities.rs`'s own `VIRTIO_MMIO_SLOT_STRIDE` duplication
/// already documents: a capability check needs the real per-slot byte range
/// to ask `check_mmio_window` about, and that value has no `pub(crate)`
/// path out of `virtio_mmio.rs` today.
const NET_MMIO_SLOT_STRIDE: u64 = 0x200;

/// The AArch64/MMIO-v2 boot-info page -- byte-for-byte the same `#[repr(C)]`
/// layout as `net-driver-host-arm::NetBootInfo`, duplicated rather than
/// shared (see this module's doc comment). `mmio_base` is a **virtual**
/// address ([`NET_MMIO_VA`]), not physical -- that binary dereferences it
/// directly from inside its own address space, exactly as its own doc
/// comment on the field states.
///
/// `mmio_base`/`rx_queue_phys`/`tx_queue_phys`/`rx_buffer_phys`/
/// `tx_buffer_phys` are computed by [`setup`] itself from the mapping it
/// performs -- a caller passes in a value (see this module's doc comment for
/// why [`setup`] still takes one by value rather than constructing it
/// internally), but every one of those five fields is overwritten before
/// use regardless of what the caller passed in.
///
/// `mode`/`remote_ip`/`remote_port` are the opposite: the caller's own, set
/// before calling [`setup`] and passed through completely untouched -- see
/// `net-driver-host-arm::NetBootInfo::mode`'s own doc comment for what they
/// mean (`0` = the fixed TCP-proof demo, ignoring all three; `1` =
/// `marshal_transport.rs`'s per-syscall MARSHAL relay, which needs
/// `remote_ip`/`remote_port` to know where to connect). `request_len` sits
/// in between: a caller may set it, but [`setup`] overwrites it too,
/// whenever it is also given `request_bytes: Some(..)` -- see that
/// parameter's own doc comment for why tying the reported length to the
/// bytes actually mapped is safer than trusting a caller-supplied count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetBootInfo {
    pub mmio_base: u64,
    pub rx_queue_phys: u64,
    pub tx_queue_phys: u64,
    pub rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    pub tx_buffer_phys: [u64; TX_BUFFER_COUNT],
    /// `0` = TCP-proof mode, `1` = MARSHAL-request mode -- matches
    /// `net-driver-host-arm::NetBootInfo::mode` exactly; see that field's
    /// own doc comment.
    pub mode: u64,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    /// Source port for `mode == 1` (`0` = driver default); fills what was
    /// padding before -- see `net-driver-host-arm::NetBootInfo::local_port`.
    pub local_port: u16,
    pub request_len: u64,
}

const _: () = assert!(core::mem::size_of::<NetBootInfo>() <= 4096);

/// `net-driver-host-arm::MARSHAL_REQUEST_VA`/`MARSHAL_RESPONSE_VA`,
/// duplicated by hand for the same reason every other fixed VA in this file
/// is -- see this module's doc comment and `net-driver-host-arm`'s own on
/// those constants.
const MARSHAL_REQUEST_VA: u64 = 0x_8860_0000;
const MARSHAL_RESPONSE_VA: u64 = 0x_8870_0000;

/// Matches `net-driver-host-arm::MARSHAL_REQUEST_CAPACITY`/
/// `MARSHAL_RESPONSE_CAPACITY` (8 KiB each) -- two 4 KiB pages.
const MARSHAL_BUFFER_PAGES: u64 = 2;

/// `MARSHAL_BUFFER_PAGES * GRANULE_4KIB`, exposed so [`crate::marshal_transport`]
/// can clamp a reported `response_len` to exactly what [`setup`] actually
/// mapped, the same discipline `net-driver-host-arm::run_marshal_request`
/// itself applies on the other side of this same buffer.
pub const MARSHAL_BUFFER_CAPACITY: usize = (MARSHAL_BUFFER_PAGES * GRANULE_4KIB) as usize;

// ---------------------------------------------------------------------------
// Address-space construction
// ---------------------------------------------------------------------------

/// Allocates one physically contiguous, zeroed `pages * 4 KiB` block and
/// maps it at `va_base..va_base + pages * 4 KiB`, returning the block's own
/// (identity-mapped) physical base. See `tcp_proof.rs`'s doc comment for why
/// this -- not repeated [`AddressSpace::map_private_page`] calls -- is what
/// a virtqueue region needs.
fn map_contiguous_region(
    space: &mut AddressSpace,
    va_base: u64,
    pages: u64,
) -> Result<u64, &'static str> {
    let layout = Layout::from_size_align((pages * GRANULE_4KIB) as usize, GRANULE_4KIB as usize)
        .map_err(|_| "bad layout for a virtqueue region")?;
    // SAFETY: `layout` has a non-zero size and a valid alignment; the
    // null check below handles allocation failure without ever
    // dereferencing the result.
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err("out of memory for a contiguous virtqueue region");
    }
    let pa_base = ptr as u64;
    for i in 0..pages {
        let va = va_base + i * GRANULE_4KIB;
        let pa = pa_base + i * GRANULE_4KIB;
        // SAFETY: `pa` is this freshly allocated block's own memory --
        // this module's, not a device's -- so there is no outstanding
        // capability check to perform before mapping it (see `tcp_proof.rs`'s
        // doc comment on why reusing `map_mmio_page` here is sound rather
        // than a bypass of its documented contract).
        unsafe {
            space.map_mmio_page(va, pa, true).map_err(|e| e.message())?;
        }
    }
    Ok(pa_base)
}

/// Maps the virtio-mmio device window (capability-gated) plus every private
/// region `net-driver-host-arm`'s own `NetBootInfo` contract expects, and
/// writes the filled-in struct into the mapped [`NET_INFO_VA`] page.
///
/// `info`'s `mmio_base`/`rx_queue_phys`/`tx_queue_phys`/`rx_buffer_phys`/
/// `tx_buffer_phys` are overwritten here with this function's computed
/// values -- see [`NetBootInfo`]'s doc comment for why [`setup`] still takes
/// one by value rather than building it from nothing. `mode`/`remote_ip`/
/// `remote_port` pass through untouched. When `request_bytes` is `Some`,
/// this also maps the fixed `MARSHAL_REQUEST_VA`/`MARSHAL_RESPONSE_VA`
/// regions, writes `request_bytes` into the request region (clamped to
/// [`MARSHAL_BUFFER_CAPACITY`]), overwrites `info.request_len` to match
/// exactly what was written, and returns the response region's own
/// physical base -- a kernel-identity-mapped address a caller can read
/// directly once the EL0 excursion reports back, the same technique
/// `tcp_proof.rs`/`el0_proof.rs` already use for their own private frames.
fn build_net_boot_info(
    space: &mut AddressSpace,
    dev: &crate::virtio_mmio::NetDevice,
    mut info: NetBootInfo,
    request_bytes: Option<&[u8]>,
) -> Result<Option<u64>, &'static str> {
    let now = crate::svc::now_ticks();

    // The device window: issue a token scoped to exactly this device's own
    // virtio-mmio slot, verify it covers the range about to be mapped, and
    // only then map it -- see `tcp_proof.rs`'s doc comment.
    //
    // `mmio_phys_base` (the slot's own base, `VIRTIO_MMIO_BASE + slot *
    // SLOT_STRIDE`) is not itself 4 KiB-aligned for most slots (`SLOT_STRIDE`
    // is `0x200`, eight slots per page) -- `map_mmio_page` requires page
    // alignment, so this maps the *containing* page and records the slot's
    // real sub-page offset in `NetBootInfo::mmio_base` instead, rather than
    // asking `map_mmio_page` to map an address it was never going to accept.
    // The capability check still verifies the real, unaligned slot range --
    // alignment is a mapping-mechanism detail, not part of what the token
    // authorizes.
    let mmio_phys_base = dev.base() as u64;
    let mmio_page_pa = mmio_phys_base & !(GRANULE_4KIB - 1);
    let mmio_page_offset = mmio_phys_base - mmio_page_pa;
    let token =
        capabilities::issue_mmio_token(capabilities::virtio_mmio_slot_resource(dev.slot), now);
    capabilities::check_mmio_window(
        &token,
        mmio_phys_base as usize,
        NET_MMIO_SLOT_STRIDE as usize,
        now,
    )
    .map_err(|_| "mmio capability check denied the virtio-net device window")?;
    // SAFETY: just verified by `check_mmio_window` above, against a token
    // scoped to this exact device slot.
    unsafe {
        space
            .map_mmio_page(NET_MMIO_VA, mmio_page_pa, true)
            .map_err(|e| e.message())?;
    }

    // The private heap.
    for i in 0..NET_HEAP_PAGES {
        space
            .map_private_page(NET_HEAP_START + i * GRANULE_4KIB)
            .map_err(|e| e.message())?;
    }

    // The NetBootInfo page itself -- filled in last, once every other
    // address below is known.
    let info_page = space
        .map_private_page(NET_INFO_VA)
        .map_err(|e| e.message())?;

    // The RX/TX virtqueue regions -- physically contiguous, see
    // `map_contiguous_region`.
    let rx_queue_phys = map_contiguous_region(space, NET_RXQ_VA, QUEUE_REGION_PAGES)?;
    let tx_queue_phys = map_contiguous_region(space, NET_TXQ_VA, QUEUE_REGION_PAGES)?;

    // The packet buffers -- individually mapped; each page's own physical
    // address (== its VA under this kernel's identity map) is recorded
    // directly, the same technique `el0_proof.rs::prove_el0_process` uses
    // for its own private frames.
    let mut rx_buffer_phys = [0u64; RX_BUFFER_COUNT];
    for (i, slot) in rx_buffer_phys.iter_mut().enumerate() {
        let page = space
            .map_private_page(NET_RXBUF_VA + (i as u64) * GRANULE_4KIB)
            .map_err(|e| e.message())?;
        *slot = page.as_ptr() as u64;
    }
    let mut tx_buffer_phys = [0u64; TX_BUFFER_COUNT];
    for (i, slot) in tx_buffer_phys.iter_mut().enumerate() {
        let page = space
            .map_private_page(NET_TXBUF_VA + (i as u64) * GRANULE_4KIB)
            .map_err(|e| e.message())?;
        *slot = page.as_ptr() as u64;
    }

    info.mmio_base = NET_MMIO_VA + mmio_page_offset;
    info.rx_queue_phys = rx_queue_phys;
    info.tx_queue_phys = tx_queue_phys;
    info.rx_buffer_phys = rx_buffer_phys;
    info.tx_buffer_phys = tx_buffer_phys;

    // MARSHAL-request-mode-only: map the fixed request/response regions and
    // write the request bytes in, clamped exactly as
    // `net-driver-host-arm::run_marshal_request`'s own `request_len`
    // clamping is -- a bogus/oversized buffer must turn into a truncated
    // send, never a write past what gets mapped.
    let response_phys = match request_bytes {
        Some(bytes) => {
            let request_phys =
                map_contiguous_region(space, MARSHAL_REQUEST_VA, MARSHAL_BUFFER_PAGES)?;
            let response_phys =
                map_contiguous_region(space, MARSHAL_RESPONSE_VA, MARSHAL_BUFFER_PAGES)?;
            let len = bytes.len().min(MARSHAL_BUFFER_CAPACITY);
            // SAFETY: `request_phys` was just mapped above, fresh and
            // zeroed, `MARSHAL_BUFFER_CAPACITY` bytes long; `len` is
            // clamped to that same capacity immediately above.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), request_phys as *mut u8, len);
            }
            info.request_len = len as u64;
            Some(response_phys)
        }
        None => None,
    };

    // SAFETY: `info_page` is a freshly mapped, zeroed, 4 KiB page --
    // large enough for `NetBootInfo` (checked by this module's own
    // `size_of` assertion) and correctly aligned for it (8-byte fields, 4
    // KiB page alignment).
    unsafe {
        (info_page.as_mut_ptr() as *mut NetBootInfo).write(info);
    }

    Ok(response_phys)
}

/// Builds a fresh [`AddressSpace`], maps every private region
/// `net-driver-host-arm` needs (the virtio-mmio device window, the private
/// heap, the `NetBootInfo` page, the virtqueue regions, the packet
/// buffers), writes `info` (with this function's own computed fields filled
/// in -- see [`NetBootInfo`]'s doc comment) into the mapped info page, and
/// loads `elf` into the space.
///
/// Does not spawn or run anything -- the caller owns the thread entry point,
/// the statics that hand `loaded.entry`/`loaded.stack_top`/the space's own
/// root to that thread, the actual `scheduler::spawn_with_address_space`
/// call, and waiting for a result, exactly as `tcp_proof.rs::prove_net_tcp`
/// still does today.
///
/// `request_bytes`: `None` for TCP-proof-mode callers (today: `tcp_proof.rs`,
/// `info.mode == 0`) -- nothing beyond the five computed fields is mapped.
/// `Some(bytes)` for MARSHAL-request-mode callers (`marshal_transport.rs`,
/// `info.mode == 1`): maps the fixed request/response regions, writes
/// `bytes` into the request region, and overwrites `info.request_len` to
/// match -- see [`build_net_boot_info`]'s doc comment. The returned
/// `Option<u64>` is the response region's own physical base in that case
/// (`None` when `request_bytes` is `None`), for the caller to read back
/// from directly once the EL0 excursion reports a response length.
pub fn setup(
    elf: &[u8],
    dev: &crate::virtio_mmio::NetDevice,
    info: NetBootInfo,
    request_bytes: Option<&[u8]>,
) -> Result<(AddressSpace, LoadedImage, Option<u64>), &'static str> {
    let elf = Elf64::parse(elf).map_err(elf_error_message)?;

    let mut space = AddressSpace::new().map_err(|e| e.message())?;

    let response_phys = build_net_boot_info(&mut space, dev, info, request_bytes)?;

    let loaded = loader::load(&elf, &mut space).map_err(loader_error_message)?;

    // Same instruction-cache reasoning as `el0_proof::prove_el0_process`:
    // the loaded bytes reached their frames as data writes, and are about
    // to be fetched through a different VA.
    //
    // SAFETY: cache maintenance on the current PE with no memory operands.
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }

    Ok((space, loaded, response_phys))
}
