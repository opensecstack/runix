//! Beta mobile item 2.5 "Stage 3: real outbound TCP at EL0" -- the
//! loader-integration slice `net-driver-host-arm/src/main.rs`'s own module
//! doc comment leaves as a `TODO(loader integration)`: discover the
//! virtio-net device, build a fresh [`AddressSpace`], map everything that
//! binary's fixed `NetBootInfo` contract expects into it, load its real
//! compiled ELF, and `eret` into it -- then read back a single flat
//! `net-driver-host-arm::ProofResult` code through one purpose-built `SVC`.
//!
//! Structurally the second caller of [`crate::el0_exec`]'s one-shot
//! EL1-to-EL0 continuation, after `el0_proof.rs` -- see that module's own
//! doc comment for the mechanism itself (`enter_el0`/`resume_el1`, the
//! single-continuation-slot cost, why no separate kernel-entry stack is
//! needed). This module supplies a *different* payload (a real compiled
//! binary rather than a hand-assembled one) and a different, simpler
//! observation (one result code rather than three bytes plus hardware
//! register checks), through [`SYS_NET_PROOF_DONE`](crate::svc::SYS_NET_PROOF_DONE)
//! rather than reusing `el0_proof.rs`'s own syscall -- see that constant's
//! doc comment in `svc.rs` for why the two stay separate numbers.
//!
//! # Why this binary needs real address-space wiring that `el0_proof.rs`'s
//! hand-assembled image never did
//!
//! `net-driver-host-arm` is a genuine virtio-mmio network driver plus a
//! `smoltcp` TCP client, not a three-instruction proof payload: it needs a
//! private heap, a mapped virtio-mmio register window, physically
//! contiguous virtqueue descriptor/avail/used-ring regions, and a page per
//! packet buffer -- none of which `el0_proof.rs`'s payload needed. Every
//! one of those VAs and the physical addresses behind them are fixed,
//! duplicated constants matching `net-driver-host-arm/src/main.rs`'s own
//! `NetBootInfo`/`HEAP_START`/`NET_*_VA` definitions exactly -- the same
//! "private, one-sided, hand-synced contract" precedent
//! `net-driver-host`/`kernel/tests/net_driver_tcp.rs` already use on the
//! x86_64 side, restated here rather than shared through a crate because
//! this boundary is a one-shot boot-time handoff, not the bidirectional
//! typed traffic `ipc::sockets` exists for.
//!
//! # The virtio-mmio window: this crate's first real `check_mmio_window`
//! caller
//!
//! `capabilities::check_mmio_window`/`issue_mmio_token`/
//! `virtio_mmio_slot_resource` existed with no caller before this module
//! (see their own doc comments in `capabilities.rs`). [`build_net_boot_info`]
//! is the real verify-then-act sequence they were written for: issue a
//! token scoped to exactly the device's own virtio-mmio slot, verify it
//! covers the physical range about to be mapped, and only then call
//! [`AddressSpace::map_mmio_page`] -- never skip the check to "simplify"
//! this boot-time demo, since this is the one place in the crate that
//! exercises the real ordering a future non-demo caller would also have to
//! follow.
//!
//! # Physical contiguity, and why it needs its own allocation path
//!
//! `AddressSpace::map_private_page`/`map_private_page_with` each allocate
//! one fresh frame per call with no contiguity guarantee across calls --
//! fine for the heap, the `NetBootInfo` page, and the per-buffer pages
//! (each independently recorded in `NetBootInfo`), but not for the RX/TX
//! virtqueue regions, whose descriptor table, avail ring, and used ring
//! must sit back-to-back in physical memory (see
//! `net-driver-host-arm::virtio_net::Virtqueue`'s own doc comment).
//! [`map_contiguous_region`] allocates one single `3 * QUEUE_ALIGN`-byte
//! block directly (so contiguity is a property of a single allocation, not
//! an assumption about allocator behavior across several), then maps each
//! page of it at the matching VA through [`AddressSpace::map_mmio_page`] --
//! reused here for ordinary, already-owned heap memory rather than a real
//! device window, which is sound: that function's own doc comment flags
//! the *capability* check as the caller's responsibility specifically for
//! physical ranges the caller does not already own, and this allocation is
//! this module's own, fresh, zeroed memory, not a device register window
//! anyone needs authorizing to touch.

use crate::capabilities;
use crate::el0_exec;
use crate::process::{self, AddressSpace};
use crate::serial_println;
use alloc::alloc::{alloc_zeroed, Layout};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use runix_kernel_arm::elf::Elf64;
use runix_kernel_arm::loader;
use runix_kernel_arm::vm::GRANULE_4KIB;
use spin::Mutex;

// ---------------------------------------------------------------------------
// net-driver-host-arm's own fixed contract, duplicated by hand
// ---------------------------------------------------------------------------
//
// Every constant below must match `net-driver-host-arm/src/main.rs`'s own
// definition exactly -- see this module's doc comment for why that is a
// deliberate duplication, not an oversight.

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
const RX_BUFFER_COUNT: usize = 8;
const TX_BUFFER_COUNT: usize = 4;

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
#[repr(C)]
struct NetBootInfo {
    mmio_base: u64,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; RX_BUFFER_COUNT],
    tx_buffer_phys: [u64; TX_BUFFER_COUNT],
}

/// The compiled `net-driver-host-arm` binary. Built separately
/// (`cd net-driver-host-arm && cargo build --target aarch64-unknown-none
/// --release`, via `rustup run stable-x86_64-pc-windows-gnu` on this
/// environment) -- the same manual-build-step convention
/// `kernel/tests/net_driver_tcp.rs` documents for its own `include_bytes!`
/// of `net-driver-host`.
static NET_DRIVER_HOST_ARM_ELF: &[u8] = include_bytes!(
    "../../net-driver-host-arm/target/aarch64-unknown-none/release/net-driver-host-arm"
);

// ---------------------------------------------------------------------------
// Address-space construction
// ---------------------------------------------------------------------------

/// Allocates one physically contiguous, zeroed `pages * 4 KiB` block and
/// maps it at `va_base..va_base + pages * 4 KiB`, returning the block's own
/// (identity-mapped) physical base. See this module's doc comment for why
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
        // capability check to perform before mapping it (see this
        // module's doc comment on why reusing `map_mmio_page` here is
        // sound rather than a bypass of its documented contract).
        unsafe {
            space.map_mmio_page(va, pa, true).map_err(|e| e.message())?;
        }
    }
    Ok(pa_base)
}

/// Maps the virtio-mmio device window (capability-gated) plus every private
/// region `net-driver-host-arm`'s own `NetBootInfo` contract expects, and
/// writes the filled-in struct into the mapped [`NET_INFO_VA`] page.
fn build_net_boot_info(
    space: &mut AddressSpace,
    dev: &crate::virtio_mmio::NetDevice,
) -> Result<(), &'static str> {
    let now = crate::svc::now_ticks();

    // The device window: issue a token scoped to exactly this device's own
    // virtio-mmio slot, verify it covers the range about to be mapped, and
    // only then map it -- see this module's doc comment.
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

    let info = NetBootInfo {
        mmio_base: NET_MMIO_VA + mmio_page_offset,
        rx_queue_phys,
        tx_queue_phys,
        rx_buffer_phys,
        tx_buffer_phys,
    };
    // SAFETY: `info_page` is a freshly mapped, zeroed, 4 KiB page --
    // large enough for `NetBootInfo` (checked below) and correctly
    // aligned for it (8-byte fields, 4 KiB page alignment).
    unsafe {
        (info_page.as_mut_ptr() as *mut NetBootInfo).write(info);
    }

    Ok(())
}

const _: () = assert!(core::mem::size_of::<NetBootInfo>() <= 4096);

// ---------------------------------------------------------------------------
// The one-shot EL1-to-EL0 continuation, and this proof's own observations
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Observation {
    thread_root: u64,
    svc_spsr: u64,
    svc_elr: u64,
    svc_root: u64,
    /// The `ProofResult` code `net-driver-host-arm` reported, or `u64::MAX`
    /// if the excursion ended some other way (a fault) before reporting
    /// one.
    result: u64,
    fault: Option<(u64, u64, u64, u64)>,
}

static OBSERVED: Mutex<Observation> = Mutex::new(Observation {
    thread_root: 0,
    svc_spsr: 0,
    svc_elr: 0,
    svc_root: 0,
    result: u64::MAX,
    fault: None,
});

/// Set by [`net_tcp_proof_thread`] once it has printed its verdict -- the
/// boot thread's bounded yield loop in [`prove_net_tcp`] stops on this.
static FINISHED: AtomicBool = AtomicBool::new(false);

/// `LoadedImage::entry`/`stack_top`/the address space's own root, handed to
/// the spawned thread through statics for the same reason
/// `el0_proof.rs::IMAGE_ENTRY`/`IMAGE_STACK_TOP`/`IMAGE_ROOT` are:
/// `scheduler::spawn_with_address_space` takes a bare `extern "C" fn() -> !`
/// with no argument slot.
static IMAGE_ENTRY: AtomicU64 = AtomicU64::new(0);
static IMAGE_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static IMAGE_ROOT: AtomicU64 = AtomicU64::new(0);

/// True only while *this module's own* EL0 excursion is in flight --
/// unlike `el0_proof::continuation_live`, which is simply
/// `el0_exec::continuation_live()` (correct only because nothing else ever
/// shared that one continuation slot with it until this module existed).
/// `el0_exec`'s continuation slot is a single global, so
/// `el0_exec::continuation_live()` alone cannot tell *whose* excursion is
/// live -- this flag is what lets `el1_vectors.rs` route a fault to the
/// right proof's `abort_from_fault` instead of `el0_proof`'s, which would
/// record it in the wrong `OBSERVED` and leave this module's own bounded
/// wait to time out with no diagnostic. Set once, before the one `eret`
/// this module ever performs; never explicitly cleared, since ANDing with
/// `el0_exec::continuation_live()` (false again once the excursion ends,
/// one way or the other) already makes [`continuation_live`] false
/// afterwards.
static TCP_PROOF_ACTIVE: AtomicBool = AtomicBool::new(false);

/// See [`TCP_PROOF_ACTIVE`]'s doc comment for why this is not simply
/// `el0_exec::continuation_live()`.
pub fn continuation_live() -> bool {
    TCP_PROOF_ACTIVE.load(Ordering::Relaxed) && el0_exec::continuation_live()
}

/// `svc.rs`'s [`crate::svc::SYS_NET_PROOF_DONE`] arm: records the reported
/// `ProofResult` code plus the hardware's own account of where the `SVC`
/// came from, then resumes the EL1 continuation -- never returning to EL0.
/// Mirrors `el0_proof::finish`'s shape exactly; see that function's doc
/// comment for why claim/record/resume is split this way between this
/// module and [`el0_exec`].
pub fn finish(result: u64) -> u64 {
    let Some(saved_sp) = el0_exec::take_continuation() else {
        return u64::MAX;
    };
    {
        let mut observed = OBSERVED.lock();
        observed.result = result;
        observed.svc_spsr = el0_exec::read_spsr_el1();
        observed.svc_elr = el0_exec::read_elr_el1();
        observed.svc_root = process::active_root();
    }
    // SAFETY: `saved_sp` was written by `el0_exec::enter_el0` on this
    // thread's own kernel stack, still live; see `el0_proof::finish`'s
    // identical safety comment.
    unsafe { el0_exec::resume_el1(saved_sp) }
}

/// Reached from `el1_vectors.rs` when this module's EL0 process takes a
/// synchronous exception that is not its `SVC`. Mirrors
/// `el0_proof::abort_from_fault` exactly, recording into this module's own
/// [`OBSERVED`] instead.
///
/// # Safety
/// Only valid from a synchronous lower-EL exception taken while
/// [`continuation_live`] is true -- see `el0_exec::abort_from_fault`'s own
/// contract.
pub unsafe fn abort_from_fault(vector: u64, esr: u64, far: u64, elr: u64) -> ! {
    unsafe {
        el0_exec::abort_from_fault(|| {
            OBSERVED.lock().fault = Some((vector, esr, far, elr));
        })
    }
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

/// This process's EL1 side: observe the live `TTBR0_EL1`, `eret` into the
/// loaded `net-driver-host-arm` entry point, and -- resumed here by
/// [`finish`] or [`abort_from_fault`] -- report the verdict. Mirrors
/// `el0_proof::el0_proof_thread`'s shape exactly.
extern "C" fn net_tcp_proof_thread() -> ! {
    {
        let mut observed = OBSERVED.lock();
        observed.thread_root = process::active_root();
    }

    let entry = IMAGE_ENTRY.load(Ordering::Relaxed);
    let stack_top = IMAGE_STACK_TOP.load(Ordering::Relaxed);
    serial_println!(
        "Runix ARM kernel: net TCP proof thread at EL1, TTBR0_EL1={:#x} (own address space), \
         about to eret to {:#x} with SP_EL0={:#x}",
        OBSERVED.lock().thread_root,
        entry,
        stack_top
    );

    TCP_PROOF_ACTIVE.store(true, Ordering::Relaxed);

    // SAFETY: `entry`/`stack_top` are `loader::load`'s own verified output
    // for the address space this thread owns and which is active right now
    // (the scheduler installed it on resume); `el0_exec`'s continuation
    // slot is a writable static that outlives this call. The process
    // reaches EL1 only through the `SVC` `finish` handles, or a fault
    // `abort_from_fault` converts into a reported failure.
    unsafe { el0_exec::enter_el0(entry, stack_top, el0_exec::continuation_slot()) };

    report();
    FINISHED.store(true, Ordering::Relaxed);
    loop {
        crate::scheduler::yield_now();
    }
}

/// Renders a `net-driver-host-arm::ProofResult` code without depending on
/// that crate (there is no shared type for this boundary -- see this
/// module's doc comment).
fn result_name(result: u64) -> &'static str {
    match result {
        0 => "Pass",
        1 => "DeviceProbeFailed",
        2 => "FeatureNegotiationFailed",
        3 => "QueueSetupFailed",
        4 => "TcpConnectTimedOut",
        5 => "TcpReplyMismatch",
        _ => "<unknown>",
    }
}

/// Compares every observation against what a genuine EL0 excursion must
/// produce and prints one greppable `PASS`/`FAILED` line. Mirrors
/// `el0_proof.rs::report`'s structure.
fn report() {
    let observed = OBSERVED.lock();
    let root = IMAGE_ROOT.load(Ordering::Relaxed);

    if let Some((vector, esr, far, elr)) = observed.fault {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- the EL0 process faulted instead of \
             finishing (vector {}, ESR_EL1={:#x} EC={:#x}, FAR_EL1={:#x}, ELR_EL1={:#x})",
            vector,
            esr,
            (esr >> 26) & 0x3F,
            far,
            elr
        );
        return;
    }

    let from_el0 = observed.svc_spsr & el0_exec::SPSR_MODE_MASK == el0_exec::SPSR_MODE_EL0T;
    let root_followed = observed.thread_root == root && observed.svc_root == root;

    serial_println!(
        "Runix ARM kernel: net TCP proof observed SPSR_EL1={:#x} (EL0t={}), TTBR0_EL1 thread={:#x} \
         svc={:#x} space={:#x}, result={} ({})",
        observed.svc_spsr,
        from_el0,
        observed.thread_root,
        observed.svc_root,
        root,
        observed.result,
        result_name(observed.result)
    );

    if observed.result == 0 && from_el0 && root_followed {
        serial_println!(
            "Runix ARM kernel: net TCP proof PASS -- a real compiled net-driver-host-arm \
             process brought up a virtio-mmio network device at EL0 and completed a real TCP \
             round trip over QEMU's guestfwd bridge"
        );
    } else {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- result={} ({}) came_from_el0={} \
             ttbr0_followed_schedule={}",
            observed.result,
            result_name(observed.result),
            from_el0,
            root_followed
        );
    }
}

/// Builds the address space, wires up every private region
/// `net-driver-host-arm` needs, loads it, spawns a thread that owns it, and
/// schedules it for real.
///
/// Called from `nonsecure.rs`'s shared EL1 bring-up right after
/// `el0_proof::prove_el0_process` -- it needs everything that proof needs
/// (the MMU, the heap, the scheduler's run queue) plus one more
/// prerequisite: `virtio_mmio::probe()` having something to find, which
/// only needs the MMU's Device block (already up by this point in the boot
/// sequence).
pub fn prove_net_tcp() {
    let scan = crate::virtio_mmio::probe();
    let Some(dev) = scan.net else {
        serial_println!("Runix ARM kernel: net TCP proof FAILED -- no virtio-net device found");
        return;
    };

    let elf = match Elf64::parse(NET_DRIVER_HOST_ARM_ELF) {
        Ok(elf) => elf,
        Err(err) => {
            serial_println!("Runix ARM kernel: net TCP proof FAILED -- parse: {}", err);
            return;
        }
    };

    let mut space = match AddressSpace::new() {
        Ok(space) => space,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: net TCP proof FAILED -- address space: {}",
                err
            );
            return;
        }
    };

    if let Err(reason) = build_net_boot_info(&mut space, &dev) {
        serial_println!("Runix ARM kernel: net TCP proof FAILED -- {}", reason);
        return;
    }

    let loaded = match loader::load(&elf, &mut space) {
        Ok(loaded) => loaded,
        Err(err) => {
            serial_println!("Runix ARM kernel: net TCP proof FAILED -- load: {}", err);
            return;
        }
    };

    // Same instruction-cache reasoning as `el0_proof::prove_el0_process`:
    // the loaded bytes reached their frames as data writes, and are about
    // to be fetched through a different VA.
    //
    // SAFETY: cache maintenance on the current PE with no memory operands.
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }

    IMAGE_ENTRY.store(loaded.entry, Ordering::Relaxed);
    IMAGE_STACK_TOP.store(loaded.stack_top, Ordering::Relaxed);
    IMAGE_ROOT.store(space.root(), Ordering::Relaxed);

    serial_println!(
        "Runix ARM kernel: net TCP proof image entry={:#x} stack_top={:#x} segment_pages={} \
         stack_pages={} (root={:#x}, slot={}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        loaded.entry,
        loaded.stack_top,
        loaded.segment_pages,
        loaded.stack_pages,
        space.root(),
        dev.slot,
        dev.mac[0],
        dev.mac[1],
        dev.mac[2],
        dev.mac[3],
        dev.mac[4],
        dev.mac[5],
    );

    if let Err(err) = crate::scheduler::spawn_with_address_space(net_tcp_proof_thread, space) {
        serial_println!("Runix ARM kernel: net TCP proof FAILED -- spawn: {}", err);
        return;
    }

    // Bounded for the same reason `el0_proof::prove_el0_process`'s loop is:
    // a switch that never comes back must surface as a FAIL line, not a
    // hang. The real TCP round trip happens entirely *inside* the one EL0
    // excursion (`net-driver-host-arm`'s own up-to-2,000,000-iteration
    // internal retry loop), so the boot thread is only ever waiting for one
    // scheduler handoff plus one `SVC` back, not polling network state
    // itself -- 64 yields is as generous here as it is there.
    let mut yields = 0;
    while !FINISHED.load(Ordering::Relaxed) && yields < 64 {
        crate::scheduler::yield_now();
        yields += 1;
    }
    if !FINISHED.load(Ordering::Relaxed) {
        serial_println!(
            "Runix ARM kernel: net TCP proof FAILED -- the EL0 thread never reported back after \
             {} boot-thread yields",
            yields
        );
    }
}
