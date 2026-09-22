//! Bootable entry point. `bootloader_api::entry_point!` is what the
//! `bootloader` crate's image builder (see `../xtask`) looks for — it wraps
//! `kernel_main` with the calling convention the bootloader itself expects
//! and hands us a `&'static mut BootInfo` describing memory regions, the
//! framebuffer, etc.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::elf::Elf64;
use runix_kernel::process::AddressSpace;
use runix_kernel::serial_println;
use x86_64::structures::paging::{FrameAllocator, Page, PageTableFlags, PhysFrame};
use x86_64::VirtAddr;

/// The real payload the CITADEL boot-authorization gate (Phase B7, below)
/// checks before loading -- see `citadel.rs`'s doc comment: this used to
/// only be exercised by `kernel/tests/grid_sandbox_wasm.rs`, not gated by
/// anything on the real boot path. Requires `grid-sandbox-host` already
/// built (`cd grid-sandbox-host && cargo build --target x86_64-unknown-none
/// --release`) before `main.rs` itself will compile -- `include_bytes!` is
/// a compile-time file read, not a Cargo dependency the build graph
/// resolves on its own. See `docs/BUILDING.md`.
static GRID_SANDBOX_HOST_ELF: &[u8] =
    include_bytes!("../../grid-sandbox-host/target/x86_64-unknown-none/release/grid-sandbox-host");

/// Must match `grid-sandbox-host/src/main.rs`'s own `HEAP_START`/`HEAP_SIZE`
/// -- that binary has no privilege to map its own memory (ring 3 code can't
/// touch page tables at all), so whoever loads it sets this up. Same
/// addresses `kernel/tests/grid_sandbox_wasm.rs` uses -- no conflict
/// possible, since `AddressSpace::new()` gives this its own private page
/// table, entirely separate from `user_hello`'s (mapped directly into the
/// boot thread's own address space, not a fresh `AddressSpace`).
const GRID_SANDBOX_HEAP_START: u64 = 0x_2222_2222_0000;
/// Must match `grid-sandbox-host/src/main.rs`'s own `HEAP_SIZE` exactly --
/// see that constant's doc comment for why it's 8 MiB, not the original
/// 256 KiB: a real `T1Critical`-tier `memory.grow` (the boot-level
/// tier-correctness probe, see `GridBootInfo`'s doc comment below) needs
/// this process's actual allocator to back the growth it permits, not just
/// a limiter that abstractly says "allowed".
const GRID_SANDBOX_HEAP_SIZE: u64 = 8 * 1024 * 1024;
const GRID_SANDBOX_STACK_VA: u64 = 0x_2222_3333_0000;
const GRID_SANDBOX_STACK_SIZE: u64 = 4096 * 4;
/// The one page `grid-sandbox-host` reads at startup to learn its CITADEL-
/// assigned sandbox tier -- same `0x_2222_...` VA family as the heap/stack
/// constants above. See [`GridBootInfo`]'s doc comment for the ABI contract.
const GRID_INFO_VA: u64 = 0x_2222_4444_0000;
/// Offset into the `GRID_INFO_VA` page `grid-sandbox-host` writes its own
/// boot-level tier-correctness result to (whether a real `memory.grow`
/// sized to succeed only under `T1Critical` actually did) -- same
/// convention `net-driver-host`'s `NET_RESULT_OFFSET` already established
/// (kernel writes the request into the page, the ring-3 process writes its
/// result back into the same page). Only read by
/// `kernel/tests/grid_sandbox_wasm.rs`/`grid_sandbox_tier_t1.rs`/`_t3.rs`
/// -- the real boot path never checks it, same as `NET_RESULT_OFFSET`
/// isn't checked outside `net_driver_icmp.rs`.
#[allow(dead_code)]
const GRID_GROW_RESULT_OFFSET: usize = 128;

/// The tier byte `grid-sandbox-host` reads at [`GRID_INFO_VA`] to select its
/// `wasm-runtime` resource limits. Not a shared type with
/// `grid-sandbox-host/src/main.rs` -- that crate has no
/// `citadel-integration` dependency (see that crate's own doc comment for
/// why) -- so, same as `NetBootInfo`'s own "no shared type, just an agreed
/// ABI" note, both sides just agree on this plain-`u8` convention:
/// `0` = T1Critical, `1` = T2Trusted, `2` = T3Untrusted.
#[repr(C)]
struct GridBootInfo {
    tier: u8,
}

/// `net-driver-host`, Phase B8's payload — see `citadel.rs`'s doc comment
/// and `docs/STATUS.md`'s network-stack section. Same `include_bytes!`
/// compile-time requirement as `GRID_SANDBOX_HOST_ELF` above: `cd
/// net-driver-host && cargo build --target x86_64-unknown-none --release`
/// must run before `main.rs` itself will compile.
static NET_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../net-driver-host/target/x86_64-unknown-none/release/net-driver-host");

// Leading nibble `0x1` -- deliberately *not* `0x3`: `scheduler.rs`'s
// `KERNEL_ENTRY_STACK_REGION_START` is `0x_3333_3333_0000`, and a P4 slot
// spans 512 GiB -- every address here originally used a `0x_3333_...`
// prefix too, differing only in bits far below that span, so all of them
// landed in the *same* P4 slot as the kernel-entry-stack region. Confirmed
// as a real bug, not a theoretical one: `NET_INFO_VA` mapped a page there,
// which detached that P4 slot in this process's own `AddressSpace` (see
// `map_frame`'s "detach on first touch" doc comment) — invisibly breaking
// *this same process's own* kernel-entry stack (mapped into that same
// shared slot by `alloc_kernel_entry_stack`, before this process's private
// copy of it got detached), which double-faulted the instant this process
// first trapped into ring 0. `0x1` shares no P4 slot with any other fixed
// region in this codebase (`0x2`/`0x4`/`0x5`/`0x6`/`0x7` are all taken —
// see `GRID_SANDBOX_*`/kernel heap/`STACK_REGION_START`/test region).
const NET_HEAP_START: u64 = 0x_1111_1111_0000;
const NET_HEAP_SIZE: u64 = 256 * 1024;
const NET_STACK_VA: u64 = 0x_1111_2222_0000;
const NET_STACK_SIZE: u64 = 4096 * 4;
/// Must match `net-driver-host/src/main.rs`'s own `NET_INFO_VA`/`NET_RXQ_VA`/
/// `NET_TXQ_VA`/`NET_RXBUF_VA`/`NET_TXBUF_VA` constants exactly — this
/// kernel maps each of these virtual regions in `net-driver-host`'s private
/// `AddressSpace` and separately hands it the matching *physical* addresses
/// via `NetBootInfo` (see that struct's doc comment on the other side for
/// why this process needs to be told, rather than compute them itself).
const NET_INFO_VA: u64 = 0x_1111_3333_0000;
const NET_RXQ_VA: u64 = 0x_1111_4444_0000;
const NET_TXQ_VA: u64 = 0x_1111_5555_0000;
const NET_RXBUF_VA: u64 = 0x_1111_6666_0000;
const NET_TXBUF_VA: u64 = 0x_1111_7777_0000;
const NET_QUEUE_ALIGN: u64 = 4096;
/// Grown from Phase 1's 4 -- see `net-driver-host/src/smoltcp_device.rs`'s
/// `RX_BUFFER_COUNT` for why (a more usable receive window under smoltcp).
const NET_RX_BUFFER_COUNT: u64 = 8;
/// New in Phase 2a -- Phase 1 only ever used one TX buffer (always
/// descriptor 0); smoltcp needs more than one in flight at once (e.g. an
/// ARP reply interleaved with the packet it's routing). See
/// `net-driver-host/src/smoltcp_device.rs`'s `TX_BUFFER_COUNT`.
const NET_TX_BUFFER_COUNT: u64 = 4;

/// Mirrors `net-driver-host/src/main.rs`'s own `NetBootInfo` — `repr(C)`,
/// same field order, in both independently-compiled crates. The only
/// contract connecting them for this struct, same as the syscall ABI itself
/// (not a shared type) connects `syscall.rs` to any ring 3 caller.
#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; 8],
    tx_buffer_phys: [u64; 4],
    /// `0` here on the real boot path -- no `guestfwd` route or host
    /// listener exists for `net-driver-host`'s Phase 2b TCP proof to
    /// reach outside a dedicated test (`kernel/tests/net_driver_tcp.rs`),
    /// so attempting it here would just add a full poll-bound's worth of
    /// wall-clock time to every boot for no benefit.
    attempt_tcp: u8,
    /// `0` on the real boot path -- no other process asks this driver for
    /// a socket here, so entering `net-driver-host`'s sockets IPC server
    /// loop would just add an unused wait to every boot, same reasoning
    /// `BlkBootInfo::serve_fs_requests`'s own doc comment already gives.
    /// `1` only in `kernel/tests/net_driver_sockets.rs`.
    serve_sockets: u8,
    /// `1` here on the real boot path -- see
    /// `net-driver-host/src/main.rs`'s `NetBootInfo::use_dhcp` doc comment
    /// for the full reasoning (production has no reason to hardcode an
    /// address QEMU/SLIRP's own DHCP server can hand out for real) and for
    /// which test files deliberately leave this `0` instead.
    use_dhcp: u8,
    /// `0` here on the real boot path -- no DNS-resolution-dependent
    /// behavior exists yet for this driver's own boot to need, same
    /// "don't add an unused attempt to every boot" reasoning `attempt_tcp`/
    /// `serve_sockets` above already give. `1` only in
    /// `kernel/tests/net_driver_dns.rs`. See
    /// `net-driver-host/src/main.rs`'s `NetBootInfo::use_dns` doc comment.
    use_dns: u8,
}

/// `blk-driver-host`, Phase B9's payload (filesystem driver, Phase 1 —
/// virtio-blk transport). Same `include_bytes!` compile-time requirement as
/// `NET_DRIVER_HOST_ELF` above: `cd blk-driver-host && cargo build --target
/// x86_64-unknown-none --release` must run before `main.rs` itself will
/// compile.
static BLK_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../blk-driver-host/target/x86_64-unknown-none/release/blk-driver-host");

// New VA family, leading group `0x0999` -- deliberately not any of the
// families already in use here (`0x1111`=net, `0x2222`=grid,
// `0x3333`=kernel-entry-stack-region, `0x4444`/`0x5555`/`0x6666`=kernel
// heap/stack/etc, `0x7777`=test-only regions). A P4 slot spans 512 GiB and
// is determined by a 16-bit group's top 9 bits, so any two groups differing
// only below `0x80` collide -- `0x0999` sits comfortably clear of every one
// of those. Also deliberately not `0x0000`: `AddressSpace::new()`'s doc
// comment leaves open the possibility slot 0 carries something from
// whatever table a process was seeded from, and an unused alternative is
// equally cheap to pick instead of gambling on it being empty.
const BLK_HEAP_START: u64 = 0x_0999_1111_0000;
const BLK_HEAP_SIZE: u64 = 256 * 1024;
const BLK_STACK_VA: u64 = 0x_0999_2222_0000;
/// Bumped from `4096 * 4` (16 KiB) to `4096 * 8` (32 KiB) for Phase 7:
/// `run_grow_proof`/`run_create_proof` each add another `[u8; 4096]`-sized
/// local buffer to the same sequential call chain Phase 6's
/// `run_partial_write_proof` already used most of this budget on —
/// confirmed for real, not guessed: the unbumped size produced a genuine
/// ring-3 stack-overflow page fault (`CAUSED_BY_WRITE | USER_MODE`, faulting
/// address a few dozen bytes past the live stack pointer) partway through
/// Phase 7's proofs, the same class of "a real bug found by actually
/// booting it" this codebase's docs/STATUS.md always calls out rather than
/// silently working around.
const BLK_STACK_SIZE: u64 = 4096 * 8;
/// Must match `blk-driver-host/src/main.rs`'s own `BLK_INFO_VA`/`BLK_QUEUE_VA`/
/// `BLK_REQBUF_VA` constants exactly -- same "kernel maps the VA, hands over
/// the matching physical address via a boot-info page" contract
/// `NET_INFO_VA` established (see that constant's doc comment).
const BLK_INFO_VA: u64 = 0x_0999_3333_0000;
/// virtio-blk legacy has exactly one request queue (unlike virtio-net's
/// RX/TX pair), so only one virtqueue region is needed -- 3 pages
/// (`NET_QUEUE_ALIGN`-sized, reusing that same alignment constant) for the
/// descriptor table + avail ring + used ring.
const BLK_QUEUE_VA: u64 = 0x_0999_4444_0000;
/// One 4 KiB page: header (offset 0, 16 bytes) + one 512-byte sector +
/// device-written status byte (offset 528) -- reused sequentially for both
/// the write and the read-back request, no concurrency needed for this
/// slice.
const BLK_REQBUF_VA: u64 = 0x_0999_5555_0000;

/// Mirrors `blk-driver-host/src/main.rs`'s own `BlkBootInfo` -- `repr(C)`,
/// same field order, in both independently-compiled crates. Not a shared
/// type, same "no shared type, just an agreed ABI" note as `NetBootInfo`'s
/// own doc comment.
#[repr(C)]
struct BlkBootInfo {
    io_base: u16,
    _pad: u16,
    queue_phys: u64,
    reqbuf_phys: u64,
    /// `0` on the real boot path -- no FAT32 image is attached there, and
    /// attempting the locate-and-read walk would just add wall-clock time
    /// to every real boot for no benefit. Same exact reasoning
    /// `NetBootInfo::attempt_tcp`'s own doc comment already gives.
    attempt_fat32: u8,
    /// Filesystem driver, Phase 3: `0` on the real boot path and every
    /// earlier test -- no other process asks for a file there, so entering
    /// a receive-loop would just add an unused, never-satisfied wait to
    /// every other boot/test. `1` only in `kernel/tests/blk_fs_ipc.rs`,
    /// which alone spawns a second process to actually send a request.
    serve_fs_requests: u8,
}

/// Filesystem driver, Phase 3's fixed IPC ports -- request (a requester
/// sends one trigger byte here) and response (`blk-driver-host` replies
/// with a 2-byte little-endian length header, then that many content
/// bytes) -- distinct from the transient demo ports (`0`-`2`) Phase
/// B4/B5's own capability-gate proof already uses during boot, though
/// those never stay live long enough to actually collide with these.
#[allow(dead_code)]
const BLK_FS_REQUEST_PORT: usize = 8;
const BLK_FS_RESPONSE_PORT: usize = 9;
/// Filesystem driver, Phase 8: a second, independently capability-gated
/// port for write requests -- a caller needs a capability scoped to
/// `port_resource(BLK_FS_WRITE_REQUEST_PORT)` specifically, separate from
/// whatever authorizes a read trigger on `BLK_FS_REQUEST_PORT`. Must match
/// `blk-driver-host/src/main.rs`'s own `FS_WRITE_REQUEST_PORT` constant.
#[allow(dead_code)]
const BLK_FS_WRITE_REQUEST_PORT: usize = 10;

/// Offset into the `BLK_INFO_VA` page `blk-driver-host` writes its own
/// write-then-read-back result byte to -- same convention `NET_RESULT_OFFSET`
/// already established (kernel writes the request into the page, the ring-3
/// process writes its result back into the same page). Only read by
/// `kernel/tests/blk_driver_rw.rs` -- the real boot path never checks it.
#[allow(dead_code)]
const BLK_RESULT_OFFSET: usize = 128;
#[allow(dead_code)]
const BLK_RESULT_PASS: u8 = 1;
#[allow(dead_code)]
const BLK_RESULT_FAIL: u8 = 2;

/// Offset for the FAT32 locate-and-read outcome (filesystem driver, Phase
/// 2) -- one past `BLK_RESULT_OFFSET`, same "room to spare, documented
/// offset convention" `NET_TCP_RESULT_OFFSET` already established relative
/// to `NET_RESULT_OFFSET`. Only read by `kernel/tests/blk_fat32_read.rs` --
/// the real boot path never checks it (`attempt_fat32` is always `0` there).
#[allow(dead_code)]
const BLK_FAT32_RESULT_OFFSET: usize = 129;

/// The default config doesn't map all of physical memory into the kernel's
/// address space — `memory::init`'s `OffsetPageTable` needs that mapping to
/// exist (it translates physical frame addresses to virtual ones by adding
/// a fixed offset), so ask the bootloader for it explicitly.
///
/// `kernel_stack_size` is bumped well past the 80 KiB default too:
/// unoptimized elliptic-curve arithmetic (see the `[profile.dev.package.*]`
/// overrides in Cargo.toml) can still use several KiB of stack per call
/// even optimized, and the boot thread runs entirely on this stack — it
/// blew straight through 80 KiB and corrupted the heap once
/// `capability-manager` calls landed here, before those overrides existed.
/// This is a size bump, not a fix in itself; the real fix is not letting a
/// single call chain need anywhere near this much in the first place.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    serial_println!("Runix kernel: boot OK (Phase 0)");

    runix_kernel::boot::init();
    serial_println!("Runix kernel: CPU init OK (Phase 2: GDT + IDT)");

    // Prove the IDT is actually wired up, not just loaded: trigger a
    // breakpoint exception and confirm execution resumes afterward instead
    // of double-faulting (which would mean the handler/IST setup is wrong).
    x86_64::instructions::interrupts::int3();
    serial_println!("Runix kernel: breakpoint exception handled, execution resumed");

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("bootloader did not map physical memory (check BOOTLOADER_CONFIG)"),
    );
    let mapper = unsafe { runix_kernel::memory::init(physical_memory_offset) };
    let frame_allocator =
        unsafe { runix_kernel::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    // From here on, `scheduler` (thread-stack guard pages) and
    // `userspace` (the ring 3 stack/code-page grant) reach the mapper and
    // frame allocator through this single global slot instead of `&mut`
    // references threaded through the rest of this function — see
    // `memory::install`'s doc comment for why there must be exactly one.
    runix_kernel::memory::install(mapper, frame_allocator);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        runix_kernel::allocator::init_heap(mapper, frame_allocator)
    })
    .expect("heap initialization failed");
    serial_println!("Runix kernel: memory init OK (Phase 3: paging + heap)");

    // Prove the heap actually works, not just that init_heap() returned Ok:
    // both a single allocation and a growing collection, which forces the
    // allocator to actually manage free space rather than just handing out
    // one block.
    let heap_value = Box::new(41);
    let mut heap_vec = Vec::new();
    for i in 0..100 {
        heap_vec.push(i);
    }
    serial_println!(
        "Runix kernel: heap alloc test OK (box={}, vec_len={}, vec_sum={})",
        heap_value,
        heap_vec.len(),
        heap_vec.iter().sum::<i32>()
    );

    x86_64::instructions::interrupts::enable();
    serial_println!("Runix kernel: interrupts enabled (Phase 4: PIC + PIT timer)");

    // Prove the timer IRQ is actually firing, not just that `sti` didn't
    // fault: spin until a handful of ticks land.
    let start_ticks = runix_kernel::interrupts::ticks();
    while runix_kernel::interrupts::ticks() < start_ticks + 5 {
        x86_64::instructions::hlt();
    }
    serial_println!(
        "Runix kernel: timer interrupt OK (Phase 4: {} ticks observed)",
        runix_kernel::interrupts::ticks()
    );

    // Round-robin scheduling: spawn three threads that each do a bit of
    // real work (proving their own saved context resumes exactly where it
    // left off — not just that a reschedule lands *somewhere* without
    // faulting), then let this thread (the boot context, folded into the
    // same run queue as a placeholder) drive several rounds of yielding so
    // their output actually interleaves instead of running to completion
    // back-to-back.
    runix_kernel::scheduler::init();
    runix_kernel::scheduler::spawn(thread_a);
    runix_kernel::scheduler::spawn(thread_b);
    runix_kernel::scheduler::spawn(thread_c);
    for _ in 0..9 {
        runix_kernel::scheduler::yield_now();
    }
    serial_println!("Runix kernel: scheduler test OK (Phase 5: context switching + round-robin)");

    // Syscall ABI: prove `int 0x80` round-trips through the naked entry
    // gate, the register-remapping shim, and back — SYS_WRITE writes '!'
    // via the same serial port everything else here uses, but through the
    // syscall path instead of a direct function call.
    unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_WRITE, b'!' as u64, 0, 0);
    }
    serial_println!("\nRunix kernel: syscall ABI OK (Phase 6: int 0x80 round-tripped)");

    // IPC channels: two more threads, talking only through port 0 (never a
    // shared variable), driven entirely through syscalls (SYS_IPC_SEND /
    // SYS_IPC_RECV) rather than calling `ipc::send`/`ipc::recv` directly —
    // this is what actually proves the syscall ABI and the IPC primitives
    // work *together*, not just each in isolation. `SYS_IPC_SEND` is now
    // capability-gated (see below), so the sender needs a token authorizing
    // "port:0" — issued here with the kernel's own demo trust root, since
    // there's no external issuer yet.
    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let port0_token = runix_capability_manager::CapabilityToken::issue(
        "thread:sender",
        runix_kernel::capabilities::port_resource(0),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    runix_kernel::scheduler::spawn_with_capability(thread_sender, Some(port0_token));
    runix_kernel::scheduler::spawn(thread_receiver);
    for _ in 0..12 {
        runix_kernel::scheduler::yield_now();
    }

    // Capability enforcement itself: same SYS_IPC_SEND path, same demo
    // trust root, but now on port 1 with two senders — one holding a valid
    // "port:1" token, one holding none at all. If the gate in
    // syscall::dispatch works, only the authorized byte ever reaches the
    // channel; the unauthorized send is denied before ipc::send() runs.
    let port1_token = runix_capability_manager::CapabilityToken::issue(
        "thread:sender_authorized",
        runix_kernel::capabilities::port_resource(1),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    runix_kernel::scheduler::spawn_with_capability(thread_sender_authorized, Some(port1_token));
    runix_kernel::scheduler::spawn(thread_sender_unauthorized);
    for _ in 0..6 {
        runix_kernel::scheduler::yield_now();
    }
    let port1_contents = runix_kernel::ipc::try_recv(1);
    serial_println!(
        "Runix kernel: capability gate OK (Phase B4: port 1 received {:?} — authorized byte only, unauthorized send was denied)",
        port1_contents.map(|b| b as char)
    );

    // Revocation: a token that's cryptographically valid on every count
    // `verify()` itself checks (right signature, not expired, right
    // resource) but has been explicitly revoked must still be denied —
    // proves the gate actually consults revocation status, not just
    // `check()`'s crypto/expiry/resource checks (that path was already
    // exercised above and would pass this token too, since nothing about
    // it is otherwise invalid).
    let port2_token = runix_capability_manager::CapabilityToken::issue(
        "thread:sender_revoked",
        runix_kernel::capabilities::port_resource(2),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    runix_kernel::capabilities::revoke(&port2_token);
    runix_kernel::scheduler::spawn_with_capability(thread_sender_revoked, Some(port2_token));
    for _ in 0..3 {
        runix_kernel::scheduler::yield_now();
    }
    let port2_contents = runix_kernel::ipc::try_recv(2);
    serial_println!(
        "Runix kernel: capability revocation OK (Phase B5: port 2 received {:?} — revoked token was denied despite passing check() on its own)",
        port2_contents
    );

    // CITADEL boot-time module authorization: proves the `citadel-integration`
    // <-> kernel wiring works end to end (see `citadel.rs`'s doc comment) —
    // an allowlist entry signed for this exact module's bytes is accepted,
    // and the same check against tampered bytes is refused. Still throwaway
    // bytes here, not a real module — Phase B7 below is what actually gates
    // a real load with this same mechanism, on `grid-sandbox-host`.
    let demo_module_bytes = b"demo module bytes - not a real loaded module yet";
    let citadel_authorized = runix_kernel::citadel::demo_authorize(
        "demo-module",
        demo_module_bytes,
        runix_kernel::citadel::SandboxTier::T2Trusted,
    );
    let citadel_tampered_rejected = runix_kernel::citadel::demo_reject_tampered(
        "demo-module",
        demo_module_bytes,
        runix_kernel::citadel::SandboxTier::T2Trusted,
    );
    serial_println!(
        "Runix kernel: CITADEL boot authorization OK (Phase B6: authorized={:?}, tampered rejected={:?})",
        citadel_authorized,
        citadel_tampered_rejected
    );

    // The real integration Phase B6 (and citadel.rs's own doc comment) was
    // building toward: gate an actual module load through the allowlist,
    // not a demo call on throwaway bytes. `grid-sandbox-host`'s real
    // compiled bytes are checked against a demo allowlist built for those
    // exact bytes -- fail-closed, same as `BootAllowlist`'s own contract --
    // and only loaded/run if authorized. The load/run mechanism itself
    // (`elf::Elf64` -> `process::AddressSpace` -> `scheduler::spawn_ring3_process`)
    // is exactly what `kernel/tests/grid_sandbox_wasm.rs` already proved
    // works; what's new here is a real boot path actually depending on the
    // gate in front of it, not a test calling both pieces independently.
    match runix_kernel::citadel::demo_authorize(
        "grid-sandbox-host",
        GRID_SANDBOX_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T2Trusted,
    ) {
        Ok(tier) => {
            serial_println!(
                "Runix kernel: grid-sandbox-host authorized by CITADEL allowlist (Phase B7)"
            );
            load_and_run_grid_sandbox_host(tier);
        }
        Err(e) => {
            // Fail-closed: an unauthorized module is never parsed, loaded,
            // or run. The demo allowlist above is built to match these
            // exact bytes, so this branch shouldn't fire in practice today
            // -- Phase B6 already proves the rejection path works, against
            // deliberately tampered bytes; this is the same gate, just
            // guarding a real load instead of a demo-only check.
            serial_println!(
                "Runix kernel: grid-sandbox-host REJECTED by CITADEL allowlist ({:?}) — not loaded (Phase B7)",
                e
            );
        }
    }

    // Network stack, Phase B8 (see docs/STATUS.md's network-stack section):
    // find virtio-net's I/O-space BAR0, CITADEL-authorize net-driver-host
    // the same way grid-sandbox-host is above, then load and run it as a
    // capability-gated ring 3 process — the driver never gets raw port I/O
    // privilege itself, only what `ioport_range_resource` grants for
    // exactly this device's register block.
    let pci_devices = runix_kernel::pci::scan();
    match runix_kernel::pci::find_virtio_net(&pci_devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => {
            match runix_kernel::citadel::demo_authorize(
                "net-driver-host",
                NET_DRIVER_HOST_ELF,
                runix_kernel::citadel::SandboxTier::T1Critical,
            ) {
                // The returned tier is plumbed here for signature-uniformity
                // with grid-sandbox-host's Phase B7 authorization, but
                // net-driver-host doesn't yet read a `GridBootInfo`-style
                // tier page or otherwise consume it downstream this slice —
                // not hidden, just not built out yet (see `docs/ROADMAP.md`).
                Ok(_tier) => {
                    serial_println!(
                        "Runix kernel: net-driver-host authorized by CITADEL allowlist (Phase B8)"
                    );
                    load_and_run_net_driver_host(io_base, now, &signing_key);
                }
                Err(e) => {
                    serial_println!(
                        "Runix kernel: net-driver-host REJECTED by CITADEL allowlist ({:?}) — not loaded (Phase B8)",
                        e
                    );
                }
            }
        }
        None => {
            serial_println!("Runix kernel: no virtio-net I/O-space BAR0 found — Phase B8 skipped");
        }
    }

    // Filesystem driver, Phase 1: virtio-blk transport (Phase B9, see
    // docs/STATUS.md's "Filesystem driver, Phase 1" section). Same
    // find-device -> CITADEL-authorize -> load-and-run shape as Phase B8,
    // reusing the same `pci_devices` scan (no need to re-scan PCI config
    // space for a second device class).
    match runix_kernel::pci::find_virtio_blk(&pci_devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => {
            match runix_kernel::citadel::demo_authorize(
                "blk-driver-host",
                BLK_DRIVER_HOST_ELF,
                runix_kernel::citadel::SandboxTier::T1Critical,
            ) {
                Ok(_tier) => {
                    serial_println!(
                        "Runix kernel: blk-driver-host authorized by CITADEL allowlist (Phase B9)"
                    );
                    load_and_run_blk_driver_host(io_base, now, &signing_key, false, false);
                }
                Err(e) => {
                    serial_println!(
                        "Runix kernel: blk-driver-host REJECTED by CITADEL allowlist ({:?}) — not loaded (Phase B9)",
                        e
                    );
                }
            }
        }
        None => {
            serial_println!("Runix kernel: no virtio-blk I/O-space BAR0 found — Phase B9 skipped");
        }
    }

    // Ring 3: map a user-accessible stack, grant ring 3 access to the one
    // code page `user_hello` lives on, then spawn it as a real scheduler
    // thread (its own dedicated kernel-entry stack, so the timer can safely
    // preempt it mid-spin — see `spawn_ring3_shared`'s doc comment for why
    // a raw, un-scheduled `enter_usermode` from the boot thread is no
    // longer safe now that preemption is real, not just cooperative).
    let user_stack_top = runix_kernel::memory::with_mapper_and_frame_allocator(
        runix_kernel::userspace::map_user_stack,
    )
    .expect("failed to map user stack");
    let user_entry = VirtAddr::new(runix_kernel::userspace::user_hello as *const () as u64);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, _frame_allocator| unsafe {
        runix_kernel::userspace::allow_user_access(mapper, user_entry);
    });
    #[allow(static_mut_refs)]
    unsafe {
        USER_HELLO_ENTRY = user_entry.as_u64();
        USER_HELLO_STACK_TOP = user_stack_top.as_u64();
    }
    serial_println!("Runix kernel: entering ring 3 (Phase 7: user-space transition)");
    runix_kernel::scheduler::spawn_ring3_shared(user_hello_trampoline);

    // The boot thread's own work is done — everything left to prove (ring 3
    // running, real preemption not corrupting anything) happens on other
    // threads now. It has no dedicated stack region of its own for
    // `exit_current_thread` to reclaim (see that function's doc comment),
    // so it joins the same forever-yield pattern `thread_a`/`b`/`c` use
    // rather than actually exiting.
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

static mut USER_HELLO_ENTRY: u64 = 0;
static mut USER_HELLO_STACK_TOP: u64 = 0;

extern "C" fn user_hello_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let (entry, stack_top) = unsafe { (USER_HELLO_ENTRY, USER_HELLO_STACK_TOP) };
    unsafe {
        runix_kernel::userspace::enter_usermode(VirtAddr::new(entry), VirtAddr::new(stack_top));
    }
}

/// Parses, loads, and runs `GRID_SANDBOX_HOST_ELF` as a real ring 3
/// process -- called only after Phase B7's CITADEL check authorizes it.
/// Identical mechanism to `kernel/tests/grid_sandbox_wasm.rs` (see that
/// file for why each step is shaped the way it is, including the two real
/// bugs -- stack under-mapping, an unzeroed heap page -- found getting
/// this working the first time); this is that same proven path, just
/// reached from the real boot sequence instead of a standalone test.
fn load_and_run_grid_sandbox_host(tier: runix_kernel::citadel::SandboxTier) {
    serial_println!(
        "Runix kernel: parsing grid-sandbox-host ({} bytes)",
        GRID_SANDBOX_HOST_ELF.len()
    );
    let elf = Elf64::parse(GRID_SANDBOX_HOST_ELF)
        .expect("grid-sandbox-host failed to parse as a valid ELF64 binary");

    let mut space = AddressSpace::new();
    let entry = elf
        .load_segments(&mut space)
        .expect("grid-sandbox-host failed to load its PT_LOAD segments");
    serial_println!(
        "Runix kernel: grid-sandbox-host loaded, entry point {:#x}",
        entry.as_u64()
    );

    // The ELF loader only maps what the ELF itself declares -- the
    // payload's heap and ring 3 stack are runtime-only regions with no
    // PT_LOAD segment behind them, so mapping those is this loader's job.
    let heap_start_page = Page::containing_address(VirtAddr::new(GRID_SANDBOX_HEAP_START));
    let heap_end_page = Page::containing_address(VirtAddr::new(
        GRID_SANDBOX_HEAP_START + GRID_SANDBOX_HEAP_SIZE - 1,
    ));
    let heap_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        // A freshly allocated frame carries whatever its previous owner
        // left in it, not guaranteed-zero -- `LockedHeap::init` only
        // writes its own free-list header, not the whole region.
        space.map_private_page(page, heap_flags).fill(0);
    }

    let stack_start_page = Page::containing_address(VirtAddr::new(GRID_SANDBOX_STACK_VA));
    let stack_end_page = Page::containing_address(VirtAddr::new(
        GRID_SANDBOX_STACK_VA + GRID_SANDBOX_STACK_SIZE - 1,
    ));
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for page in Page::range_inclusive(stack_start_page, stack_end_page) {
        space.map_private_page(page, stack_flags);
    }

    // GridBootInfo: the one page grid-sandbox-host reads at startup to learn
    // its CITADEL-assigned sandbox tier -- same pattern
    // `load_and_run_net_driver_host` uses for `NetBootInfo`.
    let info_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let info_page = Page::containing_address(VirtAddr::new(GRID_INFO_VA));
    let info_content = space.map_private_page(info_page, info_flags);
    info_content.fill(0);
    let tier_byte = match tier {
        runix_kernel::citadel::SandboxTier::T1Critical => 0u8,
        runix_kernel::citadel::SandboxTier::T2Trusted => 1u8,
        runix_kernel::citadel::SandboxTier::T3Untrusted => 2u8,
    };
    unsafe {
        core::ptr::write_volatile(
            info_content.as_mut_ptr() as *mut GridBootInfo,
            GridBootInfo { tier: tier_byte },
        );
    }

    #[allow(static_mut_refs)]
    unsafe {
        GRID_SANDBOX_ENTRY_POINT = entry.as_u64();
    }
    runix_kernel::scheduler::spawn_ring3_process(grid_sandbox_host_trampoline, space);

    // The payload writes 'H', 'i', then yields forever -- a handful of
    // round trips is plenty to let its output land before the boot thread
    // moves on; it keeps existing afterward as a background thread that
    // yields forever, same as thread_a/b/c above do once their own bursts
    // finish.
    for _ in 0..20 {
        runix_kernel::scheduler::yield_now();
    }
    serial_println!(
        "Runix kernel: grid-sandbox-host ran wasmi in an isolated ring 3 process (Phase B7)"
    );
}

/// `entry` (the ELF's own entry point, `_start` in `grid-sandbox-host`) is
/// only known at runtime, parsed from the loaded binary -- captured here so
/// the `extern "C" fn() -> !` trampoline `spawn_ring3_process` requires (a
/// bare function pointer, no captures) can still reach it.
static mut GRID_SANDBOX_ENTRY_POINT: u64 = 0;

extern "C" fn grid_sandbox_host_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { GRID_SANDBOX_ENTRY_POINT };
    unsafe {
        runix_kernel::userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(GRID_SANDBOX_STACK_VA + GRID_SANDBOX_STACK_SIZE),
        );
    }
}

/// Computes the *physical* address backing a page `map_private_page` just
/// mapped, from the `&'static mut [u8; 4096]` it returns -- that pointer is
/// `physical_memory_offset() + frame.start_address()` by construction (see
/// `map_private_page`'s own doc comment), so subtracting the offset back out
/// recovers the frame's physical address without needing a kernel API
/// change to hand the `PhysFrame` back directly. This is how
/// `load_and_run_net_driver_host` bridges the gap `NetBootInfo`'s own doc
/// comment describes: a ring 3 process has no way to learn its own physical
/// addresses, but virtio's `QueueAddress`/descriptor `addr` fields need
/// real ones.
fn page_phys_addr(page: &mut [u8; 4096]) -> u64 {
    let virt = VirtAddr::from_ptr(page.as_ptr());
    virt - runix_kernel::memory::physical_memory_offset()
}

/// Maps `page_count` zeroed pages starting at `start_va`, all landing on
/// physically *contiguous* frames, and returns the first page's physical
/// address.
///
/// A first version of this tried to get contiguity "for free" by just
/// calling `AddressSpace::map_private_page` `page_count` times in a row and
/// trusting `BootInfoFrameAllocator`'s bump allocation to hand out
/// consecutive frames -- it doesn't, reliably: `map_private_page`'s own
/// `map_to` call can itself consume *extra* frames for intermediate P1/P2/P3
/// page-table levels the first mapping in a fresh region needs, interleaved
/// with the leaf-frame allocations this function actually cares about.
/// Confirmed as a real bug, not a theoretical one: booting with this fixed
/// layout hit `left: 3547136, right: 3538944` -- frame 1 landed 2 frames
/// past frame 0, not 1, because mapping page 0 allocated a P1 table frame in
/// between.
///
/// The fix: allocate every leaf frame *first*, as one tight batch with
/// nothing else running in between (no page-table-building side effects can
/// interleave with a call that never invokes `map_to`), then map each
/// pre-allocated frame explicitly via `map_existing_frame` -- whatever table
/// frames *that* needs get allocated strictly *after* this function's own
/// leaf frames, never in between them.
fn map_zeroed_contiguous_region(
    space: &mut AddressSpace,
    start_va: u64,
    page_count: u64,
    flags: PageTableFlags,
) -> u64 {
    let frames: Vec<PhysFrame> =
        runix_kernel::memory::with_mapper_and_frame_allocator(|_mapper, frame_allocator| {
            (0..page_count)
                .map(|_| {
                    frame_allocator
                        .allocate_frame()
                        .expect("out of physical memory for net-driver-host's virtqueue region")
                })
                .collect()
        });

    for (i, frame) in frames.iter().enumerate() {
        if i > 0 {
            assert_eq!(
                frame.start_address().as_u64(),
                frames[0].start_address().as_u64() + i as u64 * NET_QUEUE_ALIGN,
                "net-driver-host's virtqueue region at {start_va:#x} landed on non-contiguous \
                 physical frames even after batching the allocation ahead of any page-table \
                 build -- BootInfoFrameAllocator's bump allocation crossed a usable-memory-region \
                 boundary mid-batch, or something else allocated a frame concurrently"
            );
        }
        let page = Page::containing_address(VirtAddr::new(start_va + i as u64 * NET_QUEUE_ALIGN));
        unsafe {
            space.map_existing_frame(page, *frame, flags);
        }
        let virt = runix_kernel::memory::physical_memory_offset() + frame.start_address().as_u64();
        unsafe {
            (*virt.as_mut_ptr::<[u8; 4096]>()).fill(0);
        }
    }
    frames[0].start_address().as_u64()
}

/// Parses, loads, and runs `NET_DRIVER_HOST_ELF` as a real ring 3 process,
/// capability-gated to exactly virtio-net's discovered I/O-port range --
/// called only after Phase B8's CITADEL check authorizes it. Same load
/// mechanism `load_and_run_grid_sandbox_host` already proved
/// (`elf::Elf64` -> `process::AddressSpace` -> `scheduler::spawn_ring3_process_with_capability`),
/// plus the virtqueue/packet-buffer regions and the `NetBootInfo` page that
/// hands their physical addresses over -- see that struct's doc comment for
/// why this process can't compute them itself.
fn load_and_run_net_driver_host(io_base: u16, now: u64, signing_key: &ed25519_dalek::SigningKey) {
    serial_println!(
        "Runix kernel: parsing net-driver-host ({} bytes)",
        NET_DRIVER_HOST_ELF.len()
    );
    let elf = Elf64::parse(NET_DRIVER_HOST_ELF)
        .expect("net-driver-host failed to parse as a valid ELF64 binary");

    let mut space = AddressSpace::new();
    let entry = elf
        .load_segments(&mut space)
        .expect("net-driver-host failed to load its PT_LOAD segments");
    serial_println!(
        "Runix kernel: net-driver-host loaded, entry point {:#x}",
        entry.as_u64()
    );

    let rw_user_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    let map_zeroed_range = |space: &mut AddressSpace, start: u64, size: u64| {
        let start_page = Page::containing_address(VirtAddr::new(start));
        let end_page = Page::containing_address(VirtAddr::new(start + size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            space.map_private_page(page, rw_user_flags).fill(0);
        }
    };

    // Heap and ring 3 stack: runtime-only regions with no PT_LOAD segment
    // behind them, same as grid-sandbox-host's.
    map_zeroed_range(&mut space, NET_HEAP_START, NET_HEAP_SIZE);
    map_zeroed_range(&mut space, NET_STACK_VA, NET_STACK_SIZE);

    // Virtqueue rings: must start zeroed -- `Virtqueue::new`'s safety
    // contract requires it, since a stale avail/used index left over from
    // whatever previously occupied this physical memory would
    // desynchronize the ring from the device's own idea of it. The device
    // only gets told *one* physical address (the descriptor table's, via
    // `QueueAddress`) and computes the avail/used rings' addresses itself as
    // fixed byte offsets from it -- so unlike the packet buffers below,
    // these 3 pages per queue must land on physically *contiguous* frames,
    // not just contiguous virtual addresses. `map_zeroed_contiguous_region`
    // asserts that held rather than silently trusting it.
    let rxq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_RXQ_VA, 3, rw_user_flags);
    let txq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_TXQ_VA, 3, rw_user_flags);

    // Packet buffers: one page each, individually mapped -- not guaranteed
    // physically contiguous with each other, which is fine, since each
    // descriptor only needs *its own* buffer to be one contiguous physical
    // range (true by construction: each buffer fits in the one page backing
    // it).
    let mut rx_buffer_phys = [0u64; 8];
    for i in 0..NET_RX_BUFFER_COUNT {
        let page = Page::containing_address(VirtAddr::new(NET_RXBUF_VA + i * 4096));
        let content = space.map_private_page(page, rw_user_flags);
        content.fill(0);
        rx_buffer_phys[i as usize] = page_phys_addr(content);
    }
    let mut tx_buffer_phys = [0u64; 4];
    for i in 0..NET_TX_BUFFER_COUNT {
        let page = Page::containing_address(VirtAddr::new(NET_TXBUF_VA + i * 4096));
        let content = space.map_private_page(page, rw_user_flags);
        content.fill(0);
        tx_buffer_phys[i as usize] = page_phys_addr(content);
    }

    // NetBootInfo itself: the one page net-driver-host reads at startup to
    // learn the physical addresses above.
    let info_page = Page::containing_address(VirtAddr::new(NET_INFO_VA));
    let info_content = space.map_private_page(info_page, rw_user_flags);
    info_content.fill(0);
    let info = NetBootInfo {
        io_base,
        _pad: 0,
        rx_queue_phys: rxq_first_frame_phys,
        tx_queue_phys: txq_first_frame_phys,
        rx_buffer_phys,
        tx_buffer_phys,
        attempt_tcp: 0,
        serve_sockets: 0,
        use_dhcp: 1,
        use_dns: 0,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut NetBootInfo).write(info);
    }

    // Capability grant: one range covering the device's whole BAR0 register
    // block (see `capabilities::ioport_range_resource`'s doc comment for why
    // a range, not a per-register-purpose scheme) -- this process's only
    // path to touching hardware at all is `SYS_PORT_IN`/`SYS_PORT_OUT`,
    // gated against exactly this resource string.
    let net_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        signing_key,
    );

    #[allow(static_mut_refs)]
    unsafe {
        NET_DRIVER_HOST_ENTRY_POINT = entry.as_u64();
    }
    runix_kernel::scheduler::spawn_ring3_process_with_capability(
        net_driver_host_trampoline,
        space,
        Some(net_token),
    );

    // Give it plenty of turns to probe the device, TX one ARP request, and
    // poll for QEMU/SLIRP's reply before boot moves on -- its own success/
    // failure marker (see net-driver-host/src/main.rs) prints via SYS_WRITE
    // regardless of exactly how many of these land before boot's own final
    // infinite yield loop picks up the slack.
    for _ in 0..2000 {
        runix_kernel::scheduler::yield_now();
    }
    serial_println!(
        "Runix kernel: net-driver-host spawned as an isolated ring 3 process (Phase B8)"
    );
}

static mut NET_DRIVER_HOST_ENTRY_POINT: u64 = 0;

extern "C" fn net_driver_host_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { NET_DRIVER_HOST_ENTRY_POINT };
    unsafe {
        runix_kernel::userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(NET_STACK_VA + NET_STACK_SIZE),
        );
    }
}

/// Parses, loads, and runs `BLK_DRIVER_HOST_ELF` as a real ring 3 process,
/// capability-gated to exactly virtio-blk's discovered I/O-port range --
/// called only after Phase B9's CITADEL check authorizes it. Same load
/// mechanism `load_and_run_net_driver_host` already proved, minus the
/// RX/TX-buffer-array plumbing (virtio-blk needs one virtqueue and one
/// request-buffer page, not paired queues and several packet buffers).
///
/// `attempt_fat32`/`serve_fs_requests` are written straight into
/// `BlkBootInfo` -- both `false` on the real boot path (see those fields'
/// own doc comments), `attempt_fat32` alone `true` for
/// `kernel/tests/blk_fat32_read.rs`, `serve_fs_requests` alone `true` for
/// `kernel/tests/blk_fs_ipc.rs`.
fn load_and_run_blk_driver_host(
    io_base: u16,
    now: u64,
    signing_key: &ed25519_dalek::SigningKey,
    attempt_fat32: bool,
    serve_fs_requests: bool,
) {
    serial_println!(
        "Runix kernel: parsing blk-driver-host ({} bytes)",
        BLK_DRIVER_HOST_ELF.len()
    );
    let elf = Elf64::parse(BLK_DRIVER_HOST_ELF)
        .expect("blk-driver-host failed to parse as a valid ELF64 binary");

    let mut space = AddressSpace::new();
    let entry = elf
        .load_segments(&mut space)
        .expect("blk-driver-host failed to load its PT_LOAD segments");
    serial_println!(
        "Runix kernel: blk-driver-host loaded, entry point {:#x}",
        entry.as_u64()
    );

    let rw_user_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    let map_zeroed_range = |space: &mut AddressSpace, start: u64, size: u64| {
        let start_page = Page::containing_address(VirtAddr::new(start));
        let end_page = Page::containing_address(VirtAddr::new(start + size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            space.map_private_page(page, rw_user_flags).fill(0);
        }
    };

    // Heap and ring 3 stack: runtime-only regions with no PT_LOAD segment
    // behind them, same as net-driver-host's.
    map_zeroed_range(&mut space, BLK_HEAP_START, BLK_HEAP_SIZE);
    map_zeroed_range(&mut space, BLK_STACK_VA, BLK_STACK_SIZE);

    // The one virtqueue: 3 physically-contiguous pages (descriptor table +
    // avail ring + used ring), same reasoning `map_zeroed_contiguous_region`'s
    // own doc comment gives for net-driver-host's RX/TX queues.
    let queue_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, BLK_QUEUE_VA, 3, rw_user_flags);

    // The one request-buffer page: header + sector data + status byte, all
    // within a single page, so no contiguity concern beyond what one page
    // already guarantees.
    let reqbuf_page = Page::containing_address(VirtAddr::new(BLK_REQBUF_VA));
    let reqbuf_content = space.map_private_page(reqbuf_page, rw_user_flags);
    reqbuf_content.fill(0);
    let reqbuf_phys = page_phys_addr(reqbuf_content);

    // BlkBootInfo itself: the one page blk-driver-host reads at startup to
    // learn the physical addresses above.
    let info_page = Page::containing_address(VirtAddr::new(BLK_INFO_VA));
    let info_content = space.map_private_page(info_page, rw_user_flags);
    info_content.fill(0);
    let info = BlkBootInfo {
        io_base,
        _pad: 0,
        queue_phys: queue_first_frame_phys,
        reqbuf_phys,
        attempt_fat32: attempt_fat32 as u8,
        serve_fs_requests: serve_fs_requests as u8,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut BlkBootInfo).write(info);
    }

    // Capability grant: one range covering the device's whole BAR0 register
    // block, same granularity net-driver-host's own token uses.
    let blk_token = runix_capability_manager::CapabilityToken::issue(
        "blk-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        signing_key,
    );

    #[allow(static_mut_refs)]
    unsafe {
        BLK_DRIVER_HOST_ENTRY_POINT = entry.as_u64();
    }

    // Filesystem driver, Phase 3: only when actually serving requests does
    // this process need a second capability (the reply port) -- every
    // other boot/test keeps using the single-capability spawn path
    // unchanged, same "additive, not a behavior change for existing
    // callers" reasoning `Thread::extra_capabilities`'s own doc comment
    // gives.
    if serve_fs_requests {
        let response_token = runix_capability_manager::CapabilityToken::issue(
            "blk-driver-host",
            runix_kernel::capabilities::port_resource(BLK_FS_RESPONSE_PORT),
            now,
            now + 1_000_000,
            "demo-key",
            signing_key,
        );
        runix_kernel::scheduler::spawn_ring3_process_with_capabilities(
            blk_driver_host_trampoline,
            space,
            Some(blk_token),
            alloc::vec![response_token],
        );
    } else {
        runix_kernel::scheduler::spawn_ring3_process_with_capability(
            blk_driver_host_trampoline,
            space,
            Some(blk_token),
        );
    }

    // Give it plenty of turns to probe the device and complete a
    // write-then-read-back round trip on sector 0 before boot moves on --
    // its own result byte (see `BLK_RESULT_OFFSET`) is only checked by
    // `kernel/tests/blk_driver_rw.rs`, not the real boot path.
    for _ in 0..2000 {
        runix_kernel::scheduler::yield_now();
    }
    serial_println!(
        "Runix kernel: blk-driver-host spawned as an isolated ring 3 process (Phase B9)"
    );
}

static mut BLK_DRIVER_HOST_ENTRY_POINT: u64 = 0;

extern "C" fn blk_driver_host_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { BLK_DRIVER_HOST_ENTRY_POINT };
    unsafe {
        runix_kernel::userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(BLK_STACK_VA + BLK_STACK_SIZE),
        );
    }
}

extern "C" fn thread_a() -> ! {
    for i in 0..3 {
        serial_println!("thread A: iteration {}", i);
        runix_kernel::scheduler::yield_now();
    }
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_b() -> ! {
    for i in 0..3 {
        serial_println!("thread B: iteration {}", i);
        runix_kernel::scheduler::yield_now();
    }
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_c() -> ! {
    for i in 0..3 {
        serial_println!("thread C: iteration {}", i);
        runix_kernel::scheduler::yield_now();
    }
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_sender() -> ! {
    for byte in *b"XYZ" {
        unsafe {
            runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND, 0, byte as u64, 0);
        }
        runix_kernel::scheduler::yield_now();
    }
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_receiver() -> ! {
    let mut received: Vec<u8> = Vec::new();
    while received.len() < 3 {
        let ret =
            unsafe { runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_RECV, 0, 0, 0) };
        if ret != u64::MAX {
            received.push(ret as u8);
        }
        runix_kernel::scheduler::yield_now();
    }
    let as_chars: Vec<char> = received.iter().map(|&b| b as char).collect();
    serial_println!(
        "Runix kernel: IPC test OK (Phase 6: received {:?} via port 0)",
        as_chars
    );
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_sender_authorized() -> ! {
    let ret = unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND, 1, b'K' as u64, 0)
    };
    serial_println!("thread sender_authorized: SYS_IPC_SEND returned {}", ret);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_sender_unauthorized() -> ! {
    // No capability was granted to this thread (spawned via plain
    // `spawn`, not `spawn_with_capability`) — this send must be denied.
    let ret = unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND, 1, b'X' as u64, 0)
    };
    serial_println!("thread sender_unauthorized: SYS_IPC_SEND returned {}", ret);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn thread_sender_revoked() -> ! {
    // This thread's capability is real and otherwise valid — it was
    // revoked (via `capabilities::revoke`) after being issued but before
    // this thread ever ran. The send must still be denied.
    let ret = unsafe {
        runix_kernel::syscall::syscall(runix_kernel::syscall::SYS_IPC_SEND, 2, b'R' as u64, 0)
    };
    serial_println!("thread sender_revoked: SYS_IPC_SEND returned {}", ret);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}
