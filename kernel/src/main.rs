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
use x86_64::structures::paging::{Page, PageTableFlags};
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
const GRID_SANDBOX_HEAP_SIZE: u64 = 256 * 1024;
const GRID_SANDBOX_STACK_VA: u64 = 0x_2222_3333_0000;
const GRID_SANDBOX_STACK_SIZE: u64 = 4096 * 4;

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

    // Cooperative round-robin scheduling: spawn three threads that each do
    // a bit of real work (proving their own saved context resumes exactly
    // where it left off — not just that switch_to() returns *somewhere*
    // without faulting), then let this thread (the boot context, folded
    // into the same run queue as a placeholder) drive several rounds of
    // yielding so their output actually interleaves instead of running to
    // completion back-to-back.
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
    let citadel_authorized =
        runix_kernel::citadel::demo_authorize("demo-module", demo_module_bytes);
    let citadel_tampered_rejected =
        runix_kernel::citadel::demo_reject_tampered("demo-module", demo_module_bytes);
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
    match runix_kernel::citadel::demo_authorize("grid-sandbox-host", GRID_SANDBOX_HOST_ELF) {
        Ok(()) => {
            serial_println!(
                "Runix kernel: grid-sandbox-host authorized by CITADEL allowlist (Phase B7)"
            );
            load_and_run_grid_sandbox_host();
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

    // Ring 3: map a user-accessible stack, grant ring 3 access to the one
    // code page `user_hello` lives on, then `iretq` into it. There's no
    // return path — this really is the last thing the boot thread does;
    // everything from here on runs at CPL 3, bouncing back into the
    // kernel only through the syscall gate.
    let user_stack_top = runix_kernel::memory::with_mapper_and_frame_allocator(
        runix_kernel::userspace::map_user_stack,
    )
    .expect("failed to map user stack");
    let user_entry = VirtAddr::new(runix_kernel::userspace::user_hello as *const () as u64);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, _frame_allocator| unsafe {
        runix_kernel::userspace::allow_user_access(mapper, user_entry);
    });
    // The scheduler watchdog (see `interrupts.rs`) expects every thread it
    // knows about to keep calling `yield_now()` — true here up to this
    // point, but ring 3 code doesn't cooperate with the scheduler at all
    // yet (see `userspace.rs`'s note on why `SYS_YIELD` is meaningless for
    // `user_hello`). Left armed, the watchdog would eventually panic on
    // `user_hello`'s intentional forever-spin, mistaking deliberate
    // behavior for a real hang.
    runix_kernel::interrupts::disarm_watchdog();
    serial_println!("Runix kernel: entering ring 3 (Phase 7: user-space transition)");
    unsafe {
        runix_kernel::userspace::enter_usermode(user_entry, user_stack_top);
    }
}

/// Parses, loads, and runs `GRID_SANDBOX_HOST_ELF` as a real ring 3
/// process -- called only after Phase B7's CITADEL check authorizes it.
/// Identical mechanism to `kernel/tests/grid_sandbox_wasm.rs` (see that
/// file for why each step is shaped the way it is, including the two real
/// bugs -- stack under-mapping, an unzeroed heap page -- found getting
/// this working the first time); this is that same proven path, just
/// reached from the real boot sequence instead of a standalone test.
fn load_and_run_grid_sandbox_host() {
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
