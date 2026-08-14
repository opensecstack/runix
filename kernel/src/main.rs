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
use runix_kernel::serial_println;
use x86_64::VirtAddr;

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
    // and the same check against tampered bytes is refused. Not yet gating
    // an actual module load: `main.rs` doesn't ELF-load anything of its own
    // today (only `kernel/tests/*.rs` do), so there's nothing real to gate
    // here yet — this demonstrates the gate itself works, the same way the
    // capability-token phases above demonstrate `capability-manager` works
    // before anything real depends on it either.
    let demo_module_bytes = b"demo module bytes - not a real loaded module yet";
    let citadel_authorized = runix_kernel::citadel::demo_authorize("demo-module", demo_module_bytes);
    let citadel_tampered_rejected =
        runix_kernel::citadel::demo_reject_tampered("demo-module", demo_module_bytes);
    serial_println!(
        "Runix kernel: CITADEL boot authorization OK (Phase B6: authorized={:?}, tampered rejected={:?})",
        citadel_authorized,
        citadel_tampered_rejected
    );

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
