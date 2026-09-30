//! Proves the "Option C" session/handle IPC primitive
//! (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`, `kernel/src/ipc.rs`'s
//! `SESSIONS`/`PENDING_BY_PORT` state and the six `SYS_IPC_SESSION_*`
//! syscalls) end to end, in QEMU — the actual bar the RFC itself names for
//! this primitive: real isolation between two concurrent sessions, real
//! capability gating, and real teardown on thread exit, not just "the
//! syscalls don't panic."
//!
//! Three phases, one boot, same "several Phase demos in one run"
//! convention `main.rs`'s own boot sequence already uses:
//!
//! - **Isolation**: two client threads open independent sessions against
//!   the same server port, each sends its own 4-byte pattern, and a single
//!   server thread accepts both sessions and echoes each back on its own
//!   session. Each client must see only its own bytes echoed back.
//! - **Capability denial**: a thread with no `port:<n>` token at all is
//!   denied both `SESSION_OPEN` and `SESSION_ACCEPT` — sessions are gated
//!   the same way every other IPC syscall in this kernel is, not ambient.
//! - **Teardown on exit**: a session's owner exits mid-session (deliberately
//!   sequenced via a shared flag so the timing is deterministic despite
//!   real timer preemption); the still-alive server thread's `SESSION_SEND`
//!   to that same session id must succeed *before* the exit and fail
//!   *after* it's been reaped — proving `scheduler::reap_zombies` ->
//!   `ipc::reap_sessions_for` actually removes the session, not just that
//!   the syscalls compile.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use runix_kernel::syscall::{
    self, SYS_IPC_SESSION_ACCEPT, SYS_IPC_SESSION_OPEN, SYS_IPC_SESSION_RECV,
    SYS_IPC_SESSION_SEND, SYS_IPC_SESSION_SEND_LOCK, SYS_IPC_SESSION_SEND_UNLOCK,
};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const ISOLATION_PORT: usize = 5;
const TEARDOWN_PORT: usize = 6;
const DENIAL_PORT: usize = 7;

// --- Phase 1: isolation ---

static CLIENT_A_ECHO: AtomicU64 = AtomicU64::new(0); // packs 4 bytes, little-endian
static CLIENT_B_ECHO: AtomicU64 = AtomicU64::new(0);
static CLIENT_A_DONE: AtomicBool = AtomicBool::new(false);
static CLIENT_B_DONE: AtomicBool = AtomicBool::new(false);

fn open_session_blocking(server_port: usize) -> u64 {
    loop {
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, server_port as u64, 0, 0) };
        if ret != u64::MAX {
            return ret;
        }
        runix_kernel::scheduler::yield_now();
    }
}

fn accept_session_blocking(server_port: usize) -> u64 {
    loop {
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_ACCEPT, server_port as u64, 0, 0) };
        if ret != u64::MAX {
            return ret;
        }
        runix_kernel::scheduler::yield_now();
    }
}

fn session_send_blocking(session_id: u64, byte: u8) {
    loop {
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_SEND, session_id, byte as u64, 0) };
        if ret != u64::MAX {
            return;
        }
        runix_kernel::scheduler::yield_now();
    }
}

fn session_recv_blocking(session_id: u64) -> u8 {
    loop {
        let ret = unsafe { syscall::syscall(SYS_IPC_SESSION_RECV, session_id, 0, 0) };
        if ret != u64::MAX {
            return ret as u8;
        }
        runix_kernel::scheduler::yield_now();
    }
}

fn send_locked_pattern(session_id: u64, pattern: [u8; 4]) {
    unsafe {
        syscall::syscall(SYS_IPC_SESSION_SEND_LOCK, session_id, 0, 0);
    }
    for byte in pattern {
        session_send_blocking(session_id, byte);
    }
    unsafe {
        syscall::syscall(SYS_IPC_SESSION_SEND_UNLOCK, session_id, 0, 0);
    }
}

fn recv_pattern(session_id: u64) -> [u8; 4] {
    let mut buf = [0u8; 4];
    for slot in &mut buf {
        *slot = session_recv_blocking(session_id);
    }
    buf
}

extern "C" fn client_a_thread() -> ! {
    let session_id = open_session_blocking(ISOLATION_PORT);
    send_locked_pattern(session_id, *b"AAAA");
    let echoed = recv_pattern(session_id);
    CLIENT_A_ECHO.store(u32::from_le_bytes(echoed) as u64, Ordering::SeqCst);
    CLIENT_A_DONE.store(true, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn client_b_thread() -> ! {
    let session_id = open_session_blocking(ISOLATION_PORT);
    send_locked_pattern(session_id, *b"BBBB");
    let echoed = recv_pattern(session_id);
    CLIENT_B_ECHO.store(u32::from_le_bytes(echoed) as u64, Ordering::SeqCst);
    CLIENT_B_DONE.store(true, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

extern "C" fn isolation_server_thread() -> ! {
    // Accepts and fully answers two independent sessions on the same port
    // — exactly the "many capability-separated clients, one server, one
    // fixed port's worth of capability" shape this primitive exists to
    // support past Option A's build-time ceiling.
    for _ in 0..2 {
        let session_id = accept_session_blocking(ISOLATION_PORT);
        let request = recv_pattern(session_id);
        send_locked_pattern(session_id, request); // plain echo
    }
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

// --- Phase 3: teardown on exit ---

static TEARDOWN_SERVER_ACCEPTED_SESSION: AtomicU64 = AtomicU64::new(0);
static TEARDOWN_CLIENT_MAY_EXIT: AtomicBool = AtomicBool::new(false);
static TEARDOWN_SEND_BEFORE_EXIT_OK: AtomicBool = AtomicBool::new(false);
static TEARDOWN_SEND_AFTER_REAP_OK: AtomicBool = AtomicBool::new(true); // starts true; set false only on denial
static TEARDOWN_SERVER_DONE: AtomicBool = AtomicBool::new(false);

extern "C" fn teardown_client_thread() -> ! {
    open_session_blocking(TEARDOWN_PORT);
    // Deliberately sends nothing — this session is abandoned mid-open,
    // proving teardown doesn't depend on a clean, completed exchange.
    // Waits for the server's explicit go-ahead before exiting, so the
    // "before exit" send below is guaranteed to observe this thread still
    // alive despite real timer preemption — see this file's own doc
    // comment on why a flag handshake, not a fixed yield count, is what
    // makes this deterministic.
    while !TEARDOWN_CLIENT_MAY_EXIT.load(Ordering::SeqCst) {
        runix_kernel::scheduler::yield_now();
    }
    runix_kernel::scheduler::exit_current_thread();
}

extern "C" fn teardown_server_thread() -> ! {
    let session_id = accept_session_blocking(TEARDOWN_PORT);
    TEARDOWN_SERVER_ACCEPTED_SESSION.store(session_id, Ordering::SeqCst);

    let before = unsafe { syscall::syscall(SYS_IPC_SESSION_SEND, session_id, 0xAA, 0) };
    TEARDOWN_SEND_BEFORE_EXIT_OK.store(before != u64::MAX, Ordering::SeqCst);

    TEARDOWN_CLIENT_MAY_EXIT.store(true, Ordering::SeqCst);
    // Generous fixed count, not a busy-wait on a client-side "I've exited"
    // flag (a thread that has exited can't set one) — every iteration is a
    // real `int` trap through `yield_now`, and `reschedule` reaps zombies
    // unconditionally at the top of every single call, so this only needs
    // to outlast however long it takes the client to actually reach its
    // own exit trap, not any particular reap timing.
    for _ in 0..64 {
        runix_kernel::scheduler::yield_now();
    }

    let after = unsafe { syscall::syscall(SYS_IPC_SESSION_SEND, session_id, 0xBB, 0) };
    TEARDOWN_SEND_AFTER_REAP_OK.store(after != u64::MAX, Ordering::SeqCst);
    TEARDOWN_SERVER_DONE.store(true, Ordering::SeqCst);
    loop {
        runix_kernel::scheduler::yield_now();
    }
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();

    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("bootloader did not map physical memory"),
    );
    let mapper = unsafe { runix_kernel::memory::init(physical_memory_offset) };
    let frame_allocator =
        unsafe { runix_kernel::memory::BootInfoFrameAllocator::init(&boot_info.memory_regions) };
    runix_kernel::memory::install(mapper, frame_allocator);
    runix_kernel::memory::with_mapper_and_frame_allocator(|mapper, frame_allocator| {
        runix_kernel::allocator::init_heap(mapper, frame_allocator)
    })
    .expect("heap initialization failed");

    runix_kernel::scheduler::init();

    let now = runix_kernel::interrupts::ticks();
    let signing_key = runix_kernel::capabilities::demo_signing_key();
    let issue_port_token = |subject: &str, port: usize| {
        runix_capability_manager::CapabilityToken::issue(
            subject,
            runix_kernel::capabilities::port_resource(port),
            now,
            now + 1_000_000,
            "demo-key",
            &signing_key,
        )
    };

    // --- Phase 2 first (capability denial), directly from this boot
    // thread — `Thread::placeholder` starts it with no capability at all,
    // so this needs no spawn: a bare, ungranted syscall from this exact
    // thread is already the scenario to prove.
    let denied_open =
        unsafe { syscall::syscall(SYS_IPC_SESSION_OPEN, DENIAL_PORT as u64, 0, 0) };
    let denied_accept =
        unsafe { syscall::syscall(SYS_IPC_SESSION_ACCEPT, DENIAL_PORT as u64, 0, 0) };
    let denial_ok = denied_open == u64::MAX && denied_accept == u64::MAX;
    serial_println!(
        "ipc_session: capability denial: open={:#x} accept={:#x} (expected both {:#x})",
        denied_open,
        denied_accept,
        u64::MAX
    );

    // --- Phase 1: isolation ---
    runix_kernel::scheduler::spawn_with_capability(
        client_a_thread,
        Some(issue_port_token("session_client_a", ISOLATION_PORT)),
    );
    runix_kernel::scheduler::spawn_with_capability(
        client_b_thread,
        Some(issue_port_token("session_client_b", ISOLATION_PORT)),
    );
    runix_kernel::scheduler::spawn_with_capability(
        isolation_server_thread,
        Some(issue_port_token("session_server", ISOLATION_PORT)),
    );

    // --- Phase 3: teardown ---
    runix_kernel::scheduler::spawn_with_capability(
        teardown_client_thread,
        Some(issue_port_token("teardown_client", TEARDOWN_PORT)),
    );
    runix_kernel::scheduler::spawn_with_capability(
        teardown_server_thread,
        Some(issue_port_token("teardown_server", TEARDOWN_PORT)),
    );

    for _ in 0..256 {
        runix_kernel::scheduler::yield_now();
        if CLIENT_A_DONE.load(Ordering::SeqCst)
            && CLIENT_B_DONE.load(Ordering::SeqCst)
            && TEARDOWN_SERVER_DONE.load(Ordering::SeqCst)
        {
            break;
        }
    }

    let client_a_echo = (CLIENT_A_ECHO.load(Ordering::SeqCst) as u32).to_le_bytes();
    let client_b_echo = (CLIENT_B_ECHO.load(Ordering::SeqCst) as u32).to_le_bytes();
    serial_println!(
        "ipc_session: isolation: client_a echoed {:?}, client_b echoed {:?}",
        client_a_echo,
        client_b_echo
    );
    let isolation_ok = CLIENT_A_DONE.load(Ordering::SeqCst)
        && CLIENT_B_DONE.load(Ordering::SeqCst)
        && client_a_echo == *b"AAAA"
        && client_b_echo == *b"BBBB";

    let before_ok = TEARDOWN_SEND_BEFORE_EXIT_OK.load(Ordering::SeqCst);
    let after_ok = TEARDOWN_SEND_AFTER_REAP_OK.load(Ordering::SeqCst);
    serial_println!(
        "ipc_session: teardown: send-before-exit ok={} send-after-reap ok={} (expected true, false)",
        before_ok,
        after_ok
    );
    let teardown_ok =
        TEARDOWN_SERVER_DONE.load(Ordering::SeqCst) && before_ok && !after_ok;

    if denial_ok && isolation_ok && teardown_ok {
        serial_println!("ipc_session: PASS — isolation, capability denial, and teardown all hold");
        exit_qemu(QemuExitCode::Success);
    } else {
        serial_println!(
            "ipc_session: FAIL — denial={} isolation={} teardown={}",
            denial_ok,
            isolation_ok,
            teardown_ok
        );
        exit_qemu(QemuExitCode::Failed);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("ipc_session: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
