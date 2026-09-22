//! Proves `grid_sandbox::spawn_instance`'s real MARSHAL enforcement gate
//! (Option B, `docs/MARSHAL-ENFORCEMENT-POLICY.md`) actually gates: a
//! `grid-sandbox-host` instance spawns normally (`Ok`, real instance-scoped
//! capability token, correct tier) when there's nothing to honor — no proxy
//! configured, or a configured proxy that's unreachable — but is genuinely
//! blocked, before any ELF parsing/address-space/token work happens, when a
//! reachable proxy answers `REFUSE`. Also proves the evaluation's outcome
//! actually lands in `grid_sandbox`'s
//! [`runix_kernel::grid_sandbox::shadow_marshal_log_entries`] (backed by
//! `runix_citadel_integration::WormLog`) in every case, whether or not it
//! ends up gating the spawn.
//!
//! Three cases, run in sequence within one boot — Paths 1-3 of the policy
//! doc's verification plan (Path 4, a real MARSHAL `Execute` deployment, is
//! explicitly out of scope until Beta):
//!
//! 1. **Unconfigured** (`grid_sandbox`'s own default — Path 1):
//!    `spawn_instance` called for `instance_id` `"shadow-unconfigured"` with
//!    no shadow proxy configured at all. No networking is attempted —
//!    `net-driver-host` isn't even loaded yet at this point in the test —
//!    the spawn succeeds (fail-open), and the recorded outcome is
//!    `ShadowMarshalOutcome::Unreachable`.
//! 2. **Configured, reachable, `REFUSE`** (Path 3): after bringing up
//!    `net-driver-host`, `grid_sandbox::set_shadow_marshal_proxy` points at
//!    `10.0.2.100:9000`, bridged via `guestfwd` to `tests/support/
//!    grid_sandbox_marshal_shadow_listener.py` (a permissive sibling of
//!    `marshal_tcp_roundtrip.rs`'s own `marshal_proof_listener.py` — that
//!    script checks the received `kerkese_json` against one fixed fixture
//!    value, which doesn't fit here since `shadow_marshal_evaluate` builds
//!    its request from the real `instance_id` being spawned; this one
//!    accepts any well-formed request and always answers `REFUSE`, same
//!    "fail closed, not open" reasoning — see that script's own doc
//!    comment). `spawn_instance` is called for `instance_id`
//!    `"shadow-refused"`. The spawn is **blocked**: `spawn_instance` returns
//!    `Err(SpawnInstanceError::MarshalEnforcement(MarshalEnforcementError::Blocked(ShadowMarshalOutcome::Refuse)))`,
//!    and the recorded shadow outcome is `ShadowMarshalOutcome::Refuse`. No
//!    `SpawnedInstance`/token is ever produced for this call — `enforce_marshal_decision`
//!    runs, and returns `Err`, before `spawn_instance` does any ELF
//!    parsing, `AddressSpace` setup, or `scheduler::spawn_ring3_process_with_capability`
//!    call (see that function's own source: the enforcement gate is placed
//!    strictly before all of that), so this is "never spawned," not
//!    "spawned then killed."
//! 3. **Configured, but unreachable** (Path 2): `set_shadow_marshal_proxy`
//!    is repointed, after case 2's real listener has already answered and
//!    its connection torn down, at a guest-side address (`10.0.2.100:9001`)
//!    that has **no** `guestfwd` mapping at all in this test's QEMU
//!    invocation — a connect attempt there gets no answer at all, which
//!    `marshal_client::evaluate` treats as a bounded, fail-fast timeout
//!    (see `SHADOW_MARSHAL_MAX_ITERS`'s own doc comment), a faithful "proxy
//!    configured but unreachable" case without needing any extra host-side
//!    process. Deliberately run *last*: an unresolved/timing-out connect
//!    attempt is exactly the kind of state you don't want sitting on a
//!    `net-driver-host` socket slot before a later case tries to open its
//!    own connection, so this case has nothing scheduled after it in this
//!    test. `spawn_instance` is called for `instance_id`
//!    `"shadow-unreachable"`; the spawn still succeeds (fail-open), and the
//!    recorded outcome is `ShadowMarshalOutcome::Unreachable`.
//!
//! Cases 2 and 3 both run on a dedicated thread holding the one capability
//! scoped to `marshal_client::SOCK_REQUEST_PORT` (same reason
//! `marshal_tcp_roundtrip.rs` uses a dedicated thread: `kernel_main`'s own
//! thread deliberately doesn't hold it).
//!
//! **Manual build steps required when running this locally** — both of
//! `grid_sandbox_multi_instance.rs`'s and `marshal_tcp_roundtrip.rs`'s:
//!
//! ```text
//! cd grid-sandbox-host && cargo build --target x86_64-unknown-none --release
//! cd net-driver-host && cargo build --target x86_64-unknown-none --release
//! ```
//!
//! **Host-side setup** — same `guestfwd` shape as `marshal_tcp_roundtrip.rs`,
//! bridged to this test's own listener's port `9004` instead of
//! `marshal_proof_listener.py`'s `9003`. Only `10.0.2.100:9000` gets a
//! `guestfwd` mapping — `10.0.2.100:9001` (case 3's target) is deliberately
//! left unmapped:
//!
//! ```text
//! python3 tests/support/grid_sandbox_marshal_shadow_listener.py &
//! RUNIX_NETDEV_ARG="user,id=net0,guestfwd=tcp:10.0.2.100:9000-cmd:nc 127.0.0.1 9004" \
//!   cargo test --target x86_64-unknown-none --test grid_sandbox_marshal_shadow
//! ```
//!
//! **Platform note: run this under Linux QEMU, not native Windows QEMU.**
//! Native Windows QEMU's Slirp network backend has no working `fork()`/
//! `exec()` to run a `guestfwd=...-cmd:...` helper process at all — confirmed
//! on this project's Windows dev machine against *both* this test and the
//! pre-existing, unmodified `marshal_tcp_roundtrip.rs`: QEMU logs `Slirp:
//! fork_exec: Failed to execute helper program (No such file or directory)`
//! and the guest-side connection to `10.0.2.100:9000` never reaches the
//! listener at all (`shadow_marshal_evaluate` correctly reports
//! `Unreachable` for that case, matching Option B's fail-open path, but
//! case 2's fail-closed `REFUSE` assertion never gets exercised). This is a
//! Windows-QEMU/test-harness gap, not a `grid_sandbox`/`net-driver-host` bug
//! — confirmed working correctly under the Fedora WSL environment already
//! set up for this project (see CLAUDE.md's "Runix dev environment" note):
//! same `RUNIX_NETDEV_ARG`/listener invocation above, run from WSL instead
//! of a native Windows shell, produces a real `Refuse` decision from the
//! listener and a genuinely blocked `"shadow-refused"` spawn — this is how
//! this test (and `marshal_tcp_roundtrip.rs`) must be run to actually
//! exercise their networked cases; run from native Windows, only the
//! no-network case (case 1) is real coverage.

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_citadel_integration::ShadowMarshalOutcome;
use runix_kernel::capabilities;
use runix_kernel::citadel::SandboxTier;
use runix_kernel::elf::Elf64;
use runix_kernel::grid_sandbox::{
    self, MarshalEnforcementError, ShadowMarshalProxyConfig, SpawnInstanceError,
};
use runix_kernel::marshal_client;
use runix_kernel::process::AddressSpace;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use runix_kernel::userspace;
use x86_64::structures::paging::{FrameAllocator, Page, PageTableFlags, PhysFrame};
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static NET_DRIVER_HOST_ELF: &[u8] =
    include_bytes!("../../net-driver-host/target/x86_64-unknown-none/release/net-driver-host");

// Must match `net-driver-host/src/main.rs`'s own constants exactly — see
// `kernel/src/main.rs`'s identical set for the full "why 0x1" account.
const NET_HEAP_START: u64 = 0x_1111_1111_0000;
const NET_HEAP_SIZE: u64 = 256 * 1024;
const NET_STACK_VA: u64 = 0x_1111_2222_0000;
const NET_STACK_SIZE: u64 = 4096 * 4;
const NET_INFO_VA: u64 = 0x_1111_3333_0000;
const NET_RXQ_VA: u64 = 0x_1111_4444_0000;
const NET_TXQ_VA: u64 = 0x_1111_5555_0000;
const NET_RXBUF_VA: u64 = 0x_1111_6666_0000;
const NET_TXBUF_VA: u64 = 0x_1111_7777_0000;
const NET_QUEUE_ALIGN: u64 = 4096;
const NET_RX_BUFFER_COUNT: u64 = 8;
const NET_TX_BUFFER_COUNT: u64 = 4;

// Same `guestfwd` target every other MARSHAL/sockets test uses. Fresh local
// port, distinct from every other test's own, so a stray leftover
// connection from a previous run is never confused with this one.
const TCP_REMOTE_IP: [u8; 4] = [10, 0, 2, 100];
const TCP_REMOTE_PORT: u16 = 9000;
const TCP_LOCAL_PORT: u16 = 49158;
// Deliberately has no `guestfwd` mapping in this test's QEMU invocation
// (see this file's own doc comment) — a connection attempt here fails
// immediately, a faithful "proxy configured but unreachable" case (Path 2).
const TCP_UNREACHABLE_PORT: u16 = 9001;
const TCP_UNREACHABLE_LOCAL_PORT: u16 = 49159;

#[repr(C)]
struct NetBootInfo {
    io_base: u16,
    _pad: u16,
    rx_queue_phys: u64,
    tx_queue_phys: u64,
    rx_buffer_phys: [u64; 8],
    tx_buffer_phys: [u64; 4],
    attempt_tcp: u8,
    serve_sockets: u8,
    use_dhcp: u8,
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();
    x86_64::instructions::interrupts::enable();

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

    // Before any `AddressSpace::new()` — see `scheduler::init`'s doc
    // comment on why.
    scheduler::init();

    let now = runix_kernel::interrupts::ticks();
    let signing_key = capabilities::demo_signing_key();

    // --- Case 1: unconfigured — no networking attempted at all -----------
    serial_println!(
        "grid_sandbox_marshal_shadow: spawning shadow-unconfigured with no shadow MARSHAL proxy \
         configured"
    );
    let instance_unconfigured = match grid_sandbox::spawn_instance(
        "shadow-unconfigured",
        SandboxTier::T2Trusted,
        now,
        &signing_key,
    ) {
        Ok(instance) => instance,
        Err(e) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — shadow-unconfigured's instance authorization \
                 was denied: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };
    let resource_unconfigured = capabilities::grid_instance_resource("shadow-unconfigured");
    if capabilities::check(&instance_unconfigured.token, &resource_unconfigured, now).is_err() {
        serial_println!(
            "grid_sandbox_marshal_shadow: FAIL — shadow-unconfigured's own token was rejected \
             against its own resource string"
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let entries_after_unconfigured = grid_sandbox::shadow_marshal_log_entries();
    let unconfigured_entry = entries_after_unconfigured
        .iter()
        .find(|e| e.instance_id.as_deref() == Some("shadow-unconfigured"));
    match unconfigured_entry.and_then(|e| e.shadow_marshal) {
        Some(ShadowMarshalOutcome::Unreachable) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: shadow-unconfigured recorded Unreachable as \
                 expected — spawn still succeeded (shadow mode confirmed for the unconfigured \
                 case)"
            );
        }
        other => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — expected a WormLog entry for \
                 shadow-unconfigured with shadow_marshal = Some(Unreachable), got {:?}",
                other
            );
            exit_qemu(QemuExitCode::Failed);
        }
    }

    // --- Case 2: configured, with a real listener answering REFUSE -------
    let devices = runix_kernel::pci::scan();
    let io_base = match runix_kernel::pci::find_virtio_net(&devices)
        .and_then(|dev| runix_kernel::pci::read_bar0_io_port(&dev))
    {
        Some(io_base) => io_base,
        None => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — no virtio-net I/O-space BAR0 found"
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if let Err(e) = runix_kernel::citadel::demo_authorize(
        "net-driver-host",
        NET_DRIVER_HOST_ELF,
        runix_kernel::citadel::SandboxTier::T1Critical,
    ) {
        serial_println!(
            "grid_sandbox_marshal_shadow: FAIL — CITADEL allowlist rejected net-driver-host: {:?}",
            e
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let elf = match Elf64::parse(NET_DRIVER_HOST_ELF) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — parse() rejected net-driver-host: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — load_segments() failed: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };
    serial_println!(
        "grid_sandbox_marshal_shadow: loaded net-driver-host, entry point {:#x}",
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
    map_zeroed_range(&mut space, NET_HEAP_START, NET_HEAP_SIZE);
    map_zeroed_range(&mut space, NET_STACK_VA, NET_STACK_SIZE);

    let rxq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_RXQ_VA, 3, rw_user_flags);
    let txq_first_frame_phys =
        map_zeroed_contiguous_region(&mut space, NET_TXQ_VA, 3, rw_user_flags);

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
        serve_sockets: 1,
        use_dhcp: 0,
    };
    unsafe {
        (info_content.as_mut_ptr() as *mut NetBootInfo).write(info);
    }

    let net_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::ioport_range_resource(io_base, 0x20),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    let response_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    // `SYS_IPC_RECV` is now capability-gated identically to `SYS_IPC_SEND`
    // (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`) -- `net-driver-host` itself
    // now needs its own token to *receive* on `SOCK_REQUEST_PORT`
    // (`run_socket_ipc_server`'s `ipc_try_recv(SOCK_REQUEST_PORT)`), not
    // only the response-port send token above -- same fix
    // `net_driver_sockets.rs` already needed.
    let request_recv_token = runix_capability_manager::CapabilityToken::issue(
        "net-driver-host",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );

    #[allow(static_mut_refs)]
    unsafe {
        NET_ENTRY_POINT = entry.as_u64();
    }
    scheduler::spawn_ring3_process_with_capabilities(
        net_driver_trampoline,
        space,
        Some(net_token),
        alloc::vec![response_token, request_recv_token],
    );

    // Give it time to probe the device, bring up the interface, and reach
    // its sockets server loop — same budget every other sockets-based
    // MARSHAL test already uses.
    for _ in 0..2000 {
        scheduler::yield_now();
    }

    // Case 2 (Path 3): configured, pointed at the real listener that always
    // answers REFUSE.
    grid_sandbox::set_shadow_marshal_proxy(Some(ShadowMarshalProxyConfig {
        remote_ip: TCP_REMOTE_IP,
        remote_port: TCP_REMOTE_PORT,
        local_port: TCP_LOCAL_PORT,
    }));

    // `spawn_instance`'s MARSHAL evaluation needs the calling thread to hold
    // a capability scoped to `marshal_client::SOCK_REQUEST_PORT` — this
    // test's own `kernel_main` thread deliberately doesn't (same posture
    // `marshal_tcp_roundtrip.rs` proves for its own boot thread), so both
    // configured-case `spawn_instance` calls happen on a separate thread
    // that does hold it. That thread also does the `set_shadow_marshal_proxy`
    // repoint from "reachable, REFUSE" (case 2) to "unreachable" (case 3,
    // run last on purpose — see this file's own doc comment) between its
    // two spawn attempts — this is a plain global, callable from any
    // thread, same as `kernel_main`'s own call above.
    let request_token = runix_capability_manager::CapabilityToken::issue(
        "test-grid-sandbox-marshal-shadow",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_REQUEST_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::spawn_with_capability(spawn_configured_instance_thread, Some(request_token));

    let mut result = TestResult::Pending;
    for _ in 0..30_000 {
        scheduler::yield_now();
        #[allow(static_mut_refs)]
        let current = unsafe { RESULT };
        if current != TestResult::Pending {
            result = current;
            break;
        }
    }

    match result {
        TestResult::Pass => {
            serial_println!(
                "grid_sandbox_marshal_shadow: PASS — shadow-unreachable spawned successfully \
                 (fail-open) and shadow-refused was genuinely blocked (fail-closed), matching \
                 Option B (docs/MARSHAL-ENFORCEMENT-POLICY.md)"
            );
            exit_qemu(QemuExitCode::Success);
        }
        _ => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — configured-case thread reported {:?} (is \
                 RUNIX_NETDEV_ARG/grid_sandbox_marshal_shadow_listener.py actually set up? see \
                 this test's own doc comment)",
                result
            );
            exit_qemu(QemuExitCode::Failed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestResult {
    Pending,
    Pass,
    Fail,
}

static mut RESULT: TestResult = TestResult::Pending;

/// Runs on the one thread holding the capability scoped to
/// `marshal_client::SOCK_REQUEST_PORT`. Performs both configured-proxy
/// cases in sequence, REFUSE first and unreachable last (see this file's
/// own doc comment for why the order matters — an unresolved/timing-out
/// connect attempt is exactly the state you don't want left on a
/// `net-driver-host` socket slot before a later case opens its own):
///
/// - **Case 2 / Path 3** (`"shadow-refused"`): proxy already pointed (by
///   `kernel_main`, before this thread was spawned) at the real listener
///   (always answers `REFUSE`). Confirms `spawn_instance` returns
///   `Err(SpawnInstanceError::MarshalEnforcement(MarshalEnforcementError::Blocked(ShadowMarshalOutcome::Refuse)))`
///   (fail-closed — genuinely blocked, no `SpawnedInstance`/token produced)
///   and the WormLog records `Refuse`.
/// - **Case 3 / Path 2** (`"shadow-unreachable"`): repoints the proxy at an
///   address with no `guestfwd` mapping, then confirms `spawn_instance`
///   still succeeds (fail-open) and the WormLog records `Unreachable`.
extern "C" fn spawn_configured_instance_thread() -> ! {
    let now = runix_kernel::interrupts::ticks();
    let signing_key = capabilities::demo_signing_key();

    // `spawn_instance`'s MARSHAL evaluation (`marshal_client::evaluate`)
    // receives on `SOCK_RESPONSE_PORT` internally
    // (`recv_socket_response`'s `SYS_IPC_RECV`), which is now
    // capability-gated too (`docs/RFC-IPC-RESPONSE-CAPABILITY.md`) — this
    // thread was only spawned with a `SOCK_REQUEST_PORT` *send* token
    // above, so it grants itself the response-port *receive* token here,
    // same pattern `marshal_tcp_roundtrip.rs`'s `authorized_client_thread`
    // fix uses for the identical need.
    let response_recv_token = runix_capability_manager::CapabilityToken::issue(
        "test-grid-sandbox-marshal-shadow",
        runix_kernel::capabilities::port_resource(marshal_client::SOCK_RESPONSE_PORT),
        now,
        now + 1_000_000,
        "demo-key",
        &signing_key,
    );
    scheduler::grant_current_extra_capability(response_recv_token);

    // --- Case 2: configured, reachable, REFUSE (Path 3) --------------------
    let refused_ok = match grid_sandbox::spawn_instance(
        "shadow-refused",
        SandboxTier::T2Trusted,
        now,
        &signing_key,
    ) {
        Ok(_instance) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: FAIL — shadow-refused's spawn succeeded, but a \
                 reachable REFUSE must block it (Path 3 is fail-closed)"
            );
            false
        }
        Err(SpawnInstanceError::MarshalEnforcement(MarshalEnforcementError::Blocked(
            ShadowMarshalOutcome::Refuse,
        ))) => {
            let entries = grid_sandbox::shadow_marshal_log_entries();
            let recorded = entries
                .iter()
                .find(|e| e.instance_id.as_deref() == Some("shadow-refused"))
                .and_then(|e| e.shadow_marshal);
            if recorded == Some(ShadowMarshalOutcome::Refuse) {
                serial_println!(
                    "grid_sandbox_marshal_shadow: shadow-refused's spawn was blocked as \
                     expected (fail-closed) with Refuse recorded in the WormLog"
                );
                true
            } else {
                serial_println!(
                    "grid_sandbox_marshal_shadow: shadow-refused's spawn was blocked as \
                     expected, but expected its WormLog entry to carry Some(Refuse), got {:?}",
                    recorded
                );
                false
            }
        }
        Err(e) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: shadow-refused's spawn failed, but not with the \
                 expected MarshalEnforcementError::Blocked(Refuse): {:?}",
                e
            );
            false
        }
    };

    // --- Case 3: configured but unreachable (Path 2) — run last on purpose,
    // see this function's own doc comment. ----------------------------------
    grid_sandbox::set_shadow_marshal_proxy(Some(ShadowMarshalProxyConfig {
        remote_ip: TCP_REMOTE_IP,
        remote_port: TCP_UNREACHABLE_PORT,
        local_port: TCP_UNREACHABLE_LOCAL_PORT,
    }));

    let unreachable_ok = match grid_sandbox::spawn_instance(
        "shadow-unreachable",
        SandboxTier::T2Trusted,
        now,
        &signing_key,
    ) {
        Ok(instance) => {
            let resource = capabilities::grid_instance_resource("shadow-unreachable");
            if capabilities::check(&instance.token, &resource, now).is_err() {
                serial_println!(
                    "grid_sandbox_marshal_shadow: shadow-unreachable's own token was rejected \
                     against its own resource string"
                );
                false
            } else {
                let entries = grid_sandbox::shadow_marshal_log_entries();
                let recorded = entries
                    .iter()
                    .find(|e| e.instance_id.as_deref() == Some("shadow-unreachable"))
                    .and_then(|e| e.shadow_marshal);
                if recorded == Some(ShadowMarshalOutcome::Unreachable) {
                    serial_println!(
                        "grid_sandbox_marshal_shadow: shadow-unreachable spawned successfully \
                         (fail-open) with Unreachable recorded, as expected"
                    );
                    true
                } else {
                    serial_println!(
                        "grid_sandbox_marshal_shadow: expected shadow-unreachable's WormLog \
                         entry to carry Some(Unreachable), got {:?}",
                        recorded
                    );
                    false
                }
            }
        }
        Err(e) => {
            serial_println!(
                "grid_sandbox_marshal_shadow: shadow-unreachable's spawn was denied (it should \
                 never be — Path 2 is fail-open): {:?}",
                e
            );
            false
        }
    };

    #[allow(static_mut_refs)]
    unsafe {
        RESULT = if unreachable_ok && refused_ok {
            TestResult::Pass
        } else {
            TestResult::Fail
        };
    }
    loop {
        scheduler::yield_now();
    }
}

/// Same as `kernel/src/main.rs`'s function of the same name.
fn map_zeroed_contiguous_region(
    space: &mut AddressSpace,
    start_va: u64,
    page_count: u64,
    flags: PageTableFlags,
) -> u64 {
    let frames: alloc::vec::Vec<PhysFrame> =
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
                 physical frames"
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

fn page_phys_addr(page: &mut [u8; 4096]) -> u64 {
    let virt = VirtAddr::from_ptr(page.as_ptr());
    virt - runix_kernel::memory::physical_memory_offset()
}

static mut NET_ENTRY_POINT: u64 = 0;

extern "C" fn net_driver_trampoline() -> ! {
    #[allow(static_mut_refs)]
    let entry = unsafe { NET_ENTRY_POINT };
    unsafe {
        userspace::enter_usermode(
            VirtAddr::new(entry),
            VirtAddr::new(NET_STACK_VA + NET_STACK_SIZE),
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("grid_sandbox_marshal_shadow: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
