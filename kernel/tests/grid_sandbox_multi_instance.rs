//! Multi-instance Grid Sandbox spawning: proves `grid_sandbox::spawn_instance`
//! (see that module's own doc comment) actually runs more than one
//! independent `grid-sandbox-host` instance at once, each isolated from the
//! other rather than sharing one module-wide authorization or capability as
//! ambient authority.
//!
//! Two instances of the exact same compiled binary are spawned, each with
//! its own `instance_id`, CITADEL instance-scoped authorization call, tier,
//! `AddressSpace`, and capability token:
//!
//! - `app-a` at `T1Critical` (128-page/8 MiB grow ceiling — the same real
//!   `memory.grow` request `grid_sandbox_tier_t1.rs` proves that tier
//!   allows).
//! - `app-b` at `T3Untrusted` (8-page/512 KiB ceiling — the same request
//!   `grid_sandbox_tier_t3.rs` proves that tier rejects).
//!
//! What this test proves that the single-instance tests above can't:
//!
//! 1. **Tier isolation**: both instances run *concurrently* (interleaved by
//!    the scheduler, not sequentially), and each one's own tier-correctness
//!    result lands in *its own* `GridBootInfo` page — `app-a`'s grow
//!    succeeds and `app-b`'s fails, at the same time, with neither result
//!    clobbering the other.
//! 2. **Memory isolation**: the two instances' `GridBootInfo` pages, despite
//!    living at the identical virtual address in each instance's own
//!    private `AddressSpace` (`grid-sandbox-host` hardcodes that VA into its
//!    own binary — see `grid_sandbox.rs`'s doc comment), are backed by two
//!    distinct physical frames — proven by comparing the raw pointers the
//!    kernel side got back from mapping each one, not just trusting they
//!    "should" differ.
//! 3. **Capability isolation**: each instance's token is scoped to
//!    `capabilities::grid_instance_resource(instance_id)` for *that*
//!    instance's `instance_id` alone — `app-a`'s token verifies against
//!    `app-a`'s resource string but is rejected against `app-b`'s (and vice
//!    versa), even though both tokens were issued under the same signing
//!    key at the same time. A capability scoped to one instance's resources
//!    never works for another's.
//!
//! **Manual build step required when running this locally** — same as
//! `grid_sandbox_wasm.rs`:
//!
//! ```text
//! cd grid-sandbox-host && cargo build --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::capabilities;
use runix_kernel::citadel::SandboxTier;
use runix_kernel::grid_sandbox;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::scheduler;
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config.kernel_stack_size = 512 * 1024;
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const GROW_RESULT_OFFSET: usize = grid_sandbox::GROW_RESULT_OFFSET;

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

    serial_println!("grid_sandbox_multi_instance: spawning instance app-a (T1Critical)");
    let instance_a = match grid_sandbox::spawn_instance(
        "app-a",
        SandboxTier::T1Critical,
        now,
        &signing_key,
    ) {
        Ok(instance) => instance,
        Err(e) => {
            serial_println!(
                "grid_sandbox_multi_instance: FAIL — app-a's instance authorization was denied: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    serial_println!("grid_sandbox_multi_instance: spawning instance app-b (T3Untrusted)");
    let instance_b = match grid_sandbox::spawn_instance(
        "app-b",
        SandboxTier::T3Untrusted,
        now,
        &signing_key,
    ) {
        Ok(instance) => instance,
        Err(e) => {
            serial_println!(
                "grid_sandbox_multi_instance: FAIL — app-b's instance authorization was denied: {:?}",
                e
            );
            exit_qemu(QemuExitCode::Failed);
        }
    };

    // Memory isolation: two instances' `GridBootInfo` pages map the exact
    // same VA in their own private `AddressSpace`s, but must be backed by
    // physically distinct frames — the kernel-side pointers into each
    // (reached through the physical-memory-offset mapping, not through
    // either instance's own page table) must differ.
    if core::ptr::eq(instance_a.info.as_ptr(), instance_b.info.as_ptr()) {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — app-a and app-b's GridBootInfo pages resolved \
             to the *same* physical frame; they are not actually isolated"
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Let both instances run concurrently (interleaved by the scheduler,
    // not sequentially) until both have written their own grow-probe
    // result.
    let mut grow_a = 0u8;
    let mut grow_b = 0u8;
    for _ in 0..40 {
        scheduler::yield_now();
        grow_a =
            unsafe { core::ptr::read_volatile(instance_a.info.as_ptr().add(GROW_RESULT_OFFSET)) };
        grow_b =
            unsafe { core::ptr::read_volatile(instance_b.info.as_ptr().add(GROW_RESULT_OFFSET)) };
        if grow_a != 0 && grow_b != 0 {
            break;
        }
    }

    // Tier isolation: app-a's T1Critical grow must succeed, app-b's
    // T3Untrusted grow (same fixed request size) must fail — independently
    // of each other, proving neither instance's tier enforcement leaked
    // into the other's outcome.
    if grow_a != grid_sandbox::GROW_RESULT_SUCCEEDED {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — expected app-a's T1Critical grow probe to \
             succeed (byte {}), got {}",
            grid_sandbox::GROW_RESULT_SUCCEEDED,
            grow_a
        );
        exit_qemu(QemuExitCode::Failed);
    }
    if grow_b != grid_sandbox::GROW_RESULT_FAILED {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — expected app-b's T3Untrusted grow probe to \
             fail (byte {}), got {}",
            grid_sandbox::GROW_RESULT_FAILED,
            grow_b
        );
        exit_qemu(QemuExitCode::Failed);
    }

    // Capability isolation: each instance's token verifies only against
    // *its own* instance-scoped resource string, never the other's.
    let resource_a = capabilities::grid_instance_resource("app-a");
    let resource_b = capabilities::grid_instance_resource("app-b");

    if capabilities::check(&instance_a.token, &resource_a, now).is_err() {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — app-a's own token was rejected against its own \
             resource string"
        );
        exit_qemu(QemuExitCode::Failed);
    }
    if capabilities::check(&instance_b.token, &resource_b, now).is_err() {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — app-b's own token was rejected against its own \
             resource string"
        );
        exit_qemu(QemuExitCode::Failed);
    }
    if capabilities::check(&instance_a.token, &resource_b, now).is_ok() {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — app-a's token was accepted against app-b's \
             resource string; instance-scoped capabilities are not actually isolated"
        );
        exit_qemu(QemuExitCode::Failed);
    }
    if capabilities::check(&instance_b.token, &resource_a, now).is_ok() {
        serial_println!(
            "grid_sandbox_multi_instance: FAIL — app-b's token was accepted against app-a's \
             resource string; instance-scoped capabilities are not actually isolated"
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "grid_sandbox_multi_instance: PASS — two concurrent grid-sandbox-host instances ran \
         isolated: independent per-instance tier enforcement (app-a T1Critical grow succeeded, \
         app-b T3Untrusted grow failed), physically distinct GridBootInfo frames, and \
         instance-scoped capability tokens that never cross-authorize"
    );
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("grid_sandbox_multi_instance: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
