//! Regression test: the MARSHAL spawn request envelope JSON-escapes
//! `module_id`/`instance_id`. Previously they were interpolated raw, so a
//! quote/backslash in an id broke the JSON (classified Unreachable => spawn
//! allowed) or injected extra members (MARSHAL evaluating a different
//! instance). Pure string test; only needs the heap.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::grid_sandbox::{build_spawn_kerkese_json, json_escape_into};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn check(name: &str, got: &str, want: &str) {
    if got != want {
        serial_println!(
            "marshal_envelope_escape: FAIL — {}\n  got:  {}\n  want: {}",
            name,
            got,
            want
        );
        exit_qemu(QemuExitCode::Failed);
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

    // Ordinary ids: byte-identical to the historical unescaped format.
    check(
        "ordinary ids unchanged",
        &build_spawn_kerkese_json("grid-sandbox-host", "app-a"),
        r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"grid_sandbox.spawn_instance","module_id":"grid-sandbox-host","instance_id":"app-a"},"actor":{"user_id":"kernel:grid_sandbox","role":"operator"},"execution_id":"app-a"}"#,
    );

    // Member-injection attempt stays inside the string value.
    check(
        "injection id escaped",
        &build_spawn_kerkese_json("grid-sandbox-host", r#"a","x":"y"#),
        r#"{"kerkese_version":"1.0","dry_run":true,"action":{"type":"grid_sandbox.spawn_instance","module_id":"grid-sandbox-host","instance_id":"a\",\"x\":\"y"},"actor":{"user_id":"kernel:grid_sandbox","role":"operator"},"execution_id":"a\",\"x\":\"y"}"#,
    );

    // Backslash, quote, control characters, non-ASCII.
    let mut s = String::new();
    json_escape_into(&mut s, "a\\b\"c\n\t\u{0}\u{1f}é");
    check("escape set", &s, "a\\\\b\\\"c\\u000a\\u0009\\u0000\\u001fé");

    serial_println!(
        "marshal_envelope_escape: PASS — hostile ids are JSON-escaped, ordinary envelope unchanged"
    );
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("marshal_envelope_escape: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
