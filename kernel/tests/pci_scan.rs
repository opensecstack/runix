//! First slice of network stack work (see the top-level README's roadmap:
//! PCI enumeration -> virtio-net driver -> smoltcp): proves the kernel can
//! actually find real PCI hardware, not just that `pci::scan()` compiles.
//! `xtask`'s `run_qemu` gives every boot/test a real `virtio-net-pci`
//! device (see its own comment) specifically so this has something
//! concrete to assert against instead of "the function returned
//! successfully."

#![no_std]
#![no_main]

extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        runix_kernel::serial::SERIAL1.lock().init();
    }
    runix_kernel::boot::init();

    // `pci::scan()` collects into a `Vec` — needs a live heap, unlike
    // `basic_boot.rs`'s bare CPU-init smoke test.
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

    serial_println!("pci_scan: scanning PCI config space");

    let devices = runix_kernel::pci::scan();
    serial_println!("pci_scan: found {} device(s)", devices.len());

    // Every PCI machine has at least a host bridge at 0:0:0 — if this is
    // empty, config-space access itself is broken, not just "no NIC
    // present."
    if devices.is_empty() {
        serial_println!("pci_scan: FAIL — scan found no devices at all");
        exit_qemu(QemuExitCode::Failed);
    }

    match runix_kernel::pci::find_virtio_net(&devices) {
        Some(nic) => {
            serial_println!(
                "pci_scan: PASS — virtio-net found at {:02x}:{:02x}.{} (class {:#04x}/{:#04x})",
                nic.bus,
                nic.device,
                nic.function,
                nic.class,
                nic.subclass
            );
            exit_qemu(QemuExitCode::Success);
        }
        None => {
            serial_println!(
                "pci_scan: FAIL — no virtio-net device found (is xtask's -device \
                 virtio-net-pci still wired into run_qemu?)"
            );
            exit_qemu(QemuExitCode::Failed);
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("pci_scan: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
