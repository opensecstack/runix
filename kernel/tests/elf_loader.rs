//! Proves `elf::Elf64::load_segments` maps a real binary's segments
//! correctly: right content, right permissions (a read+exec segment stays
//! non-writable; a read+write segment stays non-executable — real W^X,
//! not the "everything is always writable" default `AddressSpace` had
//! before this loader generalized it), and BSS (the `memsz`-beyond-`filesz`
//! tail) zero-filled rather than left as stale physical memory content.
//!
//! There's no filesystem yet to load a real ELF file from, so this test
//! hand-builds a minimal-but-valid two-segment ELF64 image as a `Vec<u8>`
//! at runtime instead — fully self-contained and reproducible, no
//! external fixture to keep in sync with the loader.
//!
//! Verifies both mapping *and* real hardware translation, same as
//! `process_isolation.rs`: switches `Cr3` into the loaded address space
//! and reads content back through the real virtual addresses, and checks
//! each segment's actual page-table flags via `AddressSpace::translate`
//! rather than only trusting what the loader *meant* to set.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use runix_kernel::elf::Elf64;
use runix_kernel::process::{self, AddressSpace};
use runix_kernel::qemu_exit::{exit_qemu, QemuExitCode};
use runix_kernel::serial_println;
use x86_64::structures::paging::mapper::TranslateResult;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

const CODE_VADDR: u64 = 0x_7777_0000_0000;
const DATA_VADDR: u64 = CODE_VADDR + 0x1000;
const CODE_BYTES: [u8; 4] = [0x90, 0x90, 0x90, 0xc3]; // nop nop nop ret — never executed, just content
const DATA_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const DATA_MEMSZ: u64 = 8; // filesz(4) + 4 bytes of BSS this test checks got zeroed

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Hand-assembles a minimal, valid little-endian ELF64 image: one header,
/// two `PT_LOAD` program headers (a read+exec "code" segment and a
/// read+write "data" segment with trailing BSS), and their raw content —
/// exactly the fields `elf::Elf64::parse`/`load_segments` actually read,
/// nothing else (no section headers, no string table).
fn build_test_elf() -> Vec<u8> {
    let ehsize = 64usize;
    let phentsize = 56usize;
    let phnum = 2usize;
    let phoff = ehsize as u64;
    let code_offset = (ehsize + phentsize * phnum) as u64;
    let data_offset = code_offset + CODE_BYTES.len() as u64;

    let mut image = Vec::new();

    // e_ident
    image.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    image.push(2); // EI_CLASS = ELFCLASS64
    image.push(1); // EI_DATA = ELFDATA2LSB
    image.push(1); // EI_VERSION
    image.extend_from_slice(&[0u8; 9]); // EI_OSABI, EI_ABIVERSION, padding
    image.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    image.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
    image.extend_from_slice(&1u32.to_le_bytes()); // e_version
    image.extend_from_slice(&CODE_VADDR.to_le_bytes()); // e_entry
    image.extend_from_slice(&phoff.to_le_bytes()); // e_phoff
    image.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    image.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    image.extend_from_slice(&(ehsize as u16).to_le_bytes()); // e_ehsize
    image.extend_from_slice(&(phentsize as u16).to_le_bytes()); // e_phentsize
    image.extend_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum
    image.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    image.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    image.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    debug_assert_eq!(image.len(), ehsize);

    // Program header 0: code segment, R+X
    image.extend_from_slice(&PT_LOAD.to_le_bytes());
    image.extend_from_slice(&(PF_R | PF_X).to_le_bytes());
    image.extend_from_slice(&code_offset.to_le_bytes());
    image.extend_from_slice(&CODE_VADDR.to_le_bytes());
    image.extend_from_slice(&CODE_VADDR.to_le_bytes()); // p_paddr, unused
    image.extend_from_slice(&(CODE_BYTES.len() as u64).to_le_bytes()); // p_filesz
    image.extend_from_slice(&(CODE_BYTES.len() as u64).to_le_bytes()); // p_memsz
    image.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // Program header 1: data segment, R+W, memsz > filesz (BSS tail)
    image.extend_from_slice(&PT_LOAD.to_le_bytes());
    image.extend_from_slice(&(PF_R | PF_W).to_le_bytes());
    image.extend_from_slice(&data_offset.to_le_bytes());
    image.extend_from_slice(&DATA_VADDR.to_le_bytes());
    image.extend_from_slice(&DATA_VADDR.to_le_bytes());
    image.extend_from_slice(&(DATA_BYTES.len() as u64).to_le_bytes()); // p_filesz
    image.extend_from_slice(&DATA_MEMSZ.to_le_bytes()); // p_memsz
    image.extend_from_slice(&0x1000u64.to_le_bytes());

    debug_assert_eq!(image.len(), code_offset as usize);
    image.extend_from_slice(&CODE_BYTES);
    debug_assert_eq!(image.len(), data_offset as usize);
    image.extend_from_slice(&DATA_BYTES);

    image
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

    serial_println!("elf_loader: building a hand-assembled two-segment ELF64 image");
    let image = build_test_elf();

    let elf = match Elf64::parse(&image) {
        Ok(elf) => elf,
        Err(e) => {
            serial_println!("elf_loader: FAIL — parse() rejected a valid image: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };

    if elf.entry_point() != CODE_VADDR {
        serial_println!(
            "elf_loader: FAIL — entry point {:#x}, expected {:#x}",
            elf.entry_point(),
            CODE_VADDR
        );
        exit_qemu(QemuExitCode::Failed);
    }

    let mut space = AddressSpace::new();
    let entry = match elf.load_segments(&mut space) {
        Ok(entry) => entry,
        Err(e) => {
            serial_println!("elf_loader: FAIL — load_segments() failed: {:?}", e);
            exit_qemu(QemuExitCode::Failed);
        }
    };
    if entry != VirtAddr::new(CODE_VADDR) {
        serial_println!("elf_loader: FAIL — load_segments() returned the wrong entry point");
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!("elf_loader: checking mapped permissions via AddressSpace::translate");
    let code_flags = match space.translate(VirtAddr::new(CODE_VADDR)) {
        TranslateResult::Mapped { flags, .. } => flags,
        _ => {
            serial_println!("elf_loader: FAIL — code segment isn't mapped at all");
            exit_qemu(QemuExitCode::Failed);
        }
    };
    let data_flags = match space.translate(VirtAddr::new(DATA_VADDR)) {
        TranslateResult::Mapped { flags, .. } => flags,
        _ => {
            serial_println!("elf_loader: FAIL — data segment isn't mapped at all");
            exit_qemu(QemuExitCode::Failed);
        }
    };

    let code_ok = !code_flags.contains(PageTableFlags::WRITABLE)
        && !code_flags.contains(PageTableFlags::NO_EXECUTE);
    let data_ok = data_flags.contains(PageTableFlags::WRITABLE)
        && data_flags.contains(PageTableFlags::NO_EXECUTE);
    if !code_ok || !data_ok {
        serial_println!(
            "elf_loader: FAIL — wrong permissions (code={:?} data={:?}), W^X not honored",
            code_flags,
            data_flags
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!("elf_loader: switching into the loaded address space to verify content");
    let previous = unsafe { space.activate() };
    let code_observed =
        unsafe { core::slice::from_raw_parts(CODE_VADDR as *const u8, CODE_BYTES.len()) };
    let code_matches = code_observed == CODE_BYTES;
    let data_observed =
        unsafe { core::slice::from_raw_parts(DATA_VADDR as *const u8, DATA_BYTES.len()) };
    let data_matches = data_observed == DATA_BYTES;
    let bss_byte = unsafe { core::ptr::read_volatile((DATA_VADDR + 4) as *const u8) };
    unsafe {
        process::restore(previous);
    }

    if !code_matches {
        serial_println!("elf_loader: FAIL — code segment content mismatch after loading");
        exit_qemu(QemuExitCode::Failed);
    }
    if !data_matches {
        serial_println!("elf_loader: FAIL — data segment content mismatch after loading");
        exit_qemu(QemuExitCode::Failed);
    }
    if bss_byte != 0 {
        serial_println!(
            "elf_loader: FAIL — BSS tail wasn't zero-filled (read {:#x})",
            bss_byte
        );
        exit_qemu(QemuExitCode::Failed);
    }

    serial_println!(
        "elf_loader: PASS — segments mapped with correct content, correct W^X permissions, \
         and zero-filled BSS"
    );
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("elf_loader: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
