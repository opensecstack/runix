//! The hardware half of the ELF loader (slice 3 of
//! `docs/BETA_MOBILE_PROGRESS.md` item 2.4): the
//! [`PrivatePageMapper`] implementation that connects
//! `runix_kernel_arm::loader`'s pure logic to `process.rs`'s real
//! `TTBR0_EL1`-rooted address spaces, plus [`prove_load`] -- the boot-time
//! proof that a real program lands in a real address space with the
//! permissions the loader claims.
//!
//! Two files instead of one, on purpose: the loader's permission
//! translation and partial-page copy arithmetic are pure and belong where
//! `cargo test --lib` can reach them (`src/loader.rs`, in the library half
//! of this crate -- see `lib.rs`'s doc comment), while `AddressSpace`,
//! `TTBR0_EL1`, and `AT S1E0R` only exist here in the freestanding binary.
//! Everything in this module is the part a host test genuinely cannot
//! check.
//!
//! # What the proof proves, and why in this shape
//!
//! Serial-grep from a boot-sequence call rather than a `kernel-arm/tests/`
//! harness, for the reason item 1.7 records and slice 2's
//! `process::prove_isolation` already follows: this crate has no
//! QEMU-native `cargo test` harness. The three properties, mirroring
//! `kernel/tests/elf_loader.rs` on the x86_64 side:
//!
//! 1. **Content** -- the text and data bytes are read back *through the
//!    loaded VA after a real `TTBR0_EL1` switch into the loaded space*, not
//!    by inspecting the kernel-side `&mut [u8; 4096]` the loader wrote
//!    through. Reading back through the mapping is what makes this a
//!    statement about translation rather than about memcpy.
//! 2. **W^X permissions** -- twice over, from two independent angles: the
//!    real level-3 descriptor bits, read back via
//!    `AddressSpace::page_descriptor` (the bit pattern), *and* `AT S1E0R`/
//!    `AT S1E0W`, which ask the MMU hardware itself whether EL0 may read
//!    and write each page (the behaviour). The second is the one that would
//!    catch a correct-looking bit pattern that doesn't mean what we think.
//! 3. **A zero BSS tail** -- read back through the loaded VA as well, since
//!    the leak this closes (a recycled physical frame's previous contents
//!    becoming a new process's `.bss`) is only closed if it is zero *at the
//!    address the process will read*.
//!
//! The image is hand-assembled as a `Vec<u8>` at runtime -- the same
//! technique `elf.rs`'s host tests and `kernel/tests/elf_loader.rs` use,
//! and still the only option here: there is no filesystem to load a real
//! ELF from.
//!
//! Nothing is executed. The loaded entry point is never jumped to, no EL0
//! drop happens, and the address space is discarded (leaked -- `process.rs`
//! has no `Drop` yet, by its own documented choice) when this returns.

use crate::process::{restore, AddressSpace};
use crate::serial_println;
use alloc::vec;
use alloc::vec::Vec;
use runix_kernel_arm::elf::{Elf64, PF_R, PF_W, PF_X};
use runix_kernel_arm::loader::{self, LoaderError, PrivatePageMapper, STACK_BASE};
use runix_kernel_arm::vm::{AP_EL0_RO, AP_EL0_RW, GRANULE_4KIB, PRIVATE_REGION_BASE, PXN, UXN};

/// Both bits of `AP[2:1]`, so a read-only page (`0b11`) can't be mistaken
/// for a read/write one (`0b01`) by masking with a single bit.
const AP_MASK: u64 = 0b11 << 6;

impl PrivatePageMapper for AddressSpace {
    fn map_page(
        &mut self,
        va: u64,
        permissions: u64,
    ) -> Result<&'static mut [u8; 4096], LoaderError> {
        self.map_private_page_with(va, permissions)
            .map_err(|err| LoaderError::MapFailed {
                va,
                // `AddressSpaceError`'s messages are already static strings
                // (see its `Display`); this keeps the real reason attached
                // to the loader's error instead of flattening it to
                // "mapping failed".
                reason: err.message(),
            })
    }
}

/// Where the proof image asks to be loaded: inside the private window, in
/// the segment region `loader.rs` reserves (well below the stack and its
/// guard gap), on two distinct pages so the two segments' permissions are
/// genuinely independent.
const TEXT_VADDR: u64 = PRIVATE_REGION_BASE + 0x0020_0000;
const DATA_VADDR: u64 = PRIVATE_REGION_BASE + 0x0021_0000;
/// `nop` -- real AArch64 instruction bytes rather than filler, since the
/// whole point of a read+exec segment is that it could be fetched.
const TEXT: &[u8] = &[0x1f, 0x20, 0x03, 0xd5];
const DATA: &[u8] = b"runix";
/// `p_memsz - p_filesz` for the data segment: the BSS tail that must read
/// back as zero.
const BSS_LEN: u64 = 32;

const ELF_HEADER_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;

struct ProofPhdr {
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

/// Hand-assembles the two-segment proof image: one read+exec segment, one
/// read+write segment with a real BSS tail.
fn build_proof_image() -> Vec<u8> {
    let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
    let phdrs = [
        ProofPhdr {
            flags: PF_R | PF_X,
            offset: payload_offset as u64,
            vaddr: TEXT_VADDR,
            filesz: TEXT.len() as u64,
            memsz: TEXT.len() as u64,
        },
        ProofPhdr {
            flags: PF_R | PF_W,
            offset: (payload_offset + TEXT.len()) as u64,
            vaddr: DATA_VADDR,
            filesz: DATA.len() as u64,
            memsz: DATA.len() as u64 + BSS_LEN,
        },
    ];

    let mut image = vec![0u8; ELF_HEADER_SIZE];
    image[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    image[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    image[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
    image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes()); // e_phoff
    image[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    image[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes()); // e_phnum
    for phdr in &phdrs {
        let mut entry = vec![0u8; PHDR_SIZE];
        entry[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        entry[4..8].copy_from_slice(&phdr.flags.to_le_bytes());
        entry[8..16].copy_from_slice(&phdr.offset.to_le_bytes());
        entry[16..24].copy_from_slice(&phdr.vaddr.to_le_bytes());
        entry[32..40].copy_from_slice(&phdr.filesz.to_le_bytes());
        entry[40..48].copy_from_slice(&phdr.memsz.to_le_bytes());
        image.extend_from_slice(&entry);
    }
    image.extend_from_slice(TEXT);
    image.extend_from_slice(DATA);
    image
}

/// Builds a fresh address space, loads the hand-assembled image into it
/// with `runix_kernel_arm::loader::load`, and verifies content, W^X
/// permissions, and a zero BSS tail against real hardware. Prints one
/// greppable `ELF loader PASS`/`FAILED` line.
///
/// Requires the MMU on and the heap initialized, and nothing else -- in
/// particular no EL0, no scheduler. Returns to the kernel's own
/// `TTBR0_EL1` on every path.
pub fn prove_load() {
    let image = build_proof_image();
    let elf = match Elf64::parse(&image) {
        Ok(elf) => elf,
        Err(err) => {
            serial_println!("Runix ARM kernel: ELF loader FAILED -- parse: {}", err);
            return;
        }
    };
    let mut space = match AddressSpace::new() {
        Ok(space) => space,
        Err(err) => {
            serial_println!(
                "Runix ARM kernel: ELF loader FAILED -- address space: {}",
                err
            );
            return;
        }
    };
    let loaded = match loader::load(&elf, &mut space) {
        Ok(loaded) => loaded,
        Err(err) => {
            serial_println!("Runix ARM kernel: ELF loader FAILED -- load: {}", err);
            return;
        }
    };

    serial_println!(
        "Runix ARM kernel: ELF load entry={:#x} stack={:#x}..{:#x} segment_pages={} \
         stack_pages={} (root={:#x})",
        loaded.entry,
        loaded.stack_base,
        loaded.stack_top,
        loaded.segment_pages,
        loaded.stack_pages,
        space.root()
    );

    // The descriptor bits that actually got written, read back out of the
    // real level-3 tables rather than recomputed.
    let text_desc = space.page_descriptor(TEXT_VADDR);
    let data_desc = space.page_descriptor(DATA_VADDR);
    let stack_desc = space.page_descriptor(STACK_BASE);
    let (Some(text_desc), Some(data_desc), Some(stack_desc)) = (text_desc, data_desc, stack_desc)
    else {
        serial_println!(
            "Runix ARM kernel: ELF loader FAILED -- a loaded VA has no private page descriptor \
             (text={:?} data={:?} stack={:?})",
            text_desc,
            data_desc,
            stack_desc
        );
        return;
    };

    serial_println!(
        "Runix ARM kernel: ELF load W^X text AP={} UXN={} PXN={}, data AP={} UXN={} PXN={}, \
         stack AP={} UXN={} PXN={}",
        ap_name(text_desc),
        bit(text_desc, UXN),
        bit(text_desc, PXN),
        ap_name(data_desc),
        bit(data_desc, UXN),
        bit(data_desc, PXN),
        ap_name(stack_desc),
        bit(stack_desc, UXN),
        bit(stack_desc, PXN),
    );

    let wx_ok = text_desc & AP_MASK == AP_EL0_RO
        && text_desc & UXN == 0
        && text_desc & PXN != 0
        && data_desc & AP_MASK == AP_EL0_RW
        && data_desc & UXN != 0
        && data_desc & PXN != 0
        && stack_desc & AP_MASK == AP_EL0_RW
        && stack_desc & UXN != 0
        && stack_desc & PXN != 0;

    // Switch into the loaded space for real and read everything back
    // through the VAs the process itself would use.
    let previous = unsafe { space.activate() };
    let mut text_read = [0u8; 4];
    for (i, byte) in text_read.iter_mut().enumerate() {
        *byte = unsafe { core::ptr::read_volatile((TEXT_VADDR + i as u64) as *const u8) };
    }
    let mut data_read = [0u8; 5];
    for (i, byte) in data_read.iter_mut().enumerate() {
        *byte = unsafe { core::ptr::read_volatile((DATA_VADDR + i as u64) as *const u8) };
    }
    let mut bss_nonzero = 0u64;
    for i in 0..BSS_LEN {
        let va = DATA_VADDR + DATA.len() as u64 + i;
        if unsafe { core::ptr::read_volatile(va as *const u8) } != 0 {
            bss_nonzero += 1;
        }
    }
    // The hardware's own answer to "may EL0 read/write this?" -- the
    // behavioural half of the W^X check, independent of the bit pattern
    // above.
    let text_el0_read = el0_can_read(TEXT_VADDR);
    let text_el0_write = el0_can_write(TEXT_VADDR);
    let data_el0_read = el0_can_read(DATA_VADDR);
    let data_el0_write = el0_can_write(DATA_VADDR);
    let stack_el0_write = el0_can_write(STACK_BASE);
    unsafe { restore(previous) };

    serial_println!(
        "Runix ARM kernel: ELF load content text={:02x}{:02x}{:02x}{:02x} data={}{}{}{}{} \
         bss_nonzero_bytes={}",
        text_read[0],
        text_read[1],
        text_read[2],
        text_read[3],
        data_read[0] as char,
        data_read[1] as char,
        data_read[2] as char,
        data_read[3] as char,
        data_read[4] as char,
        bss_nonzero
    );
    serial_println!(
        "Runix ARM kernel: ELF load EL0 access (AT S1E0R/S1E0W) text read={} write={}, \
         data read={} write={}, stack write={}",
        yes_no(text_el0_read),
        yes_no(text_el0_write),
        yes_no(data_el0_read),
        yes_no(data_el0_write),
        yes_no(stack_el0_write),
    );

    let content_ok = &text_read[..] == TEXT && &data_read[..] == DATA && bss_nonzero == 0;
    let hardware_ok = text_el0_read && !text_el0_write && data_el0_read && data_el0_write;

    if content_ok && wx_ok && hardware_ok {
        serial_println!(
            "Runix ARM kernel: ELF loader PASS -- both segments loaded at their own VAs with \
             W^X permissions (text EL0-readable and EL0-unwritable, data writable and \
             execute-never), and a zero BSS tail"
        );
    } else {
        serial_println!(
            "Runix ARM kernel: ELF loader FAILED -- content_ok={} wx_bits_ok={} \
             hardware_permissions_ok={}",
            content_ok,
            wx_ok,
            hardware_ok
        );
    }
}

fn ap_name(descriptor: u64) -> &'static str {
    match descriptor & AP_MASK {
        0 => "0b00",
        AP_EL0_RW => "0b01",
        AP_EL0_RO => "0b11",
        _ => "0b10",
    }
}

fn bit(descriptor: u64, mask: u64) -> u8 {
    u8::from(descriptor & mask != 0)
}

fn yes_no(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "fault"
    }
}

/// `AT S1E0R`: translate `va` as if for an *unprivileged* (EL0) read, and
/// report whether the MMU would allow it. `false` means `PAR_EL1.F` came
/// back set -- a real permission fault, reported by the hardware rather
/// than inferred from the descriptor bits this crate wrote.
fn el0_can_read(va: u64) -> bool {
    let par: u64;
    unsafe {
        core::arch::asm!(
            "at S1E0R, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) va,
            par = out(reg) par,
        );
    }
    par & 1 == 0
}

/// `AT S1E0W`: the same question for an unprivileged *write*. A read+exec
/// page must fail this; that failure is the W half of W^X, enforced by
/// hardware.
fn el0_can_write(va: u64) -> bool {
    let par: u64;
    unsafe {
        core::arch::asm!(
            "at S1E0W, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) va,
            par = out(reg) par,
        );
    }
    par & 1 == 0
}

/// Compile-time sanity check that the proof's own VAs sit on distinct pages
/// inside the loadable window -- a silent overlap would make the W^X half
/// of this proof vacuous (one page, one descriptor).
const _: () = {
    assert!(TEXT_VADDR % GRANULE_4KIB == 0);
    assert!(DATA_VADDR % GRANULE_4KIB == 0);
    assert!(TEXT_VADDR != DATA_VADDR);
    assert!(DATA_VADDR + 4096 < STACK_BASE);
};
