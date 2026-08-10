//! Minimal ELF64 loader: parses just enough of the format (System V ABI —
//! `e_ident`/`e_entry`/`e_phoff`/`PT_LOAD` program headers) to map a
//! binary's loadable segments into a [`crate::process::AddressSpace`],
//! honoring each segment's real read/write/execute permissions.
//!
//! Deliberately not a general-purpose ELF library: no section headers, no
//! relocations, no dynamic linking, no symbol table — this kernel has
//! exactly one thing that will ever produce these binaries (its own build,
//! for now — see `kernel/tests/elf_loader.rs`, which hand-builds a minimal
//! one rather than needing an external ELF as a fixture, since there's no
//! filesystem yet to load one from). Extend this only when something real
//! needs the extra ELF machinery, not preemptively.
//!
//! Parses, but does not yet *run*, a loaded binary — that needs ring 3
//! threads with their own kernel-entry stack and `SYS_YIELD`, still future
//! work (see `process.rs`'s module doc comment). This module's own test
//! verifies mapped content and permissions from ring 0, the same way
//! `process_isolation.rs` proved address-space separation without needing
//! to execute anything in ring 3 either.

use crate::process::AddressSpace;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

const EI_MAG0: usize = 0;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const ELFCLASS64: u8 = 2;
const EI_DATA: usize = 5;
const ELFDATA2LSB: u8 = 1;
const E_MACHINE_OFFSET: usize = 18;
const EM_X86_64: u16 = 0x3e;
const E_ENTRY_OFFSET: usize = 24;
const E_PHOFF_OFFSET: usize = 32;
const E_PHENTSIZE_OFFSET: usize = 54;
const E_PHNUM_OFFSET: usize = 56;
const ELF_HEADER_SIZE: usize = 64;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

#[derive(Debug)]
pub enum ElfError {
    /// Shorter than a fixed-size ELF64 header, or a program header table
    /// entry runs past the end of the buffer.
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    NotX86_64,
    /// `e_phentsize` doesn't match `Elf64_Phdr`'s real size (56 bytes) —
    /// this loader doesn't support any other program header layout.
    UnexpectedProgramHeaderSize,
    /// A segment's `p_offset`/`p_filesz` claims file content past the end
    /// of the buffer this loader was actually given.
    SegmentOutOfBounds,
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// One `PT_LOAD` program header — the only segment type this loader acts
/// on; every other `p_type` (dynamic linking, notes, GNU stack, ...) is
/// silently skipped by [`Elf64::load_segments`], matching "this kernel
/// doesn't do dynamic linking" rather than treating unknown types as
/// errors.
pub struct LoadSegment {
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

pub struct Elf64<'a> {
    bytes: &'a [u8],
}

impl<'a> Elf64<'a> {
    /// Validates just enough of the header to be confident this is really
    /// a little-endian, 64-bit, x86_64 ELF binary with a program header
    /// table this loader knows how to walk — not full ELF conformance.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TooShort);
        }
        if bytes[EI_MAG0..EI_MAG0 + 4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if bytes[EI_CLASS] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }
        if bytes[EI_DATA] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }
        if read_u16(bytes, E_MACHINE_OFFSET) != EM_X86_64 {
            return Err(ElfError::NotX86_64);
        }
        let phentsize = read_u16(bytes, E_PHENTSIZE_OFFSET);
        if phentsize != 56 {
            return Err(ElfError::UnexpectedProgramHeaderSize);
        }
        let phoff = read_u64(bytes, E_PHOFF_OFFSET) as usize;
        let phnum = read_u16(bytes, E_PHNUM_OFFSET) as usize;
        let phtable_end = phoff
            .checked_add(phnum * phentsize as usize)
            .ok_or(ElfError::TooShort)?;
        if phtable_end > bytes.len() {
            return Err(ElfError::TooShort);
        }
        Ok(Elf64 { bytes })
    }

    pub fn entry_point(&self) -> u64 {
        read_u64(self.bytes, E_ENTRY_OFFSET)
    }

    fn program_headers(&self) -> impl Iterator<Item = LoadSegment> + '_ {
        let phoff = read_u64(self.bytes, E_PHOFF_OFFSET) as usize;
        let phnum = read_u16(self.bytes, E_PHNUM_OFFSET) as usize;
        (0..phnum).filter_map(move |i| {
            let base = phoff + i * 56;
            let p_type = read_u32(self.bytes, base);
            if p_type != PT_LOAD {
                return None;
            }
            Some(LoadSegment {
                flags: read_u32(self.bytes, base + 4),
                offset: read_u64(self.bytes, base + 8),
                vaddr: read_u64(self.bytes, base + 16),
                filesz: read_u64(self.bytes, base + 32),
                memsz: read_u64(self.bytes, base + 40),
            })
        })
    }

    /// Maps every `PT_LOAD` segment into `space`, honoring each segment's
    /// real permissions (a read-only/executable segment is mapped without
    /// `WRITABLE`, matching W^X rather than the old
    /// `map_private_page`-always-writable default). Bytes beyond
    /// `filesz` up to `memsz` (BSS) are zero-filled, not left as whatever
    /// the freshly allocated frame happened to contain — skipping that
    /// would leak stale physical memory content into the loaded process.
    ///
    /// Requires page-aligned segment addresses (`p_vaddr % 4096 == 0`) —
    /// the common case for a linker-produced binary, and this loader
    /// doesn't yet handle the sub-page-offset case a hand-built or
    /// unusually-linked binary could produce.
    pub fn load_segments(&self, space: &mut AddressSpace) -> Result<VirtAddr, ElfError> {
        for segment in self.program_headers() {
            let file_end = segment
                .offset
                .checked_add(segment.filesz)
                .ok_or(ElfError::SegmentOutOfBounds)?;
            if file_end > self.bytes.len() as u64 {
                return Err(ElfError::SegmentOutOfBounds);
            }

            let flags = translate_flags(segment.flags);
            let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(segment.vaddr));
            let end_addr = segment
                .vaddr
                .checked_add(segment.memsz.max(1) - 1)
                .ok_or(ElfError::SegmentOutOfBounds)?;
            let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(end_addr));

            for page in Page::range_inclusive(start_page, end_page) {
                let data = space.map_private_page(page, flags);
                data.fill(0);

                let page_start = page.start_address().as_u64();
                let page_end = page_start + 4096;
                let seg_file_start = segment.vaddr;
                let seg_file_end = segment.vaddr + segment.filesz;
                let copy_start = page_start.max(seg_file_start);
                let copy_end = page_end.min(seg_file_end);
                if copy_start < copy_end {
                    let page_offset = (copy_start - page_start) as usize;
                    let file_offset = (segment.offset + (copy_start - seg_file_start)) as usize;
                    let len = (copy_end - copy_start) as usize;
                    data[page_offset..page_offset + len]
                        .copy_from_slice(&self.bytes[file_offset..file_offset + len]);
                }
            }
        }
        Ok(VirtAddr::new(self.entry_point()))
    }
}

/// `PF_R` isn't checked at all: every page this loader maps is `PRESENT`
/// regardless, since x86_64 has no "not readable but present" page state
/// to represent its absence — a `PT_LOAD` segment without `PF_R` would be
/// unusual, and this loader just treats it the same as one with it. `PF_W`
/// maps directly to `WRITABLE`. `PF_X`'s *absence* sets `NO_EXECUTE` —
/// code segments (which set `PF_X`) stay executable; data segments (which
/// don't) become non-executable, real W^X rather than the old
/// "everything is always writable" default this replaced.
fn translate_flags(pf: u32) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT;
    if pf & PF_W != 0 {
        flags |= PageTableFlags::WRITABLE;
    }
    if pf & PF_X == 0 {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}
