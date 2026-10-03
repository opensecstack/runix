//! Minimal ELF64 *parser* for AArch64 EL0 binaries -- the first, smallest
//! slice of `docs/BETA_MOBILE_PROGRESS.md`'s item 2.4 ("EL0 process/IPC
//! foundation"), deliberately built before the harder address-space and
//! scheduler work, exactly the way the x86_64 kernel built
//! `kernel/src/elf.rs` before it had ring 3 threads to run the result on.
//!
//! # Scope, and what this deliberately is not
//!
//! Parsing only: `e_ident`/`e_type`/`e_machine`/`e_entry` plus the
//! `PT_LOAD` entries of the program header table. No section headers, no
//! relocations, no dynamic linking, no symbol table, no `PT_INTERP`, no
//! notes -- same deliberate scope limit `kernel/src/elf.rs` documents, and
//! for the same reason: exactly one build produces the binaries this will
//! ever load.
//!
//! It also does **no loading**. The x86_64 equivalent maps segments into a
//! `process::AddressSpace`; this crate has no address-space abstraction at
//! all yet (`mmu.rs` installs one static, identity-mapped EL1 table), so
//! there is nothing to map *into*. The output here is therefore pure data
//! -- a list of [`LoadSegment`] descriptors plus the entry point -- and the
//! mapping/zero-filling half lands with the address-space work, not here.
//!
//! The ELF64 container format is architecture-independent (same 64-byte
//! header, same 56-byte `Elf64_Phdr`), so this logic is a direct translation
//! of the x86_64 version; the only architectural differences are
//! `e_machine` (`EM_AARCH64` = 183, not `EM_X86_64` = 62) and the fact that
//! AArch64 Linux-style ELF images are little-endian (`ELFDATA2LSB`), which
//! is also what this crate's own `aarch64-unknown-none` builds produce.
//!
//! # `e_type`: `ET_EXEC` only, on purpose
//!
//! Only `ET_EXEC` is accepted. Every freestanding ring-3/EL0 binary in this
//! workspace (`grid-sandbox-host`, `net-driver-host`, `blk-driver-host`, and
//! this crate itself) is linked at a fixed load address with
//! `-C relocation-model=static` (see `.cargo/config.toml`'s own comment on
//! why) against a hand-written linker script -- i.e. a non-relocatable
//! executable, matching `kernel-arm`'s identity-mapped, no-ASLR
//! architecture. `ET_DYN` (static-PIE) would additionally need relocation
//! processing, which this parser explicitly does not do, so accepting it
//! would silently produce a broken image rather than an honest error.
//!
//! # Why bounds validation is a security property, not tidiness
//!
//! A later loader will trust these descriptors to copy `filesz` bytes from
//! `offset` out of the image. If a corrupt or hostile image could declare a
//! segment running past the end of the buffer, that trust would become an
//! out-of-bounds read on a privileged path -- and this crate is
//! `panic = "abort"`, so even the "safe" outcome is a dead kernel. So
//! [`Elf64::parse`] validates *every* `PT_LOAD` segment's declared range
//! against the real slice length up front, and nothing in this module
//! indexes a slice without a prior `get`/length check (no `unwrap`, no bare
//! range indexing). Once `parse` returns, the segment list is known-good.

use alloc::vec::Vec;
use core::fmt;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const ELFCLASS64: u8 = 2;
const EI_DATA: usize = 5;
const ELFDATA2LSB: u8 = 1;
const E_TYPE_OFFSET: usize = 16;
const ET_EXEC: u16 = 2;
const E_MACHINE_OFFSET: usize = 18;
const EM_AARCH64: u16 = 183;
const E_ENTRY_OFFSET: usize = 24;
const E_PHOFF_OFFSET: usize = 32;
const E_PHENTSIZE_OFFSET: usize = 54;
const E_PHNUM_OFFSET: usize = 56;
const ELF_HEADER_SIZE: usize = 64;

/// Fixed size of one `Elf64_Phdr`. Checked against `e_phentsize` rather
/// than assumed: a different value means a program header layout this
/// parser's field offsets below do not describe.
const PHDR_SIZE: usize = 56;

const PH_TYPE_OFFSET: usize = 0;
const PH_FLAGS_OFFSET: usize = 4;
const PH_OFFSET_OFFSET: usize = 8;
const PH_VADDR_OFFSET: usize = 16;
const PH_FILESZ_OFFSET: usize = 32;
const PH_MEMSZ_OFFSET: usize = 40;

const PT_LOAD: u32 = 1;

/// Program header permission bits, as defined by the System V ABI.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Shorter than a fixed-size ELF64 header.
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    /// `e_machine` is not `EM_AARCH64` -- e.g. handing this parser an
    /// x86_64 image, which would otherwise pass every other check.
    NotAarch64,
    /// `e_type` is not `ET_EXEC`. See this module's doc comment on why
    /// `ET_DYN` is rejected rather than quietly loaded without relocation.
    NotExecutable,
    /// `e_phentsize` doesn't match `Elf64_Phdr`'s real size (56 bytes).
    UnexpectedProgramHeaderSize,
    /// The program header table, as located by `e_phoff`/`e_phnum`, runs
    /// past the end of the image (or overflows when computed).
    ProgramHeadersOutOfBounds,
    /// A `PT_LOAD` segment's `p_offset`/`p_filesz` claims file content past
    /// the end of the image, or `p_vaddr`/`p_memsz` overflows the address
    /// space. The security-relevant case -- see this module's doc comment.
    SegmentOutOfBounds,
    /// A `PT_LOAD` segment declares `p_memsz < p_filesz`, which has no
    /// coherent meaning (there is nowhere to put the file content).
    SegmentSmallerThanFileContent,
    /// Valid ELF, but nothing to load -- no `PT_LOAD` segment at all.
    NoLoadableSegments,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ElfError::TooShort => "image is shorter than an ELF64 header",
            ElfError::BadMagic => "not an ELF image (bad magic)",
            ElfError::Not64Bit => "not ELFCLASS64",
            ElfError::NotLittleEndian => "not ELFDATA2LSB (little-endian)",
            ElfError::NotAarch64 => "e_machine is not EM_AARCH64",
            ElfError::NotExecutable => "e_type is not ET_EXEC",
            ElfError::UnexpectedProgramHeaderSize => "e_phentsize is not 56",
            ElfError::ProgramHeadersOutOfBounds => "program header table runs past the image",
            ElfError::SegmentOutOfBounds => "PT_LOAD segment range runs past the image",
            ElfError::SegmentSmallerThanFileContent => "PT_LOAD segment has p_memsz < p_filesz",
            ElfError::NoLoadableSegments => "no PT_LOAD segment",
        };
        f.write_str(msg)
    }
}

/// One validated `PT_LOAD` program header -- the only segment type this
/// parser reports. Every other `p_type` (`PT_DYNAMIC`, `PT_NOTE`,
/// `PT_GNU_STACK`, ...) is skipped rather than treated as an error, matching
/// "this kernel does no dynamic linking" instead of rejecting binaries over
/// headers it simply doesn't need.
///
/// `filesz` and `memsz` are kept distinct on purpose: `memsz > filesz` is
/// the BSS tail, and whatever eventually maps this segment must zero those
/// extra bytes (otherwise freshly allocated frames leak their previous
/// contents into the new process). Collapsing them into one "size" would
/// erase that information at exactly the layer that still knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    /// `p_flags` -- see [`PF_R`]/[`PF_W`]/[`PF_X`] and the accessors below.
    pub flags: u32,
    /// `p_offset`: byte offset of this segment's content within the image.
    /// Validated: `offset + filesz <= image.len()`.
    pub offset: u64,
    /// `p_vaddr`: virtual address this segment wants to live at.
    pub vaddr: u64,
    /// `p_filesz`: bytes of real content in the image.
    pub filesz: u64,
    /// `p_memsz`: bytes this segment occupies in memory. `>= filesz`.
    pub memsz: u64,
}

impl LoadSegment {
    pub fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// Length of the BSS tail: bytes at `vaddr + filesz` that a loader must
    /// zero-fill because the image carries no content for them. Zero for an
    /// ordinary text segment.
    pub fn bss_len(&self) -> u64 {
        self.memsz.saturating_sub(self.filesz)
    }
}

/// A parsed, validated AArch64 ELF64 executable, borrowing the image bytes.
///
/// Construction is the validation step: if [`Elf64::parse`] returns `Ok`,
/// the entry point and every reported [`LoadSegment`] are already
/// bounds-checked against the real image, so neither [`Elf64::segments`] nor
/// [`Elf64::segment_bytes`] can fail or panic.
pub struct Elf64<'a> {
    bytes: &'a [u8],
    entry: u64,
    phoff: usize,
    phnum: usize,
}

impl<'a> Elf64<'a> {
    /// Validates the identification bytes, `e_type`, `e_machine`, the
    /// program header table's own bounds, and then every `PT_LOAD`
    /// segment's declared range -- not full ELF conformance, just enough
    /// that a later loader can trust the descriptors this hands back.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TooShort);
        }
        // Length-checked above, so these index operations are the only ones
        // in this module that don't need their own `get`.
        if bytes[..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if bytes[EI_CLASS] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }
        if bytes[EI_DATA] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }
        if read_u16(bytes, E_TYPE_OFFSET).ok_or(ElfError::TooShort)? != ET_EXEC {
            return Err(ElfError::NotExecutable);
        }
        if read_u16(bytes, E_MACHINE_OFFSET).ok_or(ElfError::TooShort)? != EM_AARCH64 {
            return Err(ElfError::NotAarch64);
        }
        if read_u16(bytes, E_PHENTSIZE_OFFSET).ok_or(ElfError::TooShort)? as usize != PHDR_SIZE {
            return Err(ElfError::UnexpectedProgramHeaderSize);
        }

        let entry = read_u64(bytes, E_ENTRY_OFFSET).ok_or(ElfError::TooShort)?;
        let phoff = usize::try_from(read_u64(bytes, E_PHOFF_OFFSET).ok_or(ElfError::TooShort)?)
            .map_err(|_| ElfError::ProgramHeadersOutOfBounds)?;
        let phnum = read_u16(bytes, E_PHNUM_OFFSET).ok_or(ElfError::TooShort)? as usize;

        let table_end = phnum
            .checked_mul(PHDR_SIZE)
            .and_then(|len| phoff.checked_add(len))
            .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
        if table_end > bytes.len() {
            return Err(ElfError::ProgramHeadersOutOfBounds);
        }

        let elf = Elf64 {
            bytes,
            entry,
            phoff,
            phnum,
        };

        // Validate every PT_LOAD *now*, so `segments()` can be infallible
        // and a caller can't accidentally act on an unchecked descriptor.
        let mut loadable = 0usize;
        for segment in elf.segments_unvalidated() {
            if segment.memsz < segment.filesz {
                return Err(ElfError::SegmentSmallerThanFileContent);
            }
            let file_end = segment
                .offset
                .checked_add(segment.filesz)
                .ok_or(ElfError::SegmentOutOfBounds)?;
            if file_end > bytes.len() as u64 {
                return Err(ElfError::SegmentOutOfBounds);
            }
            // Not an image-bounds check -- a guard that the eventual
            // mapping arithmetic (`vaddr .. vaddr + memsz`) can't wrap.
            segment
                .vaddr
                .checked_add(segment.memsz)
                .ok_or(ElfError::SegmentOutOfBounds)?;
            loadable += 1;
        }
        if loadable == 0 {
            return Err(ElfError::NoLoadableSegments);
        }

        Ok(elf)
    }

    /// `e_entry` -- the EL0 PC to `eret` to once the segments are mapped.
    /// Deliberately not validated against any segment's range: which
    /// segment must contain it is a loader-policy question, and this crate
    /// has no loader yet.
    pub fn entry_point(&self) -> u64 {
        self.entry
    }

    /// Every `PT_LOAD` segment, in program-header order. Infallible: all of
    /// these were bounds-checked by [`Elf64::parse`].
    pub fn segments(&self) -> impl Iterator<Item = LoadSegment> + '_ {
        self.segments_unvalidated()
    }

    /// [`Elf64::segments`] collected, for callers that want to hold the
    /// descriptors after dropping the borrow of the image (the eventual
    /// loader will, since mapping happens per-segment while the image
    /// itself may be elsewhere).
    pub fn load_segments(&self) -> Vec<LoadSegment> {
        self.segments().collect()
    }

    /// The file-backed bytes of `segment` (`filesz` of them, excluding the
    /// BSS tail). Cannot fail -- the range was validated at parse time --
    /// and exists so a loader never has to redo that offset arithmetic
    /// itself.
    pub fn segment_bytes(&self, segment: &LoadSegment) -> &'a [u8] {
        let start = segment.offset as usize;
        let end = start.saturating_add(segment.filesz as usize);
        self.bytes.get(start..end).unwrap_or(&[][..])
    }

    /// Walks the program header table without the parse-time bounds checks
    /// on the segments themselves. Private: every read here is still
    /// `get`-based (so a short/garbage table yields `None`, never a panic),
    /// but the descriptors it produces are not yet known to be in bounds.
    fn segments_unvalidated(&self) -> impl Iterator<Item = LoadSegment> + '_ {
        (0..self.phnum).filter_map(move |i| {
            let base = self.phoff + i * PHDR_SIZE;
            if read_u32(self.bytes, base + PH_TYPE_OFFSET)? != PT_LOAD {
                return None;
            }
            Some(LoadSegment {
                flags: read_u32(self.bytes, base + PH_FLAGS_OFFSET)?,
                offset: read_u64(self.bytes, base + PH_OFFSET_OFFSET)?,
                vaddr: read_u64(self.bytes, base + PH_VADDR_OFFSET)?,
                filesz: read_u64(self.bytes, base + PH_FILESZ_OFFSET)?,
                memsz: read_u64(self.bytes, base + PH_MEMSZ_OFFSET)?,
            })
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

/// Host-side tests (`cargo test --lib`, no `--target`) -- the same
/// `#![cfg_attr(not(test), no_std)]` split `net-driver-host`'s `lib.rs`
/// uses, for the same reason: this crate's binary has no test harness on
/// `aarch64-unknown-none`, and this module is pure data parsing with no
/// hardware dependency, so there is no reason to need a QEMU boot to test
/// it. Images are hand-assembled here as `Vec<u8>`, the same technique
/// `kernel/tests/elf_loader.rs` uses (there's no filesystem to load a real
/// one from), with `e_machine` set to `EM_AARCH64`.
#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: u64 = 0x4100_0000;
    const TEXT_VADDR: u64 = 0x4100_0000;
    const DATA_VADDR: u64 = 0x4101_0000;
    const TEXT: &[u8] = b"\x1f\x20\x03\xd5"; // `nop`, just to be real bytes
    const DATA: &[u8] = b"runix";

    struct Phdr {
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    }

    /// Builds a well-formed ELF64 image: header, `phdrs`'s program header
    /// table, then `payload` placed at `payload_offset`.
    fn build(phdrs: &[Phdr], payload_offset: usize, payload: &[u8]) -> Vec<u8> {
        build_with(phdrs, payload_offset, payload, EM_AARCH64, ET_EXEC, true)
    }

    fn build_with(
        phdrs: &[Phdr],
        payload_offset: usize,
        payload: &[u8],
        machine: u16,
        e_type: u16,
        good_magic: bool,
    ) -> Vec<u8> {
        let mut image = vec![0u8; ELF_HEADER_SIZE];
        if good_magic {
            image[..4].copy_from_slice(&ELF_MAGIC);
        } else {
            image[..4].copy_from_slice(b"\x7fELG");
        }
        image[EI_CLASS] = ELFCLASS64;
        image[EI_DATA] = ELFDATA2LSB;
        image[E_TYPE_OFFSET..E_TYPE_OFFSET + 2].copy_from_slice(&e_type.to_le_bytes());
        image[E_MACHINE_OFFSET..E_MACHINE_OFFSET + 2].copy_from_slice(&machine.to_le_bytes());
        image[E_ENTRY_OFFSET..E_ENTRY_OFFSET + 8].copy_from_slice(&ENTRY.to_le_bytes());
        image[E_PHOFF_OFFSET..E_PHOFF_OFFSET + 8]
            .copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        image[E_PHENTSIZE_OFFSET..E_PHENTSIZE_OFFSET + 2]
            .copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        image[E_PHNUM_OFFSET..E_PHNUM_OFFSET + 2]
            .copy_from_slice(&(phdrs.len() as u16).to_le_bytes());

        for phdr in phdrs {
            let mut entry = vec![0u8; PHDR_SIZE];
            entry[PH_TYPE_OFFSET..PH_TYPE_OFFSET + 4].copy_from_slice(&phdr.p_type.to_le_bytes());
            entry[PH_FLAGS_OFFSET..PH_FLAGS_OFFSET + 4].copy_from_slice(&phdr.flags.to_le_bytes());
            entry[PH_OFFSET_OFFSET..PH_OFFSET_OFFSET + 8]
                .copy_from_slice(&phdr.offset.to_le_bytes());
            entry[PH_VADDR_OFFSET..PH_VADDR_OFFSET + 8].copy_from_slice(&phdr.vaddr.to_le_bytes());
            entry[PH_FILESZ_OFFSET..PH_FILESZ_OFFSET + 8]
                .copy_from_slice(&phdr.filesz.to_le_bytes());
            entry[PH_MEMSZ_OFFSET..PH_MEMSZ_OFFSET + 8].copy_from_slice(&phdr.memsz.to_le_bytes());
            image.extend_from_slice(&entry);
        }

        if image.len() < payload_offset {
            image.resize(payload_offset, 0);
        }
        image.extend_from_slice(payload);
        image
    }

    /// One read+exec segment and one read+write segment with a BSS tail --
    /// the same two-segment shape `kernel/tests/elf_loader.rs` builds.
    fn two_segment_image() -> Vec<u8> {
        let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
        let mut payload = Vec::new();
        payload.extend_from_slice(TEXT);
        payload.extend_from_slice(DATA);
        build(
            &[
                Phdr {
                    p_type: PT_LOAD,
                    flags: PF_R | PF_X,
                    offset: payload_offset as u64,
                    vaddr: TEXT_VADDR,
                    filesz: TEXT.len() as u64,
                    memsz: TEXT.len() as u64,
                },
                Phdr {
                    p_type: PT_LOAD,
                    flags: PF_R | PF_W,
                    offset: (payload_offset + TEXT.len()) as u64,
                    vaddr: DATA_VADDR,
                    filesz: DATA.len() as u64,
                    // BSS tail: 16 bytes beyond the file content.
                    memsz: DATA.len() as u64 + 16,
                },
            ],
            payload_offset,
            &payload,
        )
    }

    #[test]
    fn parses_entry_point_and_both_segments() {
        let image = two_segment_image();
        let elf = Elf64::parse(&image).expect("well-formed image must parse");
        assert_eq!(elf.entry_point(), ENTRY);

        let segments = elf.load_segments();
        assert_eq!(segments.len(), 2);

        let text = segments[0];
        assert_eq!(text.vaddr, TEXT_VADDR);
        assert!(text.is_readable() && text.is_executable());
        assert!(!text.is_writable());
        assert_eq!(text.filesz, TEXT.len() as u64);
        assert_eq!(text.bss_len(), 0);
        assert_eq!(elf.segment_bytes(&text), TEXT);

        let data = segments[1];
        assert_eq!(data.vaddr, DATA_VADDR);
        assert!(data.is_readable() && data.is_writable());
        assert!(!data.is_executable());
        // filesz and memsz must stay distinct -- the BSS tail a loader has
        // to zero-fill.
        assert_eq!(data.filesz, DATA.len() as u64);
        assert_eq!(data.memsz, DATA.len() as u64 + 16);
        assert_eq!(data.bss_len(), 16);
        assert_eq!(elf.segment_bytes(&data), DATA);
    }

    #[test]
    fn skips_non_pt_load_headers() {
        let payload_offset = ELF_HEADER_SIZE + 2 * PHDR_SIZE;
        let image = build(
            &[
                Phdr {
                    p_type: 4, // PT_NOTE
                    flags: PF_R,
                    offset: 0,
                    vaddr: 0,
                    filesz: 0,
                    memsz: 0,
                },
                Phdr {
                    p_type: PT_LOAD,
                    flags: PF_R | PF_X,
                    offset: payload_offset as u64,
                    vaddr: TEXT_VADDR,
                    filesz: TEXT.len() as u64,
                    memsz: TEXT.len() as u64,
                },
            ],
            payload_offset,
            TEXT,
        );
        let elf = Elf64::parse(&image).expect("a PT_NOTE header must not be an error");
        assert_eq!(elf.load_segments().len(), 1);
    }

    #[test]
    fn rejects_bad_magic() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build_with(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: TEXT_VADDR,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
            EM_AARCH64,
            ET_EXEC,
            false,
        );
        assert_eq!(Elf64::parse(&image).err(), Some(ElfError::BadMagic));
    }

    #[test]
    fn rejects_wrong_machine() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build_with(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: TEXT_VADDR,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
            0x3e, // EM_X86_64 -- valid ELF, wrong architecture
            ET_EXEC,
            true,
        );
        assert_eq!(Elf64::parse(&image).err(), Some(ElfError::NotAarch64));
    }

    #[test]
    fn rejects_non_exec_type() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build_with(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: TEXT_VADDR,
                filesz: TEXT.len() as u64,
                memsz: TEXT.len() as u64,
            }],
            payload_offset,
            TEXT,
            EM_AARCH64,
            3, // ET_DYN
            true,
        );
        assert_eq!(Elf64::parse(&image).err(), Some(ElfError::NotExecutable));
    }

    /// The security-relevant case: a segment claiming content past the end
    /// of the image must be rejected at parse time, so a later loader
    /// trusting these descriptors can't be talked into an out-of-bounds
    /// read.
    #[test]
    fn rejects_segment_past_end_of_image() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                offset: payload_offset as u64,
                vaddr: TEXT_VADDR,
                // Claims far more content than the image actually carries.
                filesz: 0x1000,
                memsz: 0x1000,
            }],
            payload_offset,
            TEXT,
        );
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::SegmentOutOfBounds)
        );
    }

    /// Same class of lie, expressed as an overflow rather than a plain
    /// over-long length.
    #[test]
    fn rejects_overflowing_segment_range() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                offset: u64::MAX - 1,
                vaddr: TEXT_VADDR,
                filesz: 16,
                memsz: 16,
            }],
            payload_offset,
            TEXT,
        );
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::SegmentOutOfBounds)
        );
    }

    #[test]
    fn rejects_program_header_table_past_end_of_image() {
        let mut image = two_segment_image();
        // Point e_phoff just past the end of the real image.
        let bogus = image.len() as u64 + 8;
        image[E_PHOFF_OFFSET..E_PHOFF_OFFSET + 8].copy_from_slice(&bogus.to_le_bytes());
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::ProgramHeadersOutOfBounds)
        );
    }

    #[test]
    fn rejects_memsz_below_filesz() {
        let payload_offset = ELF_HEADER_SIZE + PHDR_SIZE;
        let image = build(
            &[Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_W,
                offset: payload_offset as u64,
                vaddr: DATA_VADDR,
                filesz: DATA.len() as u64,
                memsz: 1,
            }],
            payload_offset,
            DATA,
        );
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::SegmentSmallerThanFileContent)
        );
    }

    #[test]
    fn rejects_image_with_no_loadable_segment() {
        let image = build(
            &[Phdr {
                p_type: 4, // PT_NOTE only
                flags: PF_R,
                offset: 0,
                vaddr: 0,
                filesz: 0,
                memsz: 0,
            }],
            ELF_HEADER_SIZE + PHDR_SIZE,
            &[],
        );
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::NoLoadableSegments)
        );
    }

    #[test]
    fn rejects_truncated_image() {
        assert_eq!(Elf64::parse(&[]).err(), Some(ElfError::TooShort));
        assert_eq!(Elf64::parse(b"\x7fELF").err(), Some(ElfError::TooShort));
    }

    #[test]
    fn rejects_unexpected_program_header_size() {
        let mut image = two_segment_image();
        image[E_PHENTSIZE_OFFSET..E_PHENTSIZE_OFFSET + 2].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::UnexpectedProgramHeaderSize)
        );
    }
}
