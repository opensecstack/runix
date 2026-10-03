/* Without this, the default aarch64-unknown-none linker script places
 * `.text` near its ABI default base (observed: ~0x200000, confirmed by
 * inspecting the compiled binary's own program headers) -- nowhere near
 * `kernel-arm::vm::PRIVATE_REGION_BASE` (`0x8000_0000`), the only VA range
 * `kernel-arm`'s loader (`loader.rs::SEGMENT_WINDOW_BASE`/`_END`) will ever
 * map a `PT_LOAD` segment into (see `process.rs`'s own doc comment on why
 * that window, specifically, is the one EL0-reachable VA range this kernel
 * has). Without this script, `tcp_proof.rs`'s `loader::load` call would
 * reject every segment with `SegmentOutsideWindow` before this binary ever
 * ran a single instruction.
 *
 * Unlike `kernel-arm/linker.ld`'s single flat `.text`/`.rodata`/`.data`/
 * `.bss` run (that image runs at EL1, where `mmu.rs` never distinguishes
 * EL0-executable from EL0-writable), this script keeps `.text` in its own
 * page-aligned region, separate from `.rodata`/`.data`/`.bss` -- so
 * `loader.rs::page_permissions` sees a real W^X split: `.text` becomes
 * `PF_R | PF_X` (never writable), the rest becomes `PF_R | PF_W` (never
 * executable). `ALIGN(0x1000)` between them is required, not cosmetic:
 * `loader.rs` maps one descriptor per 4 KiB page with one permission set,
 * so two segments sharing a page would make `OverlappingSegments` in a
 * content region picked a winner between two permission sets.
 *
 * `0x8000_0000` is `PRIVATE_REGION_BASE` itself -- this binary's own ELF
 * segments come first in the private window, well clear of
 * `main.rs`'s fixed VAs for `NetBootInfo`/the virtqueue regions/the packet
 * buffers (all `>= 0x8810_0000`, more than 8 MiB higher) and of
 * `tcp_proof.rs`'s own choice of VA for the mapped virtio-mmio window.
 *
 * `.rodata`/`.data`/`.got`/`.bss` are folded into one `.data` output
 * section rather than kept as separate page-aligned groups: this binary
 * has no load-bearing reason to mark `.rodata` read-only-but-not-writable
 * at EL0 (unlike `.text`, where EL0-executable-but-not-writable is the
 * whole point of W^X), and `ALIGN(0x1000)` only between *this* group and
 * `.text` -- not also inside it -- is what keeps `loader.rs`'s per-page
 * permission check from seeing two different permission sets claim the
 * same 4 KiB page, which is `LoaderError::OverlappingSegments` (hit for
 * real while developing this script: `.rodata` and `.bss` landed
 * page-adjacent but not page-*aligned* from each other).
 */
ENTRY(_start)

SECTIONS
{
    . = 0x80000000;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    . = ALIGN(0x1000);
    .data : {
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.got .got.*)
        *(.bss .bss.*)
    }

    /* Unwind tables this binary never uses (`panic = "abort"`, no
     * landing pads) -- without an explicit discard, lld's orphan-section
     * placement puts `.eh_frame`/`.eh_frame_hdr` *before* `.text` (neither
     * is `SHF_EXECINSTR`), producing an extra read-only, non-executable
     * `PT_LOAD` ahead of the real entry point and leaving `.text` itself
     * un-page-aligned at the front -- confirmed by actually inspecting the
     * linked binary's section headers, not a theoretical concern.
     */
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .eh_frame.*) }
}
