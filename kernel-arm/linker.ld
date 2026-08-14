/* QEMU's `virt` machine loads a `-kernel` ELF image and jumps straight to
 * its entry point -- no separate bootloader stage the way x86_64 BIOS boot
 * needs one (see ../kernel's dependency on the `bootloader` crate). This is
 * a real architectural difference, not just a build detail: an ARM port
 * doesn't need anything like `xtask`'s image-building step for this stage.
 *
 * 0x40080000 is the conventional load address several bare-metal
 * aarch64/QEMU-virt tutorials use -- safely inside virt's default RAM
 * window, which starts at 0x40000000.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x40080000;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) }
}
