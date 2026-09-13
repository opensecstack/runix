#!/usr/bin/env bash
# Builds a real FAT32 disk image for `kernel/tests/blk_fat32_read.rs`'s
# Phase 2 proof — a real filesystem produced by real tooling (`mkfs.fat`/
# `mtools`), not a hand-rolled byte fixture pretending to be FAT32 (see
# `docs/ROADMAP.md`/the filesystem-driver plan for why that distinction
# matters here).
#
# Usage: make_fat32_image.sh <output-image-path>
#
# Produces a 64 MiB raw image, formatted FAT32 (`mkfs.fat` picks a 512-byte
# cluster size for a volume this size -- one sector per cluster, confirmed
# by actually inspecting the formatted image's own BPB, not assumed),
# containing:
#   - HELLO.TXT, root directory, contents `blk-driver-host/src/main.rs`
#     hardcodes as its own expected-bytes constant.
#   - SUBDIR/NESTED.TXT, one level of real subdirectory (Phase 3's
#     subdirectory-traversal proof) -- `blk-driver-host`'s expected
#     contents constant must match this byte-for-byte.
#   - BIG.TXT, root directory, exactly 3000 bytes of a deterministic
#     repeating pattern (`(i % 10) as u8 + b'0'`, generated identically
#     here and in `blk-driver-host/src/main.rs` so neither side duplicates
#     3000 literal bytes) -- large enough to span multiple 512-byte
#     clusters, proving the FAT chain-walking code Phase 2's single-cluster
#     HELLO.TXT never actually exercised.
#   - long-filename-test.txt, root directory (Phase 4's LFN proof) -- a
#     name too long for 8.3, forcing `mkfs.fat`/`mcopy` to emit real VFAT
#     long-filename entries, not something this script constructs by hand.
#   - WRITE.TXT, root directory, exactly 512 bytes (one sector, one
#     cluster on this fixture) of a deterministic initial pattern
#     (`b'A' + (i % 26)`) -- Phase 5's write-support proof overwrites this
#     file's one sector and reads it back; the *initial* pattern here only
#     needs to be real, non-zero content, not anything the test itself
#     asserts against (see that test's own doc comment for why).
#   - PARTIAL.TXT, root directory, exactly 512 bytes of a deterministic
#     lowercase-letter pattern (`b'a' + (i % 26)`) -- visually distinct
#     from every other fixture pattern here on purpose (a bug reading the
#     wrong file's sector is easy to spot). Phase 6's partial-write/resize
#     proof overwrites only the *first* 300 bytes and shrinks `file_size`
#     to 300, using real read-modify-write -- bytes 300..512 must survive
#     unchanged, which this initial pattern makes independently checkable
#     (a naive full-sector-overwrite bug would clobber them).
# Every content string here lives in exactly one place (this script), not
# duplicated independently on the driver side.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <output-image-path>" >&2
    exit 1
fi

img_path="$1"
content="RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem."
nested_content="RUNIX-FAT32-PROOF: nested file inside a real subdirectory."
long_name_content="RUNIX-FAT32-PROOF: located via a real long filename, not 8.3."

# 64 MiB, zero-filled — same `dd`-based sizing style xtask's
# `ensure_blk_test_image`/the `boot` job's `truncate -s 1M
# target/runix-blk-test.img` line already use for scratch disk images in
# this repo.
dd if=/dev/zero of="$img_path" bs=1M count=64 status=none

# FAT32 needs no loop device / root privilege to format a plain file —
# `mkfs.fat` operates directly on the image file.
mkfs.fat -F 32 "$img_path" >/dev/null

tmpfile="$(mktemp)"
nested_tmpfile="$(mktemp)"
big_tmpfile="$(mktemp)"
long_name_tmpfile="$(mktemp)"
write_tmpfile="$(mktemp)"
partial_tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile" "$nested_tmpfile" "$big_tmpfile" "$long_name_tmpfile" "$write_tmpfile" "$partial_tmpfile"' EXIT
printf '%s\n' "$content" >"$tmpfile"
printf '%s\n' "$nested_content" >"$nested_tmpfile"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i % 10) + 0x30 for i in range(3000)))" >"$big_tmpfile"
printf '%s\n' "$long_name_content" >"$long_name_tmpfile"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i % 26) + 0x41 for i in range(512)))" >"$write_tmpfile"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i % 26) + 0x61 for i in range(512)))" >"$partial_tmpfile"

# `mcopy`/`mmd` (mtools) write into a FAT image without mounting it — no
# loop-device/root privilege needed, same reasoning `mkfs.fat` above.
mcopy -i "$img_path" "$tmpfile" ::HELLO.TXT
mcopy -i "$img_path" "$big_tmpfile" ::BIG.TXT
mmd -i "$img_path" ::SUBDIR
mcopy -i "$img_path" "$nested_tmpfile" ::SUBDIR/NESTED.TXT
mcopy -i "$img_path" "$long_name_tmpfile" "::long-filename-test.txt"
mcopy -i "$img_path" "$write_tmpfile" ::WRITE.TXT
mcopy -i "$img_path" "$partial_tmpfile" ::PARTIAL.TXT
