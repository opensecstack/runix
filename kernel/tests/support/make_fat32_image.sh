#!/usr/bin/env bash
# Builds a real FAT32 disk image for `kernel/tests/blk_fat32_read.rs`'s
# Phase 2 proof — a real filesystem produced by real tooling (`mkfs.fat`/
# `mtools`), not a hand-rolled byte fixture pretending to be FAT32 (see
# `docs/ROADMAP.md`/the filesystem-driver plan for why that distinction
# matters here).
#
# Usage: make_fat32_image.sh <output-image-path>
#
# Produces a 64 MiB raw image, formatted FAT32, containing exactly one
# root-directory file, HELLO.TXT, whose contents `blk-driver-host/src/main.rs`
# hardcodes as its own expected-bytes constant — the two must match
# byte-for-byte, so this content lives in exactly one place (this script)
# and is not duplicated independently on the driver side.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <output-image-path>" >&2
    exit 1
fi

img_path="$1"
content="RUNIX-FAT32-PROOF: this file was read from a real FAT32 filesystem."

# 64 MiB, zero-filled — same `dd`-based sizing style xtask's
# `ensure_blk_test_image`/the `boot` job's `truncate -s 1M
# target/runix-blk-test.img` line already use for scratch disk images in
# this repo.
dd if=/dev/zero of="$img_path" bs=1M count=64 status=none

# FAT32 needs no loop device / root privilege to format a plain file —
# `mkfs.fat` operates directly on the image file.
mkfs.fat -F 32 "$img_path" >/dev/null

tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile"' EXIT
printf '%s\n' "$content" >"$tmpfile"

# `mcopy` (mtools) writes into a FAT image without mounting it — no
# loop-device/root privilege needed, same reasoning `mkfs.fat` above.
mcopy -i "$img_path" "$tmpfile" ::HELLO.TXT
