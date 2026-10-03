//! Pure, hardware-independent logic for `runix-kernel-arm`, in a library
//! target alongside `main.rs`'s freestanding binary -- the same split
//! `net-driver-host/src/lib.rs` already uses, and for the same reason:
//! `main.rs` is `#![no_std] #![no_main]` on `aarch64-unknown-none`, where
//! there is no test harness at all (no `test` crate, no unwinding runtime),
//! so anything worth unit-testing has to live somewhere that can also
//! compile as an ordinary host library.
//!
//! `#![cfg_attr(not(test), no_std)]` is exactly that: `no_std` for the real
//! `aarch64-unknown-none` build, `std` opted back in under `cfg(test)` so
//! `cargo test --lib` (host target, no `--target`) can run the tests.
//!
//! Only modules with no hardware/exception-level dependency belong here.
//! Everything else -- `mmu`, `vectors`, `gic`, `svc`, `el0`, ... -- stays in
//! the binary, since it is meaningless without real AArch64 system
//! registers underneath it.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod elf;
