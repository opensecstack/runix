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
//!
//! `loader` is the one module where that line needed drawing deliberately
//! rather than obviously: loading an ELF needs `process.rs`'s
//! `AddressSpace`, which is hardware-side -- so the loader takes a
//! one-method `loader::PrivatePageMapper` that the binary implements for
//! `AddressSpace`, keeping the permission translation and the partial-page
//! copy arithmetic here where `cargo test --lib` can reach them. `vm` holds
//! the descriptor-bit and VA-layout constants both halves then share, so
//! there is exactly one definition of each.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

/// `#[cfg(test)]`-only, not unconditional like [`elf`] -- unlike `elf.rs`,
/// this module is *not* wholly hardware-independent (`issue_and_hold` needs
/// `crate::svc::frequency_hz()`, a real generic-timer read that only exists
/// in `main.rs`'s binary crate root, never in this lib crate root). Gating
/// the whole `mod` on `cfg(test)` means: under `cargo test --lib` (`test`
/// cfg set), this module joins the lib tree purely so its new, genuinely
/// pure MMIO-window resource-naming and containment-check logic can run as
/// real host tests; under the real `cargo build --target
/// aarch64-unknown-none` lib build (`test` cfg unset), this module is
/// dropped entirely from the lib tree, so `crate::svc` is never looked up
/// from a crate root that doesn't have it. The binary (`main.rs`'s own
/// `mod capabilities;`) is unaffected either way -- it always has `svc` in
/// scope and always compiles the real, non-test branch.
#[cfg(test)]
pub mod capabilities;
pub mod elf;
pub mod loader;
pub mod vm;
