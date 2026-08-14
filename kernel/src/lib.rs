//! Runix microkernel (L1). Alpha scope: boot, IPC, memory management, thread
//! scheduling. Everything else lives in user-space services above this layer.
//!
//! `no_std`, freestanding (`x86_64-unknown-none`) — this crate has no access
//! to the host OS. See `kernel/.cargo/config.toml` for the pinned target and
//! `../xtask` for turning the compiled binary into a bootable image.

#![no_std]
// `extern "x86-interrupt"` (used in interrupts.rs) is still unstable
// (rust-lang/rust#40180) despite being the standard way every x86_64 Rust
// kernel tutorial/crate defines exception handlers. This is *the* reason
// kernel/ needs nightly from Phase 2 onward — see kernel/rust-toolchain.toml.
#![feature(abi_x86_interrupt)]

extern crate alloc;

pub mod allocator;
pub mod boot;
pub mod capabilities;
pub mod citadel;
pub mod elf;
pub mod gdt;
pub mod interrupts;
pub mod ipc;
pub mod memory;
pub mod pci;
pub mod process;
pub mod qemu_exit;
pub mod scheduler;
pub mod serial;
pub mod syscall;
pub mod userspace;
