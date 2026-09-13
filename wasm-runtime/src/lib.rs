//! WebAssembly runtime for app isolation (Grid Sandbox / App Runtime).
//! Alpha scope: engine bring-up, basic module loading/execution, and a
//! host-function import. Beta: [`SandboxLimits`] gives a caller (in
//! practice `grid-sandbox-host`, mapping a CITADEL-signed tier) real,
//! host-imposed per-instance memory/table ceilings independent of what a
//! loaded module declares about itself — see that type's doc comment for
//! why that distinction matters and what it does/doesn't prove. This crate
//! deliberately has no notion of tiers, CITADEL, or MARSHAL itself: it only
//! knows "what are my limits", kept decoupled from that vocabulary. A real
//! MARSHAL channel permit (a live, evaluated authorization rather than a
//! signed-at-boot resource-limit assignment) still doesn't exist — `host_print`
//! below is still an in-memory buffer, not a real syscall bridge.
//!
//! Built on `wasmi` rather than `wasmtime`: `wasmtime` needs a host OS
//! (mmap, threads, signal handlers for its JIT); `wasmi` is a pure
//! interpreter with an optional `std` feature we deliberately don't
//! enable, which matters once this crate needs to run hosted by the
//! kernel itself instead of on the dev host — see the architecture note in
//! the top-level README about `wasm-runtime`'s eventual `no_std` move.
//!
//! `no_std` + `alloc` (like `capability-manager`/`citadel-integration`),
//! not full `std` — the whole point of the Grid Sandbox architecture (see
//! README) is this crate eventually running as its own freestanding ring 3
//! binary, which has no `std` at all. `#[cfg(test)]` opts back into `std`
//! for its own test suite, same split those two crates already use.
//! `thiserror` isn't used for [`RuntimeError`] for the same reason it
//! isn't in those crates either: `thiserror` 1.x hard-requires `std::error::Error`
//! (confirmed by trying to build this crate for `x86_64-unknown-none` —
//! it fails inside `thiserror` itself, not this crate's own code), so a
//! hand-written `Display` impl is the consistent choice here, not a
//! one-off exception.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use wasmi::{Caller, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

#[derive(Debug)]
pub enum RuntimeError {
    /// Failed to parse/validate the wasm module.
    Module(wasmi::Error),
    /// Failed to define a host import.
    HostImport(wasmi::Error),
    /// Failed to instantiate the wasm module.
    Instantiate(wasmi::Error),
    /// Exported function not found, or has the wrong signature.
    Function(wasmi::Error),
    /// A wasm function call trapped.
    Call(wasmi::Error),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Module(e) => write!(f, "failed to parse/validate wasm module: {e}"),
            RuntimeError::HostImport(e) => write!(f, "failed to define host import: {e}"),
            RuntimeError::Instantiate(e) => write!(f, "failed to instantiate wasm module: {e}"),
            RuntimeError::Function(e) => {
                write!(
                    f,
                    "exported function not found, or has the wrong signature: {e}"
                )
            }
            RuntimeError::Call(e) => write!(f, "wasm function call trapped: {e}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for RuntimeError {}

/// Per-instance state a host function can reach via [`Caller::data_mut`].
/// `output` stands in for a real syscall bridge — a WASM module today has
/// exactly one way to affect anything outside its own linear memory: call
/// `host.print`, which appends a byte here. Once `citadel-integration`
/// lands, this is where a real `syscall::syscall(SYS_WRITE, ...)` call (or
/// a MARSHAL-gated equivalent) replaces the buffer push.
///
/// `limits` backs [`Store::limiter`] (installed in `instantiate` below) —
/// wasmi calls back into whatever `ResourceLimiter` this returns any time a
/// module tries to grow its linear memory or a table, independent of
/// whatever maximum the module itself declared in its own header. This is
/// the actual isolation-tier enforcement point: `SandboxLimits` (see that
/// type's doc comment) sets how tight `limits` is per tier.
struct HostState {
    output: Vec<u8>,
    limits: StoreLimits,
}

/// Host-imposed ceilings on a single WASM instance's linear memory and
/// table growth, applied via `wasmi::Store::limiter` regardless of what the
/// loaded module itself declares as its own maximum. This is the
/// distinction that matters: `wasm-runtime/tests/memory_isolation.rs`'s
/// existing tests only prove a module's *own declared* ceiling is honored
/// by the engine — a hostile module could simply declare a much larger one
/// (or none at all). `SandboxLimits` is what actually differentiates a
/// grid-sandbox isolation tier from another, per CLAUDE.md's T1/T2/T3
/// definitions, without this crate needing to know anything about CITADEL,
/// MARSHAL, or tier vocabulary at all — it only needs "what are my limits",
/// supplied by whoever loads a module (`grid-sandbox-host`, mapping a
/// CITADEL-signed tier to one of the constructors below).
///
/// The three constructors' numbers are arbitrary initial defaults, not
/// tuned against any real workload — same honesty as this crate's own
/// `HEAP_SIZE` precedent elsewhere in this codebase ("no principled sizing
/// yet, same as ... wasn't either until something real needed more").
#[derive(Debug, Clone, Copy)]
pub struct SandboxLimits {
    /// Maximum linear memory size, in bytes, for a single WASM instance.
    pub memory_size: usize,
    /// Maximum number of elements in a single WASM table.
    pub table_elements: u32,
}

impl SandboxLimits {
    /// T1 Critical (CLAUDE.md: daemons, crypto, key management) — the most
    /// generous limits of the three, though still a real, finite ceiling
    /// rather than "unlimited": even a trusted first-party module shouldn't
    /// be able to exhaust this process's whole private heap by itself.
    pub fn t1_critical() -> Self {
        SandboxLimits {
            memory_size: 8 * 1024 * 1024,
            table_elements: 4096,
        }
    }

    /// T2 Trusted (CLAUDE.md: first-party apps) — this crate's default
    /// (see [`WasmRuntime::new`]), matching what every existing call site
    /// and test already exercises today.
    pub fn t2_trusted() -> Self {
        SandboxLimits {
            memory_size: 4 * 1024 * 1024,
            table_elements: 2048,
        }
    }

    /// T3 Untrusted (CLAUDE.md: third-party/web content) — the tightest
    /// ceiling. Not a real "evidence-gated" implementation (that needs
    /// VIGIL/WORM, neither of which exists yet) — approximated here purely
    /// by resource strictness, which is an honest, real, testable property
    /// even if it isn't the full MARSHAL evidence-gating story.
    pub fn t3_untrusted() -> Self {
        SandboxLimits {
            memory_size: 512 * 1024,
            table_elements: 256,
        }
    }

    fn to_store_limits(self) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(self.memory_size)
            .table_elements(self.table_elements)
            .build()
    }
}

pub struct WasmRuntime {
    engine: Engine,
    limits: SandboxLimits,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    /// Equivalent to `Self::new_with_limits(SandboxLimits::t2_trusted())` —
    /// kept as the zero-argument constructor so every existing call site
    /// and test (none of which cares about tiering) keeps compiling
    /// unchanged.
    pub fn new() -> Self {
        Self::new_with_limits(SandboxLimits::t2_trusted())
    }

    pub fn new_with_limits(limits: SandboxLimits) -> Self {
        WasmRuntime {
            engine: Engine::default(),
            limits,
        }
    }

    fn instantiate(&self, wasm_bytes: &[u8]) -> Result<(Store<HostState>, Instance), RuntimeError> {
        let module = Module::new(&self.engine, wasm_bytes).map_err(RuntimeError::Module)?;
        let mut store = Store::new(
            &self.engine,
            HostState {
                output: Vec::new(),
                limits: self.limits.to_store_limits(),
            },
        );
        store.limiter(|state: &mut HostState| &mut state.limits);
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(
                "host",
                "print",
                |mut caller: Caller<'_, HostState>, byte: i32| {
                    caller.data_mut().output.push(byte as u8);
                },
            )
            .map_err(|e| RuntimeError::HostImport(e.into()))?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(RuntimeError::Instantiate)?
            .start(&mut store)
            .map_err(RuntimeError::Instantiate)?;
        Ok((store, instance))
    }

    /// Loads `wasm_bytes` and calls its exported `(i32, i32) -> i32`
    /// function `func_name`. Deliberately this narrow (one fixed
    /// signature) — enough to prove the engine actually executes real WASM
    /// bytecode, not just that it parses; a general dynamic-arity call API
    /// is a later step, once something real needs more than this.
    pub fn call_i32x2_to_i32(
        &self,
        wasm_bytes: &[u8],
        func_name: &str,
        a: i32,
        b: i32,
    ) -> Result<i32, RuntimeError> {
        let (mut store, instance) = self.instantiate(wasm_bytes)?;
        let func = instance
            .get_typed_func::<(i32, i32), i32>(&store, func_name)
            .map_err(RuntimeError::Function)?;
        func.call(&mut store, (a, b)).map_err(RuntimeError::Call)
    }

    /// Loads `wasm_bytes`, calls its exported no-arg, no-return function
    /// `func_name`, and returns every byte it wrote via the imported
    /// `host.print(byte: i32)` function, in call order. This is what
    /// actually proves host imports work: not that `func_wrap` didn't
    /// error, but that bytes the *WASM code* pushed round-trip back out
    /// through the host state.
    pub fn call_and_capture_output(
        &self,
        wasm_bytes: &[u8],
        func_name: &str,
    ) -> Result<Vec<u8>, RuntimeError> {
        let (mut store, instance) = self.instantiate(wasm_bytes)?;
        let func = instance
            .get_typed_func::<(), ()>(&store, func_name)
            .map_err(RuntimeError::Function)?;
        func.call(&mut store, ()).map_err(RuntimeError::Call)?;
        Ok(store.into_data().output)
    }

    /// Loads `wasm_bytes` and calls its exported `(i32) -> i32` function
    /// `func_name`. Exists for the memory-isolation tests below (a
    /// store-then-load-and-return round trip needs a one-arg signature
    /// `call_i32x2_to_i32` doesn't fit) — not a general call API, same as
    /// its sibling methods.
    pub fn call_i32_to_i32(
        &self,
        wasm_bytes: &[u8],
        func_name: &str,
        a: i32,
    ) -> Result<i32, RuntimeError> {
        let (mut store, instance) = self.instantiate(wasm_bytes)?;
        let func = instance
            .get_typed_func::<i32, i32>(&store, func_name)
            .map_err(RuntimeError::Function)?;
        func.call(&mut store, a).map_err(RuntimeError::Call)
    }

    /// Loads `wasm_bytes` and calls its exported `() -> i32` function
    /// `func_name`. For the memory-growth-limit test below (`memory.grow`
    /// returns its result, taking no meaningful args of its own).
    pub fn call_to_i32(&self, wasm_bytes: &[u8], func_name: &str) -> Result<i32, RuntimeError> {
        let (mut store, instance) = self.instantiate(wasm_bytes)?;
        let func = instance
            .get_typed_func::<(), i32>(&store, func_name)
            .map_err(RuntimeError::Function)?;
        func.call(&mut store, ()).map_err(RuntimeError::Call)
    }
}
