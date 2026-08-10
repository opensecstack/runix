//! WebAssembly runtime for app isolation (Grid Sandbox / App Runtime).
//! Alpha scope: engine bring-up, basic module loading/execution, and a
//! host-function import. No sandbox tiers or MARSHAL channel permits yet —
//! those land with `citadel-integration` in Beta, once `host_print` below
//! becomes a real syscall bridge instead of an in-memory buffer.
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
use wasmi::{Caller, Engine, Instance, Linker, Module, Store};

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
#[derive(Default)]
struct HostState {
    output: Vec<u8>,
}

pub struct WasmRuntime {
    engine: Engine,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    pub fn new() -> Self {
        WasmRuntime {
            engine: Engine::default(),
        }
    }

    fn instantiate(&self, wasm_bytes: &[u8]) -> Result<(Store<HostState>, Instance), RuntimeError> {
        let module = Module::new(&self.engine, wasm_bytes).map_err(RuntimeError::Module)?;
        let mut store = Store::new(&self.engine, HostState::default());
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
