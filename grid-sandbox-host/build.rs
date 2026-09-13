//! Compiles `src/hello.wat` into real WASM bytes at build time, written to
//! `$OUT_DIR/hello.wasm` for `src/main.rs` to `include_bytes!`. Runs on the
//! host regardless of this crate's own `x86_64-unknown-none` target — build
//! scripts always do — so using the (host-only, `std`-using) `wat` crate
//! here doesn't affect the final binary's own `no_std` requirement at all.

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    let wat_source = include_str!("src/hello.wat");
    let wasm_bytes = wat::parse_str(wat_source).expect("failed to compile src/hello.wat");
    std::fs::write(out_dir.join("hello.wasm"), &wasm_bytes)
        .expect("failed to write compiled wasm module");
    println!("cargo:rerun-if-changed=src/hello.wat");

    // Boot-level tier-correctness probe -- see grow_probe.wat's own doc
    // comment for what it proves and why it needs no maximum of its own.
    let grow_probe_source = include_str!("src/grow_probe.wat");
    let grow_probe_bytes =
        wat::parse_str(grow_probe_source).expect("failed to compile src/grow_probe.wat");
    std::fs::write(out_dir.join("grow_probe.wasm"), &grow_probe_bytes)
        .expect("failed to write compiled wasm module");
    println!("cargo:rerun-if-changed=src/grow_probe.wat");
}
