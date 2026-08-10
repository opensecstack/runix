//! Compiles `src/hello.wat` into real WASM bytes at build time, written to
//! `$OUT_DIR/hello.wasm` for `src/main.rs` to `include_bytes!`. Runs on the
//! host regardless of this crate's own `x86_64-unknown-none` target — build
//! scripts always do — so using the (host-only, `std`-using) `wat` crate
//! here doesn't affect the final binary's own `no_std` requirement at all.

use std::env;
use std::path::PathBuf;

fn main() {
    let wat_source = include_str!("src/hello.wat");
    let wasm_bytes = wat::parse_str(wat_source).expect("failed to compile src/hello.wat");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_path = out_dir.join("hello.wasm");
    std::fs::write(&out_path, &wasm_bytes).expect("failed to write compiled wasm module");

    println!("cargo:rerun-if-changed=src/hello.wat");
}
