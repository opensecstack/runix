//! Proves the engine actually enforces WASM's memory sandbox — bounds
//! checking and declared growth limits — rather than us just trusting that
//! `wasmi` does it. This is the property the whole "Grid Sandbox" idea
//! depends on: a module's linear memory must be the *only* memory it can
//! ever touch, and only within the bounds it declared.

/// 1 page (64 KiB) of linear memory, no growth allowed.
const OOB_WAT: &str = r#"
    (module
      (memory 1 1)
      (func $oob_write (export "oob_write")
        i32.const 100000  ;; past the 65536-byte (1 page) memory entirely
        i32.const 42
        i32.store))
"#;

#[test]
fn out_of_bounds_write_traps_instead_of_corrupting_anything() {
    let wasm_bytes = wat::parse_str(OOB_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    // The real assertion here is that this line returns at all — an actual
    // out-of-bounds write into process memory would be UB, not a clean
    // `Err`. wasmi's interpreter loop bounds-checks every load/store
    // against the declared memory size before touching anything.
    let err = runtime
        .call_and_capture_output(&wasm_bytes, "oob_write")
        .unwrap_err();
    assert!(matches!(err, runix_wasm_runtime::RuntimeError::Call(_)));
}

const STORE_LOAD_WAT: &str = r#"
    (module
      (memory 1)
      (func $store_and_load (export "store_and_load") (param $val i32) (result i32)
        i32.const 0
        local.get $val
        i32.store
        i32.const 0
        i32.load))
"#;

#[test]
fn in_bounds_store_and_load_round_trips_correctly() {
    // Complements the OOB test: proves valid, in-bounds memory access
    // still works correctly — bounds checking that happened to reject
    // *everything* would also make the OOB test pass for the wrong reason.
    let wasm_bytes = wat::parse_str(STORE_LOAD_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    let result = runtime
        .call_i32_to_i32(&wasm_bytes, "store_and_load", 12345)
        .expect("in-bounds access should succeed");
    assert_eq!(result, 12345);
}

/// Declares max = min = 1 page, so any growth attempt must fail.
const GROW_LIMIT_WAT: &str = r#"
    (module
      (memory 1 1)
      (func $try_grow (export "try_grow") (result i32)
        i32.const 1
        memory.grow))
"#;

#[test]
fn memory_cannot_grow_past_its_declared_maximum() {
    let wasm_bytes = wat::parse_str(GROW_LIMIT_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    // `memory.grow` signals failure by returning -1, per the WASM spec —
    // it doesn't trap. A sandbox that let modules grow past their own
    // declared ceiling would let one module gradually claim unbounded
    // memory, defeating the whole point of declaring a maximum.
    let result = runtime
        .call_to_i32(&wasm_bytes, "try_grow")
        .expect("memory.grow itself doesn't trap, it returns -1 on failure");
    assert_eq!(result, -1);
}
