//! Proves the engine actually executes WASM bytecode: compiles a trivial
//! `add(a, b) -> a + b` module from WAT source at test time (so this test
//! doesn't need a checked-in `.wasm` binary), loads it, calls it, and
//! checks a real arithmetic result — not just that loading didn't error.

const ADD_WAT: &str = r#"
    (module
      (func $add (export "add") (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.add))
"#;

#[test]
fn add_two_numbers() {
    let wasm_bytes = wat::parse_str(ADD_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    let result = runtime
        .call_i32x2_to_i32(&wasm_bytes, "add", 2, 3)
        .expect("call succeeded");
    assert_eq!(result, 5);

    // A second call with different inputs — rules out a hardcoded/lucky
    // result from the first assertion.
    let result = runtime
        .call_i32x2_to_i32(&wasm_bytes, "add", 100, -58)
        .expect("call succeeded");
    assert_eq!(result, 42);
}

#[test]
fn missing_function_is_an_error() {
    let wasm_bytes = wat::parse_str(ADD_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    let err = runtime
        .call_i32x2_to_i32(&wasm_bytes, "subtract", 2, 3)
        .unwrap_err();
    assert!(matches!(err, runix_wasm_runtime::RuntimeError::Function(_)));
}
