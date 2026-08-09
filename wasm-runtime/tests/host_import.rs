//! Proves WASM code can call back into the runtime: a module imports
//! `host.print(byte: i32)`, calls it twice with ASCII byte values, and the
//! test checks the runtime actually received those exact bytes, in order —
//! not just that instantiation with an import declared didn't error.

const PRINT_HI_WAT: &str = r#"
    (module
      (import "host" "print" (func $print (param i32)))
      (func $go (export "go")
        i32.const 72   ;; 'H'
        call $print
        i32.const 73   ;; 'I'
        call $print))
"#;

#[test]
fn host_function_receives_bytes_from_wasm() {
    let wasm_bytes = wat::parse_str(PRINT_HI_WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    let output = runtime
        .call_and_capture_output(&wasm_bytes, "go")
        .expect("call succeeded");
    assert_eq!(output, b"HI");
}

#[test]
fn missing_import_is_an_error() {
    // Imports a function the runtime doesn't define under this name —
    // instantiation itself should fail, before "go" is ever called.
    const WAT: &str = r#"
        (module
          (import "host" "does_not_exist" (func $f (param i32)))
          (func $go (export "go")
            i32.const 1
            call $f))
    "#;
    let wasm_bytes = wat::parse_str(WAT).expect("valid WAT");
    let runtime = runix_wasm_runtime::WasmRuntime::new();

    let err = runtime
        .call_and_capture_output(&wasm_bytes, "go")
        .unwrap_err();
    assert!(matches!(
        err,
        runix_wasm_runtime::RuntimeError::Instantiate(_)
    ));
}
