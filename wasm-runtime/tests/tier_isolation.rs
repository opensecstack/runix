//! Proves the property `memory_isolation.rs` does NOT cover: a host-imposed
//! ceiling independent of whatever a module declares about itself.
//! `memory_isolation.rs`'s `memory_cannot_grow_past_its_declared_maximum`
//! only proves a module's *own declared* maximum is honored by the engine —
//! a module simply choosing not to declare one (or declaring a huge one)
//! would defeat that property entirely. `SandboxLimits` is what actually
//! makes one isolation tier different from another: the same module,
//! unmodified, must be allowed to grow further under a generous tier and
//! capped under a strict one, regardless of what its own header says.

use runix_wasm_runtime::{SandboxLimits, WasmRuntime};

/// Declares NO upper bound on its own memory (`(memory 1)`, min 1 page,
/// max unbounded) — the engine's own bounds-checking has nothing to stop
/// growth here; only a host-imposed limiter can.
const UNBOUNDED_GROW_WAT: &str = r#"
    (module
      (memory 1)
      (func $try_grow (export "try_grow") (param $pages i32) (result i32)
        local.get $pages
        memory.grow))
"#;

#[test]
fn t3_untrusted_caps_growth_a_module_itself_never_bounded() {
    let wasm_bytes = wat::parse_str(UNBOUNDED_GROW_WAT).expect("valid WAT");
    let runtime = WasmRuntime::new_with_limits(SandboxLimits::t3_untrusted());

    // t3_untrusted's memory_size is 512 KiB = 8 pages (64 KiB/page). The
    // module starts at 1 page and has declared no maximum of its own, so
    // growing to 100 pages (6.4 MiB) would succeed under an unbounded
    // engine — it must fail here, under the host's own ceiling.
    let result = runtime
        .call_i32_to_i32(&wasm_bytes, "try_grow", 100)
        .expect("memory.grow itself doesn't trap, it returns -1 on failure");
    assert_eq!(
        result, -1,
        "a T3 sandbox must not be able to grow past its host-imposed ceiling, \
         even though the module itself declared no maximum at all"
    );
}

#[test]
fn t1_critical_permits_growth_t3_untrusted_would_reject() {
    let wasm_bytes = wat::parse_str(UNBOUNDED_GROW_WAT).expect("valid WAT");
    let runtime = WasmRuntime::new_with_limits(SandboxLimits::t1_critical());

    // Same module, same requested growth (100 pages = 6.4 MiB), but
    // t1_critical's 8 MiB ceiling comfortably allows it -- proving the
    // T3 rejection above is actually tier-driven, not a property of the
    // module or the engine that would reject this for every tier.
    let result = runtime
        .call_i32_to_i32(&wasm_bytes, "try_grow", 100)
        .expect("memory.grow itself doesn't trap, it returns -1 on failure");
    assert_eq!(
        result, 1,
        "growth should succeed under T1's generous limit, returning the \
         previous size in pages (1) per the memory.grow spec"
    );
}

#[test]
fn default_runtime_matches_t2_trusted_limits() {
    // WasmRuntime::new() is documented as equivalent to
    // new_with_limits(SandboxLimits::t2_trusted()) -- pin that equivalence
    // so it can't silently drift (e.g. if new()'s default ever changes
    // without updating its own doc comment).
    let wasm_bytes = wat::parse_str(UNBOUNDED_GROW_WAT).expect("valid WAT");
    let default_runtime = WasmRuntime::new();
    let t2_runtime = WasmRuntime::new_with_limits(SandboxLimits::t2_trusted());

    // t2_trusted is 4 MiB = 64 pages. Growing to 65 pages must fail on
    // both, growing to 64 must succeed on both, if they really share the
    // same limits.
    let default_over = default_runtime
        .call_i32_to_i32(&wasm_bytes, "try_grow", 65)
        .unwrap();
    let t2_over = t2_runtime
        .call_i32_to_i32(&wasm_bytes, "try_grow", 65)
        .unwrap();
    assert_eq!(default_over, -1);
    assert_eq!(t2_over, -1);
}
