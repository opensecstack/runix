;; Boot-level tier-correctness probe: declares no maximum of its own (same
;; shape as wasm-runtime/tests/tier_isolation.rs's UNBOUNDED_GROW_WAT), so
;; the only thing standing between this module and unbounded growth is
;; whatever host-imposed SandboxLimits ceiling this process's WasmRuntime
;; was constructed with. `try_grow`'s result (page count on success, -1 on
;; failure, per the memory.grow spec -- it doesn't trap) is what
;; kernel/tests/grid_sandbox_tier_t1.rs/_t3.rs and grid_sandbox_wasm.rs
;; read back to confirm the CITADEL-assigned tier actually changed this
;; live ring-3 process's behavior, not just a host-side unit test's.
(module
  (memory 1)
  (func $try_grow (export "try_grow") (param $delta i32) (result i32)
    local.get $delta
    memory.grow))
