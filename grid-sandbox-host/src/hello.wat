;; Minimal guest module: calls the host-provided `print` import twice,
;; writing "Hi" — proves the whole chain (host allocator -> wasmi engine ->
;; module instantiation -> host-function import -> guest bytecode
;; execution) works inside a real ring 3 process, not just on the dev host
;; (see wasm-runtime/tests/host_import.rs for the host-side version of
;; this same proof).
(module
  (import "host" "print" (func $print (param i32)))
  (func (export "run")
    i32.const 72   ;; 'H'
    call $print
    i32.const 105  ;; 'i'
    call $print))
