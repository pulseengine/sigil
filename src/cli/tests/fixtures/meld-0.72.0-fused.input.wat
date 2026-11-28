;; Input of meld-0.72.0-fused.wasm. Regenerate with:
;;   wasm-tools parse meld-0.72.0-fused.input.wat -o in.wasm
;;   meld fuse in.wasm -o meld-0.72.0-fused.wasm --reproducible --memory multi
;; meld 0.72.0 (tag v0.72.0, commit 36acef1, cosign-verified release asset).
;; Output sha256 86f221be29081b54230cf6fa0466e286fd7fcbea50d0ca968b3840830ad6aeea.
(component
  (core module $m
    (memory (export "memory") 1)
    (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))
  (core instance $i (instantiate $m))
  (func (export "add") (param "a" u32) (param "b" u32) (result u32) (canon lift (core func $i "add"))))
