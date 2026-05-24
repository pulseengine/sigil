# witness MC/DC harness for `wsc-verify-core`

Phase-1 proof-of-concept harness for running
[`pulseengine/witness`](https://github.com/pulseengine/witness) — an MC/DC
branch-coverage tool for WebAssembly — against sigil's verification core.

This crate is **excluded from the main workspace** (`workspace.exclude` in
the root `Cargo.toml`) because it builds for a wasm target and would
otherwise clutter native workspace builds.

## What this validates

That the `wsc-verify-core` carve achieved its goal: the verification core
now builds for a witness-instrumentable wasm target with plain cargo, with
no `ring` / TLS / X.509 detour. The next step (#128 Phase 2) is the same
mechanic with crafted signed-module fixtures over `verify_multi` so the
truth tables show MC/DC of the full verification decision logic, not just
the varint decoder.

## Running

```sh
# 1. Install witness (or use a checkout-local copy)
gh release download v0.22.0 --repo pulseengine/witness \
    --pattern '*aarch64-apple-darwin.tar.gz' --output - | tar -xz
export PATH="$PWD:$PATH"
xattr -d com.apple.quarantine witness witness-viz 2>/dev/null || true

# 2. Make sure wasm32-wasip1 is installed for sigil's pinned toolchain
rustup target add wasm32-wasip1

# 3. Build the harness (dev profile — opt-level=z dead-strips the branches
#    witness needs to see)
cd verification/witness-harness
cargo build --target wasm32-wasip1
WASM=target/wasm32-wasip1/debug/wsc_witness_harness.wasm

# 4. Instrument + run + report
mkdir -p out
witness instrument "$WASM" -o out/instrumented.wasm
witness run out/instrumented.wasm \
    --invoke-with-args 'decode_varint_5:1,0,0,0,0' \
    --invoke-with-args 'decode_varint_5:128,1,0,0,0' \
    --invoke-with-args 'decode_varint_5:128,128,1,0,0' \
    --invoke-with-args 'decode_varint_5:128,128,128,1,0' \
    --invoke-with-args 'decode_varint_5:128,128,128,128,1' \
    --invoke-with-args 'decode_varint_5:128,128,128,128,128' \
    -o out/run.json
witness report --input out/run.json --format mcdc
```

## Observed output (Phase 1)

```
decisions: 0/162 full MC/DC; conditions: 1 proved, 13 gap, 582 dead

decision #1 varint.rs:28: NoWitness
  truth table:
    row 1:  {c0=F, c1=T, c2=T} -> T
    row 10: {c0=F, c1=T, c2=T} -> T
    ...
```

`varint.rs:28` is sigil's actual LEB128 decoder — that decision is being
instrumented through the carved `wsc-verify-core`. The high "dead" count
(582) is mostly `std::result`/formatting machinery reachable from the
harness; what matters for Phase 1 is that witness can *see* sigil-core
decisions at all. Phase 2 will design scenarios that drive the
`decode_varint_5` and (later) `verify_multi` decisions to **full MC/DC**
rather than just demonstrating reachability.

## Notes on target choice

- **`wasm32-wasip1`** (used here): produces a core wasm module that
  `witness instrument` can read directly; getrandom uses WASI for
  randomness (no JS host needed).
- `wasm32-wasip2`: builds, but produces a *component* — witness emits
  `wasm-tools component unbundle` instructions for that case. Use wasip1
  for the simpler path.
- `wasm32-unknown-unknown`: also builds, but `wsc-verify-core` enables
  `getrandom`'s `wasm_js` feature (needed for `KeyPair::generate` to work
  on that target in browsers) which pulls wasm-bindgen placeholders that
  witness's standalone wasmtime cannot satisfy — would need a custom
  getrandom backend.

## Profile choice

The Cargo.toml here sets `[profile.dev] debug = 2, panic = "abort"`.
Release-profile builds with `opt-level = "z"` dead-strip the very branches
witness needs to instrument (an 860-byte release wasm vs ~3.5 MB dev wasm
on the same code). Use the dev profile.
