# witness MC/DC harness for `wsc-verify-core`

Harness for running [`pulseengine/witness`](https://github.com/pulseengine/witness)
— an MC/DC branch-coverage tool for WebAssembly — against sigil's
verification core.

| Phase | Target | Status |
|---|---|---|
| 1 | `varint::get32` (LEB128 decoder) | done |
| 2 | `Module::init_from_reader` (WASM header parser) | done |
| 3 | `PublicKey::verify_multi` (full verification with signed-module fixtures) | tracked on #128 |

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

## CI gate

[`witness-gate.sh`](witness-gate.sh) runs the whole flow below and **fails
if the MC/DC gap count rises past the committed baseline** (`SRC_BASELINE_GAP`,
currently **3** on the CI host, witness `v0.37.0`). The gate counts gaps
**only in `src/`-path decisions** — verify-core's own code — not the whole
instrumented wasm (std + allocator + crypto deps drifted the old whole-wasm
count with every toolchain bump; that total is now printed for information
only). #128 / REQ-25 closed the feasible gaps: a `WASM_COMPONENT_HEADER`
scenario drove `Module::init_from_reader`'s header decision to full MC/DC,
and short-buffer `decode_varint_N` scenarios exercise `get32`'s `read_exact`
EOF path. The residual 3 gaps are in an inlined `<&[u8] as Read>::read_exact`
decision that witness misattributes to the `get32` source line (the `^src/`
filter counts it via debug-line inheritance); its copy-path conditions are
unreachable given verify-core's fixed 1-byte / 8-byte reads — infeasible,
documented in `witness-gate.sh`, not silenced. The gate is wired as the
gating `witness-mcdc` job in `.github/workflows/formal-verification.yml`
(#165 Track C / #128) — a real gate (no `continue-on-error`), and a
*regression* gate: closing a gap lowers the count, then refresh
`SRC_BASELINE_GAP` (CI is the authoritative host).

```sh
# One-shot: build + instrument + run + report + gate (auto-downloads witness)
bash verification/witness-harness/witness-gate.sh
```

## Running manually

```sh
# 1. Install witness (or use a checkout-local copy)
gh release download v0.37.0 --repo pulseengine/witness \
    --pattern '*aarch64-apple-darwin.tar.gz' --dir . && tar -xzf witness-*.tar.gz
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
    # Phase 1: varint decoder scenarios — continuation-bit at each position
    --invoke-with-args 'decode_varint_5:1,0,0,0,0' \
    --invoke-with-args 'decode_varint_5:128,1,0,0,0' \
    --invoke-with-args 'decode_varint_5:128,128,1,0,0' \
    --invoke-with-args 'decode_varint_5:128,128,128,1,0' \
    --invoke-with-args 'decode_varint_5:128,128,128,128,1' \
    --invoke-with-args 'decode_varint_5:128,128,128,128,128' \
    # Phase 2: WASM-header parser scenarios — valid + flip each magic/version byte
    --invoke-with-args 'try_parse_wasm:0,97,115,109,1,0,0,0' \
    --invoke-with-args 'try_parse_wasm:255,97,115,109,1,0,0,0' \
    --invoke-with-args 'try_parse_wasm:0,255,115,109,1,0,0,0' \
    --invoke-with-args 'try_parse_wasm:0,97,255,109,1,0,0,0' \
    --invoke-with-args 'try_parse_wasm:0,97,115,255,1,0,0,0' \
    --invoke-with-args 'try_parse_wasm:0,97,115,109,255,0,0,0' \
    --invoke-with-args 'try_parse_wasm:0,0,0,0,0,0,0,0' \
    -o out/run.json
witness report --input out/run.json --format mcdc
```

## Observed output (Phases 1 + 2)

```
decisions: 0/164 full MC/DC; conditions: 2 proved, 19 gap, 583 dead

decision #0 mod.rs:456: NoWitness     ← Module::init_from_reader  (Phase 2)
decision #2 varint.rs:26: Partial     ← LEB128 decoder           (Phase 1)
decision #3 mod.rs:387: Unreached     ← wasm_module parser path
```

`varint.rs:26` and `mod.rs:456` are sigil's own code — instrumented through
the carved `wsc-verify-core`. The high "dead" count (583) is mostly
`std::result` / formatting / panic-runtime machinery reachable from the
harness; what matters for Phases 1 + 2 is that witness can *see* multiple
sigil-core decisions at all.

Phase 3 (#128) will design scenarios that drive `verify_multi` to full MC/DC
with crafted signed-module fixtures — that is the test-corpus design work
the [curl-comparison writeup](../../audit/witness-wasm-inspection.md) called
out as the actual cost of MC/DC adoption (the tool is the cheap part).

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
