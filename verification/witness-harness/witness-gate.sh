#!/usr/bin/env bash
# witness MC/DC regression gate for wsc-verify-core (#165 Track C / #128).
#
# Rebuilds the harness, instruments it with a pinned `witness` release, runs
# the fixed scenario set, and fails if the number of MC/DC *gap* conditions
# has INCREASED past the committed baseline. Improvements (fewer gaps) pass
# and should be followed by refreshing out/mcdc-report.txt + BASELINE_GAP.
#
# Why gap-count and not a byte-diff of the report: wasm codegen / witness
# row ordering can differ across hosts and witness versions; the gap count
# is the meaningful, stable MC/DC signal (the skill's "read the gap rows,
# not the coverage percentage").
set -euo pipefail

WITNESS_VERSION="${WITNESS_VERSION:-v0.37.0}"
# Committed baseline = the gap count on the CI host (ubuntu-latest / linux-x86_64).
#
# KNOWN LIMITATION (tracked in #128): this counts MC/DC gaps over the WHOLE
# instrumented wasm, which links the Rust std library, the allocator, and the
# crypto deps — so the count is DOMINATED by non-verify-core code. Of the ~40
# instrumented decisions, only one (src/wasm_module/varint.rs) is verify-core's
# own logic; the rest are malloc.c / panicking.rs / alloc.rs / dep internals.
# The count therefore drifts with every toolchain/dep bump, independent of any
# real change in verify-core coverage.
#
# It drifted 12 -> 17 between 2026-07-11 (baseline set) and 2026-08-05 purely
# from std/dep churn (deps bumps, wasmtime/toml/serde_jcs, new codegen) — NOT a
# verify-core regression (verify-core's single decision is unchanged). Baseline
# refreshed to 17 with that evidence rather than silently bumped. The real fix
# is to SCOPE the gate to verify-core-owned decisions (src/ paths) so it stops
# tracking std/dep noise — tracked in #128. Override via BASELINE_GAP locally
# (macOS/aarch64 codegen yields ~16).
BASELINE_GAP="${BASELINE_GAP:-17}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# --- resolve a `witness` binary (use PATH, else download the pinned release) ---
if command -v witness >/dev/null 2>&1; then
  WIT="$(command -v witness)"
else
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)   ASSET="witness-${WITNESS_VERSION}-x86_64-unknown-linux-gnu.tar.gz" ;;
    Darwin-arm64)   ASSET="witness-${WITNESS_VERSION}-aarch64-apple-darwin.tar.gz" ;;
    Darwin-x86_64)  ASSET="witness-${WITNESS_VERSION}-x86_64-apple-darwin.tar.gz" ;;
    *) echo "::error:: unsupported host $(uname -s)-$(uname -m) for witness download"; exit 2 ;;
  esac
  TMP="$(mktemp -d)"
  gh release download "$WITNESS_VERSION" --repo pulseengine/witness \
     --pattern "$ASSET" --dir "$TMP"
  tar -xzf "$TMP/$ASSET" -C "$TMP"
  WIT="$(find "$TMP" -name witness -type f | head -1)"
  chmod +x "$WIT"
fi
echo "Using $("$WIT" --version)"

# --- build the harness for the instrumentable wasm target ---
rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
cargo build --target wasm32-wasip1
WASM="target/wasm32-wasip1/debug/wsc_witness_harness.wasm"

# --- instrument + run the fixed scenario set + report ---
mkdir -p out
"$WIT" instrument "$WASM" -o out/instrumented.wasm
"$WIT" run out/instrumented.wasm \
  --invoke-with-args 'decode_varint_5:1,0,0,0,0' \
  --invoke-with-args 'decode_varint_5:128,1,0,0,0' \
  --invoke-with-args 'decode_varint_5:128,128,1,0,0' \
  --invoke-with-args 'decode_varint_5:128,128,128,1,0' \
  --invoke-with-args 'decode_varint_5:128,128,128,128,1' \
  --invoke-with-args 'decode_varint_5:128,128,128,128,128' \
  --invoke-with-args 'try_parse_wasm:0,97,115,109,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:255,97,115,109,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,255,115,109,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,97,255,109,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,97,115,255,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,97,115,109,255,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,0,0,0,0,0,0,0' \
  -o out/run.json
"$WIT" report --input out/run.json --format mcdc | tee out/mcdc-report.txt

# --- gate: gap count must not exceed the committed baseline ---
GAP="$(grep -oE '[0-9]+ gap' out/mcdc-report.txt | head -1 | grep -oE '[0-9]+')"
echo "MC/DC gap conditions: ${GAP} (baseline ${BASELINE_GAP})"
if [ "${GAP:-9999}" -gt "$BASELINE_GAP" ]; then
  echo "::error:: MC/DC regression — gap conditions rose ${BASELINE_GAP} -> ${GAP}. A verification decision lost coverage; add a scenario or restore the branch."
  exit 1
fi
if [ "${GAP}" -lt "$BASELINE_GAP" ]; then
  echo "::notice:: MC/DC improved (${BASELINE_GAP} -> ${GAP}); refresh out/mcdc-report.txt and BASELINE_GAP to lock it in."
fi
echo "witness MC/DC gate: OK"
