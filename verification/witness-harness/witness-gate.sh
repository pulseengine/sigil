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
BASELINE_GAP="${BASELINE_GAP:-16}"   # committed baseline; bump when gaps are closed
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
