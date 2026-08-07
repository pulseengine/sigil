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
# Committed baseline = MC/DC gap conditions in verify-core's OWN decisions —
# those whose instrumented source path is under src/ (varint.rs, wasm_module).
#
# SCOPED GATE (#128 fix, 2026-08-07). This gate previously counted gaps over the
# WHOLE instrumented wasm, which links the Rust std library, the wasi-libc
# allocator, and the crypto deps. Of the 142 instrumented decisions only TWO are
# verify-core's own (src/wasm_module/varint.rs:29 and src/wasm_module/mod.rs:455);
# the other ~140 are malloc.c / panicking.rs / alloc.rs / ub_checks.rs / libc.
# The whole-wasm total therefore drifted with every toolchain/dep bump and even
# with the crate VERSION STRING perturbing libc codegen — it rose 12 -> 17 (std
# churn) and then 17 -> 19 purely on the 0.9.4 -> 0.10.0 bump, tracking noise, not
# coverage. So the gate now counts gaps ONLY within src/-path decisions: that
# number is a function of verify-core's own logic and its fixed scenario set —
# far more stable than the whole-wasm total, though NOT perfectly host-invariant
# (the compiler still lays out our own branches differently per target). The
# whole-wasm total is still printed, for information only.
#
# HOST CALIBRATION: the baseline is set on the CI host (ubuntu-latest / linux
# x86_64) — the authoritative gate host — where the scoped count is 5:
# varint.rs:29 (3 gaps: c0,c3,c4) + wasm_module/mod.rs:455 (2 gaps: c0,c1). A
# local macOS/aarch64 run yields FEWER (measured: 3 — mod.rs:455 is fully covered
# there), which PASSES under the same baseline (3 <= 5), so no local override is
# ever needed to go green. The SRC_BASELINE_GAP env knob is for re-calibrating on
# CI when a scenario closes a gap, NOT for silencing a red locally: a host that
# yields MORE than the baseline is a real finding (a new uncovered branch), not
# an override target. Only lower the committed baseline from the CI (linux) count.
#
# Both baseline decisions are `Partial`; CLOSING them (adding witness scenarios
# that supply the missing unique-cause rows) is follow-up MC/DC work on #128 —
# the gate's job here is to stop a REGRESSION (a NEW gap in verify-core's own
# code) from landing.
SRC_BASELINE_GAP="${SRC_BASELINE_GAP:-5}"
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

# --- gate: gap conditions in verify-core's OWN decisions (src/ paths) must not
#     exceed the baseline. Whole-wasm total is printed for information only.
#
# Attribution: the witness report prints `decision #N <path>:<line>: <status>`,
# then that decision's truth table, then its per-condition verdicts (`GAP` rows).
# Each GAP row belongs to the most recent `decision #` header above it — verified
# against a captured report (the `Partial` decisions carry proved conditions, the
# `NoWitness` ones do not, so the grouping is not off-by-one). Count GAP rows only
# while the current decision's path starts with `src/`. ---
TOTAL_GAP="$(grep -oE '[0-9]+ gap' out/mcdc-report.txt | head -1 | grep -oE '[0-9]+')"
SRC_GAP="$(awk '
  /^decision #/ { insrc = ($3 ~ /^src\//) }
  /: GAP/       { if (insrc) n++ }
  END           { print n+0 }
' out/mcdc-report.txt)"
echo "MC/DC gaps — verify-core (src/): ${SRC_GAP} (baseline ${SRC_BASELINE_GAP}); whole-wasm total: ${TOTAL_GAP} (informational, not gated — see #128)"
if [ "${SRC_GAP:-9999}" -gt "$SRC_BASELINE_GAP" ]; then
  echo "::error:: MC/DC regression in verify-core — scoped gap conditions rose ${SRC_BASELINE_GAP} -> ${SRC_GAP}. A verify-core decision lost coverage; add a witness scenario or restore the branch."
  exit 1
fi
if [ "${SRC_GAP}" -lt "$SRC_BASELINE_GAP" ]; then
  echo "::notice:: verify-core scoped gaps ${SRC_GAP} < baseline ${SRC_BASELINE_GAP}. On the CI host (linux) this means a scenario closed a gap — lower SRC_BASELINE_GAP to lock it in. On a non-CI host (e.g. macOS yields 3) this is just per-target codegen and the committed baseline should NOT be lowered from it."
fi
echo "witness MC/DC gate: OK (verify-core scoped)"
