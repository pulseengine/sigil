#!/usr/bin/env bash
# witness MC/DC regression gate for wsc-verify-core (#165 Track C / #128).
#
# Rebuilds the harness, instruments it with a pinned `witness` release, runs
# the fixed scenario set, and fails if the number of MC/DC *gap* conditions
# has INCREASED past the committed baseline. Improvements (fewer gaps) pass
# and should be followed by lowering SRC_BASELINE_GAP (see HOST CALIBRATION).
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
# HOST CALIBRATION: baseline set on the CI host (ubuntu-latest / linux x86_64) —
# the authoritative gate host. The scoped count was 5 (varint decision 3 +
# header decision 2). #128 / REQ-25 added two kinds of scenario that close the
# feasible gaps:
#
#   (a) try_parse_wasm:0,97,115,109,13,0,1,0 — the WASM_COMPONENT_HEADER accept
#       path of Module::init_from_reader (mod.rs:456). This is a genuine second
#       accept branch of verify-core's own header decision; it supplied the
#       missing unique-cause row for `header != WASM_COMPONENT_HEADER` and drove
#       that decision to full MC/DC (was 2 gaps). Semantic, host-invariant — the
#       -2 that lowers the committed baseline from 5 to 3.
#
#   (b) decode_varint_0..4 — short-buffer exports that make get32's
#       `reader.read_exact(&mut byte)?` hit EOF at each loop iteration, covering
#       get32's EOF error-propagation path. Locally this proves one of the
#       read_exact conditions; whether that nets a -1 on linux is NOT banked
#       (see below), so the committed baseline stays at 3. CI shows what it nets.
#
# WHY 3 AND NOT 0 — the residual is (inferred) misattributed inlined std, and
# infeasible: the remaining ~3 gap conditions live in the decision witness labels
# `src/wasm_module/varint.rs:24` (macOS) / `:29` (linux). Row-count arithmetic
# indicates that decision is NOT verify-core logic — it is
# `<&[u8] as Read>::read_exact` INLINED into get32 (its truth table is 20
# length-1 rows matching the varint scenarios' iteration counts + N length-8 rows
# matching the header scenarios; inferred from the table, not from witness's own
# attribution). The `^src/` filter counts it only because inlined std inherits
# get32's debug line.
# Its residual conditions are the read_exact copy-path branches, which vary only
# with buffer length. verify-core issues read_exact at exactly two lengths — 1
# (get32, per byte) and 8 (init_from_reader, the header) — and every `c1=T`
# (length-1) row has those copy branches invariant, so no honest input flips
# them. They are INFEASIBLE without editing verify-core's own reads (which would
# be gaming the metric) — the DO-178C "masked/unreachable condition, document
# don't cover" case. NOTE: witness's `cN` condition indices are NOT stable across
# runs/hosts (a decision re-derives when the row set changes); do not diff the
# letters — e.g. macOS {c2,c3,c4} and linux {c0,c3,c4} are the same three
# read_exact conditions relabeled, not a regression.
#
# So: linux 5 - 2 (header, banked) = 3, committed. Local macOS/aarch64 also
# yields 3 (header covered by macOS codegen; three read_exact residuals), so it
# PASSES without any override. If the short-buffer EOF scenarios ALSO net a read_exact
# closure on linux without surfacing a replacement, the gate emits its own "lower
# it" notice and CI tightens to 2 — that is the only sanctioned way to lower it
# further. A host yielding MORE than the baseline is a real finding (a new
# uncovered verify-core branch / a lost scenario), never an override target: only
# ever lower from the CI (linux) count.
#
# GATE POTENCY (verified locally, macOS, this change): (1) SRC_BASELINE_GAP=2 ->
# the gate ::errors and exits 1 (comparison + exit path bites). (2) deleting the
# length-8 header reads (the try_parse_wasm scenarios) strips a read_exact
# condition's unique-cause pair, SRC_GAP rises 3 -> 4 > baseline, exit 1 (a real
# verify-core coverage regression is caught, not just a threshold trip).
SRC_BASELINE_GAP="${SRC_BASELINE_GAP:-3}"
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
  --invoke-with-args 'decode_varint_0:' \
  --invoke-with-args 'decode_varint_1:128' \
  --invoke-with-args 'decode_varint_2:128,128' \
  --invoke-with-args 'decode_varint_3:128,128,128' \
  --invoke-with-args 'decode_varint_4:128,128,128,128' \
  --invoke-with-args 'try_parse_wasm:0,97,115,109,1,0,0,0' \
  --invoke-with-args 'try_parse_wasm:0,97,115,109,13,0,1,0' \
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
