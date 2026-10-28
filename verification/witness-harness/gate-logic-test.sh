#!/usr/bin/env bash
# Decision table for witness-gate.sh's verdict logic, over synthetic reports.
#
# The gate itself needs a wasm build, the pinned witness binary and ~2 minutes;
# this runs in milliseconds and covers the part that decides red vs green. It
# exists because the gate silently went VACUOUS: on macOS + rustc 1.96.1 the
# `^src/` scope collapsed to zero decisions, so SRC_GAP was 0, and the
# "below baseline" branch reported OK while measuring nothing.
#
# Case 4 is the important one: it proves that recalibrating the baseline 3 -> 4
# for the 1.96 codegen did not make the gate toothless — a further regression
# still trips it.
#
# Usage: bash verification/witness-harness/gate-logic-test.sh
# Exit:  0 = every case behaves · 1 = the verdict logic drifted
set -uo pipefail

decide () {  # mirrors witness-gate.sh; keep in sync
  local report="$1" baseline="$2"
  local gaps decisions
  gaps="$(awk '/^decision #/ { insrc = ($3 ~ /^src\//) } /: GAP/ { if (insrc) n++ } END { print n+0 }' "$report")"
  decisions="$(awk '/^decision #/ { if ($3 ~ /^src\//) n++ } END { print n+0 }' "$report")"
  if [ "${decisions:-0}" -eq 0 ]; then echo "empty-scope"; return; fi
  if [ "${gaps:-9999}" -gt "$baseline" ]; then echo "regression"; return; fi
  echo "pass"
}

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# Only inlined-std decisions in scope — what macOS/1.96.1 actually produced.
cat > "$T/empty" <<'R'
decision #0 result.rs:2189: NoWitness
    c0 (branch 6): GAP — try a row
decision #1 int_macros.rs:615: NoWitness
    c0 (branch 40): GAP — try a row
R
# linux/1.96.1: varint.rs:28 (2) + wasm_module/mod.rs:455 (2) = 4.
cat > "$T/linux196" <<'R'
decision #0 src/wasm_module/varint.rs:28: NoWitness
    c0 (branch 9): GAP — try a row
    c1 (branch 10): GAP — try a row
decision #1 result.rs:2189: NoWitness
    c0 (branch 6): GAP — try a row
decision #4 src/wasm_module/mod.rs:455: NoWitness
    c0 (branch 9): GAP — try a row
    c1 (branch 10): GAP — try a row
R
# linux/1.94.0: varint.rs:28 only = 2.
cat > "$T/linux194" <<'R'
decision #1 src/wasm_module/varint.rs:28: NoWitness
    c0 (branch 5): GAP — try a row
    c1 (branch 6): GAP — try a row
decision #3 src/wasm_module/varint.rs:29: FullMcdc
decision #4 boxed.rs:1879: NoWitness
    c0 (branch 14): GAP — try a row
R
# A genuine further regression: a third verify-core decision loses coverage.
cat > "$T/regress" <<'R'
decision #0 src/wasm_module/varint.rs:28: NoWitness
    c0 (branch 1): GAP — try a row
    c1 (branch 2): GAP — try a row
decision #1 src/wasm_module/mod.rs:455: NoWitness
    c0 (branch 3): GAP — try a row
    c1 (branch 4): GAP — try a row
decision #2 src/signature/simple.rs:10: NoWitness
    c0 (branch 5): GAP — try a row
R

bad=0
check () {  # name, report, baseline, expected
  got="$(decide "$2" "$3")"
  if [ "$got" = "$4" ]; then printf 'ok    %-46s -> %s\n' "$1" "$got"
  else printf 'FAIL  %-46s -> %s (expected %s)\n' "$1" "$got" "$4"; bad=$((bad+1)); fi
}

check "empty scope (macOS/1.96.1, real)"            "$T/empty"    4  empty-scope
check "linux/1.96.1 (real) vs baseline 4"           "$T/linux196" 4  pass
check "linux/1.94.0 (real) vs baseline 4"           "$T/linux194" 4  pass
check "a further regression still trips it (5>4)"   "$T/regress"  4  regression
check "linux/1.96.1 vs the OLD baseline 3"          "$T/linux196" 3  regression
check "inlined-std gaps alone never count"          "$T/empty"   99  empty-scope

echo
if [ "$bad" -eq 0 ]; then echo "6/6 verdict cases hold."; else echo "$bad case(s) drifted."; fi
exit $(( bad > 0 ))
