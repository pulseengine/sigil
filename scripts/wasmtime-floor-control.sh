#!/usr/bin/env bash
# The wasmtime floor for wasip2 components built by the pinned toolchain.
#
# rustc 1.100's std makes every wasm32-wasip2 component import
# `wasi:cli/exit@0.2.12` `exit-with-code`. wasmtime 46.0.0 and later provide it;
# 45.0.0 and earlier refuse the component at instantiate (measured fleet-wide in
# ordeal#309). This checks both sides on one component:
#   1. the current wasmtime runs it: exit 0 and "self-test ok";
#   2. the old wasmtime refuses it, and the refusal is the missing
#      `wasi:cli/exit@0.2.12` `exit-with-code` import. Any other failure (a
#      download problem, a crash, a different link error) fails this check
#      instead of counting as the refusal.
# If (2) starts passing, the floor moved and the CHANGELOG statement is wrong.
#
# Usage: scripts/wasmtime-floor-control.sh <component.wasm> <current-wasmtime> <old-wasmtime>
set -euo pipefail

COMPONENT="${1:?usage: $0 <component.wasm> <current-wasmtime> <old-wasmtime>}"
CURRENT="${2:?current wasmtime binary}"
OLD="${3:?old wasmtime binary}"

cur_ver="$("$CURRENT" --version)"
old_ver="$("$OLD" --version)"

set +e
cur_out="$("$CURRENT" run --dir . "$COMPONENT" --self-test 2>&1)"
cur_rc=$?
old_out="$("$OLD" run --dir . "$COMPONENT" --self-test 2>&1)"
old_rc=$?
set -e

if [ "$cur_rc" -ne 0 ] || ! grep -qx 'self-test ok' <<<"$cur_out"; then
  echo "::error::$cur_ver did not run the component (exit $cur_rc)"
  printf '%s\n' "$cur_out" | tail -20
  exit 1
fi
echo "ok  $cur_ver runs the component (self-test ok)"

if [ "$old_rc" -eq 0 ]; then
  echo "::error::$old_ver ran the component: the >=46.0.0 floor no longer holds"
  exit 1
fi
if ! grep -qF 'wasi:cli/exit@0.2.12' <<<"$old_out" || ! grep -qF 'exit-with-code' <<<"$old_out"; then
  echo "::error::$old_ver failed (exit $old_rc), but not on the wasi:cli/exit@0.2.12 exit-with-code import"
  printf '%s\n' "$old_out" | tail -20
  exit 1
fi
echo "ok  $old_ver refuses the component on wasi:cli/exit@0.2.12 exit-with-code (exit $old_rc)"
