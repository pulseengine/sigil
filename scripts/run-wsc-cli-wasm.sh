#!/usr/bin/env bash
# Run the shipped wsc CLI component (wsc-cli.wasm) and check that it works.
#
# release.yml signs and ships wsc-cli.wasm, but nothing ran it: a component
# that fails to instantiate, or signs wrongly, would ship. This runs the
# component under a WebAssembly runtime and asserts, with key-based signing
# (no network):
#   1. `keygen`, `sign` and `verify` run inside the component and exit 0;
#   2. the native wsc accepts the component's signature, and the component
#      accepts the native wsc's signature (same format both ways);
#   3. one byte changed inside the signed module makes the component's
#      `verify` exit non-zero with wsc's own "No valid signatures" message, so
#      the control cannot pass on a runtime failure.
#
# Usage: scripts/run-wsc-cli-wasm.sh wasmtime <wsc-cli.wasm> <native-wsc>
#        scripts/run-wsc-cli-wasm.sh kiln     <wsc-cli.wasm> <native-wsc>
#
# wasmtime runs the component as built; it needs `-S http` because the CLI
# imports wasi:http (GitHub key fetch). kiln runs only meld-fused modules
# (kiln RFC #46), so the kiln mode fuses first with `meld` from PATH.
set -euo pipefail

RUNTIME="${1:?usage: $0 wasmtime|kiln <wsc-cli.wasm> <native-wsc>}"
CLI_WASM="${2:?usage: $0 wasmtime|kiln <wsc-cli.wasm> <native-wsc>}"
NATIVE="${3:?usage: $0 wasmtime|kiln <wsc-cli.wasm> <native-wsc>}"
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
CLI_WASM="$(abs "$CLI_WASM")"
NATIVE="$(abs "$NATIVE")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

case "$RUNTIME" in
  wasmtime)
    command -v wasmtime >/dev/null || { echo "::error::wasmtime not on PATH"; exit 2; }
    echo "runtime: $(wasmtime --version)"
    # Guest paths: $WORK is mounted at /w.
    G=/w
    wsc_wasm() { wasmtime run -S http --dir "$WORK::/w" "$CLI_WASM" "$@"; }
    ;;
  kiln)
    command -v kiln >/dev/null || { echo "::error::kiln not on PATH"; exit 2; }
    command -v meld >/dev/null || { echo "::error::meld not on PATH"; exit 2; }
    echo "runtime: $(kiln --version), $(meld --version)"
    meld fuse "$CLI_WASM" -o fused.wasm --memory multi --emit-import-map map.json >/dev/null
    G="$WORK"
    wsc_wasm() {
      local a=()
      for x in "$@"; do a+=(--wasi-arg "$x"); done
      kiln --wasi --wasi-fs "$WORK" --import-map "$WORK/map.json" "${a[@]}" "$WORK/fused.wasm"
    }
    ;;
  *) echo "::error::unknown runtime '$RUNTIME' (wasmtime|kiln)"; exit 2 ;;
esac

# The thing signed: a copy of the CLI component itself (a wasip2 component).
cp "$CLI_WASM" input.wasm
echo "wsc-cli.wasm: $(wc -c < "$CLI_WASM") bytes"

wsc_wasm keygen -k "$G/sk.key" -K "$G/pk.key" >/dev/null 2>&1 \
  || { echo "::error::wsc-cli.wasm keygen failed under $RUNTIME"; wsc_wasm keygen -k "$G/sk.key" -K "$G/pk.key" 2>&1 | tail -5; exit 1; }
[ -s sk.key ] && [ -s pk.key ] || { echo "::error::keygen under $RUNTIME exited 0 but wrote no key files"; exit 1; }
chmod 600 sk.key
echo "ok  keygen in the component"

wsc_wasm sign -k "$G/sk.key" -i "$G/input.wasm" -o "$G/signed.wasm" >/dev/null \
  || { echo "::error::wsc-cli.wasm sign failed under $RUNTIME"; exit 1; }
wsc_wasm verify -K "$G/pk.key" -i "$G/signed.wasm" >/dev/null \
  || { echo "::error::wsc-cli.wasm verify rejected its own signature under $RUNTIME"; exit 1; }
echo "ok  sign + verify in the component"

"$NATIVE" verify -K pk.key -i signed.wasm >/dev/null \
  || { echo "::error::native wsc rejected a signature made by wsc-cli.wasm"; exit 1; }
"$NATIVE" sign -k sk.key -i input.wasm -o native-signed.wasm >/dev/null
wsc_wasm verify -K "$G/pk.key" -i "$G/native-signed.wasm" >/dev/null \
  || { echo "::error::wsc-cli.wasm rejected a signature made by native wsc"; exit 1; }
echo "ok  native and component accept each other's signatures"

# Negative control: flip one byte in the middle of the signed file, well past
# the signature section at the front.
cp signed.wasm tampered.wasm
size="$(wc -c < tampered.wasm)"
off=$((size / 2))
orig="$(od -An -tu1 -j"$off" -N1 tampered.wasm | tr -d ' ')"
printf '%b' "$(printf '\\%03o' $(( (orig ^ 1) & 255 )))" \
  | dd of=tampered.wasm bs=1 seek="$off" conv=notrunc 2>/dev/null
if out="$(wsc_wasm verify -K "$G/pk.key" -i "$G/tampered.wasm" 2>&1)"; then
  echo "::error::wsc-cli.wasm accepted a module with byte $off changed: the checks above cannot fail"
  exit 1
fi
grep -q "No valid signatures" <<<"$out" || {
  echo "::error::verify of the tampered module failed, but not with wsc's rejection; the runtime may have failed instead"
  printf '%s\n' "$out" | tail -5
  exit 1
}
echo "ok  the component rejects the module with byte $off changed"
