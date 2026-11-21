#!/usr/bin/env bash
# wsc signs and verifies a wasm32-wasip2 component built by the pinned toolchain.
#
# release.yml fails the release if `wsc sign` cannot parse wsc-cli.wasm, a
# wasip2 component (#164). Each rustc / wit-component release can change the
# component layout (core module count, shim and fixup modules), and the release
# is the first place such a change would otherwise show up. This builds a
# minimal wasip2 component with the toolchain from rust-toolchain.toml, then
# asserts, with key-based signing (no network):
#   1. `wsc sign` exits 0 and `wsc verify` on its output exits 0;
#   2. one byte changed inside the signed module makes `wsc verify` exit non-zero
#      (the negative control: a verify that cannot fail proves nothing).
#
# Usage: scripts/wasip2-sign-roundtrip.sh <path-to-wsc-binary>
set -euo pipefail

WSC="${1:?usage: $0 <path-to-wsc-binary>}"
WSC="$(cd "$(dirname "$WSC")" && pwd)/$(basename "$WSC")"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO/rust-toolchain.toml")"
[ -n "$TOOLCHAIN" ] || { echo "::error::no channel in rust-toolchain.toml"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

rustup target add --toolchain "$TOOLCHAIN" wasm32-wasip2 >/dev/null
cargo "+$TOOLCHAIN" new -q --vcs none fixture
cargo "+$TOOLCHAIN" build -q --release --target wasm32-wasip2 --manifest-path fixture/Cargo.toml
COMPONENT="fixture/target/wasm32-wasip2/release/fixture.wasm"
# A component starts with the magic and layer byte 0x01 at offset 6
# (\0asm 0d 00 01 00); a core module has 01 00 00 00 there.
layer="$(od -An -tx1 -j6 -N1 "$COMPONENT" | tr -d ' ')"
[ "$layer" = "01" ] || { echo "::error::$COMPONENT is not a component (layer byte $layer)"; exit 1; }
echo "fixture: $(wc -c < "$COMPONENT") bytes, wasm32-wasip2 component, rustc $TOOLCHAIN"

"$WSC" keygen -k sk.key -K pk.key >/dev/null
"$WSC" sign -k sk.key -i "$COMPONENT" -o signed.wasm >/dev/null \
  || { echo "::error::wsc sign failed on a rustc $TOOLCHAIN wasip2 component (#164)"; exit 1; }
"$WSC" verify -K pk.key -i signed.wasm >/dev/null \
  || { echo "::error::wsc verify failed on its own signature over a rustc $TOOLCHAIN wasip2 component"; exit 1; }
echo "ok  sign + verify on the rustc $TOOLCHAIN component"

# Negative control: flip one byte in the middle of the signed file (inside the
# main core module's code, well past the signature section at the front).
cp signed.wasm tampered.wasm
size="$(wc -c < tampered.wasm)"
off=$((size / 2))
orig="$(od -An -tu1 -j"$off" -N1 tampered.wasm | tr -d ' ')"
printf '%b' "$(printf '\\%03o' $(( (orig ^ 1) & 255 )))" \
  | dd of=tampered.wasm bs=1 seek="$off" conv=notrunc 2>/dev/null
if "$WSC" verify -K pk.key -i tampered.wasm >/dev/null 2>&1; then
  echo "::error::wsc verify accepted a component with byte $off changed: the round-trip check above cannot fail"
  exit 1
fi
echo "ok  verify rejects the component with byte $off changed"
