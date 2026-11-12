#!/usr/bin/env bash
# The `wsc verify` exit contract (#366): a gate may trust the exit code.
#
#   valid signature            -> exit 0, prints "Signature is valid"
#   tampered payload           -> exit non-zero, never prints it
#   tampered signature bytes   -> exit non-zero, never prints it
#   wrong public key           -> exit non-zero, never prints it
#   unsigned module            -> exit non-zero, never prints it
#
# Usage: scripts/cli-exit-contract.sh <path-to-wsc>
# Exits 0 only if every case holds; prints one line per case.
#
# Negative control: scripts/cli-exit-contract.sh --self-test runs the same
# cases against a stub wsc that always exits 0 and prints "Signature is
# valid", and must FAIL — proof the check can go red.
set -uo pipefail

if [ "${1:-}" = "--self-test" ]; then
  stub_dir=$(mktemp -d)
  trap 'rm -rf "$stub_dir"' EXIT
  real_wsc=${2:?usage: --self-test <path-to-real-wsc>}
  case "$real_wsc" in /*) ;; *) real_wsc="$PWD/$real_wsc" ;; esac
  # The stub defers keygen/sign to the real binary so the fixtures are real,
  # and lies only about verify: the fail-open behaviour #366 describes.
  cat > "$stub_dir/wsc" <<EOF
#!/usr/bin/env bash
if [ "\$1" = verify ]; then echo "No valid signatures" >&2; exit 0; fi
exec "$real_wsc" "\$@"
EOF
  chmod +x "$stub_dir/wsc"
  if "$0" "$stub_dir/wsc" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: the contract check passed a wsc whose verify always exits 0"
    exit 1
  fi
  echo "self-test ok: the contract check rejects a fail-open verify"
  exit 0
fi

WSC=${1:?usage: $0 <path-to-wsc> | --self-test <path-to-wsc>}
# Resolve before cd: a relative path would stop resolving inside $work.
case "$WSC" in /*) ;; *) WSC="$PWD/$WSC" ;; esac
[ -x "$WSC" ] || { echo "FAIL  wsc not executable: $WSC"; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# A module with a type, a function and a code body, so a payload tamper
# lands in real content rather than the header.
printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x0a\x04\x01\x02\x00\x0b' > module.wasm

# Fixture setup must succeed; a failed setup is a FAIL, never a vacuous pass.
"$WSC" keygen -k sk.key -K pk.key >/dev/null || { echo "FAIL  keygen"; exit 1; }
"$WSC" keygen -k sk2.key -K pk2.key >/dev/null || { echo "FAIL  keygen"; exit 1; }
"$WSC" sign -i module.wasm -o signed.wasm -k sk.key >/dev/null || { echo "FAIL  sign"; exit 1; }

# Flip one byte at a given offset (python3 is on every runner image).
flip() { python3 -c 'import sys
p,o=sys.argv[1],int(sys.argv[2]); b=bytearray(open(p,"rb").read()); b[o]^=0xFF; open(p,"wb").write(b)' "$1" "$2"; }

size=$(wc -c < signed.wasm)
cp signed.wasm payload-tampered.wasm; flip payload-tampered.wasm $((size - 2))
# The signature custom section precedes the payload; its last bytes are
# the signature itself. Locate it from the section name, not a fixed offset.
sig_off=$(python3 -c 'import sys
b=open(sys.argv[1],"rb").read(); i=b.find(b"signature"); print(i+40 if i>=0 else -1)' signed.wasm)
cp signed.wasm sig-tampered.wasm
[ "$sig_off" -ge 0 ] && flip sig-tampered.wasm "$sig_off"

fail=0
check() { # name expect(0|nonzero) file key
  local name=$1 expect=$2 file=$3 key=$4 out rc
  out=$("$WSC" verify --input-file "$file" --public-key "$key" 2>&1); rc=$?
  local ok=1
  if [ "$expect" = 0 ]; then
    [ $rc -eq 0 ] && grep -q "Signature is valid" <<<"$out" || ok=0
  else
    # 126/127 mean the binary did not run; that is not a rejection.
    [ $rc -ne 0 ] && [ $rc -ne 126 ] && [ $rc -ne 127 ] && ! grep -q "Signature is valid" <<<"$out" || ok=0
  fi
  if [ $ok = 1 ]; then echo "ok    $name -> exit $rc"; else echo "FAIL  $name -> exit $rc: $out"; fail=1; fi
}

if [ "$sig_off" -lt 0 ]; then echo "FAIL  no signature section found in the signed module"; fail=1; fi
check "valid signature"          0       signed.wasm          pk.key
check "tampered payload"         nonzero payload-tampered.wasm pk.key
check "tampered signature bytes" nonzero sig-tampered.wasm    pk.key
check "wrong public key"         nonzero signed.wasm          pk2.key
check "unsigned module"          nonzero module.wasm          pk.key
exit $fail
