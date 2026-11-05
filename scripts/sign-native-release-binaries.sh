#!/usr/bin/env bash
# Self-sign the native release binaries with sigil — or say exactly why not. (#352)
#
# The release step this replaces ran each signing as
#     "$SIGIL" sign --format elf --keyless ... || echo "Warning: failed to sign ..."
# inside a step that was ALSO `continue-on-error: true`, then printed
# "Self-signing complete". On every release, v0.12.0 included, sigil refused:
#     Usage error: Keyless signing is currently supported only for WASM format.
# so no native signature has ever been produced, and the job reported success.
#
# This script makes exactly ONE failure skippable: sigil's own, exact refusal of
# ELF keyless signing. That refusal is re-tested on every run by the act of
# signing — the day sigil supports ELF keyless, signatures are produced instead
# and the skip stops happening. ANY other failure is fatal. A skip is logged as
# a ::notice:: with its reason; it is never reported as a completed signing.
#
# Usage:  sign-native-release-binaries.sh <sigil-binary> <binary>...
# Exit:   0 every binary signed, or refused with the known ELF-keyless message
#         1 any other signing failure, or no binaries · 2 usage
set -uo pipefail

# The refusal sigil prints for `sign --format elf --keyless`. Matched verbatim:
# if sigil rewords it, this stops matching and the release fails loudly, which
# is the right direction — a changed message must be re-read, not assumed.
KNOWN_REFUSAL="Keyless signing is currently supported only for WASM format"

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <sigil-binary> <binary>..." >&2
  exit 2
fi
sigil=$1
shift

signed=0
refused=0
for bin in "$@"; do
  if [ ! -f "$bin" ]; then
    echo "::error::native binary to sign does not exist: $bin" >&2
    exit 1
  fi
  # A stale signature from an earlier run must not satisfy the success check
  # below: a signer that exited 0 without writing would otherwise pass.
  rm -f -- "${bin}.sig" "${bin}.signed"
  echo "Signing $bin..."
  out=$("$sigil" sign --format elf --keyless \
          --input-file "$bin" \
          --output-file "${bin}.signed" \
          --signature-file "${bin}.sig" 2>&1)
  rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -eq 0 ]; then
    if [ ! -s "${bin}.sig" ]; then
      echo "::error::sigil reported success for $bin but wrote no signature" >&2
      exit 1
    fi
    echo "signed: $bin"
    signed=$((signed + 1))
  elif printf '%s' "$out" | grep -qF "$KNOWN_REFUSAL"; then
    refused=$((refused + 1))
  else
    echo "::error::sigil failed to sign $bin (exit $rc), and NOT with the known ELF-keyless refusal — this is a real failure" >&2
    exit 1
  fi
done

total=$((signed + refused))
if [ "$total" -eq 0 ]; then
  echo "::error::no native binaries were signed or checked" >&2
  exit 1
fi
if [ "$refused" -gt 0 ]; then
  echo "::notice::${refused} native binary/binaries NOT self-signed: sigil does not support keyless signing for ELF (\"${KNOWN_REFUSAL}\"). They remain covered by the cosign-signed SHA256SUMS.txt. Signing them needs ELF keyless support in sigil, or a managed signing key (#352)."
fi
echo "native self-signing: ${signed} signed, ${refused} refused by sigil (ELF keyless unsupported)"
