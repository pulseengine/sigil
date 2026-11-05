#!/usr/bin/env bash
# Verify keyless cosign signatures on digest-pinned OCI images, and FAIL if any
# does not verify. (#350)
#
# The release workflow used to run
#     cosign verify ... || echo "Note: Signature verification may require specific conditions"
# so a release whose image signature did not verify still passed the step: the
# check could never go red. This script has no such escape. Every reference must
# verify against an ANCHORED identity regexp, or the script exits non-zero.
#
# Usage:
#   verify-oci-signatures.sh <identity-regexp> <oidc-issuer> <image@sha256:...>...
#
# The identity regexp is passed to `cosign verify --certificate-identity-regexp`
# verbatim. Callers should anchor it (^...$) and escape it: an unanchored
# `https://github.com/org/repo` matches any identity that merely CONTAINS that
# string — `org/repo-evil/...` included — and its unescaped `.` matches any
# character. That was the release workflow's second problem.
#
# Exit: 0 every reference verified · 1 a reference failed, or none were given,
#       or one is not digest-pinned · 2 usage
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <identity-regexp> <oidc-issuer> <image@sha256:...>..." >&2
  exit 2
fi

identity_regexp=$1
issuer=$2
shift 2

# An identity regexp with no anchors is refused outright rather than trusted.
case "$identity_regexp" in
  ^*\$) ;;
  *) echo "::error::identity regexp must be anchored as ^...\$, got: $identity_regexp" >&2
     exit 1 ;;
esac

verified=0
for ref in "$@"; do
  # A tag can be repointed after signing; only a digest names what was signed.
  case "$ref" in
    *@sha256:*) ;;
    *) echo "::error::refusing to verify a reference that is not digest-pinned: $ref" >&2
       exit 1 ;;
  esac
  if ! cosign verify \
        --certificate-identity-regexp "$identity_regexp" \
        --certificate-oidc-issuer "$issuer" \
        "$ref" >/dev/null; then
    echo "::error::signature did NOT verify: $ref (identity ${identity_regexp}, issuer ${issuer})" >&2
    exit 1
  fi
  echo "verified: $ref"
  verified=$((verified + 1))
done

# Zero references is a failure, not a vacuous pass.
if [ "$verified" -eq 0 ]; then
  echo "::error::no image references were verified" >&2
  exit 1
fi
echo "all ${verified} signature(s) verified"
