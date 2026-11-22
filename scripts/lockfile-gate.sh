#!/usr/bin/env bash
# Every Cargo lockfile in the repository is committed, current, and audited.
#
#   scripts/lockfile-gate.sh locked
#     1. every cargo root (a Cargo.toml that is not a member of another
#        workspace) has a committed Cargo.lock beside it;
#     2. `cargo metadata --locked` passes on each, i.e. the lock matches its
#        manifests and cargo would not rewrite it;
#     3. planted control, per lock: one [[package]] entry removed must make
#        step 2 fail with cargo's --locked refusal. A root whose stale lock
#        passes would turn the whole check vacuous for that root.
#
#   scripts/lockfile-gate.sh audit [cargo-audit args, e.g. --ignore ID ...]
#     4. `cargo audit --file <lock>` on every committed Cargo.lock, with the
#        same arguments, so a nested lock gets the gate the root lock gets;
#     5. planted control: verification/lockfile-controls/vulnerable.lock
#        (smallvec 1.6.0) must fail the audit and name RUSTSEC-2021-0003.
#
# The set of locks comes from `git ls-files`, so a new nested project is
# covered the moment its lock is committed, and step 1 fails until it is.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# Cargo.toml files that are not cargo roots of their own: src/crypto inherits
# workspace fields but is built only by Bazel (not a workspace member), so
# cargo cannot resolve it on its own and it has no lock.
NOT_A_CARGO_ROOT=("src/crypto/Cargo.toml")

locks() { git ls-files -- '*Cargo.lock' ':!:verification/lockfile-controls/*'; }

mode="${1:?usage: $0 locked | audit [cargo-audit args]}"
shift

case "$mode" in
locked)
  fail=0
  # 1. every root has a lock
  while IFS= read -r manifest; do
    for skip in "${NOT_A_CARGO_ROOT[@]}"; do [ "$manifest" = "$skip" ] && continue 2; done
    root="$(cargo locate-project --workspace --message-format plain --manifest-path "$manifest")"
    root="${root#"$REPO"/}"
    lock="$(dirname "$root")/Cargo.lock"
    if ! git ls-files --error-unmatch -- "$lock" >/dev/null 2>&1; then
      echo "::error::$manifest resolves through $root, but $lock is not committed"
      fail=1
    fi
  done < <(git ls-files -- '*Cargo.toml')
  [ "$fail" -eq 0 ] || exit 1
  echo "ok  every cargo root has a committed Cargo.lock"

  while IFS= read -r lock; do
    dir="$(dirname "$lock")"
    # 2. current
    if ! out="$(cargo metadata --locked --format-version 1 --manifest-path "$dir/Cargo.toml" 2>&1 >/dev/null)"; then
      echo "::error::$lock is stale or broken: cargo metadata --locked failed"
      printf '%s\n' "$out" | tail -5
      fail=1
      continue
    fi
    # 3. planted control: drop the last [[package]] entry, expect the refusal
    cp "$lock" "$lock.orig"
    trap 'mv -f "$lock.orig" "$lock"' EXIT
    last="$(grep -n '^\[\[package\]\]' "$lock.orig" | tail -1 | cut -d: -f1)"
    head -n $((last - 1)) "$lock.orig" > "$lock"
    if out="$(cargo metadata --locked --format-version 1 --manifest-path "$dir/Cargo.toml" 2>&1 >/dev/null)"; then
      echo "::error::$lock with a package removed still passes --locked: the check is vacuous for $dir"
      fail=1
    elif ! grep -q -- '--locked' <<<"$out"; then
      echo "::error::$lock with a package removed failed, but not on the --locked refusal"
      printf '%s\n' "$out" | tail -5
      fail=1
    fi
    mv -f "$lock.orig" "$lock"
    trap - EXIT
    echo "ok  $lock is current; with a package removed --locked refuses it"
  done < <(locks)
  exit "$fail"
  ;;
audit)
  fail=0
  while IFS= read -r lock; do
    echo "== cargo audit --file $lock"
    cargo audit --file "$lock" "$@" || fail=1
  done < <(locks)
  control="verification/lockfile-controls/vulnerable.lock"
  if out="$(cargo audit --file "$control" "$@" 2>&1)"; then
    echo "::error::cargo audit passed $control (smallvec 1.6.0): the audit above cannot fail"
    exit 1
  fi
  if ! grep -q 'RUSTSEC-2021-0003' <<<"$out"; then
    echo "::error::cargo audit failed on $control, but not on RUSTSEC-2021-0003"
    printf '%s\n' "$out" | tail -10
    exit 1
  fi
  echo "ok  the planted smallvec 1.6.0 lock fails the audit on RUSTSEC-2021-0003"
  exit "$fail"
  ;;
*)
  echo "usage: $0 locked | audit [cargo-audit args]" >&2
  exit 2
  ;;
esac
