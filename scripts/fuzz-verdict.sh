#!/usr/bin/env bash
# Verdict for the nightly fuzz run. Fails closed on everything that is not
# "every target ran and left no finding":
#
#   - the fuzz matrix did not succeed (a leg failed, was cancelled, or skipped)
#   - ANY file in a fuzz-artifacts-* download: libFuzzer writes crash-*, oom-*,
#     timeout-*, leak-* and slow-unit-* there, and all of them are findings
#   - an expected target with no corpus download: the fuzzer never ran
#     (failed build, missing matrix entry), which used to read as "no crashes"
#
# Expected targets come from fuzz/Cargo.toml [[bin]] names, so a target that
# falls out of the workflow matrix fails here instead of going silent.
#
# Usage: scripts/fuzz-verdict.sh <artifacts-dir> <needs.fuzz.result> <Cargo.toml>
#        scripts/fuzz-verdict.sh --self-test
set -uo pipefail

verdict() {
  local dir=$1 result=$2 manifest=$3 fail=0 t n
  local targets
  targets=$(awk '/^\[\[bin\]\]/{b=1;next} b&&/^name *=/{gsub(/.*= *"|".*/,"");print;b=0}' "$manifest")
  if [ -z "$targets" ]; then echo "FAIL  no [[bin]] targets in $manifest"; return 1; fi

  if [ "$result" != success ]; then
    echo "FAIL  fuzz matrix result: $result"; fail=1
  fi

  while IFS= read -r f; do
    echo "FAIL  finding: ${f#"$dir"/}"; fail=1
  done < <(find "$dir" -path "$dir/fuzz-artifacts-*" -type f 2>/dev/null | sort)

  for t in $targets; do
    n=$(find "$dir/fuzz-corpus-$t" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "${n:-0}" -eq 0 ]; then
      echo "FAIL  $t produced no corpus: the fuzzer did not run"; fail=1
    else
      echo "ok    $t: $n corpus inputs, no artifacts"
    fi
  done
  return $fail
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  printf '[[bin]]\nname = "fa"\npath = "a.rs"\n\n[[bin]]\nname = "fb"\npath = "b.rs"\n' > "$tmp/Cargo.toml"
  mk() { # case-dir: two targets with corpus, nothing else
    mkdir -p "$1/fuzz-corpus-fa" "$1/fuzz-corpus-fb"
    echo x > "$1/fuzz-corpus-fa/c1"; echo y > "$1/fuzz-corpus-fb/c1"
  }
  bad=0
  expect() { # name want(0|1) dir result
    verdict "$3" "$4" "$tmp/Cargo.toml" >/dev/null 2>&1; local rc=$?
    local got=$(( rc != 0 ))
    if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1 (want $2, got $got)"; bad=1; fi
  }
  mk "$tmp/clean";                                             expect "clean run passes" 0 "$tmp/clean" success
  for k in crash oom timeout leak slow-unit; do
    mk "$tmp/$k"; mkdir -p "$tmp/$k/fuzz-artifacts-fa"; echo z > "$tmp/$k/fuzz-artifacts-fa/$k-deadbeef"
    expect "$k-* artifact fails" 1 "$tmp/$k" success
  done
  mkdir -p "$tmp/none";                                        expect "no downloads at all fails" 1 "$tmp/none" success
  mk "$tmp/miss"; rm -rf "$tmp/miss/fuzz-corpus-fb";           expect "a target with no corpus fails" 1 "$tmp/miss" success
  mk "$tmp/emp"; rm -f "$tmp/emp/fuzz-corpus-fb/c1";           expect "an empty corpus fails" 1 "$tmp/emp" success
  mk "$tmp/can";                                               expect "a cancelled matrix fails" 1 "$tmp/can" cancelled
  mk "$tmp/fl";                                                expect "a failed matrix fails" 1 "$tmp/fl" failure
  [ $bad = 0 ] && echo "self-test ok" || echo "SELF-TEST FAILED"
  exit $bad
fi

verdict "${1:?artifacts dir}" "${2:?fuzz result}" "${3:?fuzz/Cargo.toml}"
