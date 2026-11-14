#!/usr/bin/env python3
"""No fork PR reaches a self-hosted runner.

Adapted from pulseengine/ordeal scripts/check_selfhosted_fork_guard.py
(ordeal#322). GitHub routes a job by labels, so `runs-on: light`,
`[linux, light]` or `{group: X}` reach the self-hosted pool without the word
`self-hosted`. The check therefore allowlists runs-on instead of hunting for
a word. Each job's runs-on must be one of:

  - a GitHub-hosted image string: ubuntu-*, macos-*, windows-*;
  - exactly the fail-closed form
      ${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && fromJSON('[...]') || 'ubuntu-latest' }}
    which picks self-hosted only for a non-PR event or a PR whose head
    repository is this one (a fork, or a deleted fork with a null head.repo,
    falls to the hosted runner), in a workflow whose triggers are all in
    TRUSTED. The expression trusts every event that is not `pull_request`,
    so a trigger a fork can cause under another name (pull_request_target,
    workflow_run, issue_comment, workflow_call from such a caller, ...)
    would reach the runner;
  - `${{ matrix.KEY }}` where every literal value of KEY (list and include
    entries) is a hosted image.

Anything else fails: bare or listed labels, runner groups, the fail-open
`head.repo.fork && 'ubuntu-latest' || [...]` form, a runner taken from
needs/inputs/vars, a matrix built from an expression. It also fails when no
job uses the fail-closed form, so a pass always compared something.

Usage: check.py [REPO_ROOT]     check.py --self-test
"""
import pathlib
import re
import sys
import tempfile

import yaml

FORM = re.compile(
    r"^\$\{\{ \(github\.event_name != 'pull_request' \|\| "
    r"github\.event\.pull_request\.head\.repo\.full_name == github\.repository\) && "
    r"fromJSON\('\[[^\]]*\"self-hosted\"[^\]]*\]'\) \|\| 'ubuntu-latest' \}\}$"
)
# Triggers only a maintainer or this repository's own branches can cause, plus
# pull_request, which the expression itself sends to a hosted runner unless the
# head repository is this one. `release` (sigil addition, for wasm-signing.yml):
# only maintainers publish releases. workflow_call is NOT trusted: a called
# workflow inherits its caller's event, which could be a fork-PR context.
TRUSTED = {"push", "pull_request", "schedule", "workflow_dispatch", "merge_group",
           "release"}


HOSTED = re.compile(r"^(ubuntu|macos|windows)-[A-Za-z0-9._-]+$")
MATRIX_REF = re.compile(r"^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$")


def matrix_values(spec, key):
    """Literal values of matrix.KEY, or None if any is not a plain string."""
    m = (spec.get("strategy") or {}).get("matrix")
    if not isinstance(m, dict):
        return None
    vals = []
    if key in m:
        if not isinstance(m[key], list):
            return None
        vals += m[key]
    for inc in m.get("include") or []:
        if isinstance(inc, dict) and key in inc:
            vals.append(inc[key])
    if not vals or not all(isinstance(v, str) for v in vals):
        return None
    return vals


def check(root):
    bad, jobs, guarded = {}, [], 0
    wfdir = pathlib.Path(root) / ".github" / "workflows"
    for wf in sorted([*wfdir.glob("*.yml"), *wfdir.glob("*.yaml")]):
        doc = yaml.safe_load(wf.read_text()) or {}
        on = doc.get(True, doc.get("on")) or {}
        events = set(on) if isinstance(on, (dict, list)) else {on}
        for job, spec in (doc.get("jobs") or {}).items():
            if "uses" in spec and "runs-on" not in spec:
                continue  # reusable-workflow call: the callee's jobs are checked in its own file
            where = f"{wf.name}:{job}"
            jobs.append(where)
            ro = spec.get("runs-on")
            text = ro.strip() if isinstance(ro, str) else None
            if text is not None and HOSTED.match(text):
                continue
            if text is not None and FORM.match(text):
                guarded += 1
                untrusted = sorted(str(e) for e in events - TRUSTED)
                if untrusted:
                    bad[where] = f"self-hosted under trigger(s) outside the allowlist: {', '.join(untrusted)}"
                continue
            mref = MATRIX_REF.match(text) if text is not None else None
            if mref:
                vals = matrix_values(spec, mref.group(1))
                if vals is not None and all(HOSTED.match(v) for v in vals):
                    continue
                bad[where] = f"matrix.{mref.group(1)} has a value that is not a hosted image: {vals}"
                continue
            bad[where] = f"runs-on {ro!r} is neither a hosted image nor the fail-closed form"
    return jobs, bad, guarded


def run(root):
    jobs, bad, guarded = check(root)
    for w in jobs:
        print(f"FAIL  {w}: {bad[w]}" if w in bad else f"ok    {w}")
    if not guarded:
        print("FAIL  no job uses the fail-closed form: this check compared nothing")
        return 1
    if bad:
        print(f"FAIL  {len(bad)} job(s) a fork PR could route to a self-hosted runner")
        return 1
    print(f"{len(jobs)} job(s) ok, {guarded} on self-hosted behind the fail-closed form")
    return 0


GOOD = ("${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name"
        " == github.repository) && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') || 'ubuntu-latest' }}")
FAIL_OPEN = ("${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || "
             "fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') }}")


def self_test():
    cases = [  # name, trigger block, extra job body (runs-on etc.), want exit
        ("fail-closed form on pull_request passes", "pull_request:", f"runs-on: {GOOD}", 0),
        ("hosted image passes", "pull_request:", "runs-on: ubuntu-24.04", 0),
        ("matrix of hosted images passes", "pull_request:",
         "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n"
         "        include:\n          - os: windows-latest", 0),
        ("plain self-hosted list fails", "pull_request:", "runs-on: [self-hosted, linux, x64, light]", 1),
        ("bare label without the word self-hosted fails", "pull_request:", "runs-on: light", 1),
        ("label list without the word self-hosted fails", "pull_request:", "runs-on: [linux, light]", 1),
        ("runner group fails", "pull_request:", "runs-on:\n      group: hetzner-private", 1),
        ("fail-open .fork form fails", "pull_request:", f"runs-on: {FAIL_OPEN}", 1),
        ("matrix with a self-hosted label fails", "pull_request:",
         "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, light]", 1),
        ("matrix include with a label fails", "pull_request:",
         "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n"
         "        include:\n          - os: lean-mem", 1),
        ("matrix from an expression fails", "pull_request:",
         "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}", 1),
        ("runner from needs output fails", "pull_request:", "runs-on: ${{ needs.a.outputs.runner }}", 1),
        ("runner from vars fails", "pull_request:", "runs-on: ${{ vars.RUNNER }}", 1),
        ("good form under pull_request_target fails", "pull_request_target:", f"runs-on: {GOOD}", 1),
        ("good form under workflow_run fails", "workflow_run:\n    workflows: [CI]", f"runs-on: {GOOD}", 1),
        ("good form under workflow_call fails", "workflow_call:", f"runs-on: {GOOD}", 1),
    ]
    cases.append(("only hosted jobs fails (compared nothing)", "pull_request:", "runs-on: ubuntu-latest", 1))
    bad = 0
    for name, trig, ro, want in cases:
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t) / ".github" / "workflows"
            d.mkdir(parents=True)
            # Every case but the last also carries one good guarded job, so a
            # bad case cannot pass the test merely by "compared nothing".
            guard = "" if name.startswith("only hosted") else f"  g:\n    runs-on: {GOOD}\n    steps: []\n"
            (d / "w.yml").write_text(f"on:\n  {trig}\njobs:\n{guard}  j:\n    {ro}\n    steps: []\n")
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                got = run(t)
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'}  {name}")
        bad |= not ok
    print("self-test ok" if not bad else "SELF-TEST FAILED")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[2]))
