#!/usr/bin/env python3
"""No fork PR reaches a self-hosted runner.

Adapted from pulseengine/ordeal scripts/check_selfhosted_fork_guard.py
(ordeal#322). Every job in .github/workflows/ whose runs-on names
`self-hosted` must use exactly the fail-closed form

  ${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && fromJSON('[...]') || 'ubuntu-latest' }}

so self-hosted labels are chosen only for a non-PR event or a PR whose head
repository is this one. A fork, or a deleted fork whose head.repo is null,
falls to the hosted runner. Rejected:
  - a plain self-hosted label (list or string);
  - the fail-open form `head.repo.fork && 'ubuntu-latest' || [...]`, which
    picks self-hosted whenever .fork is not true, including a null head.repo;
  - a self-hosted job in a workflow with a trigger outside TRUSTED. The
    expression trusts every event that is not `pull_request`, so a trigger a
    fork can cause under another name (pull_request_target, workflow_run,
    issue_comment, pull_request_review*, ...) would reach the runner;
  - no self-hosted job at all, so the check never passes having compared
    nothing.

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
# head repository is this one. `release` (sigil addition): only maintainers
# publish releases.
TRUSTED = {"push", "pull_request", "schedule", "workflow_dispatch", "merge_group",
           "workflow_call", "release"}


def check(root):
    bad, seen = {}, []
    wfdir = pathlib.Path(root) / ".github" / "workflows"
    for wf in sorted([*wfdir.glob("*.yml"), *wfdir.glob("*.yaml")]):
        doc = yaml.safe_load(wf.read_text()) or {}
        on = doc.get(True, doc.get("on")) or {}
        events = set(on) if isinstance(on, (dict, list)) else {on}
        for job, spec in (doc.get("jobs") or {}).items():
            ro = spec.get("runs-on")
            text = " ".join(map(str, ro)) if isinstance(ro, list) else str(ro or "")
            if "self-hosted" not in text:
                continue
            where = f"{wf.name}:{job}"
            seen.append(where)
            untrusted = sorted(str(e) for e in events - TRUSTED)
            if untrusted:
                bad[where] = f"workflow trigger(s) outside the allowlist: {', '.join(untrusted)}"
            elif isinstance(ro, list) or not FORM.match(text.strip()):
                bad[where] = "runs-on is not the fail-closed same-repo form"
    return seen, bad


def run(root):
    seen, bad = check(root)
    for w in seen:
        print(f"FAIL  {w}: {bad[w]}" if w in bad else f"ok    {w}")
    if not seen:
        print("FAIL  no self-hosted job found: this check compared nothing")
        return 1
    if bad:
        print(f"FAIL  {len(bad)} self-hosted job(s) a fork PR could reach")
        return 1
    print(f"{len(seen)} self-hosted job(s), each in the fail-closed form")
    return 0


GOOD = ("${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name"
        " == github.repository) && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') || 'ubuntu-latest' }}")
FAIL_OPEN = ("${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || "
             "fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') }}")


def self_test():
    cases = [  # name, trigger block, runs-on, want exit
        ("fail-closed form on pull_request passes", "pull_request:", GOOD, 0),
        ("plain self-hosted list fails", "pull_request:", "[self-hosted, linux, x64, light]", 1),
        ("fail-open .fork form fails", "pull_request:", FAIL_OPEN, 1),
        ("good form under pull_request_target fails", "pull_request_target:", GOOD, 1),
        ("good form under workflow_run fails", "workflow_run:\n    workflows: [CI]", GOOD, 1),
        ("no self-hosted job fails (compared nothing)", "pull_request:", "ubuntu-latest", 1),
    ]
    bad = 0
    for name, trig, ro, want in cases:
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t) / ".github" / "workflows"
            d.mkdir(parents=True)
            (d / "w.yml").write_text(f"on:\n  {trig}\njobs:\n  j:\n    runs-on: {ro}\n    steps: []\n")
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
