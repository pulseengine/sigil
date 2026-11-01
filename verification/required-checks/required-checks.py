#!/usr/bin/env python3
"""required-checks — the one status context main's branch protection requires.

Why this exists
---------------
Audited 2026-10-21: main's `required_status_checks.contexts` was EMPTY and the
repository had no rulesets, so every check in this repo was advisory. Six PRs
merged over a board nothing enforced.

Requiring the individual contexts instead is the obvious fix and it is a trap:
`rust.yml`, `formal-verification.yml` and `supply-chain.yml` all carry
`on: pull_request: paths:` filters, so on a PR that touches none of their paths
those workflows never run, never report, and a required context that never
reports blocks the PR forever. Worse, a job skipped *inside* a workflow reports
`skipped`, and on GitHub **a skipped required context satisfies the merge
button** — so a paths filter is a gate-disabler.

So this job is the only required context, it always runs (no paths filter), and
it judges the conclusions the other workflows actually reported.

The rules
---------
1. **Every completed check-run must have an acceptable conclusion.** Exactly
   one predicate decides this: `success`, `skipped` and `neutral` are accepted
   and everything else — including a conclusion GitHub adds tomorrow — is not.
2. **`ALWAYS_PRESENT` contexts must exist.** A workflow that silently stops
   running — deleted, renamed, broken trigger — is otherwise indistinguishable
   from a quiet PR. `claim-check.yml` has no paths filter, so its context must
   be there on every PR; its absence is this gate's canary.
3. **Everything must be finished.** Poll until no non-self check-run is still
   in progress. Hitting the deadline FAILS; a gate that gives up and passes is
   worse than no gate.
4. **Every error fails closed.** An API error, unparseable JSON, a missing
   token — all exit non-zero. This is the classifier error path the audit calls
   out as the usual place a gate fails open.

What it deliberately does NOT do
--------------------------------
It does not re-derive which workflows *should* have run from the path globs.
That would duplicate three workflows' filter lists here, and a copy that drifts
is how this class of bug starts. The cost is honest and stated: a job skipped by
an in-workflow filter is accepted on its own word. Rule 2 is the floor that
keeps that from meaning "nothing ran".

Usage
-----
  required-checks.py --sha <head-sha> [--repo owner/name] [--deadline-secs N]
  required-checks.py --self-test        # decision table, no network

Exit: 0 = mergeable · 1 = a check failed, is missing, or never finished · 2 = usage
"""
import argparse
import json
import os
import subprocess
import sys
import time

# The ONE decision this gate makes: a conclusion is acceptable, or it is not.
#
# An allowlist, deliberately, and deliberately NOT paired with a blocklist. The
# first draft here carried both — `c in BLOCKING` then `c not in OK` — and two
# of six mutations survived the decision table because of it: emptying BLOCKING
# changed nothing (the allowlist still rejected), and sneaking "failure" INTO
# OK changed nothing (the blocklist still rejected). Two mechanisms, neither
# isolable, which is how a guard rots unnoticed behind its redundant twin. One
# predicate means one oracle.
#
# `skipped` is accepted because an in-workflow paths filter legitimately
# produces it; ALWAYS_PRESENT below is the floor that stops "everything was
# skipped" from reading as green.
OK = {"success", "skipped", "neutral"}

# Wording only — never a decision input. Lets the message say "failed" instead
# of "unrecognised" for the states GitHub documents today.
KNOWN_BLOCKING = {"failure", "cancelled", "timed_out", "action_required", "stale"}

# Contexts whose ABSENCE is itself a failure. Keep this to workflows with no
# paths filter — anything filtered cannot be required to appear.
ALWAYS_PRESENT = ("Documentation claims hold",)

SELF = "Required checks"


def classify(runs, self_name=SELF, always_present=ALWAYS_PRESENT):
    """Pure decision function: (runs) -> (verdict, reasons).

    verdict is "pass", "fail" or "wait". Kept free of I/O so --self-test can
    drive it over a table instead of over the network.
    """
    reasons = []
    others = [r for r in runs if r.get("name") != self_name]

    pending = [r["name"] for r in others if r.get("status") != "completed"]
    if pending:
        return "wait", [f"{len(pending)} still running: {', '.join(sorted(pending)[:6])}"]

    for r in others:
        c = r.get("conclusion")
        if c not in OK:
            # A conclusion this gate does not recognise is not a pass. A new
            # GitHub state must be classified deliberately, never inherited
            # as green.
            label = "failed" if c in KNOWN_BLOCKING else "unrecognised conclusion"
            reasons.append(f"{r['name']}: {label} ({c!r})")

    present = {r.get("name") for r in others}
    for name in always_present:
        if name not in present:
            reasons.append(
                f"required context never reported: {name!r} — its workflow has no "
                f"paths filter, so absence means it stopped running"
            )

    return ("fail", reasons) if reasons else ("pass", [])


def fetch(repo, sha):
    """All check-runs for a commit, paginated. Any failure raises."""
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/commits/{sha}/check-runs",
         "--jq", ".check_runs[] | {name, status, conclusion}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh api failed ({out.returncode}): {out.stderr.strip()[:400]}")
    runs = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line:
            runs.append(json.loads(line))
    return runs


SELF_TEST_CASES = [
    # (name, runs, expected verdict)
    ("all green + canary present",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "cargo on ubuntu-latest", "status": "completed", "conclusion": "success"}],
     "pass"),
    ("one failure blocks",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Cargo Audit", "status": "completed", "conclusion": "failure"}],
     "fail"),
    ("cancelled is not green",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Cargo Deny", "status": "completed", "conclusion": "cancelled"}],
     "fail"),
    ("timed_out is not green",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Kani merkle", "status": "completed", "conclusion": "timed_out"}],
     "fail"),
    ("skipped is accepted (in-workflow paths filter)",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Full Benchmark Suite", "status": "completed", "conclusion": "skipped"}],
     "pass"),
    ("canary missing fails even when everything else is green",
     [{"name": "cargo on ubuntu-latest", "status": "completed", "conclusion": "success"}],
     "fail"),
    ("empty board fails — the canary is absent",
     [], "fail"),
    ("only ourselves on the board still fails the canary",
     [{"name": SELF, "status": "in_progress", "conclusion": None}], "fail"),
    ("we never wait on ourselves",
     [{"name": SELF, "status": "in_progress", "conclusion": None},
      {"name": "Documentation claims hold", "status": "completed", "conclusion": "success"}],
     "pass"),
    ("in-progress means wait, not pass",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Kani varint", "status": "in_progress", "conclusion": None}],
     "wait"),
    ("queued means wait",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "bazel on macos-latest", "status": "queued", "conclusion": None}],
     "wait"),
    ("a failure still waits while others run — ordering must not matter",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Cargo Audit", "status": "completed", "conclusion": "failure"},
      {"name": "Kani varint", "status": "queued", "conclusion": None}],
     "wait"),
    ("an unknown conclusion is NOT inherited as green",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
      {"name": "Something New", "status": "completed", "conclusion": "brand_new_state"}],
     "fail"),
    ("a null conclusion on a completed run is not green either",
     [{"name": "Documentation claims hold", "status": "completed", "conclusion": None},
      {"name": "cargo on ubuntu-latest", "status": "completed", "conclusion": "success"}],
     "fail"),
]


def self_test():
    bad = 0
    for name, runs, expected in SELF_TEST_CASES:
        got, reasons = classify(runs)
        ok = got == expected
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {name}: expected {expected}, got {got}"
              + (f"  [{'; '.join(reasons)}]" if not ok and reasons else ""))
    print(f"\n{len(SELF_TEST_CASES) - bad}/{len(SELF_TEST_CASES)} decision cases hold.")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sha")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    ap.add_argument("--deadline-secs", type=int, default=3600)
    ap.add_argument("--poll-secs", type=int, default=30)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if not a.sha or not a.repo:
        print("required-checks: --sha and --repo (or GITHUB_REPOSITORY) are required",
              file=sys.stderr)
        return 2

    deadline = time.time() + a.deadline_secs
    while True:
        try:
            runs = fetch(a.repo, a.sha)
        except Exception as e:
            # Fail closed. The audit's finding is that a classifier's error path
            # is usually its permissive branch.
            print(f"::error::required-checks could not read the check board: {e}")
            return 1

        verdict, reasons = classify(runs)
        if verdict == "pass":
            print(f"All {len(runs) - 1} other check-runs are acceptable, and every "
                  f"always-present context reported. Mergeable.")
            return 0
        if verdict == "fail":
            for r in reasons:
                print(f"::error::{r}")
            print(f"\n{len(reasons)} blocking condition(s).")
            return 1

        if time.time() >= deadline:
            print(f"::error::required-checks hit its {a.deadline_secs}s deadline with "
                  f"checks still running — {reasons[0] if reasons else 'unknown'}. "
                  f"Failing closed: a gate that gives up and passes is worse than none.")
            return 1
        print(f"waiting: {reasons[0]}")
        time.sleep(a.poll_secs)


if __name__ == "__main__":
    sys.exit(main())
