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
   in progress AND no non-self workflow run for this commit is still in
   progress. Check-runs alone are not enough: a job behind `needs:` has no
   check-run until its prerequisites finish, so a board where every EXISTING
   check-run is complete can still be missing jobs. A workflow run stays
   in progress until its last job ends. Two clocks, and hitting either FAILS;
   a gate that gives up and passes is worse than no gate:
   - the stall clock (--deadline-secs, per check-run) starts when a check-run
     is first seen `in_progress`. Time spent `queued` waiting for a runner
     never counts: a PR must not fail because the runner pool is full
     (owner decision 2026-11-18; the hosted queue had failed PRs at 3600 s
     with 17 jobs still queued and none of them running long);
   - the overall cap (--max-wait-secs, default 5 h) bounds the whole wait, so
     a job that is never scheduled (or a workflow run that never ends) still
     fails closed, with a message, before the job's own timeout cancels it.
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
  required-checks.py --sha <head-sha> [--repo owner/name] [--deadline-secs N] [--max-wait-secs N]
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

# Contexts whose absence fails a merge_group run only. These live in workflows
# with a pull_request paths filter, so a PR may legitimately lack them, but
# every such workflow also triggers on merge_group without a filter: on the
# merge-group commit they must report, or the queue would merge past a gate
# that never ran.
MERGE_GROUP_PRESENT = ("Lean Ed25519 proofs",)

SELF = "Required checks"


def classify(runs, self_name=SELF, always_present=ALWAYS_PRESENT,
             workflow_runs=(), self_run_id=None, event=None,
             merge_group_present=MERGE_GROUP_PRESENT):
    """Pure decision function: (check-runs, workflow runs) -> (verdict, reasons).

    verdict is "pass", "fail" or "wait". Kept free of I/O so --self-test can
    drive it over a table instead of over the network.
    """
    reasons = []
    others = [r for r in runs if r.get("name") != self_name]

    pending = [r["name"] for r in others if r.get("status") != "completed"]
    if pending:
        return "wait", [f"{len(pending)} still running: {', '.join(sorted(pending)[:6])}"]

    # Jobs gated by `needs:` have no check-run yet while their workflow run is
    # still going; without this, the first poll after the existing check-runs
    # finish could pass before those jobs exist.
    wf_pending = [w.get("name", "?") for w in workflow_runs
                  if w.get("id") != self_run_id and w.get("status") != "completed"]
    if wf_pending:
        return "wait", [f"{len(wf_pending)} workflow run(s) not finished: "
                        f"{', '.join(sorted(wf_pending)[:6])}"]

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
    if event == "merge_group":
        for name in merge_group_present:
            if name not in present:
                reasons.append(
                    f"required context never reported on the merge group: {name!r} "
                    f"— its workflow runs on every merge_group, so absence means it "
                    f"stopped running"
                )

    return ("fail", reasons) if reasons else ("pass", [])


def stalled(clock, runs, now, deadline_secs, self_name=SELF):
    """Per-job stall clock. Pure apart from updating `clock`.

    `clock` maps a check-run name to when it was first seen `in_progress`; a
    `queued` (or `waiting`, `pending`, `requested`) check-run starts no clock.
    Returns the names in progress for longer than `deadline_secs`.
    """
    out = []
    for r in runs:
        name = r.get("name")
        if name == self_name or r.get("status") != "in_progress":
            continue
        started = clock.setdefault(name, now)
        if now - started >= deadline_secs:
            out.append(name)
    return sorted(out)


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


def fetch_workflow_runs(repo, sha, event):
    """Workflow runs for a commit (one event type), paginated. Any failure raises."""
    q = f"repos/{repo}/actions/runs?head_sha={sha}&per_page=100"
    if event:
        q += f"&event={event}"
    out = subprocess.run(
        ["gh", "api", "--paginate", q, "--jq", ".workflow_runs[] | {id, name, status}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh api failed ({out.returncode}): {out.stderr.strip()[:400]}")
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


GREEN_BOARD = [{"name": "Documentation claims hold", "status": "completed", "conclusion": "success"},
               {"name": "Kani varint", "status": "completed", "conclusion": "success"}]

# (name, check-runs, workflow runs, self_run_id, expected verdict)
WORKFLOW_CASES = [
    ("every existing check-run done, but a workflow run with needs:-gated jobs "
     "is still in progress -> wait, not pass",
     GREEN_BOARD, [{"id": 1, "name": "Fuzz Testing", "status": "in_progress"},
                   {"id": 9, "name": "Required", "status": "in_progress"}], 9, "wait"),
    ("a queued workflow run is not finished either",
     GREEN_BOARD, [{"id": 2, "name": "CI", "status": "queued"}], 9, "wait"),
    ("our own workflow run never blocks us",
     GREEN_BOARD, [{"id": 9, "name": "Required", "status": "in_progress"}], 9, "pass"),
    ("all workflow runs completed -> pass",
     GREEN_BOARD, [{"id": 1, "name": "CI", "status": "completed"},
                   {"id": 9, "name": "Required", "status": "in_progress"}], 9, "pass"),
]


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


# (name, [(seconds since start, check-runs) per poll], deadline, expected stalled at the last poll)
_Q = lambda n: {"name": n, "status": "queued", "conclusion": None}
_R = lambda n: {"name": n, "status": "in_progress", "conclusion": None}
_LEAN = {"name": "Lean Ed25519 proofs", "status": "completed", "conclusion": "success"}
_DOCS = {"name": "Documentation claims hold", "status": "completed", "conclusion": "success"}
EVENT_CASES = [
    # (name, runs, event, expected verdict)
    ("merge_group without the Lean context -> fail", [_DOCS], "merge_group", "fail"),
    ("merge_group with the Lean context green -> pass", [_DOCS, _LEAN], "merge_group", "pass"),
    ("merge_group with the Lean context failed -> fail",
     [_DOCS, dict(_LEAN, conclusion="failure")], "merge_group", "fail"),
    ("pull_request without the Lean context (paths-filtered) -> pass",
     [_DOCS], "pull_request", "pass"),
]

CLOCK_CASES = [
    ("queued for longer than the deadline is not a stall",
     [(0, [_Q("Kani varint")]), (7200, [_Q("Kani varint")])], 3600, []),
    ("the clock starts at first in_progress, not at the first poll",
     [(0, [_Q("Kani varint")]), (5000, [_R("Kani varint")]), (8000, [_R("Kani varint")])], 3600, []),
    ("in progress past the deadline is a stall",
     [(0, [_Q("Kani varint")]), (100, [_R("Kani varint")]), (3700, [_R("Kani varint")])], 3600,
     ["Kani varint"]),
    ("a queued job does not hide a stalled one",
     [(0, [_R("Kani dsse"), _Q("Kani format")]), (3600, [_R("Kani dsse"), _Q("Kani format")])], 3600,
     ["Kani dsse"]),
    ("this gate's own check-run never stalls itself",
     [(0, [_R(SELF)]), (9999, [_R(SELF)])], 3600, []),
]


def self_test():
    bad = 0
    for name, polls, deadline, expected in CLOCK_CASES:
        clock, got = {}, []
        for t, runs in polls:
            got = stalled(clock, runs, t, deadline)
        ok = got == expected
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {name}: expected stalled {expected}, got {got}")
    cases = ([(n, r, (), None, None, e) for n, r, e in SELF_TEST_CASES]
             + [(n, r, w, i, None, e) for n, r, w, i, e in WORKFLOW_CASES]
             + [(n, r, (), None, ev, e) for n, r, ev, e in EVENT_CASES])
    for name, runs, wruns, self_id, event, expected in cases:
        got, reasons = classify(runs, workflow_runs=wruns, self_run_id=self_id,
                                event=event)
        ok = got == expected
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {name}: expected {expected}, got {got}"
              + (f"  [{'; '.join(reasons)}]" if not ok and reasons else ""))
    total = len(cases) + len(CLOCK_CASES)
    print(f"\n{total - bad}/{total} decision cases hold.")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sha")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    ap.add_argument("--deadline-secs", type=int, default=3600,
                    help="stall clock per check-run, counted from first in_progress")
    ap.add_argument("--max-wait-secs", type=int, default=5 * 3600,
                    help="overall cap on the wait, queued time included")
    ap.add_argument("--poll-secs", type=int, default=30)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if not a.sha or not a.repo:
        print("required-checks: --sha and --repo (or GITHUB_REPOSITORY) are required",
              file=sys.stderr)
        return 2

    self_run_id = int(os.environ["GITHUB_RUN_ID"]) if os.environ.get("GITHUB_RUN_ID") else None
    event = os.environ.get("GITHUB_EVENT_NAME")
    start = time.time()
    clock = {}
    while True:
        try:
            runs = fetch(a.repo, a.sha)
            wruns = fetch_workflow_runs(a.repo, a.sha, event)
        except Exception as e:
            # Fail closed. The audit's finding is that a classifier's error path
            # is usually its permissive branch.
            print(f"::error::required-checks could not read the check board: {e}")
            return 1

        verdict, reasons = classify(runs, workflow_runs=wruns, self_run_id=self_run_id,
                                    event=event)
        if verdict == "pass":
            print(f"All {len(runs) - 1} other check-runs are acceptable, and every "
                  f"always-present context reported. Mergeable.")
            return 0
        if verdict == "fail":
            for r in reasons:
                print(f"::error::{r}")
            print(f"\n{len(reasons)} blocking condition(s).")
            return 1

        now = time.time()
        stuck = stalled(clock, runs, now, a.deadline_secs)
        if stuck:
            print(f"::error::required-checks: {len(stuck)} check-run(s) in progress for "
                  f"over {a.deadline_secs}s: {', '.join(stuck[:6])}. Failing closed: a gate "
                  f"that gives up and passes is worse than none.")
            return 1
        if now - start >= a.max_wait_secs:
            print(f"::error::required-checks hit its {a.max_wait_secs}s overall cap with "
                  f"checks still unfinished (queued time included) — "
                  f"{reasons[0] if reasons else 'unknown'}. Failing closed.")
            return 1
        print(f"waiting: {reasons[0]}")
        time.sleep(a.poll_secs)


if __name__ == "__main__":
    sys.exit(main())
