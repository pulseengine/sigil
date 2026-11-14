#!/usr/bin/env python3
"""Perf-gate verdict: PR head vs base commit, both measured on one runner.

Inputs are two gungraun `--home` directories, each holding one summary.json
per benchmark (from `cargo bench --bench verification_callgrind --
--save-summary`). Rules, per benchmark:

  heap allocations   DHAT TotalBlocks and TotalBytes. FAIL when head exceeds
                     base by more than `alloc_pct` (default 2 %), or when base
                     is 0 and head is not. DHAT counts are exact, so there is
                     no noise floor.
  instructions       Callgrind Ir. REPORT (a ::warning::, exit status
                     unaffected) when head exceeds base by more than
                     `instr_report_pct` (default 3 %). Benchmarks whose base
                     Ir is under `instr_min_share_pct` (default 0.5 %) of the
                     summed base Ir are listed but not reported.
  wall time          not measured here (criterion sanity run, report-only).

Fails closed: an empty or unreadable directory, a benchmark without a DHAT or
Callgrind profile, a missing metric, or a benchmark present at base but absent
at head (list it under "retired" in the limits file to remove it on purpose).
A benchmark new at head has no base and is listed as new.

Usage:
  perf-verdict.py [--limits limits.json] BASE_HOME HEAD_HOME
  perf-verdict.py --measure-only HEAD_HOME
  perf-verdict.py --self-test
"""

import json
import sys
import tempfile
from pathlib import Path

DEFAULTS = {"alloc_pct": 2.0, "instr_report_pct": 3.0}
DEFAULT_SHARE = 0.5
ALLOC_METRICS = ("TotalBlocks", "TotalBytes")


class GateError(Exception):
    pass


def metric(profile, name, where):
    m = profile.get("data", {}).get("total", {}).get("metrics", {}).get(name)
    if m is None:
        raise GateError(f"{where}: metric {name} missing")
    v = m.get("values", m)
    new = v.get("new") if isinstance(v, dict) else v
    if not isinstance(new, (int, float)):
        raise GateError(f"{where}: metric {name} has no numeric 'new' value: {m!r}")
    return new


def load(home):
    home = Path(home)
    files = sorted(home.rglob("summary.json")) if home.is_dir() else []
    if not files:
        raise GateError(f"no summary.json under {home}")
    out = {}
    for f in files:
        try:
            s = json.loads(f.read_text())
        except (OSError, ValueError) as e:
            raise GateError(f"{f}: unreadable ({e})") from e
        key = s["function_name"] + (f".{s['id']}" if s.get("id") else "")
        tools = {p.get("tool"): p for p in s.get("profiles", [])}
        cg, dh = tools.get("Callgrind"), tools.get("DHAT")
        if cg is None or dh is None:
            raise GateError(f"{key}: needs Callgrind and DHAT profiles, has {sorted(map(str, tools))}")
        if key in out:
            raise GateError(f"{key}: duplicate summary ({f})")
        out[key] = {"Ir": metric(cg, "Ir", key)}
        for a in ALLOC_METRICS:
            out[key][a] = metric(dh, a, key)
    return out


def pct(base, head):
    if base == 0:
        return 0.0 if head == 0 else float("inf")
    return (head - base) * 100.0 / base


def fmt_pct(p):
    return "+inf %" if p == float("inf") else f"{p:+.2f} %"


def verdict(base_home, head_home, limits):
    base, head = load(base_home), load(head_home)
    rules = limits.get("benchmarks", {})
    share_floor = limits.get("instr_min_share_pct", DEFAULT_SHARE)
    retired = set(limits.get("retired", []))
    total_ir = sum(b["Ir"] for b in base.values()) or 1
    fails, warns = [], []
    rows = ["| benchmark | Ir base → head | Ir Δ | blocks base → head | bytes base → head | verdict |",
            "|---|---|---|---|---|---|"]
    for key in sorted(set(base) | set(head)):
        if key not in head:
            if key in retired:
                rows.append(f"| `{key}` | | | | | retired |")
            else:
                fails.append(f"{key}: present at base, missing at head (add to 'retired' to remove it)")
                rows.append(f"| `{key}` | | | | | **FAIL** missing at head |")
            continue
        h = head[key]
        if key not in base:
            rows.append(f"| `{key}` | {h['Ir']} | | {h['TotalBlocks']} | {h['TotalBytes']} | new, no base |")
            continue
        b = base[key]
        r = {**DEFAULTS, **rules.get(key, {})}
        notes = []
        for a in ALLOC_METRICS:
            p = pct(b[a], h[a])
            if p > r["alloc_pct"]:
                fails.append(f"{key}: {a} {b[a]} → {h[a]} ({fmt_pct(p)}, limit {r['alloc_pct']} %)")
                notes.append(f"**FAIL** {a} {fmt_pct(p)}")
        ip = pct(b["Ir"], h["Ir"])
        share = b["Ir"] * 100.0 / total_ir
        if ip > r["instr_report_pct"]:
            if share < share_floor:
                notes.append(f"Ir {fmt_pct(ip)} ignored ({share:.2f} % share)")
            else:
                warns.append(f"{key}: Ir {b['Ir']} → {h['Ir']} ({fmt_pct(ip)}, report above {r['instr_report_pct']} %)")
                notes.append(f"report: Ir {fmt_pct(ip)}")
        rows.append(f"| `{key}` | {b['Ir']} → {h['Ir']} | {fmt_pct(ip)} | {b['TotalBlocks']} → {h['TotalBlocks']} "
                    f"| {b['TotalBytes']} → {h['TotalBytes']} | {'; '.join(notes) or 'ok'} |")
    return rows, fails, warns


def report(rows, fails, warns):
    print("### Perf gate: head vs base (Callgrind Ir, DHAT heap)\n")
    print("\n".join(rows))
    print()
    for w in warns:
        print(f"::warning::perf report: {w}")
    for f in fails:
        print(f"::error::perf gate: {f}")
    print(f"\n{'FAIL' if fails else 'PASS'}: {len(fails)} allocation regression(s), "
          f"{len(warns)} instruction report(s)")
    return 1 if fails else 0


def measure_only(home):
    head = load(home)
    print("### Perf gate: measurements only (no base to compare)\n")
    print("| benchmark | Ir | blocks | bytes |\n|---|---|---|---|")
    for k in sorted(head):
        print(f"| `{k}` | {head[k]['Ir']} | {head[k]['TotalBlocks']} | {head[k]['TotalBytes']} |")
    return 0


# ── self-test ──────────────────────────────────────────────────────────────

def write_home(root, benches):
    for key, (ir, blocks, nbytes) in benches.items():
        fn, _, bid = key.partition(".")
        d = Path(root) / "wsc" / "verification_callgrind" / "verification" / key
        d.mkdir(parents=True)
        prof = lambda tool, ms: {"tool": tool, "data": {"parts": [], "total": {
            "metrics": {k: {"values": {"new": v}} for k, v in ms.items()}, "regressions": []}}}
        profiles = []
        if ir is not None:
            profiles.append(prof("Callgrind", {"Ir": ir}))
        if blocks is not None:
            profiles.append(prof("DHAT", {"TotalBlocks": blocks, "TotalBytes": nbytes}))
        (d / "summary.json").write_text(json.dumps(
            {"function_name": fn, "id": bid or None, "profiles": profiles}))


def self_test():
    base = {"verify.a": (1_000_000, 50, 4000), "verify.zero": (500_000, 0, 0), "tiny.x": (1_000, 2, 64)}
    cases = [
        # name, head (or callable on base), limits, want_fail, want_warn
        ("identical passes", dict(base), {}, False, False),
        ("allocations decrease passes", {**base, "verify.a": (900_000, 40, 3000)}, {}, False, False),
        ("+1 block of 50 (2 %) passes at the limit", {**base, "verify.a": (1_000_000, 51, 4000)}, {}, False, False),
        ("+2 blocks of 50 (4 %) fails", {**base, "verify.a": (1_000_000, 52, 4000)}, {}, True, False),
        ("+3 % bytes fails", {**base, "verify.a": (1_000_000, 50, 4120)}, {}, True, False),
        ("+1 % bytes passes", {**base, "verify.a": (1_000_000, 50, 4040)}, {}, False, False),
        ("first allocation on a zero path fails", {**base, "verify.zero": (500_000, 1, 8)}, {}, True, False),
        ("+5 % Ir reports, does not fail", {**base, "verify.a": (1_050_000, 50, 4000)}, {}, False, True),
        ("+5 % Ir under the share floor is ignored", {**base, "tiny.x": (1_050, 2, 64)}, {}, False, False),
        ("per-benchmark override allows +4 % blocks",
         {**base, "verify.a": (1_000_000, 52, 4000)}, {"benchmarks": {"verify.a": {"alloc_pct": 5}}}, False, False),
        ("benchmark missing at head fails", {k: v for k, v in base.items() if k != "verify.zero"}, {}, True, False),
        ("retired benchmark missing at head passes", {k: v for k, v in base.items() if k != "verify.zero"},
         {"retired": ["verify.zero"]}, False, False),
        ("new benchmark at head passes", {**base, "verify.new": (10, 1, 1)}, {}, False, False),
    ]
    bad = 0
    for name, head, limits, want_fail, want_warn in cases:
        with tempfile.TemporaryDirectory() as t:
            write_home(f"{t}/b", base)
            write_home(f"{t}/h", head)
            _, fails, warns = verdict(f"{t}/b", f"{t}/h", limits)
        ok = bool(fails) == want_fail and bool(warns) == want_warn
        print(f"{'ok  ' if ok else 'FAIL'}  {name}" + ("" if ok else f"  fails={fails} warns={warns}"))
        bad |= not ok
    error_cases = [
        ("empty base directory fails closed", {}, base),
        ("missing DHAT profile fails closed", base, {**base, "verify.a": (1_000_000, None, None)}),
        ("missing Callgrind profile fails closed", base, {**base, "verify.a": (None, 50, 4000)}),
    ]
    for name, b, h in error_cases:
        with tempfile.TemporaryDirectory() as t:
            Path(f"{t}/b").mkdir()
            write_home(f"{t}/b", b)
            write_home(f"{t}/h", h)
            try:
                verdict(f"{t}/b", f"{t}/h", {})
                ok = False
            except GateError:
                ok = True
        print(f"{'ok  ' if ok else 'FAIL'}  {name}")
        bad |= not ok
    print("self-test ok" if not bad else "SELF-TEST FAILED")
    return 1 if bad else 0


def main(argv):
    try:
        if argv[:1] == ["--self-test"]:
            return self_test()
        if argv[:1] == ["--measure-only"] and len(argv) == 2:
            return measure_only(argv[1])
        limits = {}
        if argv[:1] == ["--limits"]:
            limits = json.loads(Path(argv[1]).read_text())
            argv = argv[2:]
        if len(argv) != 2:
            print(__doc__, file=sys.stderr)
            return 2
        return report(*verdict(argv[0], argv[1], limits))
    except GateError as e:
        print(f"::error::perf gate: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
