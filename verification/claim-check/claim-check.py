#!/usr/bin/env python3
"""claim-check — gate a repo's documentation claims against live evidence.

Reference implementation for the `claim-verification` skill. A repo drops a
`claims.yaml` next to its docs; CI runs this; drift between a claim, its recorded
ledger, and the *actual source* fails the build. Truth-over-time becomes a property
of the gate, not the author.

Usage:  claim-check.py [claims.yaml]     (default: ./claims.yaml)
Exit:   0 = all claims hold · 1 = one or more drifted

A repo may reimplement this in Rust (cf. tools/fetch-reports); the shape is what
matters. Evidence predicates re-derive from source — never a number typed in prose.

claims.yaml shape:
  claims:
    - id: LOOM-BADGE
      doc: README.md
      text: "Translation-Validated"          # must appear VERBATIM in `doc`
      evidence:
        - kind: file-exists
          path: proofs/Correctness.v
        - kind: count-max                      # re-count from source; fail if over
          pattern: '#\\[verifier::external_body\\]'
          glob: ['src/**/*.rs']
          max: 133
        - kind: no-new                         # no new sorry/admit since recorded
          pattern: '\\bAdmitted\\b'
          glob: ['proofs/**/*.v']
          recorded: 74
        - kind: captures-agree                 # N hand-kept copies of one value must be equal
          patterns: ['tool@(v[0-9.]+)', 'tool-version:\\s*(v[0-9.]+)']
          glob: ['.github/workflows/*.yml']
          min-captures: 4
"""
import sys
import re
import glob
import pathlib

try:
    import yaml
except ImportError:
    sys.exit("claim-check: needs PyYAML  (pip install pyyaml)")


def _count(pattern, globs, root):
    rx = re.compile(pattern)
    globs = [globs] if isinstance(globs, str) else globs
    total = 0
    matched_any = False
    for g in globs:
        # Resolve globs relative to the claims file's directory, NOT the CWD —
        # otherwise the predicate silently matches nothing and greens a claim it
        # never checked (the "oracle that measures nothing" failure).
        for f in glob.glob(str(root / g), recursive=True):
            p = pathlib.Path(f)
            if p.is_file():
                matched_any = True
                total += len(rx.findall(p.read_text(errors="ignore")))
    return total, matched_any


def _capture(patterns, globs, root):
    """Collect capture-group 1 of every match of every pattern across globs.

    Returns (found, matched_any_file, bad) where `found` is a list of
    (value, filename, pattern) so a disagreement can name both sides rather
    than just reporting that one exists, and `bad` holds defects in the claim
    itself (a pattern with no capture group, or a group that did not
    participate) — reported as failures, never swallowed.
    """
    patterns = [patterns] if isinstance(patterns, str) else patterns
    globs = [globs] if isinstance(globs, str) else globs
    rxs = [re.compile(p) for p in patterns]
    found = []
    bad = []
    matched_any = False
    for g in globs:
        # Same root-relative resolution as _count: a glob resolved against the
        # CWD silently matches nothing and greens a claim it never checked.
        for f in sorted(glob.glob(str(root / g), recursive=True)):
            p = pathlib.Path(f)
            if not p.is_file():
                continue
            matched_any = True
            body = p.read_text(errors="ignore")
            for rx in rxs:
                if rx.groups < 1:
                    bad.append(f'pattern has no capture group: /{rx.pattern}/')
                    continue
                for m in rx.finditer(body):
                    v = m.group(1)
                    if v is None:
                        # An alternation can match while group 1 does not
                        # participate. That is a defect in the CLAIM, and it
                        # used to raise a TypeError in the sort below — which
                        # aborted main() and left every later claim
                        # unevaluated. Name it instead.
                        bad.append(
                            f'group 1 did not participate in a match of '
                            f'/{rx.pattern}/ in {p.name} — the pattern cannot '
                            f'express the value it claims to compare'
                        )
                        continue
                    found.append((v, p.name, rx.pattern))
    return found, matched_any, bad


def check_claim(c, root):
    fails = []
    doc_path = root / c["doc"]
    doc = doc_path.read_text(errors="ignore") if doc_path.exists() else ""
    if not doc_path.exists():
        return [f'doc not found: {c["doc"]}']

    text = c.get("text")
    if text and text not in doc:
        fails.append(f'claim text not found verbatim in {c["doc"]}: "{text}"')

    for ev in c.get("evidence", []):
        kind = ev.get("kind")
        if kind == "verbatim":
            s = ev.get("text", text)
            if s and s not in doc:
                fails.append(f'verbatim string absent from {c["doc"]}: "{s}"')
        elif kind == "file-exists":
            if not (root / ev["path"]).exists():
                fails.append(f'evidence file missing: {ev["path"]}')
        elif kind == "count-max":
            n, matched = _count(ev["pattern"], ev["glob"], root)
            if not matched:
                fails.append(f'predicate matched NO files (measures nothing): glob {ev["glob"]}')
            elif n > ev["max"]:
                fails.append(
                    f'trusted base grew: {n} > recorded max {ev["max"]}  '
                    f'[/{ev["pattern"]}/]  — update the claim, not the number'
                )
        elif kind == "count-min":
            # PRESENCE claim: the pattern MUST appear >= min times. The dual of
            # count-max (which greens a 0-match, since 0 > max is false). Catches
            # DRIFT-TO-ABSENT — a string the doc asserts that the source no longer
            # carries (e.g. a version bumped in Cargo.toml the README still names).
            n, matched = _count(ev["pattern"], ev["glob"], root)
            if not matched:
                fails.append(f'predicate matched NO files (measures nothing): glob {ev["glob"]}')
            elif n < ev["min"]:
                fails.append(
                    f'claim evidence absent: {n} < required min {ev["min"]}  '
                    f'[/{ev["pattern"]}/]  — the doc asserts it; the source no longer carries it'
                )
        elif kind == "no-new":
            n, matched = _count(ev["pattern"], ev["glob"], root)
            if not matched:
                fails.append(f'predicate matched NO files (measures nothing): glob {ev["glob"]}')
            elif n > ev.get("recorded", 0):
                fails.append(
                    f'new unproven obligations: {n} > recorded {ev.get("recorded", 0)}  '
                    f'[/{ev["pattern"]}/]'
                )
        elif kind == "captures-agree":
            # AGREEMENT claim: two or more hand-maintained copies of the SAME
            # value must stay equal, with group 1 of each pattern being one copy.
            # Fails three ways — no files matched (measures nothing), fewer
            # captures than `min-captures` (a copy was deleted or a pattern
            # rotted into matching nothing), or more than one distinct value.
            # The third is the drift the gate exists for; the second is what
            # stops the gate from going quietly vacuous when the first vanishes.
            found, matched, bad = _capture(ev["patterns"], ev["glob"], root)
            need = ev.get("min-captures", 2)
            distinct = sorted({v for v, _, _ in found})
            # dedupe: one defective pattern otherwise reports once per file
            fails.extend(dict.fromkeys(bad))
            if not matched:
                fails.append(f'predicate matched NO files (measures nothing): glob {ev["glob"]}')
            elif len(found) < need:
                fails.append(
                    f'captures missing: {len(found)} < required min-captures {need}  '
                    f'[{" , ".join(ev["patterns"])}]  — a copy was removed, or a '
                    f'pattern no longer matches the file it was written for'
                )
            elif len(distinct) > 1:
                sites = "; ".join(f"{v} in {f}" for v, f, _ in found)
                fails.append(
                    f'copies disagree: {distinct}  — {sites}  '
                    f'— these must name the same version'
                )
        else:
            fails.append(f'unknown evidence kind: {kind!r}')
    return fails


def main():
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "claims.yaml")
    if not path.exists():
        sys.exit(f"claim-check: {path} not found")
    root = path.parent
    data = yaml.safe_load(path.read_text()) or {}
    claims = data.get("claims", [])
    if not claims:
        print("claim-check: no claims declared — nothing to gate.")
        return

    bad = 0
    for c in claims:
        fails = check_claim(c, root)
        if fails:
            bad += 1
            print(f"✗ {c['id']}")
            for f in fails:
                print(f"    {f}")
        else:
            print(f"✓ {c['id']}")

    print(f"\n{len(claims) - bad}/{len(claims)} claims hold.")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
