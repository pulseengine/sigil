#!/usr/bin/env python3
"""lean-proof-gate: compare Lean's own axiom report with lean/PROOF_LEDGER.txt.

Input 1: the output of `lake env lean lean/ProofAudit.lean`, one line per
declaration of the Ed25519 module:  decl <name> <kind> <ax1>,<ax2>,...
Input 2: the ledger (see lean/PROOF_LEDGER.txt for the format).

Fails (exit 1) when:
  - a declared axiom has no `axiom` ledger entry;
  - any declaration (theorem, def, or other) depends on sorryAx and has no
    `open` entry;
  - any declaration depends on an axiom that is neither standard nor ledgered;
  - a ledger entry names nothing, or an `open` theorem no longer uses sorry,
    or an entry has no reason;
  - the audit lists no theorem at all (an empty report is not a pass).
Every error path exits non-zero.

Usage:
  lean-proof-gate.py <audit.txt> <PROOF_LEDGER.txt>
  lean-proof-gate.py --self-test
"""

import sys

STANDARD = {"propext", "Quot.sound", "Classical.choice"}


def parse_audit(text):
    decls = {}
    for line in text.splitlines():
        if not line.startswith("decl "):
            continue
        parts = line.split(" ")
        if len(parts) < 3:
            raise ValueError(f"malformed audit line: {line!r}")
        name, kind = parts[1], parts[2]
        axs = parts[3].split(",") if len(parts) > 3 and parts[3] else []
        decls[name] = (kind, set(axs))
    return decls


def parse_ledger(text):
    axioms, opens, errors = {}, {}, []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or parts[0] not in ("axiom", "open"):
            errors.append(f"ledger line {n}: expected '<axiom|open> <name> <reason>': {raw!r}")
            continue
        (axioms if parts[0] == "axiom" else opens)[parts[1]] = parts[2]
    return axioms, opens, errors


def check(decls, axioms, opens):
    errors = []
    theorems = {n: a for n, (k, a) in decls.items() if k == "theorem"}
    declared_axioms = {n for n, (k, _) in decls.items() if k == "axiom"}
    if not theorems:
        errors.append("the audit lists no theorem: an empty report is not a pass")
    for ax in sorted(declared_axioms - set(axioms)):
        errors.append(f"axiom {ax} is declared but not in the ledger")
    for name in sorted(set(axioms) - declared_axioms):
        errors.append(f"ledger axiom {name} is not a declared axiom (stale entry)")
    for name in sorted(set(opens) - set(decls)):
        errors.append(f"ledger open {name} is not a declaration (stale entry)")
    checked, still_open = [], []
    # Every declaration kind, not only theorems: a `def x : P := sorry` or a
    # def resting on an unledgered axiom is as much a hole as a theorem.
    for name, (kind, deps) in sorted(decls.items()):
        if kind == "axiom":
            continue  # checked against the ledger above; deps is itself
        if "sorryAx" in deps:
            if name not in opens:
                errors.append(f"{kind} {name} uses sorry and is not ledgered as open")
            still_open.append(name)
        elif name in opens:
            errors.append(f"{kind} {name} no longer uses sorry: remove its open entry")
        elif kind == "theorem":
            checked.append(name)
        for ax in sorted(deps - STANDARD - {"sorryAx"} - set(axioms)):
            errors.append(f"{kind} {name} depends on unledgered axiom {ax}")
    return errors, checked, still_open


def self_test():
    audit = (
        "decl CurvePoint axiom CurvePoint\n"
        "decl thm_ok theorem CurvePoint,propext\n"
        "decl thm_open theorem CurvePoint,sorryAx\n"
    )
    ledger = "axiom CurvePoint opaque\nopen thm_open roadmap only\n"
    cases = [
        ("clean", audit, ledger, 0),
        ("new sorry", audit + "decl planted theorem sorryAx\n", ledger, 1),
        ("new axiom used", audit.replace("CurvePoint,propext", "CurvePoint,evil"), ledger, 1),
        ("declared axiom unledgered", audit + "decl evil axiom evil\n", ledger, 1),
        ("open now proved", audit.replace("CurvePoint,sorryAx", "CurvePoint"), ledger, 1),
        ("stale axiom entry", audit, ledger + "axiom Gone was here\n", 1),
        ("stale open entry", audit, ledger + "open gone was here\n", 1),
        ("entry without reason", audit, ledger + "axiom CurvePoint\n", 1),
        ("empty audit", "", ledger, 1),
        ("def with sorry", audit + "decl sneaky def sorryAx\n", ledger, 1),
        ("def on an unledgered axiom", audit + "decl sneaky def evil\n", ledger, 1),
        ("other-kind decl with sorry", audit + "decl sneaky other sorryAx\n", ledger, 1),
        ("unmangled private theorem with sorry",
         audit + "decl planted_private theorem sorryAx\n", ledger, 1),
        ("Classical.choice is standard", audit.replace("CurvePoint,propext", "Classical.choice,CurvePoint"), ledger, 0),
    ]
    bad = 0
    for label, a, l, want in cases:
        decls = parse_audit(a)
        axioms, opens, perr = parse_ledger(l)
        errs, _, _ = check(decls, axioms, opens)
        got = 1 if (perr or errs) else 0
        ok = got == want
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {label}: exit {got}, want {want}")
    print(f"self-test: {len(cases) - bad}/{len(cases)} cases")
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        decls = parse_audit(open(argv[1], encoding="utf-8").read())
        axioms, opens, errors = parse_ledger(open(argv[2], encoding="utf-8").read())
    except (OSError, ValueError) as e:
        print(f"lean-proof-gate: {e}", file=sys.stderr)
        return 1
    errs, checked, still_open = check(decls, axioms, opens)
    errors += errs
    print(f"checked (relative to {len(axioms)} ledgered axioms): {len(checked)}: {', '.join(checked)}")
    print(f"open (sorry, ledgered): {len(still_open)}: {', '.join(still_open)}")
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
