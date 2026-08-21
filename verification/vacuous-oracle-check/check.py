#!/usr/bin/env python3
"""Vacuous-oracle CI gate (REQ-30 / #258).

Fails CI when a CI test/proof selector matches *zero* targets, or when the
coverage run silently omits a lib-bearing workspace crate. Both failures make a
"passing" job vacuous: a green check that verifies nothing.

What it catches
---------------
1. Zero-match test/proof selectors in `.github/workflows/*.yml`:
   * `cargo kani ... --harness <H>` (with its `-p <pkg>`): at least one
     `#[kani::proof]` in that package's `src/` must have a fully-qualified path
     (crate + module path + enclosing `mod`s) containing <H>. A matrix that
     drives `--harness "$HARNESS" -p "$PACKAGE"` is expanded from its
     `matrix.include` (pkg/harness) pairs.
   * `cargo test|llvm-cov|nextest ... -p <pkg>` / `--package <pkg>`: <pkg> must
     be a real workspace member.
   * `--test <target>`: `src/*/tests/<target>.rs` must exist.
2. Coverage crate omission: every lib-bearing workspace member (Cargo.toml has a
   `[lib]` or a `src/lib.rs`) must appear in a `cargo llvm-cov -p ...` list, or
   be listed in COVERAGE_EXEMPT below.

Stdlib only; no `cargo`, no PyYAML — the gate job runs `python3` alone.

Exit codes: 0 = clean, 1 = at least one finding (or, in --list mode, always 0).

To add an exemption: put the crate name in COVERAGE_EXEMPT with a one-line
reason. Exempt only crates with genuinely nothing host-coverable (see README).
"""

from __future__ import annotations

import os
import re
import sys

# Crates deliberately excluded from the coverage-omission check. Seeded with the
# one crate that has no host-coverable code; everything else must be measured.
COVERAGE_EXEMPT = {
    # wsc-component is a `cdylib` WebAssembly component: every item in its
    # src/lib.rs is `#[cfg(target_arch = "wasm32")]`, so nothing is coverable on
    # the host (x86_64) coverage runner. Measuring it would add a 0-line crate.
    "wsc-component": "cdylib wasm component; all code is #[cfg(target_arch=wasm32)], nothing host-coverable",
}

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
SRC_DIR = os.path.join(REPO_ROOT, "src")


# --------------------------------------------------------------------------- #
# Workspace model
# --------------------------------------------------------------------------- #
class Member:
    def __init__(self, name, crate_dir, has_lib):
        self.name = name
        self.crate_dir = crate_dir
        self.has_lib = has_lib

    @property
    def src(self):
        return os.path.join(self.crate_dir, "src")


def _workspace_member_dirs():
    """Parse the root Cargo.toml `[workspace] members = [...]` list. Only these
    directories are real workspace members — a `src/*/Cargo.toml` that is NOT
    listed (or is under `exclude`) is a sibling crate, not a member, and must
    not be flagged for coverage."""
    manifest = os.path.join(REPO_ROOT, "Cargo.toml")
    if not os.path.isfile(manifest):
        return []
    with open(manifest, "r", encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"(?ms)^\s*members\s*=\s*\[(.*?)\]", text)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def discover_members():
    """Workspace members declared in the root Cargo.toml (name + lib-bearing)."""
    members = {}
    for rel in _workspace_member_dirs():
        crate_dir = os.path.join(REPO_ROOT, rel)
        manifest = os.path.join(crate_dir, "Cargo.toml")
        if not os.path.isfile(manifest):
            continue
        with open(manifest, "r", encoding="utf-8") as fh:
            text = fh.read()
        name = _parse_package_name(text)
        if name is None:
            continue
        has_lib_section = re.search(r"(?m)^\s*\[lib\]", text) is not None
        has_lib_rs = os.path.isfile(os.path.join(crate_dir, "src", "lib.rs"))
        members[name] = Member(name, crate_dir, has_lib_section or has_lib_rs)
    return members


def _parse_package_name(manifest_text):
    """Return the `name` from the [package] table, ignoring other tables."""
    in_package = False
    for raw in manifest_text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_package = line == "[package]"
            continue
        if in_package:
            m = re.match(r'name\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Comment stripping
# --------------------------------------------------------------------------- #
def strip_comment(line):
    """Remove a YAML/shell comment (`#` at line start or after whitespace,
    outside quotes). Prevents selectors inside comments from being matched."""
    out = []
    quote = None
    prev_ws = True  # start-of-line counts as preceded-by-whitespace
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            prev_ws = False
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            prev_ws = False
            continue
        if ch == "#" and prev_ws:
            break
        out.append(ch)
        prev_ws = ch in (" ", "\t")
    return "".join(out)


# --------------------------------------------------------------------------- #
# Kani proof discovery
# --------------------------------------------------------------------------- #
def _module_path_from_file(src_dir, file_path):
    rel = os.path.relpath(file_path, src_dir)
    parts = rel[:-3].split(os.sep) if rel.endswith(".rs") else rel.split(os.sep)
    # Drop crate-root / module-root file stems that add no path segment.
    if parts and parts[-1] in ("mod", "lib", "main"):
        parts = parts[:-1]
    return "::".join(parts)


def kani_search_strings(member):
    """Set of fully-qualified-ish identifiers a `--harness` filter could match
    for this package: crate name, per-file module paths, and enclosing `mod`s."""
    crate_us = member.name.replace("-", "_")
    strings = {crate_us}
    if not os.path.isdir(member.src):
        return strings
    for root, _dirs, files in os.walk(member.src):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(root, fn)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if "kani::proof" not in text:
                continue
            mod_path = _module_path_from_file(member.src, path)
            base = crate_us + ("::" + mod_path if mod_path else "")
            strings.add(base)
            for mod_name in re.findall(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)", text):
                strings.add(base + "::" + mod_name)
    return strings


def harness_matches(member, harness):
    return any(harness in s for s in kani_search_strings(member))


# --------------------------------------------------------------------------- #
# Workflow parsing
# --------------------------------------------------------------------------- #
class Selector:
    def __init__(self, kind, value, wf_file, lineno, pkg=None):
        self.kind = kind        # 'kani-harness' | 'pkg' | 'test-target' | 'llvm-cov-pkglist'
        self.value = value
        self.wf_file = wf_file
        self.lineno = lineno
        self.pkg = pkg          # for kani-harness: the package to search

    def loc(self):
        return "{}:{}".format(os.path.relpath(self.wf_file, REPO_ROOT), self.lineno)


def _matrix_pairs(lines):
    """Extract (pkg, harness) pairs from a `matrix.include:` list. Each list
    entry (a line starting with `- `) may set `pkg:` and `harness:`."""
    pairs = []
    in_include = False
    include_indent = None
    cur = None
    entries = []
    for raw in lines:
        line = strip_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if re.match(r"include\s*:", stripped):
            in_include = True
            include_indent = indent
            continue
        if in_include:
            # Leaving the include block: a key at or below its indent.
            if indent <= include_indent and not stripped.startswith("- "):
                in_include = False
                continue
            if stripped.startswith("- "):
                cur = {}
                entries.append(cur)
                stripped = stripped[2:].strip()
            if cur is not None:
                m = re.match(r"(pkg|harness)\s*:\s*(\S+)", stripped)
                if m:
                    cur[m.group(1)] = m.group(2).strip('"\'')
    for e in entries:
        if "pkg" in e and "harness" in e:
            pairs.append((e["pkg"], e["harness"]))
    return pairs


def parse_workflow(path):
    selectors = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()
    lines = [strip_comment(l) for l in raw_lines]
    matrix_pairs = _matrix_pairs(raw_lines)

    for i, line in enumerate(lines, start=1):
        if "cargo" not in line:
            continue

        # cargo kani ... --harness <H>
        if re.search(r"\bcargo\s+kani\b", line):
            hm = re.search(r"--harness\s+(\S+)", line)
            if hm:
                harness = hm.group(1).strip('"\'')
                pkg_m = re.search(r"(?:-p|--package)\s+(\S+)", line)
                pkg = pkg_m.group(1).strip('"\'') if pkg_m else None
                if _is_var(harness) or (pkg and _is_var(pkg)):
                    # Matrix-driven: expand pairs from this file's include block.
                    for p_pkg, p_harness in matrix_pairs:
                        selectors.append(Selector("kani-harness", p_harness, path, i, pkg=p_pkg))
                else:
                    selectors.append(Selector("kani-harness", harness, path, i, pkg=pkg))
            continue

        # cargo test / llvm-cov / nextest
        if re.search(r"\bcargo\s+(?:\S+\s+)*?(?:test|llvm-cov|nextest)\b", line):
            pkgs = [m.strip('"\'') for m in re.findall(r"(?:-p|--package)\s+(\S+)", line)]
            pkgs = [p for p in pkgs if not _is_var(p)]
            if re.search(r"\bcargo\s+llvm-cov\b", line) and pkgs:
                selectors.append(Selector("llvm-cov-pkglist", pkgs, path, i))
            for p in pkgs:
                selectors.append(Selector("pkg", p, path, i))
            for tgt in re.findall(r"--test\s+(\S+)", line):
                if not _is_var(tgt):
                    selectors.append(Selector("test-target", tgt.strip('"\''), path, i))
    return selectors


def _is_var(tok):
    return "$" in tok or "{{" in tok


def find_test_target(target):
    for entry in os.listdir(SRC_DIR):
        cand = os.path.join(SRC_DIR, entry, "tests", target + ".rs")
        if os.path.isfile(cand):
            return cand
    return None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run(list_mode):
    members = discover_members()
    lib_members = {n for n, m in members.items() if m.has_lib}

    workflows = []
    if os.path.isdir(WORKFLOW_DIR):
        workflows = sorted(
            os.path.join(WORKFLOW_DIR, f)
            for f in os.listdir(WORKFLOW_DIR)
            if f.endswith((".yml", ".yaml"))
        )

    selectors = []
    for wf in workflows:
        selectors.extend(parse_workflow(wf))

    findings = []
    covered_pkgs = set()

    for sel in selectors:
        if sel.kind == "kani-harness":
            if sel.pkg is None:
                findings.append(
                    "{}: `cargo kani --harness {}` has no resolvable -p package".format(
                        sel.loc(), sel.value
                    )
                )
            elif sel.pkg not in members:
                findings.append(
                    "{}: kani package '{}' is not a workspace member".format(sel.loc(), sel.pkg)
                )
            elif not harness_matches(members[sel.pkg], sel.value):
                findings.append(
                    "{}: kani --harness '{}' matches no #[kani::proof] in package '{}'".format(
                        sel.loc(), sel.value, sel.pkg
                    )
                )
        elif sel.kind == "pkg":
            if sel.value not in members:
                findings.append(
                    "{}: -p '{}' is not a workspace member".format(sel.loc(), sel.value)
                )
        elif sel.kind == "test-target":
            if find_test_target(sel.value) is None:
                findings.append(
                    "{}: --test '{}' has no src/*/tests/{}.rs".format(
                        sel.loc(), sel.value, sel.value
                    )
                )
        elif sel.kind == "llvm-cov-pkglist":
            covered_pkgs.update(sel.value)

    # Coverage-omission check.
    if any(s.kind == "llvm-cov-pkglist" for s in selectors):
        for name in sorted(lib_members):
            if name in covered_pkgs:
                continue
            if name in COVERAGE_EXEMPT:
                continue
            findings.append(
                "coverage: lib-bearing crate '{}' is not measured by any `cargo llvm-cov -p` "
                "list and is not in COVERAGE_EXEMPT".format(name)
            )

    if list_mode:
        _print_list(members, lib_members, selectors, covered_pkgs)
        return 0

    print("== vacuous-oracle gate (REQ-30 / #258) ==")
    print("workflows scanned : {}".format(len(workflows)))
    print("selectors checked : {}".format(len(selectors)))
    if not findings:
        print("result            : OK — no vacuous selectors or coverage omissions")
        return 0
    print("result            : FAIL — {} finding(s):".format(len(findings)))
    for f in findings:
        print("  - {}".format(f))
    return 1


def _print_list(members, lib_members, selectors, covered_pkgs):
    print("== workspace members ==")
    for n in sorted(members):
        tag = "lib" if n in lib_members else "no-lib"
        exempt = "  (COVERAGE_EXEMPT)" if n in COVERAGE_EXEMPT else ""
        print("  {:20s} [{}]{}".format(n, tag, exempt))
    print("\n== selectors found ==")
    for sel in selectors:
        if sel.kind == "kani-harness":
            print("  {}  kani --harness {} (-p {})".format(sel.loc(), sel.value, sel.pkg))
        elif sel.kind == "pkg":
            print("  {}  -p {}".format(sel.loc(), sel.value))
        elif sel.kind == "test-target":
            print("  {}  --test {}".format(sel.loc(), sel.value))
        elif sel.kind == "llvm-cov-pkglist":
            print("  {}  llvm-cov -p {}".format(sel.loc(), " ".join(sel.value)))
    print("\n== coverage ==")
    print("  measured   : {}".format(", ".join(sorted(covered_pkgs)) or "(none)"))
    print("  lib-bearing: {}".format(", ".join(sorted(lib_members))))
    missing = sorted(lib_members - covered_pkgs - set(COVERAGE_EXEMPT))
    print("  missing    : {}".format(", ".join(missing) or "(none)"))


def main(argv):
    list_mode = "--list" in argv[1:]
    return run(list_mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
