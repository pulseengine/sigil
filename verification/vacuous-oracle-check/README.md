# Vacuous-oracle gate

`check.py` is a CI gate (REQ-30 / issue #258) that fails when a test or proof
**selector matches zero targets**, or when **coverage silently omits a
lib-bearing crate**. Both make a green CI job *vacuous* — it reports success
while verifying nothing.

It is pure-stdlib Python 3 and reads only files (no `cargo`, no network), so the
CI job needs no Rust toolchain.

## What it catches

Scanning `.github/workflows/*.yml` (YAML comments are stripped first, so a
selector mentioned inside a comment is never counted):

1. **Zero-match test/proof selectors**
   - `cargo kani ... --harness <H>` (with its `-p <pkg>`): at least one
     `#[kani::proof]` in that package's `src/` must have a fully-qualified path
     (crate name + module path + enclosing `mod`s) that contains `<H>`. A matrix
     that drives `--harness "$HARNESS" -p "$PACKAGE"` is expanded from its
     `matrix.include` `pkg`/`harness` pairs.
   - `cargo test|llvm-cov|nextest ... -p <pkg>` / `--package <pkg>`: `<pkg>` must
     be a real workspace member (from the root `Cargo.toml` `[workspace]
     members`).
   - `--test <target>`: `src/*/tests/<target>.rs` must exist.

2. **Coverage crate omission**
   - Every lib-bearing workspace member (its `Cargo.toml` has a `[lib]` or a
     `src/lib.rs`) must appear in a `cargo llvm-cov -p ...` list, unless it is in
     `COVERAGE_EXEMPT`.

Each finding is reported with the workflow `file:line`. Exit code is `1` on any
finding, `0` when clean.

## Usage

```sh
python3 verification/vacuous-oracle-check/check.py          # gate: exits 1 on findings
python3 verification/vacuous-oracle-check/check.py --list   # print what was discovered
```

`--list` prints the workspace members (with `lib` / `no-lib` tags), every
selector found with its location, and the coverage measured/lib-bearing/missing
sets. It always exits `0`.

## Wiring

Runs as the `vacuous-oracle-gate` job in `.github/workflows/rust.yml`
(ubuntu-latest, `python3 verification/vacuous-oracle-check/check.py`, no
`continue-on-error`).

## Adding an exemption

Only the coverage-omission check is exemptable. Add the crate name to
`COVERAGE_EXEMPT` in `check.py` **with a one-line reason**:

```python
COVERAGE_EXEMPT = {
    "wsc-component": "cdylib wasm component; all code is #[cfg(target_arch=wasm32)], nothing host-coverable",
}
```

Exempt a crate only when it has genuinely nothing measurable on the host
coverage runner (e.g. an all-`#[cfg(target_arch = "wasm32")]` `cdylib`). If a
crate has real host-runnable code, add it to the `cargo llvm-cov -p` list
instead of exempting it. There is no exemption for zero-match selectors: a
selector that matches nothing is always a bug in the workflow or the code.
