# selfhosted-guard — no fork PR reaches a self-hosted runner

Allowlist check over `.github/workflows`: every job's `runs-on` is a hosted
image, the fail-closed fork-guard expression (in a workflow whose triggers
are all trusted), or a matrix of hosted images. The rules and the rationale
are in the doc comment of `src/lib.rs`.

This crate is **excluded from the main workspace**. CI (`claim-check.yml`,
job "No fork PR reaches a self-hosted runner") builds it as a WASI component
and runs it under wasmtime:

```sh
cargo build --release --target wasm32-wasip2 --manifest-path verification/selfhosted-guard/Cargo.toml
wasmtime run --dir . target/wasm32-wasip2/release/selfhosted-guard.wasm --self-test
wasmtime run --dir . target/wasm32-wasip2/release/selfhosted-guard.wasm .
```

## Port from check.py

`check.py` is the original Python checker. It no longer gates CI. It stays
as the oracle of `tests/equivalence.rs`, which runs both on the same inputs
and requires identical stdout and exit code: the 21-case decision table, 29
extra inputs (27 single-file shapes, a multi-file tree, an empty tree),
the `--self-test` report and the live workflow tree. External controls (pulseengine/plant `examples/sigil`) match the rejection text, so
the text is part of the contract. The test needs `python3` with PyYAML and
fails, not skips, without it.

Known divergence, in rejection text only: PyYAML reads YAML 1.1, this reads
YAML 1.2, so a plain `yes`, `017` or `2001-12-14` prints as a string here.
The verdict should not change, because a hosted-image or fail-closed-form
string resolves to a string in both schemas; that argument is not
exhaustively tested.

`check.py` can be deleted once nothing needs the oracle; until then a change
to the rules is made in both and the equivalence test holds them together.
