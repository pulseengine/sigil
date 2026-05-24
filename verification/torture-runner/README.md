# torture-runner — I/O fault-injection for `wsc-verify-core`

Curl-style torture testing adapted for Rust's error model. Runs each
target parser/verifier against every byte-offset fault point and asserts
no panic.

This crate is **excluded from the main workspace** (run via
`cargo run --manifest-path verification/torture-runner/Cargo.toml --bin <name>`).

## Why I/O fault injection, not allocation fault injection

The classic curl torture model overrides `malloc` to fail on the Nth
call, exercising every out-of-memory path in C code. **That model does
not transfer cleanly to Rust.** Safe-Rust collection APIs
(`Vec::with_capacity`, `Box::new`, `String::from`, …) abort the process
via `handle_alloc_error` on null-return from `GlobalAlloc` — they do
not return `Result<_, AllocError>`. There is no stable pathway from
"alloc returned null" to a clean `Err` propagation in safe Rust, so
"fail Nth alloc" in Rust produces aborts, not the `Result` error-path
exercise curl actually got out of malloc-failure injection.

The Rust analog is **I/O fault injection**. Every `?` on `std::io::Read`
and every error variant in `WSError`/`CoreError` is a reachable error
path *by design*. A `Read` impl that returns `Err` at a chosen byte
offset exercises the same kind of "every error branch reached" curl's
torture model produces — on the surface where Rust actually surfaces
errors.

## How the runner works

For target `f(reader) -> Result<_, _>` and a valid byte input of
length `N`:

1. The runner runs `f` once per fault point `0..=N`.
2. Each run feeds `f` a `FaultyReader` that returns the first `k`
   bytes cleanly, then `Err(ErrorKind::Other)` on every subsequent
   call.
3. The runner asserts that **every** run returns cleanly — `Ok(_)` if
   `f` consumed less than `k` bytes, `Err(_)` otherwise. A panic from
   any run is a torture failure.

`ErrorKind::Other` (not `Interrupted`) is deliberate: `std::io`
auto-retries `Interrupted` in several stdlib wrappers (`BufReader`,
`read_to_end`, etc.), which would silently swallow the injected fault
into an infinite loop. `Other` is terminal — the target's error path
actually fires.

## Running

```sh
cd verification/torture-runner

cargo run --bin torture_module_parser
# [Module::init_from_reader + iterate] input 15 bytes
#   — 16 fault points exercised: ok=1 err=15 panic=0
# ✔ Module::init_from_reader survived I/O torture at every byte offset.

cargo run --bin torture_sig_parser
# [SignatureForHashes::deserialize] input 7 bytes
#   — 8 fault points exercised: ok=1 err=7 panic=0
# ✔ SignatureForHashes::deserialize survived I/O torture at every byte offset.
```

`ok=1` is the no-fault sanity-check run (`fail_at >= input.len()`);
`err=N` is each fault offset returning cleanly through the target's
error path; `panic=N` would be the torture failure condition — zero is
the gate.

## Phase 1 scope and follow-ups

This PoC demonstrates the harness works end-to-end on two real
verification-core entry points. Natural extensions:

- **More targets.** `PublicKey::verify_multi` (needs a real signed-module
  fixture), `Module::init_from_reader` with larger / multi-section
  inputs, every public `*_from_reader` entry in the verify-core surface.
- **Filesystem / syscall torture.** A `FaultyOpenOptions` for
  `secure_file::read_secure`, so the "file permissions check fails
  partway through key load" path is exercised.
- **Network torture for `wsc`.** A fault-injecting `ureq::Transport`
  for the keyless Fulcio/Rekor calls in `wsc` (outside this crate
  since `wsc-verify-core` deliberately has no network layer).
- **CI gate.** Wire `torture_*` binaries into a workflow that runs them
  on each PR — surviving torture becomes a non-negotiable acceptance
  criterion, the same way the existing mutation-test gate is.

The runner deliberately stays small (~110 lines of `lib.rs`) so the
fault-injection mechanism itself is auditable.
