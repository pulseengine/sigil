# `verification/rocq/` — translation-pipeline scaffolding (NOT a Rocq proof)

**Status:** unrealised. There is currently **no Rocq (Coq) formal proof**
in this directory. CV-22 ("Rocq proof — signature verification protocol
correctness") in `artifacts/cybersecurity/goals-and-requirements.yaml`
remains in `in-progress` status, pending an actual `.v` file with a
machine-checked proof.

This README is part of the 2026-04-30 audit honesty fix (finding C-3).

## What lives here today

- `pae.rs` — a Rust extraction of `compute_pae` from `src/lib/src/dsse.rs`,
  shaped for `coq-of-rust` translation. It is plain Rust with unit tests;
  it does not contain any Rocq (`.v`) source.
- `BUILD.bazel` — declares a `rocq_rust_verified_library` target named
  `pae_verified`. Today this target exercises **pipeline scaffolding only**:
  it confirms that the `coq-of-rust` translation can be invoked on the
  Rust source. It does **not** discharge any verification obligation,
  because no Rocq proof script is fed to the pipeline.

## What would need to happen to elevate this to a real proof

1. Author one or more `.v` files in this directory containing a Rocq
   formalisation of the PAE injectivity property (`forall t1 t2 p1 p2,
   (t1 <> t2 \/ p1 <> p2) -> compute_pae t1 p1 <> compute_pae t2 p2`),
   stated against the `coq-of-rust`-translated definition of
   `compute_pae`.
2. Wire those `.v` files into `BUILD.bazel` via `rules_rocq_rust` so the
   Bazel target type-checks the proof end-to-end (not merely compiles
   the translation).
3. Make the Bazel test step in `.github/workflows/formal-verification.yml`
   non-`continue-on-error` for this target (cf. audit finding C-7 in
   `audit/2026-04-30/findings.md`), and update CV-22 in
   `artifacts/cybersecurity/goals-and-requirements.yaml` from
   `in-progress` to `proved` only after step 2 lands.

Until all three steps are complete, treat any claim of "Rocq-verified
PAE" as aspirational. The Verus track in `src/lib/src/verus_proofs/`
covers the same property, but its proof body is also currently
admitted (see audit C-1).
