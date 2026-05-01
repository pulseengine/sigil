# Changelog

All notable changes to sigil are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] — 2026-04-30

Audit-driven hardening release. Closes 26 of 33 findings from the
2026-04-30 14-perspective audit of the repository (`audit/2026-04-30/`).
No public-API changes. Two findings (cert-pinning enforcement, no_std
verifier) are deferred to issue #95 and issue #79 respectively.

### Security

- **JWT algorithm-confusion hardening** (audit C-6). The OIDC parser now
  validates the JWT `alg` field against an allowlist of asymmetric
  algorithms (RS256/384/512, ES256/384/512) **before** any payload claim
  is parsed. `none` and HMAC variants (`HS256/384/512`) are rejected
  outright. Closes a textbook algorithm-confusion path where forged
  tokens could be trusted by `parse_issuer()` / `parse_identity()`.
- **OIDC issuer-validation env var clarified** (audit H-4). The
  `WSC_EXPECTED_OIDC_ISSUER` env var no longer treats an empty value as
  "disable validation". Disabling validation now requires an explicit
  `WSC_DISABLE_OIDC_ISSUER_CHECK=1`.
- **Rekor SET cache poisoning prevention** (audit H-5). Rekor entries
  with empty `signed_entry_timestamp` or empty `inclusion_proof` are
  now rejected before any cache write, so subsequent verifications
  cannot hit a cache populated by a partial Rekor response.
- **Single-owner zeroize discipline** (audit M-5, M-6). `OidcToken` is
  no longer `Clone`. JWT payload buffers are wrapped in
  `Zeroizing<String>` so they zero on every return path.

### Hardening

- **Bounded WASM section iteration** (audit H-1). New
  `MAX_SECTIONS = 4096` constant in `src/lib/src/wasm_module/mod.rs`
  caps the parser; `WSError::TooManySections(usize)` returned beyond.
- **Bounded x509 chain depth** (audit H-2). New
  `MAX_CHAIN_DEPTH = 8` constant gates `verify_cert_chain` in
  `src/lib/src/signature/keyless/format.rs` before x509 / WebPKI
  invocation; `WSError::ChainTooDeep(usize)` returned beyond.
- **DSSE envelope fuzz target added** (audit H-7). New
  `fuzz/fuzz_targets/fuzz_dsse_envelope.rs` with a parse → serialise →
  re-parse equality oracle, registered in `fuzz/Cargo.toml`.
- **`PAYLOAD_TYPE_SLSA` mime-type fix** (audit H-6). The constant in
  `src/attestation/src/dsse.rs` is now
  `"application/vnd.slsa.provenance+json"`, no longer colliding with
  `PAYLOAD_TYPE_INTOTO`.

### Honesty

- **Verus `theorem_*` admits relabelled** (audit C-1). Verus functions
  ending in `assume(false)` in `src/lib/src/verus_proofs/dsse_proofs.rs`
  and `merkle_proofs.rs` are now annotated as **SPECIFICATION ONLY**
  with explicit doc-comments stating the open proof obligation. No
  proof was discharged in this release; the labelling is now honest.
- **Lean status table corrected** (audit C-2). `lean/Ed25519.lean`
  status table at the top of the file matches the proof bodies.
  `verification_equation_complete` and `basepoint_prime_order` are
  marked `sorry` / open. `verification_equation_sound` (which IS
  proved) is unchanged.
- **Rocq pipeline status clarified** (audit C-3). New
  `verification/rocq/README.md` states the directory holds Rust
  extraction stubs only; no `.v` files have been written.
- **Phantom DO-178C / ISO 26262 trace claims softened** (audit L-3).
  `SECURITY.md` now distinguishes between modelled compliance frames
  (ISO/SAE 21434, IEC 62443, CRA, UNECE R155-156) and aspirational ones
  (DO-178C, ISO 26262).
- **Artifact `implementation-status` field added** (audit L-4). Sample
  of 7 `approved`-status SC/CCs now carry `implementation-status:
  design-only` (e.g. SC-26 SCT cryptographic verification).

### CI / Build

- **Audit C-7 partially closed** — Bazel CI now ATTEMPTS to run tests
  (`bazel test --build_tests_only //src/...`); previously only
  `bazel build //...` was invoked. The `continue-on-error: true` mask
  remains on formal-verification jobs but is now **per-job and
  documented**: each masked job carries an explicit `# WIP — see audit
  C-X` comment naming the blocking finding. Verus jobs cite C-1 (admits
  not yet discharged); Kani format/merkle/wasm_module cite C-7 partial
  closure (varint and dsse pass cleanly today and could be ungated
  selectively in a follow-up); Rocq cites C-3 (directory is a stub);
  the new Bazel `Test` step cites C-7 partial closure (macOS Bazel
  toolchain regressions observed in this batch). The audit's principle
  is now in place: masking is a tracked WIP list, not a blanket coverup.
- **Path filters added to `rust.yml`** (audit M-9). Doc-only changes
  no longer fire the cross-OS cargo + bazel matrix.
- **Memory-profile and TPM2 tests gated to `workflow_dispatch` +
  nightly** (audit M-8). Removes per-PR cost of two expensive jobs.
- **`@main` action references pinned** (audit M-7).
  `pulseengine/rivet/.github/actions/compliance` now pinned to
  `@v0.6.0`.
- **Crate-version drift collapsed to a single source** (audit H-8).
  `Cargo.toml`, `MODULE.bazel`, and `src/cli/BUILD.bazel` all read the
  same version (this release: 0.8.1). Comments cross-reference
  `Cargo.toml` as canonical.
- **Dual-publish race fixed** (audit H-9). `release.yml`'s duplicate
  `publish-crates` job removed; `publish-to-crates-io.yml` is now the
  sole crates.io publisher with the `pulseengine/sigil` repo guard.
- **Dockerfile.bytehound disclaimer** (audit L-6). Top-of-file note
  declares the image is intentionally outside the Nix flake's
  hermeticity guarantee.

### Developer experience

- **`build.rs` declares the `kani` cfg** (audit M-10). Five
  `unexpected cfg condition` warnings on every `cargo build` are
  gone.
- **Stale `wasmsign2` references in user-facing docs corrected**
  (audit L-1). `docs/keyless.md` and `docs/bazel-build-guide.md` now
  use the current binary name and repo URL.
- **README gained a "Quick Try" section** (audit L-2). Eight-byte
  WASM round-trip lets new contributors validate their build without
  any artefact.
- **CLI verb normalised** (audit M-11). `verify_matrix` →
  `verify-matrix` for tab-completion consistency.
- **CLI help gained `EXAMPLES:` blocks** (audit L-5). `keygen`,
  `sign`, `verify`, and `bundle create` show invocation patterns
  inline.

### Deferred

The following audit findings require larger work and are tracked
separately:

- **C-4 — enforce SPKI cert pinning** at the TLS layer. Requires
  migrating off `ureq` to a client that exposes
  `rustls::ServerCertVerifier`. Tracked at issue #95.
- **M-1 / M-2 / M-3 / M-4 — `no_std` verifier path** for embedded
  / cFS targets. Tracked at issue #79 (per-component cFS attestation)
  with audit context appended in the comments.

### Contributors

This release was driven by a parallel multi-agent audit + fix-PR
pipeline. PRs in this release: #96 (STPA-Sec / docs), #97 (hygiene),
#98 (parser hardness), #99 (formal-verif honesty + CI), #100
(keyless / OIDC hardening).

[0.8.1]: https://github.com/pulseengine/sigil/compare/v0.8.0...v0.8.1
