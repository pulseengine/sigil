# Changelog

All notable changes to sigil are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] — 2026-05-25

Security release. Closes two verification-bypass gaps in the keyless
verify path that allowed `wsc verify --keyless` to return exit 0 on
modules the cert holder did not sign. Both gaps were of the same
"load-bearing property never enforced" class — the verifier had
*structure* matching the intended checks but was missing the actual
hash / cross-reference comparisons.

### Fixed (security)

- **Artifact binding** (#135 / PR #136). `KeylessVerifier::verify`
  verified the Fulcio cert chain and Rekor SET but never recomputed
  the module hash or ECDSA-verified the signature against the leaf
  cert. A tampered module — byte flipped, signature section spliced in
  from a different artifact — returned exit 0. The new
  `KeylessSignature::verify_artifact_binding` strips the signature
  section, recomputes `SHA256`, and `verify_digest`s the signature
  under the leaf cert's SPKI. Wired as step 4 of `verify()`.
- **Rekor body binding (UCA-2)** (#135 / PR #136). The verify path
  proved the Rekor entry was logged by Rekor, but never decoded the
  entry's `body` to check that the logged `(hash, signature, public
  key)` triple actually referenced *this* bundle. An attacker holding
  any legitimate Fulcio cert could sign a malicious module and embed
  any unrelated public Rekor entry to pass verification — the original
  attack class re-emerges one layer up. The new
  `KeylessSignature::verify_rekor_body_binds_to_bundle` decodes the
  hashedrekord JSON body and asserts (a) `body.spec.data.hash.value ==
  hex(module_hash)`, (b) `body.spec.signature.content == signature`,
  (c) the leaf cert DER from `body.spec.signature.publicKey.content`
  byte-equals the bundle's leaf cert DER. Wired as step 5 of `verify()`.

Both checks emit `WSError::VerificationFailed` with a `log::error!`
identifying the specific mismatch; the error variant deliberately does
not discriminate, so an attacker cannot probe which leg of the check
rejected their forgery. Seventeen new tamper-rejection unit tests in
`src/lib/src/signature/keyless/format.rs` cover byte-flip,
signature-substitution, hash-substitution, cert-substitution,
missing-signature-section, empty-chain, artifact-hash mismatch,
signature-content mismatch, public-key mismatch, unsupported
kind / apiVersion / hash-algorithm, garbage / non-JSON body, and
uppercase-hex-hash acceptance.

Downstream consumers (synth #140 case 3) that asserted the tampered-
rejection property as an xfail can flip back to a positive assertion
once they pick up this release.

### Documented

- New STPA-Sec report at `docs/security/stpa-keyless-2026-05-25.md` enumerating
  the five UCAs identified in the analysis that produced this release:
  UCA-1 (Rekor inclusion proof never run on verify path), UCA-2 (fixed
  here), UCA-3 (cert validity bound to attacker-pickable
  `integrated_time`), UCA-4 (cache hit skips SET re-verify without
  bundle-equality check), UCA-5 (audit log records hash from
  silently-discarded serialize error). Each UCA includes a code
  citation, the STPA-4 questions, a loss scenario, suggested fix, and
  the verification trail that confirms the finding against HEAD.
  UCA-1, UCA-3, UCA-4, UCA-5 remain open and are tracked as follow-up
  issues.

## [0.9.0] — 2026-05-20

Cleanup-cycle release: a criterion benchmark regression gate and a
fail-closed hardening of Sigstore certificate pinning. Minor-versioned
because the keyless client constructors now return a `Result` — a
breaking change for code that uses `wsc` as a library.

### Added

- **Criterion benchmark regression gate** (#89, PR #122). New
  `.github/workflows/benchmarks.yml`: a fast sample-reduced sanity run
  on every PR touching `src/lib`, plus a full nightly run that uploads
  the criterion output as an artifact. The benchmark code already
  existed (`src/lib/benches/verification_benchmarks.rs` — four groups:
  Ed25519 verify, DSSE parse+verify, Merkle validation, cert-chain
  validation); this adds the CI gate that turns it into a regression
  guard for the signature-verification hot path.

### Changed (breaking)

- **Sigstore certificate pinning is now fail-closed** (#95, PR #123).
  TLS-layer pin enforcement was already in place — `PinnedCertVerifier`
  implements `rustls::ServerCertVerifier`, so a pin mismatch aborts the
  handshake. The residual gap was in agent *construction*:
  `create_agent_with_optional_pinning` silently fell back to an
  unpinned standard agent on failure, and the `RekorClient` /
  `FulcioClient` constructors swallowed even the hard error. Now,
  whenever a non-empty pin set is supplied, pinning is mandatory —
  construction failure propagates as an error, never a silent
  downgrade. This closes audit finding C-4.
  - **API change:** `FulcioClient::{new, with_url}` and
    `RekorClient::{new, with_url}` now return `Result<Self, WSError>`;
    the `Default` impls (which assumed an infallible `new()`) are
    removed. Direct library callers must handle the `Result`.
  - `WSC_REQUIRE_CERT_PINNING` is redundant for the Sigstore
    production path (pinning is unconditional there); retained for
    backwards compatibility, documented as deprecated.
  - Corrects the v0.8.4 "Audit observation": pinning **is** enforced
    at the rustls handshake layer today, not post-handshake.

### Deferred

- **#88 — Kani harness for the signature-section parser.** The varint
  and DSSE harnesses already exist; the signature-parser harness is
  blocked on `SignatureForHashes::deserialize` building an 8 KiB
  `BufReader` internally, which is intractable for Kani's bounded
  model checker (a single one-symbolic-byte harness ran 24+ minutes).
  Needs a `deserialize` refactor exposing a `BufRead`-taking entry
  point. Tracked on #88.
- **#46 — SLH-DSA / FIPS 205 post-quantum backend.** Blocked upstream:
  usable `slh-dsa` versions need either a `signature` pre-release or
  `signature 3.x`, and the matching `ecdsa 0.17` / `p256 0.14` crates
  have no stable release yet — only release candidates. Integrating
  now would put RC crypto on the production Sigstore signing path.
  Tracked on #46 with the precise unblock condition.

### Closed without code

- **#91 — MIRAI abstract-interpretation prototype.** The MIRAI
  repository is archived (last commit 2024-08, pinned to an
  18-month-old nightly); its property classes are already covered by
  the existing Kani and Verus harnesses.

### Contributors

PRs in this release: #121 (gitignore audit notes), #122 (benchmark
gate), #123 (cert-pinning fail-closed).

[0.9.0]: https://github.com/pulseengine/sigil/compare/v0.8.4...v0.9.0

## [0.8.4] — 2026-05-19

Hotfix release. Single-commit content: rotate the pinned Fulcio leaf
SPKI to the new Sigstore-issued cert.

### Why this exists

v0.8.3 tagged cleanly and shipped to crates.io, but the
`release.yml::Build & Release WASM Component` job failed (and so the
GitHub Release object for v0.8.3 was never created) because Sigstore
rotated the `fulcio.sigstore.dev` leaf certificate between the pin
set's last update (2026-04-14, leaf `6611c54b...`) and the v0.8.3
release date (2026-05-16, observed leaf `e30da317...`). The keyless
signing flow correctly fail-closed on the pin mismatch.

This release bumps the version, lands the pin fix from PR #119, and
re-triggers `release.yml` at a tag (v0.8.4) whose code does contain
the new pin. The crates.io packages already at 0.8.3 are unaffected;
v0.8.4 will publish over them as the canonical version going forward.

### Changed

- `src/lib/src/signature/keyless/cert_pinning.rs` —
  `FULCIO_PRODUCTION_PINS` adds the new leaf SPKI
  `e30da317897121cb8fba4b1285d4d51207dfbe6272c245bc1c19694317658275`.
  Verified by direct `openssl s_client` fetch; chain identity
  (subject CN, issuer `Google Trust Services WR3`) cross-checked.
  Previous leaf retained for transition / rollback safety. GTS WR3
  intermediate pin and Rekor leaf pin both unchanged and re-verified.

### Audit observation

The v0.8.3 release-blocking failure provided strong evidence that
audit C-4 (issue #95) was partly mis-framed: cert pinning **is**
enforced today on the keyless HTTP path (post-handshake check, fail-
closed), even though it is not enforced at the rustls handshake
layer. The right framing for #95 is "move enforcement to the
handshake layer for defense-in-depth", not "enable enforcement".

### Operational follow-up (issue thread)

A scheduled "compare live SPKI vs pinned set" job would surface the
next Sigstore rotation **before** it blocks a release rather than
after. Tracked as a follow-up to #117 (already filed and closed by
this PR), not blocking.

### Contributors

PRs in this release: #119 (Fulcio pin rotation).

[0.8.4]: https://github.com/pulseengine/sigil/compare/v0.8.3...v0.8.4

## [0.8.3] — 2026-05-16

Audit-followup continuation. Closes the residual security-ignore-list
entry from v0.8.2, restructures the Kani matrix masking pattern, and
lands a second Verus proof attempt. No public-API changes; mostly
hygiene-and-honesty work.

### Security

- **Bump regorus 0.2.8 → 0.10 to fully clear RUSTSEC-2026-0097**
  (PR #115). The audit fix in v0.8.2 bumped `rand` 0.9.x to 0.9.4 but
  left the residual `rand 0.8.5` (transitive via regorus) under an
  `--ignore RUSTSEC-2026-0097` flag in `supply-chain.yml` + `deny.toml`.
  regorus 0.10 drops the rand 0.8.5 transitive entirely; both ignore
  entries removed. Net effect: `cargo audit` returns 0 vulnerabilities
  (the only remaining entry is `rustls-pemfile`, which is unmaintained
  upstream and stays in the ignore list pending upstream deprecation).
- **Surfaced an out-of-band finding: Sigstore Fulcio cert rotation**
  invalidated sigil's pinned fingerprints (filed as issue #117). The
  pin set in `cert_pinning.rs::fulcio_production()` is stale as of
  2026-05-16; the keyless integration test catches this when run.
  Resolution scope: update the pin set + add a monitoring job. Not
  blocking this release because audit C-4 (issue #95) documented that
  pinning is currently warn-only — the mismatch is logged, not
  fail-closed.

### Honesty

- **Second Verus admit attempt: `theorem_pae_injective_on_types`**
  (PR #116). Replaces `assume(false)` with an explicit ~70-line proof
  using `Seq::add` indexing axioms and length-additive structural
  reasoning, building on PR #108's discharge of `lemma_le64_injective`.
  The proof has not yet been validated by Verus — CI's Bazel-side
  toolchain dependency on Nix was unavailable on the run that would
  have checked it, and the Verus job carries `continue-on-error: true`
  per audit C-1. Even if Verus eventually rejects the attempt, the
  structured `assert` chain is a substantive improvement on the bare
  admit and gives the next attempt a concrete starting point.
- **Kani matrix mask is now per-job and documented** (PR #112). The
  filter for `wasm_module` was renaming-bug — it pointed at a module
  named `tests` that doesn't exist; the real module is `component_proofs`.
  Filter fixed. The unwind-loop failures that came out once the filter
  matched real harnesses (in `wasm_module`, `dsse`, `merkle`, `format`)
  are now masked per-entry via a `tolerate_failure` matrix field, with
  inline diagnostic comments explaining what the next attempt needs
  (per-harness `#[kani::unwind(N)]` or rewriting equality checks).

### Documentation

- **Cerisier formalization companion docs** (PR #114) added to
  `docs/security/`:
  - `attestation-cerisier-mapping.md` — translates each sigil
    attestation primitive into Cerisier's program-logic vocabulary,
    identifies four extension gaps (G1 time-indexed predicates,
    G2 cross-scheme transitions, G3 content-addressed store,
    G4 key rotation).
  - `attestation-trust-scenarios.md` — three concrete trust-evolution
    scenarios (cross-scheme PQ migration, admits in proof chain, key
    rotation) with proposed Cerisier-style judgements.

  Companion blog post on pulseengine.eu:
  *"Reasoning about attestation chains: from TrustMee to Cerisier"*
  (published 2026-05-11).

### Deferred (still tracked)

- **#117** — Sigstore Fulcio cert pin rotation (new this release).
- **#95** — enforce SPKI cert pinning at the TLS layer (audit C-4).
- **#79** — `no_std` verifier path for embedded / cFS targets.
- **#46** — post-quantum SLH-DSA backend.
- **#91** — MIRAI abstract-interpretation prototype.
- **#88 follow-up** — extend Kani harness coverage beyond varint;
  needs per-harness `#[kani::unwind]` for the masked entries.
- **Audit C-1 (further)** — discharge the remaining Verus admits
  (`theorem_pae_injective_on_payloads`, `theorem_domain_separation`,
  `theorem_content_type_separation`, plus the merkle_proofs.rs admits).

### Contributors

PRs in this release: #112 (Kani matrix), #114 (Cerisier docs),
#115 (regorus bump), #116 (Verus proof attempt). #111 (criterion
benches, implements #89) also landed in this cycle but is not
release-coupled.

[0.8.3]: https://github.com/pulseengine/sigil/compare/v0.8.2...v0.8.3

## [0.8.2] — 2026-05-11

Audit-followup patch release. Clears three supply-chain advisories,
repairs CI hygiene from the 2026-04-30 audit, discharges one previously-
relabelled Verus admit, and repairs a broken fuzz target. No public-API
changes.

### Security

- **Clear RUSTSEC-2026-0097 (`rand` 0.9.x line)** — bumped `rand`
  0.9.2 → 0.9.4 via `cargo update`. The residual `rand 0.8.5`
  transitive (via `regorus`, the OPA / Rego policy engine) cannot be
  patched until upstream `regorus` releases with `rand = "0.9"+`;
  `wsc` does not use custom rand loggers so the unsoundness does not
  affect us. `deny.toml` already carried this justification; the
  `cargo audit` step in `supply-chain.yml` now matches. (PR #110,
  fixes #102.)
- **Clear RUSTSEC-2026-0114 (`wasmtime` panic on table allocation)** —
  bumped `wasmtime` 43.0.1 → 43.0.2 via `cargo update`. (PR #110.)
- **Clear RUSTSEC-2026-0104 (`rustls-webpki` CRL parsing panic)** —
  bumped `rustls-webpki` 0.103.12 → 0.103.13 via `cargo update`.
  (PR #110.)

### Honesty

- **Discharge first Verus `assume(false)`** — `lemma_le64_injective`
  in `src/lib/src/verus_proofs/dsse_proofs.rs` is now an actual proof,
  not a relabelled specification. The proof uses `assert ... by(bit_vector)`
  on the byte-mask equality and explicit unfolding of `spec_le64`'s
  indexed bytes. The other Verus admits remain marked SPECIFICATION
  ONLY per audit C-1; the Verus CI job keeps its `continue-on-error`
  mask until more admits are discharged. (PR #108, refs audit C-1.)
- **Lift Kani `wasm_module` matrix mask** — the matrix entry was
  filtering on `wasm_module::tests`, which matched zero harnesses
  (Kani exits non-zero on no-match). The harness module is actually
  `wasm_module::component_proofs`. Updated the filter and lifted
  `continue-on-error` for that entry. The single harness
  (`proof_component_module_header_mutual_exclusivity`) runs cleanly.
  Kani `merkle` and `format` masks retained with per-harness
  diagnostic comments. (PR #112, refs audit C-7.)

### CI hygiene

- **Cargo Deny step hardening** — remove `|| true` that was
  silently swallowing install failures; add explicit step names;
  reword the rationale comment to reference `rust-toolchain.toml`
  and `rules_unprivileged_userns_clone` (the actual root cause that
  PR #106 addressed). (PR #107, fixes #103.)

### Fixed

- **Repair `fuzz_public_key.rs`** — the target referenced four APIs
  that had been removed from `SecretKey` / `PublicKey`
  (`from_openssh`, `from_any`). Rewritten against the current surface
  with round-trip preservation, PEM, and DER oracles. Module-level
  comment documents the dropped APIs to prevent reintroduction.
  (PR #109, original flag from audit PR #98.)

### Deferred

The following audit items remain open and are tracked separately:

- **C-4 / #95** — enforce SPKI cert pinning at the TLS layer
  (ureq → rustls-direct migration).
- **M-1 ff / #79 comment** — `no_std` verifier path for embedded /
  cFS targets.
- **C-1 (partial)** — discharge the remaining Verus admits
  (`theorem_pae_injective_on_types`, `theorem_pae_injective_on_payloads`,
  `theorem_domain_separation`, `theorem_content_type_separation`,
  `lemma_leaf_node_domain_separation`).
- **Kani `merkle` / `format` mask removal** — depends on harness
  rework (sha2 unwind > 4, SMT state-space blow-up).
- **#88 follow-up** — extend Kani harness coverage to more parser
  paths beyond varint / DSSE.
- **#89** — criterion benches CI integration (the bench harness lands
  in **PR #111**; CI gating deferred to a follow-up).
- **#46** — post-quantum SLH-DSA signature backend.
- **#91** — MIRAI abstract-interpretation prototype.

### Contributors

PRs in this release: #107 (cargo-deny), #108 (Verus discharge), #109
(fuzz repair), #110 (RUSTSEC bumps). Companion work landing on
0.8.2+next: #111 (criterion benches, #89), #112 (Kani mask lift).

[0.8.2]: https://github.com/pulseengine/sigil/compare/v0.8.1...v0.8.2

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
