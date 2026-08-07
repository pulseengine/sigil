# Attestation × Cerisier — vocabulary mapping

Companion to [docs/security/attestation-trust-formalization.md](attestation-trust-formalization.md).
Where the predoc explains *why* sigil needs a Cerisier-derived sister
logic, this document specifies *which* Cerisier vocabulary each sigil
attestation type translates into. The intended audience is anyone
sketching the sister logic in detail; the document is descriptive, not
prescriptive — it documents the proposed mapping, not a committed
design.

## Cerisier vocabulary recap (one screen)

Recall from [docs/security/attestation-trust-formalization.md](attestation-trust-formalization.md)
and `/Users/r/tmp/cerisier-work/cerisier-notes.md`:

- **Sealing predicate `P_i`** for each enclave identity `i`, registered
  by the verifier *before* execution, capturing the semantic invariant
  the enclave preserves.
- **Universal contract `𝒱(w)`** — the value-relation / "safe to share"
  predicate, inherited from Cerise and extended with the sealed-value
  case.
- **Discharge lemmas `safe_to_unseal` and `safe_to_deinit`** — the
  former trades a sealed value plus identity witness for the underlying
  value with `P_i` discharged; the latter discharges enclave termination
  unconditionally, backed by the CHERI-TrEE memory-sweep primitive.
- **Capability points-to `a ↦ w` and register-bound `r ↦ᵣ w`** over the
  machine's address space and register file.
- **The frame rule of separation logic** — local proofs compose into
  whole-program claims; sealed values pass through frame contexts
  without losing their `P_i` obligation.

These are the building blocks. The mapping below proposes a translation
of sigil's attestation primitives into this vocabulary, with deliberate
extensions where Cerisier's scope (local, atemporal, in-machine) does
not cover sigil's (remote, time-indexed, content-addressed).

## Mapping table

| sigil primitive | Cerisier operator(s) | translation note |
|---|---|---|
| **Transformation attestation** (per pipeline stage; emitted by `meld → loom → synth → kiln`) | sealing-with-identity `P_stage` + frame composition | Each stage's transformation produces an artefact whose downstream semantic invariant is encoded as `P_stage`. The verifier registers `(stage_id, P_stage)` per stage; on successful chain verification, Cerisier's `safe_to_unseal` analog discharges that the artefact bytes satisfy `P_stage`. Chaining four such discharges along the pipeline is the frame rule: each stage's `P` survives passage through later stages' frames. The mismatch this row hides — Cerisier sees a single machine, sigil sees four separate processes over weeks — is the time-indexing gap (G1). |
| **SLSA Build L3 provenance** (emitted by `release.yml` + `scripts/publish.rs`) | sealing predicate over `(builder_id, predicate_invariants)` + `safe_to_unseal` per verification step | The provenance statement is a sealed object whose identity is `builder_id` (the hardened GitHub Actions runner under SLSA Build L3) and whose `P_builder` captures the SLSA `predicate` requirements (hermeticity, isolation, parameter-pinning). The verifier unsealing it gets the materials + builder identity, modulo the SLSA requirement that `predicate_invariants` are satisfied. The builder is structurally an "enclave" emitting sealed claims, even though no hardware TEE is involved. The non-trivial extension is that `builder_id` is a long-lived identity, not a per-execution enclave handle. |
| **Sigstore keyless** (OIDC → Fulcio cert → ephemeral keypair → Rekor log entry) | nested sealing `P_OIDC ⊗ P_Fulcio` + a temporal-witness predicate `P_Rekor^t` Cerisier does not natively express. **Identifies a real extension need.** | The trickiest row. Cerisier doesn't model time or remote PKI; sigil's keyless flow is fundamentally temporal (the Fulcio cert is valid for ~10 minutes; the Rekor entry's value is precisely that it pins the signature to a moment before cert expiry). Closest analog: nested sealing — the OIDC token is `P_OIDC`-sealed by the issuer, the ephemeral keypair carries a `P_Fulcio`-seal binding it to the OIDC identity, and the Rekor entry adds an inclusion-proof-bound predicate `P_Rekor^t` meaning "this seal existed at log index `t`." The sister logic must add a time-indexed predicate operator (G1) and a transparency-log inclusion predicate; neither lives in Cerisier. |
| **Ed25519 module signature** (`src/lib/src/signature/`) | direct sealing `P_module`; the keypair is the witness for `i = module_id` | The closest fit to Cerisier's local enclave case — once you accept the Ed25519 keypair (rather than a hashed code+data identity) as the source of `i`. The seal is the signature, the witness is the verification key, `safe_to_unseal` corresponds to a successful `Ed25519.verify` call yielding the underlying message with `P_module` discharged. The honest gap is that Cerisier's sealing is abstract and machine-mediated; Ed25519 is cryptographic and detachable, so the witness can be re-presented offline by anyone who saw it once. The sister logic needs to make the witness's distribution model explicit. |
| **SLH-DSA WIP** (FIPS 205 post-quantum signature; tracked at #46) | same as Ed25519 from Cerisier's POV — sealing is abstract; the underlying scheme is opaque. **But:** the transition between schemes is exactly where the predoc says the sister logic needs to bind. | Cerisier's sealing relation is scheme-agnostic, so SLH-DSA inherits the Ed25519 row's mapping verbatim *as long as* you stay within a single scheme. The interesting case is chains that mix Ed25519-sealed stages (pre-rotation, TS-019) with SLH-DSA-sealed stages (post-rotation, TS-020). Cerisier has no operator stating "the same identity `i` is sealed under two different schemes σ, σ', and these seals agree." This is gap G2, the load-bearing one for the PQ migration worked example. |

Every cell is filled. Translation notes are 2–5 sentences per row; the
Sigstore keyless and SLH-DSA rows carry the most extension weight.

## Where Cerisier's vocabulary is insufficient

This section is the load-bearing one. For each gap, state precisely
what's missing and what extension would close it.

### Time-indexed predicates (G1)

Cerisier predicates `P_i` are atemporal: registration happens once and
the predicate holds for the enclave's lifetime. Sigil chains have
explicit timestamps in Rekor entries and in-toto `buildPlatform` /
`metadata.buildFinishedOn` fields, and the trust meaning of a chain
depends on those timestamps (Fulcio cert validity windows, Rekor
monotonicity, freshness windows). A sister logic needs `P_i^t` indexed
by a totally-ordered time domain, with rules connecting `P_i^t` and
`P_i^t'` for `t < t'`. Iris' step-indexing `▷` is structurally similar
but measures execution steps, not wall-clock time; whether the lift is
semantically faithful is an open research question.

### Cross-scheme transition predicates (G2)

Ed25519 → SLH-DSA migration produces co-signed chains where consecutive
links sign under different schemes for the same logical identity.
Cerisier has no notion of "the same identity sealed under two different
schemes." The sister logic needs either:

(a) a scheme parameter on the sealing relation — `P_i^σ` for scheme
    `σ` — plus an introduction rule `P_i^σ ∧ P_i^σ' → P_i` capturing
    semantic agreement of the two schemes on the same identity (with
    the appropriate soundness obligation on `σ` and `σ'`); OR

(b) explicit `P_i^Ed25519 ⇒ P_i^SLH-DSA` reduction lemmas per migration
    event, with the predoc's worked example (TS-019 → TS-020) as the
    motivation. This option is heavier on bookkeeping but matches how
    operators reason about real migrations today.

Either form requires a notion of "scheme" first-class in the logic;
Cerisier as written has neither.

### Content-addressed artefact store (G3)

Cerisier's points-to `a ↦ w` is over machine memory: mutable,
hardware-checked, single-machine. Sigil artefacts live in OCI
registries, Sigstore Rekor, and local content-addressed stores; they
are immutable, globally-named-by-hash, and survive across machines
and time. The sister logic needs `digest(w) ↦ w` over a global
content-addressed store, plus a non-malleability lemma (no two
distinct artefacts share a digest, modulo the collision-resistance
assumption on the hash). Maps cleanly to Iris' authoritative-ghost-
state pattern, but the lift is not free: revocation and GC semantics
on a content-addressed store are subtle.

### Key-rotation (G4)

Cerisier has no `rotate(i_old, i_new)` primitive; its only revocation
primitive is the memory-sweep on `EDeInit`, which is local and
unconditional. Sigil's deployment includes legitimate key-rotation
events (operator rotates Fulcio root, project rotates Ed25519 module-
signing key, organisation migrates to SLH-DSA). The sister logic needs
a rotation operator with a proof obligation that the new key's `P_i`
matches the old key's — i.e. that rotation preserves semantic identity,
even though cryptographic identity changes. Without this, a rotated
chain has no formal trust-state mapping and verifiers fall back to
ad-hoc "trust both" or "trust newest" policies.

## Composition with TrustMee

TrustMee (`/Users/r/tmp/cerisier-work/trustmee-notes.md`) verifies
single-shot attestation results: a TEE hardware quote plus a signed
Wasm verification component is reduced to a signed EAR (EAT
Attestation Result). Where Cerisier reasons about a *chain* of sealed
values, TrustMee provides a *verified Wasm verifier* for each link.
The composition story:

- Cerisier's `P_i` for a sigil chain stage = "this stage's attestation
  was verified by a TrustMee-style verifier whose own attestation
  satisfies `P_i^verifier`."
- TrustMee's verifier emits a signed EAR; the downstream consumer
  treats the EAR as the witness needed to discharge `P_i` via the
  sister logic's `safe_to_unseal` analog.
- Full picture: TrustMee covers "trust the individual verification"
  (verifier-component soundness as engineering, no formal proof);
  the sister logic covers "trust the composition of N verifications"
  across the pipeline.

The two pieces fit at the seam where TrustMee outputs an EAR and the
sister logic accepts it as a witness. Neither alone suffices for
sigil's chain.

## Footnotes

- Both source papers (Cerisier arXiv 2604.13638, TrustMee arXiv
  2602.13148) were read in summary-only mode (search-engine fallback);
  see the notes files for the caveat. Cite the notes files, not the
  papers directly, until a real PDF read exists.
- This document supersedes the predoc's "Three operational gaps" with
  a more granular four-gap (G1–G4) framing. The predoc's "local vs.
  remote attestation" framing is partially absorbed into G1 (time)
  and G3 (content-addressed store); "no key rotation" is G4; the
  cross-scheme transition gap (G2) is new here, pulled from the PQ-
  migration worked example.
- Status: **draft.** Like the predoc, research-stage; the Cerisier-
  derived sister logic does not yet exist, and G1–G4 are the minimum
  extension surface a first sketch must cover.
