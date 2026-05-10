# Attestation-Trust Formalisation — Pre-Document

**Status:** Draft / pre-document. Tracked as CG-14 / CR-25 / CD-28.
**Owner:** TBD.
**Last updated:** 2026-04-28.

## Source caveat

This document is built on two `WebFetch` summaries of the arXiv abstract
and HTML rendering of *Cerisier: A Program Logic for Attestation in a
Capability Machine* (arXiv 2604.13638). The summarising model is small
and may have paraphrased or hallucinated specific notation (e.g. the
literal form of Theorem 3.1 or the Secure Outsourced Computation
example). Before any of this informs publication, a contract-binding
spec, or an implementation effort, the paper needs an end-to-end read.
Claims marked *(verbatim)* below were quoted by the summariser; treat
even those as second-hand until verified.

## Motivation

Sigil today produces a flat chain of transformation attestations
(`meld → loom → synth → kiln`) where each link carries a Sigstore-keyless
OIDC + Fulcio + Rekor signature plus SLSA L4 provenance. Verification
walks the entire `TransformationAuditTrail` linearly. There is **no
formal logic for how trust evolves across the chain** — every consumer
question reduces to "did each link verify, yes/no?" with no compositional
answer for questions like:

- "Stage *N* signed under Ed25519 *before* a key rotation; stage *N+1*
  signed under SLH-DSA / FIPS 205 *after*. What memory-safety claim
  about the final artefact survives?"
- "Stage *N*'s attestation references a Verus proof that admits a lemma
  about an external function. What is the residual trust?"
- "I trust the Rocq rules of `rules_rocq_rust`. The build attests that
  *synth* produced the ARM blob from Verus-verified Rust. What is my
  trust state for the blob's memory-safety properties?"

These are exactly the questions a program logic for attestation is
designed to answer. The relevant external work is *Cerisier* (Rousseau,
Carnier, Van Strydonck, Keuchel, Devriese, Birkedal — arXiv 2604.13638,
April 2026), which provides a program logic for modular reasoning about
trust evolution after attestation, mechanised in Iris and Rocq.

## (a) What Cerisier actually is

- Built on **Iris separation logic**, fully **mechanised in Rocq**.
- Extends the **Cerise** capability-machine program logic with
  **CHERI-TrEE**'s enclave primitives.
- Targets **local enclave attestation**. The authors *explicitly* state:
  "Remote attestation (cryptographically signed certificates) is
  mentioned but not formalised; only local attestation is addressed."
  This single sentence reframes everything below.

### Primitives (literal where the WebFetch summary quoted them)

| Primitive | Form |
|---|---|
| Capability | `(p, b, e, a)` — permission, bounds `[b,e)`, address |
| Sealing capability | `[sp, ob, oe, oa]` |
| Sealed capability | `{sc}oa` — opaque, immutable, identity-bound via otype |
| Iris propositions | `iProp`, separating conjunction `P ∗ Q`, magic wand `P −∗ Q`, persistent `□P`, later `⊳P` |
| Points-to | `r⤇w` (register), `a↦w` (memory), `[b,e)↦l` (range) |
| Logical relation | `𝒱(w)` — "safe to share" |
| Universal contract | (Theorem 3.1, *as paraphrased by summariser*) `⊢ {∗r∈RegName(∃w. r⤇w ∗ 𝒱(w))} ↝ ∙` — if every register holds a safe-to-share value, the machine executes safely |
| Sealing predicates | Bind an identity predicate `P` to an otype: "this sealed value comes from an enclave whose identity satisfies `P`" |

### Worked example (per the summariser)

*Secure Outsourced Computation (SOC).* A trusted client invokes
untrusted adversary code which initialises an enclave that computes the
result `42`. The enclave obtains attestation keys `(kp, ks)`, computes
`r = 42`, returns `Attest(r, ks)` with `kp`. The client verifies the key
matches identity `IDsoc` and the message signature, then asserts the
attested value equals `42`.

## (b) Mapping Cerisier primitives to sigil's actual primitives

Sigil's canonical attestation schema lives in
[`src/attestation/src/lib.rs`](../../src/attestation/src/lib.rs). The
relevant types are `TransformationAttestation`, `InputArtifact`,
`AttestationSignature`, `SignatureStatus`, `TransformationAuditTrail`.

| Cerisier | Sigil's actual primitive | Mapping quality |
|---|---|---|
| Capability `(p,b,e,a)` | `InputArtifact { artifact, signature_status, signature_info }` | **Loose analogy.** Both encode "I have access to X under conditions Y", but capabilities are *runtime-checked by hardware over shared memory*; sigil's are *cryptographic claims over content-addressed bytes*. |
| `r⤇w` register holds word | `inputs: Vec<InputArtifact>` (this transformation depends on these inputs) | **Decent.** Both name dependencies. |
| Sealing predicate (otype ↔ identity *P*) | `AttestationSignature.signer_identity` (Fulcio OIDC identity) | **Strongest mapping.** "OIDC identity X ⇒ build pipeline Y" is structurally identical to "otype Z ⇒ enclave identity W". This is the genuine bridge. |
| Sealed capability `{sc}oa` | DSSE-signed attestation | **Decent operationally** (both opaque / immutable / identity-bound), **but the freshness model is different** — sealed capabilities are alive in the verifier's memory; DSSE envelopes are dead bytes from another machine months ago. |
| Logical relation `𝒱(w)` "safe to share" | *Nothing.* Sigil has no logical-relation analogue. | **Pure gap.** |
| Iris `P ∗ Q` separating conjunction | *Nothing.* Sigil verifies attestation chains by walking them, not by composing local proofs. | **Pure gap.** |
| Universal contract for unknown code | *Nothing.* No notion of "worst-case trust I retain about a stage I cannot inspect". | **Pure gap.** |
| Frame rule | *Nothing.* Each end-to-end verification re-walks the whole `TransformationAuditTrail`. | **Pure gap — the one that matters most.** |
| Points-to `a↦w` over machine memory | SHA-256 content-addressed artefact lookup | **Wrong model entirely.** Cerisier memory is mutable, hardware-checked, single-machine. Sigil's "memory" is an immutable global content-addressed store across time and machines. |

## (c) Where the gap matters, in order of severity

### 1. Local vs. remote attestation is not a small thing

Cerisier's reasoning chain — "I hold a sealed capability with otype `o`,
I know `o ↦ P`, therefore the value satisfies `P`" — depends on
operational state the sigil verifier does not have. Cerisier's enclave
attestation works because the verifier sees the sealing capability, the
otype, and the identity predicate **in the same memory at the same
time**: the runtime mediates. Sigil's verifier sees a JSON envelope
detached from the signing environment by months, networks, and possibly
air gaps.

Bridging this needs a new model of attestation-as-token-that-survives-detachment,
which Cerisier does not provide.

### 2. No time, no revocation, no key rotation

Cerisier's SOC example is a single execution. The PQ migration scenario
that motivates this work — *"stage N (Ed25519, pre-rotation) ⋈ stage
N+1 (SLH-DSA, fresh)"* — has no analogue in Cerisier's model. The logic
has no time index, no concept of "this sealing predicate was valid at
time *t* but not at time *t'*", no revocation. This is exactly the
engineering question sigil needs answered, and it is the question
Cerisier as written cannot answer.

### 3. The WIT-as-capability mapping is structurally appealing but operationally distant

WIT interfaces are typed and unforgeable at runtime *within a wasmtime
instance*. They become Cerisier-style capabilities only inside that
single runtime — exactly the local-attestation regime. Across the
**build** pipeline, there is no shared runtime: each stage produces
bytes, signs them, and walks away. So WIT-↔-capability is a real mapping
for **runtime composition**, but **not for the build-time attestation
chain that is the load-bearing part of sigil**.

## Conclusion

The strategic direction is right; the cost estimate in the original
intake brief is wrong by roughly an order of magnitude.

The honest framing is:

> Cerisier is a strong **template** — its sealing-predicate-with-identity
> primitive, its universal-contract-for-untrusted-code pattern, its
> frame-rule-based modular reasoning — for what a sister logic over
> **content-addressed artefact stores with time-indexed trust predicates**
> would look like. That sister logic does not exist. Building it is a
> real research contribution, not an engineering port. The PQ migration
> is the right forcing-function example for that research, but it is a
> *paper-driving* example, not a *next-quarter-engineering* example.

This actually *strengthens* the publication case: the contribution is
not "compose two existing systems (TrustMee + Cerisier)" but **"lift
a successful local-attestation logic to the remote / time-indexed
setting that real supply chains live in, with sigil + TrustMee as the
artefact"**. Stronger pitch for PLDI / OOPSLA / CCS 2027.

## Implications for the action plan

The original intake brief listed six actions. Re-prioritised in light
of the gap analysis:

0. **(NEW, gating)** Sketch the sister logic's primitives in 2–3 pages:
   the artefact-store points-to relation, the time-indexed sealing
   predicate, the worst-case universal-contract for stages with
   weakened keys. This document is the gate to actions 2, 4, 5, 6.
1. *(was 1)* Read Cerisier in full. Verify the WebFetch caveats above.
2. *(was 2)* Map sigil's attestation chain to **the sister logic's**
   vocabulary (not Cerisier's directly).
3. *(was 3)* Write down concrete trust-evolution scenarios sigil cannot
   reason about today; for each, what the sister logic would say.
4. *(was 4, **deferred**)* PQ migration as worked example. Cannot be
   first because it requires the sister logic to exist in sketch form.
5. *(was 5)* Compose with TrustMee (arXiv 2602.13148) — the
   "Wasm-as-the-attestation-verifier" complement. Publication target:
   PLDI / OOPSLA / CCS 2027.
6. *(was 6)* Public write-up on pulseengine.eu. Stronger when framed as
   "we found Cerisier formalises the wrong half of the problem; here is
   the half that needs lifting" rather than "we are adopting Cerisier".

## Open questions

- Is the reframing of action 4 (deferred behind a sister-logic sketch)
  acceptable, or does the engineering forcing-function (real PQ artefacts
  arriving) require an interim ad-hoc approach?
- Does the publication target group at PulseEngine include a Coq/Iris
  user who can drive the sister-logic work, or does this need an
  external collaborator?
- What is the right scope for the sister logic's first version — full
  time-indexed predicates, or a simpler "two-epoch" model (pre-PQ vs
  post-PQ) that can ship sooner?

## References

- arXiv 2604.13638 — *Cerisier: A Program Logic for Attestation in a
  Capability Machine* (Rousseau, Carnier, Van Strydonck, Keuchel,
  Devriese, Birkedal, April 2026).
- arXiv 2602.13148 — *TrustMee* (Wasm-as-the-attestation-verifier).
- [`src/attestation/src/lib.rs`](../../src/attestation/src/lib.rs) —
  sigil's canonical attestation schema.
- PulseEngine blog, April 2026 — sigil pipeline overview (meld, loom,
  synth, kiln).
