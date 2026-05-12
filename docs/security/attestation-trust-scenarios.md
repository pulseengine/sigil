# Three trust-evolution scenarios — proposed Cerisier-style judgements

Companion to [docs/security/attestation-trust-formalization.md](attestation-trust-formalization.md)
and the vocabulary mapping document. The three scenarios below
illustrate trust-evolution patterns that sigil's current flat
verification model cannot answer compositionally. For each, we sketch
a Cerisier-style judgement that the proposed sister logic would
discharge.

**Status: draft.** The sister logic does not yet exist; these
judgements are proposed, not proven. They serve to make the predoc's
G1–G4 gaps concrete in the language of a working proof system.

## Notational conventions

- `P_i` — sealing-predicate for identity `i`
- `P_i^t` — time-indexed extension (G1 of the mapping doc)
- `P_i^σ` — scheme-parameterised extension (G2)
- `digest(w) ↦ w` — content-addressed points-to (G3)
- `rotate(i_old, i_new)` — key-rotation primitive (G4)
- `⊢ J` — the sister logic derives judgement `J`
- `∗` — separating conjunction
- `▷` — Iris later-modality / one possible candidate for time-indexing

These are working notations; the formal sister logic may pick different
symbols. The shape of each judgement is the substantive claim, not the
typeface.

## Scenario 1 — Cross-scheme transition during PQ migration

### Setting

A signing pipeline produces artefact `A_N` at stage `N` signed under
classical **Ed25519**, and artefact `A_{N+1}` at stage `N+1` signed
under **SLH-DSA / FIPS 205** (post-quantum). The transition is the
expected mid-migration state — the cutover is staged, not atomic. A
consumer receives the full chain and must decide what trust they
have on `A_{N+1}`.

### Threat scenarios mitigated

- TS-019 (PQC signature stripping)
- TS-020 (PQC negotiation downgrade)

### Today's answer (sigil's flat model)

The current verification walks the chain linearly. It can answer:
"are both signatures valid?" — yes or no. It **cannot** answer:
"given that stage N uses scheme `σ` and stage N+1 uses scheme `σ'`,
what does the composed trust state mean?" The downgrade risk is
implicit; the verifier has no formal handle on it.

### Proposed Cerisier-style judgement

```
P_i^{Ed25519}(A_N) ∗ P_i^{SLH-DSA}(A_{N+1}) ∗ migration_witness(σ_old=Ed25519, σ_new=SLH-DSA, between=N→N+1)
  ⊢ P_i^{post-migration}(A_{N+1})
```

In words: if (a) `A_N` carries the Ed25519-scheme sealing predicate for
identity `i`, AND (b) `A_{N+1}` carries the SLH-DSA-scheme sealing
predicate for the same identity, AND (c) we have a witness that the
migration from `Ed25519` to `SLH-DSA` happened between stages `N` and
`N+1`, then the post-migration trust predicate holds on `A_{N+1}`.

The load-bearing piece is `migration_witness`: it's a first-class
proof object that the migration was legitimate (signed under both
schemes, or signed by a designated migration authority). Without it,
no judgement can be derived — preventing the downgrade attack.

### What would have to be added to Cerisier

- The scheme parameter `σ` on the sealing predicate (extension G2)
- A `migration_witness` type (a sigil-specific primitive)
- The composition lemma derived from these

### Detailed obligations and frame-rule role

The obligation list the verifier must discharge to reach the
conclusion is:

1. **Sealing-predicate validity at the old scheme.** `P_i^{Ed25519}(A_N)`
   must be in the context — i.e. sigil already verified the Ed25519
   signature on `A_N` and registered `(i, Ed25519, A_N)` as a sealing
   fact.
2. **Sealing-predicate validity at the new scheme.** `P_i^{SLH-DSA}(A_{N+1})`
   must be similarly in the context for the post-quantum signature.
3. **Migration witness.** A separate proof object — itself a sealing
   predicate with a specially-designated identity `i_migrate` — that
   testifies "identity `i` migrated from `Ed25519` to `SLH-DSA` at the
   gap between `N` and `N+1`". In practice this is a transparency-log
   record (Rekor) entry co-signed under both schemes.

The frame rule of separation logic is what makes this composable: the
three premises live in disjoint resources, and once the conclusion
fires, an unrelated downstream proof for some `A_{N+2}` does not have
to re-walk the migration. The frame rule preserves the
post-migration predicate as a stable assertion. Under the flat model
sigil has today, no such stability exists — every downstream consumer
re-walks the entire chain and is implicitly re-asking the downgrade
question.

For **TS-020 (negotiation downgrade)** the danger is that a malicious
intermediary strips the post-quantum signature off `A_{N+1}` and
presents only the Ed25519 chain. In the flat model the verifier sees
"both signatures present? No → reject; only Ed25519 present? Accept,
because Ed25519 was the historically valid scheme." The sister logic
forbids this: the judgement's conclusion `P_i^{post-migration}` is
*only* derivable from the SLH-DSA premise. A consumer trying to
discharge "post-migration trust holds" with a stripped chain fails
syntactically — there is no `P_i^{SLH-DSA}` premise to feed the rule.
The downgrade attack becomes a proof-shaped impossibility rather than
a policy-layer check.

---

## Scenario 2 — Admitted lemma in upstream proof

### Setting

Stage `N+1`'s attestation references a Verus proof of a property `Q`.
The Verus proof body contains an `admit` (an unproven assumption) about
an externally-imported function, say `external_hash`. A consumer of the
attestation believes "we have proven `Q`," but the truth is "we have
proven `Q` modulo the assumption that `external_hash` behaves
correctly."

### Threat scenarios mitigated

Audit C-1 (the relabelled-spec issue from the 2026-04-30 audit), and
the broader class of trust-on-faith proof references.

### Today's answer

Sigil's verification doesn't know about Verus admits at all — the proof
is opaque. The consumer cannot tell whether `Q` was proven cleanly or
modulo assumptions.

### Proposed Cerisier-style judgement

```
P_i(A) carries "proof_of_Q with assumptions A_set"
  ⊢ Trust(Q on A) = ⨅_{a ∈ A_set} Trust(a)
```

In words: the trust state on a derived property `Q` is the meet (or
infimum, in a trust lattice) over the trust states of every assumption
the proof depends on. The "trust lattice" is the second extension we
need: trust isn't binary, it's ordered — proven ⪰ proven-modulo-trusted-axiom
⪰ proven-modulo-unverified-import ⪰ unproven.

### What would have to be added

- A trust lattice (not in Cerisier; partially in dependent-type theories
  like Lean4 with `Inhabited`-class typeclasses but not exactly the same)
- A proof-carrying-attestation primitive that explicitly lists
  assumptions (sigil could emit this today from Verus output)
- The composition lemma: `Trust(Q) = meet over assumptions`

### Worked example from audit PR #108

The 2026-04-30 audit raised two related findings on Verus proofs in
the codebase:

- `lemma_le64_injective` — fully discharged: no `admit`, no `assume`,
  no imported axiom beyond Verus's core. Under the proposed lattice,
  its trust label is `proven`.
- The remaining audit C-1 finding — a `proof fn` whose body contained
  `assume(false)` to short-circuit verification under a relabelled
  spec. Under the lattice this collapses to the bottom element
  `unproven`, because `assume(false)` is a maximally-weak assumption
  (it discharges everything by exploding the proof context).

The judgement's force is that a consumer of the attestation can
mechanically extract `A_set` — the list of admits, assumes, and
imported-but-unverified externs — and compute `⨅ Trust(a)`. If any
element of `A_set` is `assume(false)` or an opaque `extern`, the
overall trust collapses. The audit's manual review would have been
automated: the verifier would have rejected the attestation at
ingestion, surfacing the relabelled-spec issue without human
inspection of the proof body.

The frame-rule role here is dual to Scenario 1: rather than carrying a
strengthening predicate through a frame, this judgement carries a
*weakening* (the meet over an assumption set), which propagates
monotonically down any chain that re-uses `Q`. A downstream stage
that builds on `Q` cannot launder away the assumption — its own
conclusion is meet-bounded by the same `A_set`.

---

## Scenario 3 — Key rotation between stages

### Setting

The Ed25519 signing key was rotated between the signing of stage `N`
and stage `N+1`. The old keypair `K_old` is no longer in use; the new
keypair `K_new` is the canonical identity going forward. A consumer
of the chain must decide whether the chain is still trustworthy.

### Threat scenarios mitigated

- TS-012 (Rollback — signing an old artefact under a current key to
  re-trigger a deprecated trust state)
- TS-021 (Verified-then-revoked — the case where `K_old` is revoked
  after stage `N` was signed; does the chain still hold?)

### Today's answer

Sigil's flat verification has no notion of "key rotation event." If
both signatures verify under their respective keys, the chain is
accepted. The rollback risk is left to operational discipline (e.g.,
never reuse old keys for new artefacts) rather than enforced by the
verifier.

### Proposed Cerisier-style judgement

```
P_{K_old}(A_N) ∗ P_{K_new}(A_{N+1}) ∗ rotate(K_old → K_new, at time t)
  ⊢ Chain_Trust(A_N → A_{N+1}) ↔ (timestamp(A_N) < t < timestamp(A_{N+1}))
```

In words: chain trust survives the rotation **iff** the rotation
happened between the two stages' timestamps. The biconditional is
load-bearing: a rotation event whose time is outside `[timestamp(A_N),
timestamp(A_{N+1})]` invalidates the chain — covering both rollback
and verified-then-revoked.

### What would have to be added

- A first-class `rotate` primitive in the sister logic (extension G4)
- A time-indexed sealing predicate `P_i^t` (extension G1)
- The biconditional composition lemma

### Worked example using Sigstore Rekor's `signed_entry_timestamp`

In practice the time `t` is sourced from a transparency-log entry. The
Sigstore Rekor record for the rotation event carries a
`signed_entry_timestamp` countersigned by the log's own key, giving
the verifier a third-party-attested time witness that the rotation
was committed to the log at a particular moment. `timestamp(A_N)` and
`timestamp(A_{N+1})` are likewise read from the per-artefact Rekor
`signed_entry_timestamp` values.

Discharging the judgement then reduces to three checks the sister
logic can mechanise:

1. Look up the rotation record's `signed_entry_timestamp` → `t`.
2. Look up each artefact's `signed_entry_timestamp` → `t_N`, `t_{N+1}`.
3. Verify the strict inequality `t_N < t < t_{N+1}`.

Failure modes the biconditional explicitly catches:

- **Rollback (TS-012).** An attacker re-signs old content `A_N'` under
  `K_new` at present-day `t' > t_{N+1}`. Then `timestamp(A_N') > t`,
  so the rotation event is *before* `A_N'` and the left-hand side of
  the iff is false. Chain trust does not hold.
- **Verified-then-revoked (TS-021).** `K_old` is revoked at `t_rev`
  with `t_rev < t_N`. Then the rotation effectively happened before
  `A_N` was signed, so `t < t_N`, the inequality fails, and the chain
  is rejected — even though both individual signatures verify.

The Iris later-modality `▷` is a natural fit for `P_i^t`: a
sealing-predicate guarded by `▷^k` is one whose validity is asserted
only after `k` steps of logical time, lining up with the
step-indexed model Iris already supports. Whether `▷` carries enough
expressive power for *real* wall-clock comparisons or whether the
sister logic needs a richer time-monoid is an open design question
for the Iris embedding.

---

## What these three scenarios show

Together, the three scenarios cover the predoc's G1 (time), G2 (cross-
scheme), G3 is implicit in the content-addressed nature of sigil
artefacts, and G4 (key rotation). The mapping document's table breaks
down which sigil primitives need which extensions; this document shows
*why* each extension is load-bearing — i.e. what concrete threat scenario
each enables.

A sister logic that supports just the four extensions G1-G4 layered
on Cerisier's core would let sigil's verifier discharge all three
judgements. None of the three is currently derivable in the flat model.
