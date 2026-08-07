# STPA-Sec on the keyless verification subsystem — 2026-05-25

Triggered by issue #135 (`wsc verify --keyless` accepted tampered WASM).
Systems-Theoretic Process Analysis (security extension) applied to
`src/lib/src/signature/keyless/` and the verify CLI dispatch at
`src/cli/main.rs:895–917`. Read-only analysis; all findings independently
verified against the code at HEAD of branch `fix/keyless-verify-binds-artifact`
before being reported here.

PRs landing fixes from this analysis:
- **PR #136** (v0.9.1): closes the original #135 finding + **UCA-2** below.
- **v0.9.2**: closes **UCA-4** (#139) and **UCA-5** (#140) below.

Outstanding work tracked as separate issues:
- **UCA-1** → #137 — **still open, reclassified.** Wiring the existing
  inclusion-proof verifier into the verify path (v0.9.2 attempt) revealed
  the verifier recomputes the wrong Merkle root for fresh production Rekor
  entries (`log2025-*` shards, Rekor v2 / tiled-log migration). Blocked on
  fixing the verifier; until then verify relies on the SET alone.
- **UCA-3** → see #138 — **still open** (needs a clock-policy decision).
- **UCA-4** → #139 — **closed in v0.9.2.**
- **UCA-5** → #140 — **closed in v0.9.2.**

## 1. Subsystem under analysis

The keyless signature verification path of `sigil`/`wsc`: the code that,
when a user runs `wsc verify --keyless <module.wasm>`, decides whether to
return exit 0 or exit non-zero. Rooted at `KeylessVerifier::verify()`
(`src/lib/src/signature/keyless/signer.rs:554–678`), dispatched from
`src/cli/main.rs:899–917`.

## 2. Losses and hazards

| ID | Description |
|---|---|
| **L1** | Verifier returns success on a module the cert holder did not sign. |
| **L2** | Verifier returns success on a module whose contents differ from what the cert holder signed. |
| **L3** | Verifier returns success despite the cert/identity/issuer being attacker-controlled or expired. |
| **L4** | Verifier returns success when Rekor evidence is missing, forged, stale, or refers to a different artifact. |
| **L5** | A signature blob is replayable across artifacts, identities, or time windows beyond design intent. |
| **L6** | Audit log records an artifact hash that does not match what was verified, breaking forensic traceability. |

Hazards (worst-case system states that lead to losses):
- **H-A** A control action that should gate the outcome on a property is never invoked.
- **H-B** A control action observes attacker-supplied feedback as if it were trusted.
- **H-C** A cached decision is reused across requests that do not share the cached property's scope.
- **H-D** A property is checked against fields the attacker can independently set.

## 3. Control structure

```
                +---------------------------+
                |   CLI verb 'verify'       |
                |   src/cli/main.rs:895-917 |
                +-------------+-------------+
                              | constructs KeylessVerifier::new()
                              v
  +-------------------------------------------------------+
  |  KeylessVerifier::verify()  signer.rs:554-678         |
  |---|extract_signature|--|verify_cert_chain|--|SET|--|  |
  |                                       |--|cache|--|  |
  |                                            |verify_artifact_binding|
  |                                            |verify_rekor_body_binds_to_bundle  ← NEW (UCA-2)
  +---|-----------------|----------------|--------|------+
      v                 v                v        v
  extract_signature  cert_pool         RekorKeyring    KeylessSignature
  (signer.rs:498)    .verify_pem_cert  .verify_set     .verify_artifact_binding
                     (cert_verifier.rs (rekor_verifier  (format.rs:483)
                     :194)             .rs:498)        .verify_rekor_body_binds_to_bundle
                                       (NOT verify_inclusion_proof!)  (format.rs, new)

Controlled processes: candidate Module bytes, OS exit code, audit log.

Feedback consumed:
  - cert_chain (attacker-controlled until pinned root chains it)
  - rekor_entry.signed_entry_timestamp + body + integrated_time + log_id
    (attacker-controlled before SET check; Rekor-bound after SET check)
  - signature (P-256 sig, attacker-controlled)
  - module_hash field stored in signature (attacker-controlled until
    artifact-binding check)
  - candidate module bytes (attacker-controlled)
```

## 4. Verified UCAs

### UCA-1 — Rekor Merkle inclusion proof is never verified on the production verify path

**Status:** open, reclassified (#137). The v0.9.2 attempt to wire
`verify_rekor_inclusion()` into the verify path showed the existing
inclusion-proof verifier (`RekorKeyring::verify_inclusion_proof`)
recomputes the wrong Merkle root for fresh production Rekor entries on the
`log2025-*` shards — the SET verifies, but the computed root does not match
the proof's `root_hash` (observed e.g. computed `a3dd3a1b…` vs expected
`b32b6966…` for log index 1672253805). This is the Rekor v2 / tiled-log
migration: the leaf-index→Merkle-path mapping (and/or leaf-hash derivation)
the verifier uses no longer matches the live log. The gap is therefore
broader than "verifier unwired" — the verifier itself does not work against
current Rekor. Wiring it in fail-closed would reject all legitimate
keyless signatures, so it stays unwired until fixed.

- **Mapped losses:** L4, L5
- **Code citation:** `signer.rs:583–623` (`KeylessVerifier::verify`); the
  missing call would be `keyless_sig.verify_rekor_inclusion()` defined at
  `format.rs:437` but never invoked.
- **STPA-4 questions:**
  1. Provided when it shouldn't be? — N/A
  2. **Not provided when it should be? — YES.** Only `RekorKeyring::verify_set`
     runs (`signer.rs:612`). `verify_inclusion_proof`
     (`rekor_verifier.rs:724`) is never reached.
  3. Too early/late? — N/A
  4. Stopped too soon? — In the sense that SET-only is treated as the
     full Rekor proof: yes.
- **Loss scenario:** Rekor's SET only attests "Rekor signed this
  `(body, integratedTime, logID, logIndex)` tuple at some point." It
  does **not** prove inclusion in the Merkle tree. A misbehaving Rekor
  instance, a Rekor key-compromise, or a Rekor operator producing
  parallel "side log" entries that are signed but never integrated would
  pass `verify_set`. SLSA Build L3 non-falsifiability is dropped.
- **Suggested fix:** After `verify_set` succeeds at `signer.rs:612`, also
  call `verifier.verify_inclusion_proof(&keyless_sig.rekor_entry)?`. Cache
  the verified inclusion proof in the same cache slot (see UCA-4 for
  cache-consumption semantics).
- **Verification trail:**
  - `grep -n "verify_inclusion_proof\|verify_rekor_inclusion\|verify_entry" src/lib/src/signature/keyless/signer.rs` → 0 hits.
  - `grep -rn 'verify_rekor_inclusion'` → only `format.rs:452` (definition)
    and `format.rs:787` (unit test). No production caller.
- **Cross-ref:** Strengthens audit **C-5** from 2026-04-30. C-5 framed
  this as "inclusion-proof failures silently downgraded to SET-only
  fallback" — the actual code is stronger: there is no inclusion-proof
  attempt at all from `verify()`, so nothing to fall back from.

### UCA-2 — Rekor body field never decoded or cross-referenced with the bundle (FIXED IN PR #136)

**Status:** closed by PR #136.

- **Mapped losses:** L4, L5
- **Code citation (before fix):** `signer.rs:554–678`;
  `grep -rn "rekor_entry.body" src/lib/src/signature/keyless/ | grep -v test`
  returned only `rekor_verifier.rs:544,754,755` (SET canonicalisation
  and inclusion-proof leaf-hash inputs), never a comparison against the
  artifact's signature or pubkey.
- **STPA-4 questions:**
  1. Provided when it shouldn't be? — N/A
  2. **Not provided when it should be? — YES.**
  3. Too early/late? — N/A
  4. Stopped too soon? — Yes; SET verification stopped before body
     interpretation.
- **Loss scenario (concrete):** An attacker
  1. Generates a fresh ECDSA P-256 keypair.
  2. Requests a *legitimate* Fulcio cert for their own OIDC identity —
     any signed-in GitHub/Google user can do this; no privilege needed.
  3. Signs malicious module M' with their key.
  4. Constructs a `KeylessSignature` with their genuine signature,
     their genuine cert chain, `module_hash = SHA256(M')`, **and any
     unrelated public Rekor entry** — e.g., the entry for someone else's
     hello-world module from 2024.
  5. Runs `wsc verify --keyless`. All gates pass:
     - `extract_signature` ✓
     - `verify_cert_chain` ✓ (the cert is real)
     - `verify_set` ✓ (the borrowed Rekor entry is real)
     - `verify_artifact_binding` ✓ (PR #136 only proves bundle-internal
       consistency — the attacker's sig really does verify against M'
       under their cert)
     - identity/issuer ✓ (defaults to None on the CLI; attacker's
       identity is *displayed*, not constrained)
  6. Exit 0. A consumer reading "verified successfully" trusts the
     artifact. The Rekor entry referenced a completely different artifact.
- **Fix landed (PR #136):** `KeylessSignature::verify_rekor_body_binds_to_bundle`
  decodes the hashedrekord body and asserts three equalities:
  1. `body.spec.data.hash.algorithm == "sha256"` and
     `body.spec.data.hash.value == hex(self.module_hash)`.
  2. `base64_decode(body.spec.signature.content) == self.signature`.
  3. Leaf cert DER from
     `base64_decode(body.spec.signature.publicKey.content)` byte-equals
     the bundle's leaf cert DER (PEM-parsed for normalisation).

  Wired into `KeylessVerifier::verify` as step 5, between artifact
  binding and identity-claim checks. Ten new unit tests cover happy
  path + each tamper type.
- **Verification trail (before fix):**
  - `grep -rn "rekor_entry.body\|entry.body" src/lib/src/signature/keyless/ | grep -v test`
    → only SET canonicalisation and leaf-hash inputs.
  - Read of `verify_set` (`rekor_verifier.rs:498–573`) confirms `body`
    passed verbatim into JCS canonicalisation; never parsed as
    hashedrekord.

### UCA-3 — Cert validity window is bound to attacker-pickable `integrated_time`

**Status:** open. Tracked as issue.

- **Mapped losses:** L3, L5
- **Code citation:** `format.rs:396–415` parses `integrated_time` from
  `self.rekor_entry.integrated_time` and uses it as the
  `verification_time` passed to WebPKI's `verify_for_usage` via
  `CertificatePool::verify_pem_cert` (`cert_verifier.rs:194–238`).
- **STPA-4 questions:**
  1. Provided when it shouldn't be? — N/A
  2. Not provided when it should be? — Partially; missing is "is this
     `integrated_time` bound to *this* artifact?"
  3. **Too early/late? — YES.** Cert validity is checked at a moment the
     attacker chooses (by selecting which Rekor entry to embed), not at
     the moment this artifact was signed.
  4. Stopped too soon? — N/A
- **Loss scenario:** Builds on UCA-2. Attacker's Fulcio cert was valid
  for, say, 10 minutes on 2025-03-01 (Fulcio short-lived certs). The
  cert has now expired. The attacker generates a new malicious module M',
  signs it with the *expired* cert's still-held private key, and
  packages it with any Rekor entry whose `integrated_time` falls within
  the cert's old validity window. Since `integrated_time` drives the
  WebPKI verification clock (`format.rs:402,412`), the cert appears valid.

  After PR #136 closes UCA-2, this attack collapses to "you also have to
  control a Rekor entry whose body matches your bundle." Forging such an
  entry is hard, but cherry-picking an old `integrated_time` for a body
  the attacker controls remains a partial loss of forward security.
- **Suggested fix:** Tie cert-validity time to a field bound to the
  artifact. The natural fix is to use the Rekor entry's logged time
  (now safely bound to the bundle after UCA-2) but additionally verify
  the cert was valid at *signing* time per the body's logged signature,
  not just at *log integration* time.
- **Verification trail:** Re-read `format.rs:396–415` and
  `cert_verifier.rs:194–238`; `integrated_time` flows directly into
  `UnixTime::since_unix_epoch(...)` with no artifact-bound anchoring.
- **Cross-ref:** Adjacent to audit **H-3** but a different shape — H-3
  is about clock manipulation; this is about which clock the verifier
  reads.

### UCA-4 — Proof cache hit skips SET re-verification with no bundle-equality check

**Status:** closed in v0.9.2 (#139). `CacheKey::from_entry` now binds the
full entry content (all fields, length-prefixed), so a hit can only occur
for a byte-identical, already-fully-verified entry.

- **Mapped losses:** L4, L5
- **Code citation:** `signer.rs:593–623`; cache key construction at
  `signer.rs:594–597`; cache definition at `proof_cache.rs:36–60`.
- **STPA-4 questions:**
  1. **Provided when it shouldn't be? — YES.** On cache hit, SET
     re-verification is skipped (`signer.rs:609`); the cached
     `RekorEntry` itself is *not consulted at all* — note
     `let Some(_cached_proof) = cache.get(&cache_key)` at `signer.rs:600`,
     where the cached proof is bound to `_` and discarded.
  2. Not provided when it should be? — Yes (re-validation that the
     cached entry's `body` matches the current bundle).
  3. **Too early/late? — YES.** The cache is consulted *before* SET, but
     the key is only `(SHA256(signed_module_bytes), keyless_sig.rekor_entry.uuid)`,
     both attacker-controllable, and `keyless_sig.rekor_entry` is *not*
     asserted to equal the cached `RekorEntry`.
  4. Stopped too soon? — N/A
- **Loss scenario:** Combine with UCA-2 (pre-fix) or with a not-yet-found
  partial UCA-2 bypass. Suppose a legitimate signed module M was cached
  after a successful network verification — the cache holds
  `(hash(M), uuid_X) -> CachedProof { entry: real_entry_X }`. An
  attacker constructs a new bundle: keeps the same signed module bytes M
  (so `hash(M)` is unchanged) but mutates the *embedded* `keyless_sig`
  so its `rekor_entry` is `RekorEntry { uuid: "uuid_X", body: <forged>, ... }`.
  Because the cache key is `(hash(M), "uuid_X")`, the cache hits; SET
  re-verification is skipped; the cached `CachedProof` is discarded
  (`_cached_proof`); the verifier proceeds with the attacker's *mutated*
  `keyless_sig.rekor_entry` for downstream extraction.

  Today (post-PR-#136) the downstream consumer is identity/issuer
  extraction + body cross-check. UCA-2 fix means the forged body must
  still match the bundle — but the cache made the SET check itself
  irrelevant, which loses one layer of defence in depth.
- **Suggested fix:** Either (a) use the cached `CachedProof.entry` for
  downstream steps, replacing `keyless_sig.rekor_entry` so the cache
  becomes authoritative; or (b) on cache hit, assert
  `cached_proof.entry == keyless_sig.rekor_entry` before skipping the
  network round-trip; or (c) make the cache key include a hash of
  `keyless_sig.rekor_entry` itself, not just its `uuid`.
- **Verification trail:** Read `signer.rs:599–607`; `_cached_proof`
  explicitly discarded. Cache key at `signer.rs:594–597` shows only
  `(hash_hex, uuid)`. `proof_cache.rs:34–60` confirms `CacheKey` has no
  signature/body field.
- **Cross-ref:** Adjacent to **H-5** but a distinct failure mode
  (consumption-side rather than population-side).

### UCA-5 — Audit log records artifact hash from silently-discarded serialize error

**Status:** closed in v0.9.2 (#140). The artifact-hash computation now
propagates the serialize error with `?` instead of `.ok()`, so no
empty-input hash is ever recorded.

- **Mapped losses:** L6
- **Code citation:** `signer.rs:569–573`:

  ```rust
  let mut module_bytes = Vec::new();
  module.serialize(&mut module_bytes).ok();        // error swallowed
  let module_hash = Sha256::digest(&module_bytes); // hash over possibly-empty vec
  let artifact_hash = format!("sha256:{}", hex::encode(&module_hash));
  ```
- **STPA-4 questions:**
  1. Provided when it shouldn't be? — Yes; the audit-logged
     `artifact_hash` is recorded as if authoritative.
  2. Not provided when it should be? — Yes; the verifier swallows a
     serialization failure that should abort.
  3. Too early/late? — N/A
  4. Stopped too soon? — Yes; `.ok()` discards the `Result`.
- **Loss scenario:** If `module.serialize` errors (e.g., on a malformed
  input the serializer cannot round-trip), `module_bytes` remains empty
  and the audit log writes
  `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  (SHA-256 of empty) as the "artifact hash that was verified." Forensics
  on the audit trail sees an empty-hash record. The cache key
  (`signer.rs:594–597`) uses the same `module_hash`, so all such error
  cases share a single cache slot — observable collision.

  The artifact-binding step (`format.rs:495–499`) uses its own
  serialization that propagates errors, so this is **not** a verification
  bypass — but it is a correctness gap and audit-trail integrity loss.
- **Suggested fix:** Replace `.ok()` with `?`; or compute the audit-hash
  from the stripped-bytes already produced inside `verify_artifact_binding`.
- **Verification trail:** `signer.rs:569–573`; `module.serialize(...)`
  returns `Result<(), CoreError>` (`src/verify-core/src/wasm_module/mod.rs:323`).
  Cache key reuse confirmed at `signer.rs:594–597`.
- **Cross-ref:** Not in prior audit. Novel.

## 5. Cross-reference to existing audit

| This report | Prior audit (`audit/2026-04-30/findings.md`) | Relationship |
|---|---|---|
| UCA-1 | **C-5** | Same root cause; this report finds gap is broader (inclusion not attempted, not just degraded). |
| UCA-2 | none | Novel. Most direct #135-class gap. **Closed by PR #136.** |
| UCA-3 | adjacent to **H-3** | Different shape — H-3 is clock manipulation; UCA-3 is artifact-bound time-source choice. |
| UCA-4 | adjacent to **H-5** | Different shape — H-5 is cache population; UCA-4 is cache consumption. |
| UCA-5 | none | Novel. Audit-trail correctness, not verification correctness. |

## 6. Speculative items not verified

- **Multi-SAN selection** (`format.rs:249–268`): `get_identity()` returns
  the first `RFC822Name` SAN. Behaviour under multi-identity SANs
  unverified; depends on Fulcio policy.
- **`module.serialize` determinism**: `verify_artifact_binding` recomputes
  the hash by stripping then re-serializing. Byte-exact reversibility
  across `deserialize → strip → serialize` for all valid inputs not
  verified (e.g., custom sections with non-canonical varint encoding).
- **Section-ordering ambiguity**: `extract_signature` (`signer.rs:498–512`)
  uses `.find()`; `detach_signature` (`split.rs:70–88`) requires FIRST
  section to be signature header. If a module had two custom sections
  both named `"signature"`, the helpers would disagree. Could not
  construct a verifying attack (both fail-closed) but worth pinning down.
- **`module.clone()` inside `verify_artifact_binding`** (`format.rs:491–494`):
  could not confirm there are no `Module` fields whose `Clone` impl
  loses information relevant to serialization.

## 7. What this analysis explicitly cleared

- **Skip-Rekor sentinel** (`signer.rs:587–591`) correctly rejects modules
  signed with `skip_rekor=true` before the cache path. Confirmed against
  `rekor.rs:45–50`.
- **Empty cert chain on artifact binding** (`format.rs:516–519`)
  fails-closed with `VerificationFailed` even though `verify()` already
  catches it. Defence-in-depth holds (test at `format.rs:1136–1145`).
- **Chain depth bound** (`format.rs:387–389`) caps at `MAX_CHAIN_DEPTH = 8`
  before any x509 parsing. 100-cert synthetic test (`format.rs:835–854`)
  confirms rejection at the depth guard. Closes audit H-2 in keyless scope.
- **Negative `integrated_time`** (`cert_verifier.rs:221–226`) explicitly
  rejected before the `i64 → u64` cast — bypass via wrap-to-future
  closed.
- **Tampered-byte detection (PR #136)**: `verify_artifact_binding`
  (`format.rs:483–571`) catches all four bundle-tampering attacks its
  test suite demonstrates: byte flip, corrupted signature, substituted
  `module_hash`, substituted cert. Original #135 attack class is closed.
- **Rekor body cross-check (PR #136)**: `verify_rekor_body_binds_to_bundle`
  (`format.rs`) catches the cross-binding gap of UCA-2 — body's
  `data.hash`, `signature.content`, and `signature.publicKey` must all
  match bundle. Tests for each tamper case.
- **Issuer normalisation on signing** (`signer.rs:322–331`) normalises
  trailing slashes (closes audit AS-13). Slight inconsistency vs verify
  path (`signer.rs:651–660` uses exact match) but neither is
  over-permissive.
- **Rekor SET signing-key fingerprint mismatch** (`rekor_verifier.rs:585–609`)
  validates checkpoint signature's key fingerprint against keyring.
- **Empty `signed_entry_timestamp` rejection** (`rekor_verifier.rs:499–503`)
  rejects on empty SET. Note: only fires in non-cache branch — see UCA-4.

## Out-of-scope observations (noted, not elaborated)

- `src/lib/src/sct.rs:124–131` is a non-functional stub with placeholder
  CT-log keys, and `keyless/` never invokes the SCT verifier — Fulcio's
  embedded SCTs are entirely unchecked. Separate subsystem; deserves its
  own STPA. Touches audit L-4 / SC-26.
- DSSE/attestation paths, airgapped bundle verification, and the
  traditional `pk.verify` path (`src/cli/main.rs:919–962`) were not
  analysed. They deserve their own STPA passes.
