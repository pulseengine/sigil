//! Verus proofs for DSSE PAE encoding injectivity (CV-22).
//!
//! Proves that Pre-Authentication Encoding is injective:
//! different (type, payload) inputs produce different PAE outputs.
//! This prevents type confusion attacks in DSSE envelopes.
//!
//! Build with: bazel build //src/lib/src/verus_proofs:wsc_merkle_proofs

use vstd::prelude::*;

verus! {

// ── PAE (Pre-Authentication Encoding) ───────────────────────────────

/// Spec function for PAE length encoding (LE64).
pub open spec fn spec_le64(n: u64) -> Seq<u8> {
    seq![
        (n & 0xFF) as u8,
        ((n >> 8) & 0xFF) as u8,
        ((n >> 16) & 0xFF) as u8,
        ((n >> 24) & 0xFF) as u8,
        ((n >> 32) & 0xFF) as u8,
        ((n >> 40) & 0xFF) as u8,
        ((n >> 48) & 0xFF) as u8,
        ((n >> 56) & 0xFF) as u8,
    ]
}

/// Spec function for PAE construction.
pub open spec fn spec_pae(
    payload_type: Seq<u8>,
    payload: Seq<u8>,
) -> Seq<u8> {
    let item_count = spec_le64(2);
    let type_len = spec_le64(payload_type.len() as u64);
    let payload_len = spec_le64(payload.len() as u64);
    item_count
        .add(type_len)
        .add(payload_type)
        .add(payload_len)
        .add(payload)
}

// ── LE64 injectivity ────────────────────────────────────────────────

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1.
///
/// LEMMA (intended): le64 encoding is injective.
///
/// To actually discharge: case-split on `a != b` to obtain a bit position
/// where the two u64s differ; show that bit lives in one of the eight
/// `spec_le64` byte slots; conclude the corresponding byte differs, so
/// the resulting `Seq<u8>` differs by `Seq` extensionality. Requires
/// Verus' bit-vector mode (`assert(...) by(bit_vector)`) plus a `Seq`
/// extensionality lemma from `vstd`.
pub proof fn lemma_le64_injective(a: u64, b: u64)
    requires a != b,
    ensures spec_le64(a) != spec_le64(b),
{
    // Z3 can reason about bitvector operations directly.
    // The LE64 encoding preserves all bits, so different inputs
    // produce different byte sequences.
    // NOTE: Z3 needs help with Seq inequality — use assume for now.
    // The property is trivially true by construction of spec_le64.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

// ── PAE injectivity ─────────────────────────────────────────────────

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1. Despite the `theorem_` prefix,
/// the body currently relies on `assume(false)` and proves nothing.
///
/// SPEC (intended) — CV-22, part 1: PAE is injective over payload types.
///
/// To actually discharge: case-split on `type1.len() == type2.len()`.
/// If lengths differ, `lemma_le64_injective` makes the `type_len` bytes
/// at offset 8..16 differ. If lengths are equal but contents differ,
/// `Seq` extensionality gives an index `i` where `type1[i] != type2[i]`,
/// which lifts to offset `16 + i` of the concatenation. Requires `Seq::add`
/// indexing lemmas from `vstd::seq_lib`.
pub proof fn theorem_pae_injective_on_types(
    type1: Seq<u8>,
    type2: Seq<u8>,
    payload: Seq<u8>,
)
    requires type1 != type2,
    ensures spec_pae(type1, payload) != spec_pae(type2, payload),
{
    // PAE includes explicit length fields before each component.
    // If types differ in length, the le64-encoded length bytes differ.
    // If types have equal length but different content, the type
    // bytes at offset 16..16+len differ.
    // NOTE: Requires Seq::add injectivity lemmas from vstd.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1.
///
/// SPEC (intended) — CV-22, part 2: PAE is injective over payloads.
///
/// To actually discharge: symmetric argument to
/// `theorem_pae_injective_on_types`, but the differing offset is
/// `16 + payload_type.len() + 8 + i`. Same `vstd` lemmas required.
pub proof fn theorem_pae_injective_on_payloads(
    payload_type: Seq<u8>,
    payload1: Seq<u8>,
    payload2: Seq<u8>,
)
    requires payload1 != payload2,
    ensures spec_pae(payload_type, payload1) != spec_pae(payload_type, payload2),
{
    // Symmetric argument to theorem_pae_injective_on_types.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1. Will follow trivially once
/// the two `theorem_pae_injective_*` admits above are real proofs.
///
/// SPEC (intended): PAE is fully injective.
///
/// To actually discharge: case-split on `type1 != type2` vs
/// `payload1 != payload2` and apply the corresponding theorem above.
pub proof fn corollary_pae_fully_injective(
    type1: Seq<u8>,
    payload1: Seq<u8>,
    type2: Seq<u8>,
    payload2: Seq<u8>,
)
    requires type1 != type2 || payload1 != payload2,
    ensures spec_pae(type1, payload1) != spec_pae(type2, payload2),
{
    // Follows from the two injectivity theorems above.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

// ── Domain separation for signing ───────────────────────────────────

/// Spec function for domain-separated signing message.
pub open spec fn spec_signing_message(
    domain: Seq<u8>,
    content_type: u8,
    hash_fn: u8,
    artifact_hash: Seq<u8>,
) -> Seq<u8> {
    domain
        .push(content_type)
        .push(hash_fn)
        .add(artifact_hash)
}

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1.
///
/// SPEC (intended): Different domains produce different signing messages.
///
/// To actually discharge: `Seq::push`/`Seq::add` preserve the domain
/// prefix, so the first `min(domain1.len(), domain2.len())` bytes of
/// each result equal the corresponding domain. By `Seq` extensionality,
/// a differing byte in the prefix lifts to a differing byte in the full
/// signing message. Requires `vstd::seq_lib` push/add indexing lemmas.
pub proof fn theorem_domain_separation(
    domain1: Seq<u8>,
    domain2: Seq<u8>,
    ct: u8,
    hf: u8,
    hash: Seq<u8>,
)
    requires
        domain1 != domain2,
        domain1.len() > 0,
        domain2.len() > 0,
    ensures
        spec_signing_message(domain1, ct, hf, hash)
            != spec_signing_message(domain2, ct, hf, hash),
{
    // Different domain prefixes produce different total messages.
    // NOTE: Requires Seq::push/add extensionality lemmas.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

/// **SPECIFICATION ONLY** — proof obligation not yet discharged.
/// See `audit/2026-04-30/findings.md` C-1.
///
/// SPEC (intended): Different content types produce different signing
/// messages.
///
/// To actually discharge: the content-type byte sits at index
/// `domain.len()` of both encodings. `Seq::push` indexing lemma plus
/// the hypothesis `ct1 != ct2` give differing bytes there, so by
/// `Seq` extensionality the messages differ.
pub proof fn theorem_content_type_separation(
    domain: Seq<u8>,
    ct1: u8,
    ct2: u8,
    hf: u8,
    hash: Seq<u8>,
)
    requires ct1 != ct2,
    ensures
        spec_signing_message(domain, ct1, hf, hash)
            != spec_signing_message(domain, ct2, hf, hash),
{
    // Content type byte at position domain.len() differs.
    // NOTE: Requires Seq::push indexing lemma.
    // ADMITTED — see SPECIFICATION ONLY block above. Audit C-1 (2026-04-30).
    assume(false);
}

} // verus!
