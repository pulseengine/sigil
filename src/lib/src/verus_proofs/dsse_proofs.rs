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

/// LEMMA (CV-22 supporting): little-endian u64 encoding is injective.
///
/// Proof approach: contrapositive via byte-wise equality.
///   1. If the two `Seq<u8>` outputs are equal, all eight indexed bytes
///      are equal. Indexing `seq![x0..x7][i]` reduces to `xi` directly
///      from the macro expansion, so each `sa[i] == sb[i]` exposes the
///      corresponding `(a >> 8*i) & 0xFF` slice.
///   2. A single `assert(...) by(bit_vector)` call discharges that the
///      eight byte-slice equalities together imply `a == b`. This is a
///      pure bit-vector tautology that Verus' bit-vector solver decides
///      directly — every bit of `a` and `b` is captured by exactly one
///      of the eight `0xFF`-masked shifts.
///   3. Combining (1) and (2) under the assumption `sa == sb` yields
///      `a == b`, contradicting the `requires a != b` precondition.
pub proof fn lemma_le64_injective(a: u64, b: u64)
    requires a != b,
    ensures spec_le64(a) != spec_le64(b),
{
    let sa = spec_le64(a);
    let sb = spec_le64(b);

    // Step 1: Bit-vector tautology — if all eight LE byte-slice equalities
    // hold simultaneously, the u64s themselves are equal. Phrased as a
    // closed quantifier-free goal in (a, b) so the bit-vector solver
    // decides it directly. Slices stay as u64 (`0xFF` mask) rather than
    // `as u8` so the bv backend reasons in a single sort.
    assert(
        (
            (a & 0xFF) == (b & 0xFF)
            && ((a >> 8) & 0xFF) == ((b >> 8) & 0xFF)
            && ((a >> 16) & 0xFF) == ((b >> 16) & 0xFF)
            && ((a >> 24) & 0xFF) == ((b >> 24) & 0xFF)
            && ((a >> 32) & 0xFF) == ((b >> 32) & 0xFF)
            && ((a >> 40) & 0xFF) == ((b >> 40) & 0xFF)
            && ((a >> 48) & 0xFF) == ((b >> 48) & 0xFF)
            && ((a >> 56) & 0xFF) == ((b >> 56) & 0xFF)
        ) ==> a == b
    ) by (bit_vector);

    // Step 2: Bit-vector bridge — `(x & 0xFF) as u8 == (y & 0xFF) as u8`
    // is equivalent to `(x & 0xFF) == (y & 0xFF)` because the masked
    // value already fits in u8, so the truncating cast is value-preserving.
    // Eight concrete instantiations so no triggers are needed.
    assert((a & 0xFF) as u8 == (b & 0xFF) as u8
        <==> (a & 0xFF) == (b & 0xFF)) by (bit_vector);
    assert(((a >> 8) & 0xFF) as u8 == ((b >> 8) & 0xFF) as u8
        <==> ((a >> 8) & 0xFF) == ((b >> 8) & 0xFF)) by (bit_vector);
    assert(((a >> 16) & 0xFF) as u8 == ((b >> 16) & 0xFF) as u8
        <==> ((a >> 16) & 0xFF) == ((b >> 16) & 0xFF)) by (bit_vector);
    assert(((a >> 24) & 0xFF) as u8 == ((b >> 24) & 0xFF) as u8
        <==> ((a >> 24) & 0xFF) == ((b >> 24) & 0xFF)) by (bit_vector);
    assert(((a >> 32) & 0xFF) as u8 == ((b >> 32) & 0xFF) as u8
        <==> ((a >> 32) & 0xFF) == ((b >> 32) & 0xFF)) by (bit_vector);
    assert(((a >> 40) & 0xFF) as u8 == ((b >> 40) & 0xFF) as u8
        <==> ((a >> 40) & 0xFF) == ((b >> 40) & 0xFF)) by (bit_vector);
    assert(((a >> 48) & 0xFF) as u8 == ((b >> 48) & 0xFF) as u8
        <==> ((a >> 48) & 0xFF) == ((b >> 48) & 0xFF)) by (bit_vector);
    assert(((a >> 56) & 0xFF) as u8 == ((b >> 56) & 0xFF) as u8
        <==> ((a >> 56) & 0xFF) == ((b >> 56) & 0xFF)) by (bit_vector);

    // Step 3: Unfold spec_le64 at every index so each byte of the encoding
    // is visible to the SMT solver as the exact masked-shift slice. These
    // identities hold unconditionally (by the macro/spec definition of
    // `spec_le64`), not as a claim about the two encodings agreeing.
    assert(sa[0] == (a & 0xFF) as u8);
    assert(sa[1] == ((a >> 8) & 0xFF) as u8);
    assert(sa[2] == ((a >> 16) & 0xFF) as u8);
    assert(sa[3] == ((a >> 24) & 0xFF) as u8);
    assert(sa[4] == ((a >> 32) & 0xFF) as u8);
    assert(sa[5] == ((a >> 40) & 0xFF) as u8);
    assert(sa[6] == ((a >> 48) & 0xFF) as u8);
    assert(sa[7] == ((a >> 56) & 0xFF) as u8);
    assert(sb[0] == (b & 0xFF) as u8);
    assert(sb[1] == ((b >> 8) & 0xFF) as u8);
    assert(sb[2] == ((b >> 16) & 0xFF) as u8);
    assert(sb[3] == ((b >> 24) & 0xFF) as u8);
    assert(sb[4] == ((b >> 32) & 0xFF) as u8);
    assert(sb[5] == ((b >> 40) & 0xFF) as u8);
    assert(sb[6] == ((b >> 48) & 0xFF) as u8);
    assert(sb[7] == ((b >> 56) & 0xFF) as u8);
    assert(sa.len() == 8);
    assert(sb.len() == 8);

    // Step 4: Explicit contradiction in the equal-encoding case. Verus
    // takes the conditional as a hint to specialise reasoning to the
    // `sa == sb` branch, where congruence over `==` gives byte equalities
    // that, via the bridges (Step 2) and the bit-vector tautology (Step 1),
    // force `a == b` — contradicting `requires a != b`. Outside the
    // branch, the goal `sa != sb` follows trivially.
    if sa == sb {
        assert(sa[0] == sb[0]);
        assert(sa[1] == sb[1]);
        assert(sa[2] == sb[2]);
        assert(sa[3] == sb[3]);
        assert(sa[4] == sb[4]);
        assert(sa[5] == sb[5]);
        assert(sa[6] == sb[6]);
        assert(sa[7] == sb[7]);
        assert(a == b);
    }
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
