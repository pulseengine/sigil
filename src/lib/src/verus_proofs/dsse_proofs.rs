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

/// THEOREM (CV-22, part 1): PAE is injective over the payload-type
/// component. If `type1 != type2`, the PAE encodings differ regardless
/// of which (common) payload is appended.
///
/// Proof structure (contrapositive on `pae1 == pae2`):
///
///   1. **Structural length.** Each `add` adds `Seq` lengths, so
///      `spec_pae(t, p).len() == 24 + t.len() + p.len()`. Equality of
///      the full encodings therefore forces `type1.len() == type2.len()`
///      directly — without needing `lemma_le64_injective`, which was the
///      original plan but turns out to be redundant because `Seq::add`
///      already exposes the length structurally.
///   2. **Byte-by-byte at the type slot.** For `0 <= i < type1.len()`,
///      byte `16 + i` of `spec_pae(t, p)` equals `t[i]`. This is just
///      iterated `Seq::add` indexing: the first two `add`s contribute
///      bytes 0..16 (item_count, type_len), the third `add` puts the
///      type bytes at offsets 16..16+t.len(), and the final two `add`s
///      do not perturb earlier indices.
///   3. **Extensionality.** Same length + byte-wise equality lifts to
///      `type1 =~= type2`, contradicting `requires type1 != type2`.
pub proof fn theorem_pae_injective_on_types(
    type1: Seq<u8>,
    type2: Seq<u8>,
    payload: Seq<u8>,
)
    requires type1 != type2,
    ensures spec_pae(type1, payload) != spec_pae(type2, payload),
{
    let ic = spec_le64(2);
    let tl1 = spec_le64(type1.len() as u64);
    let tl2 = spec_le64(type2.len() as u64);
    let pl = spec_le64(payload.len() as u64);
    let pae1 = spec_pae(type1, payload);
    let pae2 = spec_pae(type2, payload);

    // ── Step 1: length of every prefix ────────────────────────────────
    // `spec_le64` always produces a length-8 sequence (8 explicit
    // elements in the `seq!` macro). Verus sees this by unfolding the
    // `seq![..]` expansion.
    assert(ic.len() == 8);
    assert(tl1.len() == 8);
    assert(tl2.len() == 8);
    assert(pl.len() == 8);

    // `Seq::add` is total and length-additive; these are pure facts
    // about `+` on sequence lengths.
    let s1a = ic.add(tl1);                          // len 16
    let s1b = s1a.add(type1);                        // len 16 + |type1|
    let s1c = s1b.add(pl);                           // len 24 + |type1|
    let s1d = s1c.add(payload);                      // len 24 + |type1| + |payload|
    assert(s1a.len() == 16);
    assert(s1b.len() == 16 + type1.len());
    assert(s1c.len() == 24 + type1.len());
    assert(s1d.len() == 24 + type1.len() + payload.len());
    assert(pae1 == s1d);

    let s2a = ic.add(tl2);
    let s2b = s2a.add(type2);
    let s2c = s2b.add(pl);
    let s2d = s2c.add(payload);
    assert(s2a.len() == 16);
    assert(s2b.len() == 16 + type2.len());
    assert(s2c.len() == 24 + type2.len());
    assert(s2d.len() == 24 + type2.len() + payload.len());
    assert(pae2 == s2d);

    // ── Step 2: contrapositive ────────────────────────────────────────
    if pae1 == pae2 {
        // Total lengths match ⇒ |type1| == |type2|.
        assert(pae1.len() == pae2.len());
        assert(24 + type1.len() + payload.len()
            == 24 + type2.len() + payload.len());
        assert(type1.len() == type2.len());

        // For every i in [0, type1.len()), expose
        //   pae1[16 + i] == type1[i]   and   pae2[16 + i] == type2[i].
        //
        // Proof per index: with offset `off = 16 + i` and `i' = off - 16`,
        //   - `s1b[off] == type1[i']` by `Seq::add` indexing on
        //     `ic.add(tl1).add(type1)`, since `off >= 16 == s1a.len()`
        //     and `i' < type1.len()`.
        //   - `s1c[off] == s1b[off]` because `off < s1b.len() == s1c.len() - 8`,
        //     so the `add(pl)` does not affect this index.
        //   - `s1d[off] == s1c[off]` for the same reason on `add(payload)`.
        //   Combined: `pae1[off] == type1[i]`.
        // The same chain applies symmetrically to pae2.
        assert forall|i: int| 0 <= i < type1.len() implies type1[i] == type2[i] by {
            let off = 16 + i;
            assert(0 <= off);
            assert(off < pae1.len());

            // pae1[off] == type1[i]
            assert(s1a.len() == 16);
            assert(off >= s1a.len());
            assert(off - s1a.len() == i);
            assert(off - s1a.len() < type1.len());
            assert(s1b[off] == type1[i]);
            assert(off < s1b.len());
            assert(s1c[off] == s1b[off]);
            assert(s1d[off] == s1c[off]);
            assert(pae1[off] == type1[i]);

            // pae2[off] == type2[i]
            assert(s2a.len() == 16);
            assert(off >= s2a.len());
            assert(off - s2a.len() == i);
            assert(off - s2a.len() < type2.len());
            assert(s2b[off] == type2[i]);
            assert(off < s2b.len());
            assert(s2c[off] == s2b[off]);
            assert(s2d[off] == s2c[off]);
            assert(pae2[off] == type2[i]);

            // Equality of pae1 and pae2 at this index forces the
            // type-bytes to agree.
            assert(pae1[off] == pae2[off]);
        };

        // Extensionality: same length + agree at every index ⇒ equal.
        assert(type1 =~= type2);
        assert(type1 == type2);
    }
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
